"""Tests for end-to-end CLI control flow and PTY edge cases."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import nocap.cli as cli
import nocap.routing as routing
import nocap.subcommands as subcommands


def test_dry_run_does_not_create_output_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit, match="0"):
        cli._main(["-D", "-s", "new/deep", "printf", "ok"])

    assert not (tmp_path / "new").exists()
    assert "new/deep/printf_ok.txt" in capsys.readouterr().out


def test_dot_subdir_writes_to_active_root(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit, match="0"):
        cli._main(["-D", "-s", ".", "printf", "ok"])

    assert capsys.readouterr().out.strip() == str(tmp_path / "printf_ok.txt")


def test_reports_positional_shorthand(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit, match="0"):
        cli._main(["-D", "reports", "printf", "ok"])

    assert capsys.readouterr().out.strip() == str(
        tmp_path / "reports" / "printf_ok.txt"
    )


def test_double_dash_escapes_subcommand_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subcommands, "_LAST_FILE", tmp_path / "last")
    invoked: list[list[str]] = []

    def fake_run(cmd: list[str], outfile: Path) -> int:
        invoked.append(cmd)
        return 0

    monkeypatch.setattr(cli, "_run_pty", fake_run)
    monkeypatch.setattr(cli, "_remember_last", lambda path: True)

    with pytest.raises(SystemExit, match="0"):
        cli._main(["--", "ls", "-la"])

    assert invoked == [["ls", "-la"]]
    assert (tmp_path / "ls_la.txt").is_file()


def test_rm_rejects_more_than_one_selector(capsys):
    with pytest.raises(SystemExit) as exc:
        subcommands._cmd_rm(["one", "two"])

    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_global_parse_error_stays_concise(capsys):
    with pytest.raises(SystemExit, match="2"):
        cli._main(["--bogus"])

    error = capsys.readouterr().err
    assert "unrecognized arguments: --bogus" in error
    assert "NOCAP — keep" not in error


def test_grab_help_does_not_require_tmux(monkeypatch, capsys):
    monkeypatch.delenv("TMUX", raising=False)

    with pytest.raises(SystemExit, match="0"):
        subcommands._cmd_grab(["--help"])

    assert "usage: cap grab" in capsys.readouterr().out


@pytest.mark.parametrize("subdir", ["../outside", "/tmp/outside"])
def test_output_dir_rejects_paths_outside_capture_base(subdir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="relative path"):
        routing._get_output_dir(subdir)


def test_explicit_missing_workspace_fails_closed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NOCAP_WORKSPACE", str(tmp_path / "missing"))

    with pytest.raises(ValueError, match="configured workspace does not exist"):
        routing._get_output_dir()


def test_explicit_missing_target_fails_closed_even_for_dry_run(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NOCAP_WORKSPACE", str(workspace))
    monkeypatch.setenv("TACMUX_TARGET", "typo/target")

    with pytest.raises(SystemExit, match="2"):
        cli._main(["-D", "id"])

    assert not (workspace / "typo").exists()


def test_header_write_failure_discards_claim_and_pending_metadata(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli,
        "_write_capture_header",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    with pytest.raises(SystemExit, match="2"):
        cli._main(["-q", "id"])

    assert list(tmp_path.glob("*.txt")) == []
    records = tmp_path / ".nocap" / "records"
    assert not records.exists() or list(records.glob("*.json")) == []


def test_redirected_stdin_reaches_child_process(tmp_path):
    """Regression test for commands hanging after stdin was replaced by a PTY."""
    outfile = tmp_path / "capture.txt"
    source_root = Path(__file__).resolve().parents[1] / "src"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(source_root)
    runner = (
        "import sys; from pathlib import Path; from nocap.cli import _run_pty; "
        f"raise SystemExit(_run_pty([sys.executable, '-c', "
        "'import sys; print(sys.stdin.read().upper(), end=\"\")'], "
        f"Path({str(outfile)!r})))"
    )

    result = subprocess.run(
        [sys.executable, "-c", runner],
        input=b"hello from pipe\n",
        capture_output=True,
        env=env,
        timeout=5,
    )

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"HELLO FROM PIPE" in result.stdout
    assert b"HELLO FROM PIPE" in outfile.read_bytes()


def test_signalled_child_returns_shell_compatible_status(tmp_path):
    outfile = tmp_path / "capture.txt"
    source_root = Path(__file__).resolve().parents[1] / "src"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(source_root)
    runner = (
        "import sys; from pathlib import Path; from nocap.cli import _run_pty; "
        f"raise SystemExit(_run_pty([sys.executable, '-c', "
        "'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'], "
        f"Path({str(outfile)!r})))"
    )

    result = subprocess.run(
        [sys.executable, "-c", runner],
        capture_output=True,
        env=env,
        timeout=5,
    )

    assert result.returncode == 143


def test_tmux_scrollback_reports_command_failure(monkeypatch):
    failed = subprocess.CompletedProcess(
        args=["tmux", "capture-pane"],
        returncode=1,
        stdout="",
        stderr="no server running",
    )
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: failed)

    with pytest.raises(RuntimeError, match="no server running"):
        subcommands._tmux_scrollback()


def test_remember_last_uses_absolute_path(tmp_path, monkeypatch):
    pointer = tmp_path / "cache" / "nocap" / "last"
    capture = tmp_path / "capture.txt"
    capture.write_text("output", encoding="utf-8")
    monkeypatch.setattr(subcommands, "_LAST_FILE", pointer)

    assert subcommands._remember_last(Path(os.path.relpath(capture))) is True
    assert Path(pointer.read_text(encoding="utf-8")) == capture.resolve()


@pytest.mark.parametrize(
    ("size", "expected"),
    [(42, "42B"), (1024, "1.0K"), (1024**2, "1.0M"), (3 * 1024**3, "3.0G")],
)
def test_format_size(size, expected):
    assert subcommands._format_size(size) == expected


def test_status_json_reports_effective_target_and_source(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TARGET", "10.10.10.5")
    workspace = tmp_path / "workspace"
    (workspace / "10.10.10.5").mkdir(parents=True)
    monkeypatch.setenv("NOCAP_WORKSPACE", str(workspace))

    subcommands._cmd_status(["--json"])

    result = json.loads(capsys.readouterr().out)
    assert result["target"] == "10.10.10.5"
    assert result["target_source"] == "TARGET"
    assert "tacmux_target" in result
