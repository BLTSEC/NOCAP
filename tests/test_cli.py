"""Tests for end-to-end CLI control flow and PTY edge cases."""

from __future__ import annotations

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
    monkeypatch.setenv("NOCAP_WORKSPACE", str(tmp_path / "missing-workspace"))

    with pytest.raises(SystemExit, match="0"):
        cli._main(["-D", "-s", "new/deep", "printf", "ok"])

    assert not (tmp_path / "new").exists()
    assert "new/deep/printf_ok.txt" in capsys.readouterr().out


def test_double_dash_escapes_subcommand_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NOCAP_WORKSPACE", str(tmp_path / "missing-workspace"))
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


def test_subcommand_rejects_ignored_arguments(capsys):
    with pytest.raises(SystemExit) as exc:
        subcommands._cmd_rm(["unexpected"])

    assert exc.value.code == 2
    assert "cap -- rm" in capsys.readouterr().err


@pytest.mark.parametrize("subdir", ["../outside", "/tmp/outside"])
def test_output_dir_rejects_paths_outside_capture_base(subdir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NOCAP_WORKSPACE", str(tmp_path / "missing-workspace"))

    with pytest.raises(ValueError, match="relative path"):
        routing._get_output_dir(subdir)


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
