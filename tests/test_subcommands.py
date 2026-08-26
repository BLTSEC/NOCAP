"""Tests for capture discovery and summary behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import nocap.subcommands as subcommands
from nocap.config import Settings
from nocap.metadata import retained_records, sync_records, tag_record


def _write_capture(path: Path, output: str = "captured output") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "Command: echo test\n"
        "Date:    Wed Jul 15 12:00:00 CDT 2026\n"
        "---\n"
        f"{output}\n",
        encoding="utf-8",
    )


def test_is_capture_file_requires_complete_header(tmp_path):
    capture = tmp_path / "capture.txt"
    unrelated = tmp_path / "notes.txt"
    near_match = tmp_path / "partial.txt"
    _write_capture(capture)
    unrelated.write_text("ordinary notes\n", encoding="utf-8")
    near_match.write_text("Command: echo test\nDate: missing spacing\n---\n", encoding="utf-8")

    assert subcommands._is_capture_file(capture) is True
    assert subcommands._is_capture_file(unrelated) is False
    assert subcommands._is_capture_file(near_match) is False


def test_find_capture_files_excludes_unrelated_text_files(tmp_path):
    capture = tmp_path / "recon" / "nmap.txt"
    _write_capture(capture)
    (tmp_path / "notes.txt").write_text("not a capture\n", encoding="utf-8")

    assert subcommands._find_capture_files(tmp_path) == [capture]


def test_summary_table_only_includes_nocap_captures(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_capture(tmp_path / "capture.txt")
    (tmp_path / "unrelated.txt").write_text("ordinary notes\n", encoding="utf-8")

    subcommands._cmd_summary([])

    output = capsys.readouterr().out
    assert "capture.txt" in output
    assert "unrelated.txt" not in output


def test_summary_search_ignores_matches_in_unrelated_text(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_capture(tmp_path / "capture.txt", output="safe output")
    (tmp_path / "unrelated.txt").write_text("needle\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        subcommands._cmd_summary(["needle"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no matches" in captured.err


def test_update_uses_pipx_upgrade(monkeypatch):
    invoked: list[list[str]] = []

    monkeypatch.setattr(subcommands.shutil, "which", lambda command: "/usr/bin/pipx")

    def fake_run(command: list[str]):
        invoked.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subcommands.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as exc:
        subcommands._cmd_update([])

    assert exc.value.code == 0
    assert invoked == [["pipx", "upgrade", "nocap"]]


def test_search_context_streams_neighboring_lines(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_capture(tmp_path / "capture.txt", output="before\nneedle\nafter")

    subcommands._cmd_search(["needle", "--context", "1"])

    output = capsys.readouterr().out
    assert "before" in output
    assert ">      5: needle" in output
    assert "after" in output


def test_ls_dot_lists_active_root_without_fzf(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_capture(tmp_path / "recon" / "capture.txt")
    monkeypatch.setattr(
        subcommands,
        "_fzf_select",
        lambda *args, **kwargs: pytest.fail("cap ls must never invoke fzf"),
    )

    subcommands._cmd_ls(["."])

    output = capsys.readouterr().out
    assert "STARTED" in output
    assert "CAPTURE" in output
    assert "recon/capture.txt" in output


def test_browse_print_returns_absolute_path_without_opening(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    capture = tmp_path / "recon" / "capture.txt"
    _write_capture(capture)
    sync_records(tmp_path)
    selected = retained_records(tmp_path)
    tag_record(tmp_path, selected[0], ["keep"])
    monkeypatch.setattr(subcommands, "_fzf_select", lambda root, records, **kwargs: [records[0]])
    monkeypatch.setattr(
        subcommands,
        "_view_file",
        lambda *args, **kwargs: pytest.fail("--print must not open the capture"),
    )

    subcommands._cmd_browse([".", "--tag", "keep", "--print"])

    assert capsys.readouterr().out.strip() == str(capture.resolve())


def test_browse_uses_same_default_limit_as_ls(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_capture(tmp_path / "one.txt")
    _write_capture(tmp_path / "two.txt")
    sync_records(tmp_path)
    seen: list[dict] = []
    monkeypatch.setattr(subcommands, "_settings", lambda: Settings(list_limit=1))

    def select(root, records, **kwargs):
        seen.extend(records)
        return []

    monkeypatch.setattr(subcommands, "_fzf_select", select)
    subcommands._cmd_browse([])

    assert len(seen) == 1


def test_ls_and_browse_announce_default_truncation(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_capture(tmp_path / "one.txt")
    _write_capture(tmp_path / "two.txt")
    sync_records(tmp_path)
    monkeypatch.setattr(subcommands, "_settings", lambda: Settings(list_limit=1))

    subcommands._cmd_ls(["--json"])
    payload = __import__("json").loads(capsys.readouterr().out)
    assert payload["limit"] == 1
    assert payload["truncated"] is True

    seen_header = []
    monkeypatch.setattr(
        subcommands,
        "_fzf_select",
        lambda root, records, **kwargs: seen_header.append(kwargs.get("header")) or [],
    )
    subcommands._cmd_browse([])
    assert "use --all" in seen_header[0]
    assert "result limit reached" in capsys.readouterr().err


def test_ls_deleted_filter_requires_explicit_visibility(capsys):
    with pytest.raises(SystemExit, match="2"):
        subcommands._cmd_ls(["--status", "deleted"])
    assert "requires --include-deleted" in capsys.readouterr().err


def test_fzf_missing_error_suggests_ls(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(subcommands.shutil, "which", lambda command: None)

    with pytest.raises(SystemExit):
        subcommands._fzf_select(tmp_path, [], multi=False, prompt="captures")

    assert "cap ls" in capsys.readouterr().err


def test_summary_rejects_multiple_arguments(capsys):
    with pytest.raises(SystemExit) as exc:
        subcommands._cmd_summary(["two", "arguments"])

    assert exc.value.code == 2
    assert "at most one" in capsys.readouterr().err


def test_summary_is_regex_first_but_search_is_literal(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_capture(tmp_path / "capture.txt", output="needle-123")

    subcommands._cmd_summary([r"needle-\d+"])
    assert "needle-123" in capsys.readouterr().out

    with pytest.raises(SystemExit, match="1"):
        subcommands._cmd_search([r"needle-\d+"])
    assert "no matches" in capsys.readouterr().err


def test_search_only_warns_when_an_additional_match_exists(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_capture(tmp_path / "capture.txt", output="needle")

    subcommands._cmd_search(["needle", "--limit", "1"])
    assert "result limit" not in capsys.readouterr().err

    _write_capture(tmp_path / "second.txt", output="needle")
    subcommands._cmd_search(["needle", "--limit", "1"])
    assert "result limit reached" in capsys.readouterr().err


def test_timeline_markdown_handles_backtick_runs():
    text = subcommands._timeline_markdown(
        [
            {
                "started_at": "2026-08-26T00:00:00Z",
                "status": "completed",
                "effective_tool": "printf",
                "duration_ms": 1,
                "command": "printf '```code```'",
                "path": "notes/`capture`.txt",
                "tags": [],
            }
        ]
    )

    assert "````printf '```code```'````" in text
    assert "``notes/`capture`.txt``" in text
