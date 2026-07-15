"""Tests for capture discovery and summary behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import nocap.subcommands as subcommands


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
    monkeypatch.setattr(subcommands, "_get_base_dir", lambda: None)
    _write_capture(tmp_path / "capture.txt")
    (tmp_path / "unrelated.txt").write_text("ordinary notes\n", encoding="utf-8")

    subcommands._cmd_summary([])

    output = capsys.readouterr().out
    assert "capture.txt" in output
    assert "unrelated.txt" not in output


def test_summary_search_ignores_matches_in_unrelated_text(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subcommands, "_get_base_dir", lambda: None)
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
