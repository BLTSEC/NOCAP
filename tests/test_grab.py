"""Tests for cap grab helpers — _extract_output and _last_command_from_history."""

import os
import textwrap
from pathlib import Path

import pytest

from nocap.cli import _extract_output, _last_command_from_history


# ---------------------------------------------------------------------------
# _extract_output
# ---------------------------------------------------------------------------

class TestExtractOutput:
    """Pure-logic tests for scrollback parsing."""

    def test_basic_extraction(self):
        scrollback = textwrap.dedent("""\
            user@box:~$ ls -la
            total 8
            drwxr-xr-x  2 user user 4096 Mar 13 09:00 .
            drwxr-xr-x 10 user user 4096 Mar 13 09:00 ..
            -rw-r--r--  1 user user    0 Mar 13 09:00 file.txt
            user@box:~$ cap grab
        """)
        result = _extract_output(scrollback, "ls -la")
        assert "total 8" in result
        assert "file.txt" in result
        assert "cap grab" not in result
        assert "ls -la" not in result

    def test_multiline_output(self):
        scrollback = textwrap.dedent("""\
            root@kali:~$ nmap -sCV 10.10.10.5
            Starting Nmap 7.94
            PORT   STATE SERVICE VERSION
            22/tcp open  ssh     OpenSSH 8.9
            80/tcp open  http    Apache 2.4
            Nmap done: 1 IP address (1 host up) scanned
            root@kali:~$ cap grab
        """)
        result = _extract_output(scrollback, "nmap -sCV 10.10.10.5")
        assert "Starting Nmap" in result
        assert "22/tcp open" in result
        assert "Nmap done" in result
        assert "cap grab" not in result

    def test_empty_output(self):
        scrollback = textwrap.dedent("""\
            user@box:~$ true
            user@box:~$ cap grab
        """)
        result = _extract_output(scrollback, "true")
        assert result == ""

    def test_command_not_found_falls_back_to_prompt(self):
        scrollback = textwrap.dedent("""\
            user@box:~$ some-cmd
            output line 1
            output line 2
            user@box:~$ cap grab
        """)
        # Search for a command that doesn't appear in scrollback
        result = _extract_output(scrollback, "nonexistent-command")
        # Falls back to prompt detection — should still grab something
        assert len(result) > 0

    def test_trailing_blanks_stripped(self):
        scrollback = "user@box:~$ echo hello\nhello\n\n\nuser@box:~$ cap grab\n\n\n"
        result = _extract_output(scrollback, "echo hello")
        assert result == "hello"
        assert not result.endswith("\n")

    def test_leading_blanks_stripped(self):
        scrollback = "user@box:~$ cmd\n\n\noutput here\nuser@box:~$ cap grab\n"
        result = _extract_output(scrollback, "cmd")
        assert result.startswith("output here")

    def test_multiple_cap_grab_lines_stripped(self):
        scrollback = textwrap.dedent("""\
            user@box:~$ whoami
            root
            user@box:~$ cap grab -n test
        """)
        result = _extract_output(scrollback, "whoami")
        assert result == "root"
        assert "cap grab" not in result

    def test_finds_last_occurrence_of_command(self):
        scrollback = textwrap.dedent("""\
            user@box:~$ id
            uid=1000(user)
            user@box:~$ id
            uid=0(root)
            user@box:~$ cap grab
        """)
        # Should find the LAST occurrence
        result = _extract_output(scrollback, "id")
        assert "uid=0(root)" in result

    def test_p10k_prompt_stripped(self):
        """Multi-line prompts (p10k, starship) should be stripped from output."""
        scrollback = (
            "╭─    /tmp ···· ✔  10:27:27 \n"
            "╰─ nmap -p 80 scanme.nmap.org\n"
            "Starting Nmap 7.98\n"
            "PORT   STATE SERVICE\n"
            "80/tcp open  http\n"
            "Nmap done: 1 IP address\n"
            "\n"
            "╭─    /tmp ···· ✔  10:27:31 \n"
            "╰─ cap grab\n"
        )
        result = _extract_output(scrollback, "nmap -p 80 scanme.nmap.org")
        assert "Starting Nmap" in result
        assert "80/tcp open" in result
        assert "Nmap done" in result
        assert "╭─" not in result
        assert "╰─" not in result
        assert "cap grab" not in result

    def test_starship_prompt_stripped(self):
        scrollback = (
            "❯ ls -la\n"
            "total 8\n"
            "-rw-r--r-- 1 user user 0 file.txt\n"
            "❯ cap grab\n"
        )
        result = _extract_output(scrollback, "ls -la")
        assert "total 8" in result
        assert "file.txt" in result
        assert "❯" not in result

    def test_earlier_command_stops_at_next_prompt(self):
        """When grabbing a non-last command, output should stop at the next prompt."""
        scrollback = (
            "╭─    /tmp ···· ✔  10:27:27 \n"
            "╰─ nmap -p 80 scanme.nmap.org\n"
            "Starting Nmap 7.98\n"
            "80/tcp open  http\n"
            "Nmap done: 1 IP address\n"
            "\n"
            "╭─    /tmp ···· ✔  10:27:31 \n"
            "╰─ nmap -p 53 scanme.nmap.org\n"
            "Starting Nmap 7.98\n"
            "53/tcp open  domain\n"
            "Nmap done: 1 IP address\n"
            "\n"
            "╭─    /tmp ···· ✔  10:27:35 \n"
            "╰─ cap grab nmap -p 80\n"
        )
        result = _extract_output(scrollback, "nmap -p 80")
        assert "80/tcp open  http" in result
        assert "53/tcp" not in result
        assert "cap grab" not in result

    def test_earlier_command_basic_prompt(self):
        """Same test with basic user@host:~$ prompts."""
        scrollback = (
            "user@box:~$ nmap -p 80 target\n"
            "80/tcp open  http\n"
            "user@box:~$ whoami\n"
            "root\n"
            "user@box:~$ cap grab nmap -p 80\n"
        )
        result = _extract_output(scrollback, "nmap -p 80")
        assert "80/tcp open" in result
        assert "whoami" not in result
        assert "root" not in result

    def test_no_scrollback(self):
        result = _extract_output("", "ls")
        assert result == ""

    def test_only_cap_grab_in_scrollback(self):
        scrollback = "user@box:~$ cap grab\n"
        result = _extract_output(scrollback, "ls")
        assert result == ""


# ---------------------------------------------------------------------------
# _last_command_from_history
# ---------------------------------------------------------------------------

class TestLastCommandFromHistory:
    """Tests for shell history parsing."""

    def test_zsh_extended_format(self, tmp_path, monkeypatch):
        hist = tmp_path / ".zsh_history"
        hist.write_text(
            ": 1710000000:0;ls -la\n"
            ": 1710000001:0;nmap -sCV 10.10.10.5\n"
            ": 1710000002:0;cap grab\n"
        )
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setenv("HISTFILE", str(hist))
        result = _last_command_from_history()
        assert result == "nmap -sCV 10.10.10.5"

    def test_bash_plain_format(self, tmp_path, monkeypatch):
        hist = tmp_path / ".bash_history"
        hist.write_text("ls -la\nwhoami\ncap grab\n")
        monkeypatch.setenv("SHELL", "/bin/bash")
        monkeypatch.setenv("HISTFILE", str(hist))
        result = _last_command_from_history()
        assert result == "whoami"

    def test_skips_cap_grab_with_args(self, tmp_path, monkeypatch):
        hist = tmp_path / ".zsh_history"
        hist.write_text(
            ": 1710000000:0;curl http://example.com\n"
            ": 1710000001:0;cap grab -n test\n"
        )
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setenv("HISTFILE", str(hist))
        result = _last_command_from_history()
        assert result == "curl http://example.com"

    def test_no_history_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setenv("HISTFILE", str(tmp_path / "nonexistent"))
        result = _last_command_from_history()
        assert result is None

    def test_empty_history(self, tmp_path, monkeypatch):
        hist = tmp_path / ".bash_history"
        hist.write_text("")
        monkeypatch.setenv("SHELL", "/bin/bash")
        monkeypatch.setenv("HISTFILE", str(hist))
        result = _last_command_from_history()
        assert result is None

    def test_all_cap_grab(self, tmp_path, monkeypatch):
        hist = tmp_path / ".bash_history"
        hist.write_text("cap grab\ncap grab -n foo\n")
        monkeypatch.setenv("SHELL", "/bin/bash")
        monkeypatch.setenv("HISTFILE", str(hist))
        result = _last_command_from_history()
        assert result is None
