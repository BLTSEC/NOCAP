"""Tests for _build_filename — pure logic, no subprocess or filesystem needed."""

import pytest
from nocap.cli import _build_filename


# ---------------------------------------------------------------------------
# Basic tool name extraction
# ---------------------------------------------------------------------------

def test_tool_only():
    assert _build_filename(["nmap"]) == "nmap"


def test_tool_with_flag():
    assert _build_filename(["nmap", "-sCV"]) == "nmap_sCV"


def test_tool_with_subcommand():
    assert _build_filename(["gobuster", "dir"]) == "gobuster_dir"


# ---------------------------------------------------------------------------
# IP / URL / path stripping
# ---------------------------------------------------------------------------

def test_ipv4_stripped():
    assert _build_filename(["nmap", "-sCV", "10.10.10.5"]) == "nmap_sCV"


def test_ipv4_cidr_stripped():
    assert _build_filename(["nmap", "-sP", "10.10.10.0/24"]) == "nmap_sP"


def test_ipv6_stripped():
    assert _build_filename(["nmap", "-sCV", "dead:beef::1"]) == "nmap_sCV"


def test_url_stripped():
    result = _build_filename(["gobuster", "dir", "-u", "http://10.10.10.5", "-w", "/wl.txt"])
    assert result == "gobuster_dir"


def test_absolute_path_stripped():
    result = _build_filename(["hashcat", "-m", "1000", "/path/to/hashes.txt"])
    assert "/path" not in result
    assert "hashes" not in result


def test_hostname_stripped():
    # Dotted tokens (hostnames, filenames) are stripped
    result = _build_filename(["nmap", "-sCV", "target.htb"])
    assert "target" not in result
    assert result == "nmap_sCV"


# ---------------------------------------------------------------------------
# Numeric stripping
# ---------------------------------------------------------------------------

def test_number_stripped():
    # Pure numeric args stripped
    result = _build_filename(["nmap", "--min-rate", "5000"])
    assert "5000" not in result
    assert result == "nmap_min-rate"


def test_port_list_stripped():
    # Comma-separated port list stripped
    result = _build_filename(["nmap", "--open", "80,443,8080"])
    assert "80" not in result
    assert result == "nmap_open"


# ---------------------------------------------------------------------------
# SKIP_FLAGS: flags that consume the next token
# ---------------------------------------------------------------------------

def test_skip_flag_wordlist():
    result = _build_filename(["gobuster", "dir", "-w", "/path/to/wordlist.txt"])
    assert "wordlist" not in result
    assert result == "gobuster_dir"


def test_skip_flag_output():
    result = _build_filename(["nmap", "-sCV", "-oN", "out.txt", "10.10.10.5"])
    assert "out" not in result
    assert result == "nmap_sCV"


def test_skip_flag_port():
    # -p consumes next; 80 would also match _NUM_RE but should be gone either way
    result = _build_filename(["nmap", "-p", "80", "10.10.10.5"])
    assert "80" not in result


def test_skip_flag_threads():
    result = _build_filename(["ffuf", "-w", "/wl.txt", "-t", "50"])
    assert "50" not in result
    assert result == "ffuf"


# ---------------------------------------------------------------------------
# Note appending
# ---------------------------------------------------------------------------

def test_note_appended():
    result = _build_filename(["nmap", "-sCV"], note="after-creds")
    assert result == "nmap_sCV_after-creds"


def test_note_empty():
    result = _build_filename(["nmap", "-sCV"], note="")
    assert result == "nmap_sCV"


def test_note_sanitised():
    # Special chars stripped from note
    result = _build_filename(["nmap"], note="my note/here!")
    assert "/" not in result
    assert "!" not in result
    assert "mynotehere" in result


# ---------------------------------------------------------------------------
# Length and deduplication
# ---------------------------------------------------------------------------

def test_flag_part_truncated():
    long_flag = "--" + "x" * 30
    result = _build_filename(["tool", long_flag])
    parts = result.split("_")
    # Each flag part capped at 15 chars
    assert all(len(p) <= 15 for p in parts[1:])


def test_total_stem_truncated():
    # Many flags → stem capped at 60 chars
    flags = [f"--flag{i}" for i in range(20)]
    result = _build_filename(["tool"] + flags)
    assert len(result) <= 60


def test_consecutive_underscores_collapsed():
    result = _build_filename(["tool", "-a", "10.10.10.5", "-b"])
    assert "__" not in result


# ---------------------------------------------------------------------------
# key=value assignments
# ---------------------------------------------------------------------------

def test_key_path_assignment_stripped():
    result = _build_filename(["msfconsole", "RHOSTS=192.168.1.1"])
    # value is an IP, so the whole arg is skipped
    assert "RHOSTS" not in result
    assert result == "msfconsole"


def test_key_value_non_path_kept():
    # key=value where value is not a path/IP — currently the whole arg is
    # kept if it doesn't match path heuristics
    result = _build_filename(["tool", "MODE=active"])
    # 'MODE=active' has '=' but value doesn't start with / or ./
    # so it falls through to normal processing; '=' is stripped by sanitize
    # The test just confirms it doesn't crash
    assert isinstance(result, str)
    assert len(result) > 0
