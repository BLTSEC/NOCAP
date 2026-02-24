"""Tests for CLI argument parsing via the module-level _PARSER instance."""

import pytest
from nocap.cli import _PARSER


# ---------------------------------------------------------------------------
# Basic flag parsing
# ---------------------------------------------------------------------------

def test_no_flags():
    ns = _PARSER.parse_args(["nmap", "-sCV", "10.10.10.5"])
    assert ns.note == ""
    assert ns.subdir == ""
    assert ns.auto is False
    assert ns.dry_run is False
    assert ns.command == ["nmap", "-sCV", "10.10.10.5"]


def test_note_short():
    ns = _PARSER.parse_args(["-n", "label", "nmap"])
    assert ns.note == "label"
    assert ns.command == ["nmap"]


def test_note_long():
    ns = _PARSER.parse_args(["--note", "label", "nmap"])
    assert ns.note == "label"
    assert ns.command == ["nmap"]


def test_subdir_short():
    ns = _PARSER.parse_args(["-s", "notes", "nmap"])
    assert ns.subdir == "notes"
    assert ns.command == ["nmap"]


def test_subdir_long():
    ns = _PARSER.parse_args(["--subdir", "pivoting", "nmap"])
    assert ns.subdir == "pivoting"
    assert ns.command == ["nmap"]


def test_auto_short():
    ns = _PARSER.parse_args(["-a", "nmap"])
    assert ns.auto is True
    assert ns.command == ["nmap"]


def test_auto_long():
    ns = _PARSER.parse_args(["--auto", "nmap"])
    assert ns.auto is True
    assert ns.command == ["nmap"]


def test_dry_run_short():
    ns = _PARSER.parse_args(["-D", "nmap"])
    assert ns.dry_run is True
    assert ns.command == ["nmap"]


def test_dry_run_long():
    ns = _PARSER.parse_args(["--dry-run", "nmap"])
    assert ns.dry_run is True
    assert ns.command == ["nmap"]


# ---------------------------------------------------------------------------
# Combined short flags
# ---------------------------------------------------------------------------

def test_combined_auto_note():
    # -an label → -a -n label
    ns = _PARSER.parse_args(["-an", "label", "nmap"])
    assert ns.auto is True
    assert ns.note == "label"
    assert ns.command == ["nmap"]


def test_combined_auto_dry():
    # -aD → -a -D
    ns = _PARSER.parse_args(["-aD", "nmap"])
    assert ns.auto is True
    assert ns.dry_run is True
    assert ns.command == ["nmap"]


# ---------------------------------------------------------------------------
# REMAINDER behaviour: child flags are NOT consumed by nocap
# ---------------------------------------------------------------------------

def test_child_flags_after_command_not_consumed():
    # -a appearing AFTER the command belongs to the child, not nocap
    ns = _PARSER.parse_args(["nmap", "-a", "-sCV"])
    assert ns.auto is False
    assert ns.command == ["nmap", "-a", "-sCV"]


def test_child_flags_preserved_in_command():
    ns = _PARSER.parse_args(["-a", "nmap", "-sCV", "10.10.10.5"])
    assert ns.auto is True
    assert ns.command == ["nmap", "-sCV", "10.10.10.5"]


def test_child_note_flag_not_consumed():
    # --note appearing after the command is part of the child's args
    ns = _PARSER.parse_args(["nmap", "--script", "vuln"])
    assert ns.note == ""
    assert ns.command == ["nmap", "--script", "vuln"]


# ---------------------------------------------------------------------------
# Multiple nocap flags together
# ---------------------------------------------------------------------------

def test_multiple_flags():
    ns = _PARSER.parse_args(["-a", "-n", "after-auth", "-s", "recon", "nmap", "-sCV"])
    assert ns.auto is True
    assert ns.note == "after-auth"
    assert ns.subdir == "recon"
    assert ns.command == ["nmap", "-sCV"]


# ---------------------------------------------------------------------------
# Version / help flags
# ---------------------------------------------------------------------------

def test_version_flag():
    ns = _PARSER.parse_args(["--version"])
    assert ns.version is True


def test_help_flag():
    ns = _PARSER.parse_args(["--help"])
    assert ns.help is True


# ---------------------------------------------------------------------------
# Empty command (no tool specified)
# ---------------------------------------------------------------------------

def test_empty_command():
    ns = _PARSER.parse_args(["-a"])
    assert ns.command == []
