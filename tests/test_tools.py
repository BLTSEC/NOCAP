"""Tests for static and action-aware capture routing."""

from __future__ import annotations

import pytest

from nocap import cli
from nocap.config import Settings
from nocap.tools import route_for_tool


@pytest.mark.parametrize(
    ("tool", "args", "route"),
    [
        ("nmap", ["-sCV", "10.10.10.10"], "recon"),
        ("nxc", ["smb", "dc", "--shares"], "recon"),
        ("nxc", ["smb", "dc", "--sam"], "loot"),
        ("nxc", ["smb", "dc", "-M", "lsassy"], "loot"),
        ("nxc", ["smb", "dc", "-x", "whoami"], "exploitation"),
        ("nxc", ["smb", "dc", "-M", "coerce_plus"], "exploitation"),
        ("nxc", ["smb", "dc", "-M", "enum_av"], "recon"),
        ("certipy", ["find", "-u", "operator"], "recon"),
        ("certipy-ad", ["cert", "-pfx", "user.pfx"], "loot"),
        ("certipy", ["req", "-ca", "corp-CA"], "exploitation"),
        ("kerbrute", ["userenum", "users.txt"], "recon"),
        ("kerbrute", ["passwordspray", "users.txt", "Password1!"], "exploitation"),
        ("secretsdump.py", ["corp/user@dc"], "loot"),
        ("GetNPUsers.py", ["corp/", "-usersfile", "users.txt"], "loot"),
        ("GetUserSPNs.py", ["corp/user"], "loot"),
        ("hydra", ["-L", "users", "-P", "passwords", "ssh://host"], "exploitation"),
    ],
)
def test_route_for_tool(tool, args, route):
    assert route_for_tool(tool, args) == route


def test_wrappers_are_normalized_before_action_routing():
    tool, route = cli._route_for(
        ["sudo", "proxychains", "nxc", "smb", "dc", "--dpapi"], Settings()
    )

    assert (tool, route) == ("nxc", "loot")


def test_configured_tool_route_beats_action_routing():
    tool, route = cli._route_for(
        ["nxc", "smb", "dc", "--sam"], Settings(routes={"nxc": "reports"})
    )

    assert (tool, route) == ("nxc", "reports")
