"""Engagement and capture-directory resolution for NOCAP."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _get_base_dir() -> Path | None:
    """Return the engagement directory from $LOADOUT_TARGET, $TARGET, or tmux.

    Returns None if the workspace root does not exist so callers fall back to
    cwd gracefully instead of crashing on read-only or missing mounts.
    """
    raw_workspace = os.environ.get("NOCAP_WORKSPACE", "/workspace").strip()
    workspace = Path(raw_workspace or "/workspace").expanduser()

    # Bail out early if the workspace root isn't accessible
    if not workspace.is_dir():
        return None

    # LOADOUT_TARGET is the normalized workspace name (e.g. 10.10.10.5_1337)
    # set by both `loadout start` and `settarget`.  Prefer it over TARGET
    # which holds the raw host IP (for tool compatibility with nmap etc.).
    target = os.environ.get("LOADOUT_TARGET", "").strip()
    if not target:
        target = os.environ.get("TARGET", "").strip()
    if target:
        return workspace / target

    try:
        result = subprocess.run(
            ["tmux", "display-message", "-p", "#S"],
            capture_output=True, text=True, timeout=2,
        )
        sess = result.stdout.strip()
        if sess.startswith("op_"):
            tgt = sess.removeprefix("op_").replace("_", ".")
            return workspace / tgt
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


def _get_output_dir(subdir: str = "") -> Path:
    """Resolve an optional relative capture subdirectory under the active base."""
    base = _get_base_dir() or Path.cwd()
    if not subdir:
        return base

    relative = Path(subdir)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("subdir must be a relative path without '..'")
    return base / relative
