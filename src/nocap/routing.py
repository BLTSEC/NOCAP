"""Engagement and capture-directory resolution for NOCAP."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from nocap.config import Settings, load_settings


def _safe_relative(value: str, *, label: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"{label} must be a relative path without '..'")
    if not candidate.parts or any(part in {"", "."} for part in candidate.parts):
        raise ValueError(f"{label} must name a relative path")
    return candidate


def _contained(root: Path, candidate: Path, *, label: str) -> Path:
    resolved_root = root.resolve(strict=False)
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(resolved_root):
        raise ValueError(f"{label} escapes workspace {resolved_root}")
    return resolved


def _tmux_target() -> str:
    if not os.environ.get("TMUX"):
        return ""
    try:
        result = subprocess.run(
            ["tmux", "show-environment", "TACMUX_TARGET"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    value = result.stdout.strip()
    return value.partition("=")[2].strip() if value.startswith("TACMUX_TARGET=") else ""



def _target_value() -> tuple[str, str]:
    value = os.environ.get("TACMUX_TARGET", "").strip()
    if value:
        return value, "TACMUX_TARGET"
    value = _tmux_target()
    if value:
        return value, "tmux TACMUX_TARGET"
    value = os.environ.get("TARGET", "").strip()
    if value:
        return value, "TARGET"
    return "", ""


def _get_base_dir(settings: Settings | None = None) -> Path | None:
    """Return the active target root, or ``None`` for cwd fallback.

    Explicit target/workspace configuration fails closed. Only the untouched
    standalone default may fall back to the current directory.
    """
    settings = settings or load_settings()
    workspace = settings.workspace.expanduser()
    target, source = _target_value()

    if settings.workspace_explicit and not workspace.is_dir():
        raise ValueError(f"configured workspace does not exist: {workspace}")
    if not target:
        return None
    if not workspace.is_dir():
        raise ValueError(f"{source} is set but workspace does not exist: {workspace}")

    relative = _safe_relative(target, label=source)
    resolved = _contained(workspace, workspace / relative, label=source)
    if not resolved.is_dir():
        raise ValueError(f"{source} target does not exist: {resolved}")
    return resolved


def _get_output_dir(subdir: str = "", settings: Settings | None = None) -> Path:
    """Resolve a capture directory without allowing base-directory escapes."""
    base = _get_base_dir(settings) or Path.cwd().resolve()
    prefix = os.environ.get("NOCAP_ROUTE_PREFIX", "").strip()
    if prefix:
        relative_prefix = _safe_relative(prefix, label="NOCAP_ROUTE_PREFIX")
        base = _contained(base, base / relative_prefix, label="NOCAP_ROUTE_PREFIX")
    if not subdir or Path(subdir).parts in {(), (".",)}:
        return base
    relative = _safe_relative(subdir, label="subdir")
    return _contained(base, base / relative, label="subdir")


def _route_label(subdir: str = "") -> str:
    """Return the metadata route after applying an optional TACMUX prefix."""
    parts: list[str] = []
    prefix = os.environ.get("NOCAP_ROUTE_PREFIX", "").strip()
    if prefix:
        parts.append(_safe_relative(prefix, label="NOCAP_ROUTE_PREFIX").as_posix())
    if subdir and Path(subdir).parts not in {(), (".",)}:
        parts.append(_safe_relative(subdir, label="subdir").as_posix())
    return "/".join(parts)


def _active_root(settings: Settings | None = None) -> Path:
    """Return the root under which capture paths and metadata are scoped."""
    return (_get_base_dir(settings) or Path.cwd()).resolve(strict=False)


def _ensure_contained(root: Path, path: Path, *, label: str = "path") -> Path:
    """Validate an arbitrary path against an active root."""
    candidate = path if path.is_absolute() else root / path
    return _contained(root, candidate, label=label)
