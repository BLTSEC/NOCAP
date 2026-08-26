"""Configuration loading for NOCAP.

Configuration stays intentionally small.  User settings are loaded first,
then workspace settings, and finally environment variables override both.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


def _truthy(value: str) -> bool:
    return bool(value) and value.strip().lower() not in {"0", "false", "no", "off"}


def _int_setting(value: Any, default: int, *, minimum: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= minimum else default


@dataclass(frozen=True)
class Settings:
    workspace: Path = Path("/workspace")
    workspace_explicit: bool = False
    auto_route: bool = False
    bell: bool = False
    list_limit: int = 50
    search_limit: int = 100
    review_limit: int = 10
    review_max_lines: int = 200
    review_max_bytes: int = 32768
    aliases: dict[str, str] = field(default_factory=dict)
    routes: dict[str, str] = field(default_factory=dict)
    sources: tuple[Path, ...] = ()


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"config root must be a table: {path}")
    return data


def _merge(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _merge(dict(result[key]), value)
        else:
            result[key] = value
    return result


def _config_home(environ: Mapping[str, str]) -> Path:
    raw = environ.get("XDG_CONFIG_HOME", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".config"


def load_settings(
    *,
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> Settings:
    env = os.environ if environ is None else environ
    cwd = Path.cwd() if cwd is None else cwd

    user_path = _config_home(env) / "nocap" / "config.toml"
    user_data = _read_toml(user_path)
    sources: list[Path] = [user_path] if user_path.is_file() else []

    capture = user_data.get("capture", {})
    configured_workspace = capture.get("workspace") if isinstance(capture, Mapping) else None
    env_workspace = env.get("NOCAP_WORKSPACE", "").strip()
    if env_workspace:
        workspace = Path(env_workspace).expanduser()
        workspace_explicit = True
    elif isinstance(configured_workspace, str) and configured_workspace.strip():
        workspace = Path(configured_workspace).expanduser()
        workspace_explicit = True
    else:
        workspace = Path("/workspace")
        workspace_explicit = False

    workspace_path = workspace.resolve(strict=False)
    workspace_config = workspace_path / ".nocap" / "config.toml"
    workspace_data = _read_toml(workspace_config) if workspace_path.is_dir() else {}
    if workspace_config.is_file():
        sources.append(workspace_config)
    data = _merge(user_data, workspace_data)

    capture = data.get("capture", {}) if isinstance(data.get("capture", {}), Mapping) else {}
    limits = data.get("limits", {}) if isinstance(data.get("limits", {}), Mapping) else {}
    routing = data.get("routing", {}) if isinstance(data.get("routing", {}), Mapping) else {}
    aliases_raw = routing.get("aliases", {}) if isinstance(routing.get("aliases", {}), Mapping) else {}
    routes_raw = routing.get("tools", {}) if isinstance(routing.get("tools", {}), Mapping) else {}

    env_auto = env.get("NOCAP_AUTO", "").strip()
    auto_route = _truthy(env_auto) if env_auto else bool(capture.get("auto_route", False))
    env_bell = env.get("NOCAP_BELL", "").strip()
    bell = _truthy(env_bell) if env_bell else bool(capture.get("bell", False))

    aliases = {
        str(key): str(value)
        for key, value in aliases_raw.items()
        if str(key).strip() and str(value).strip()
    }
    routes = {
        str(key): str(value)
        for key, value in routes_raw.items()
        if str(key).strip() and str(value).strip()
    }

    # When /workspace does not exist and no workspace was explicitly selected,
    # current-directory fallback remains the least surprising standalone mode.
    if not workspace_path.exists() and not workspace_explicit:
        workspace_path = Path("/workspace")

    return Settings(
        workspace=workspace_path,
        workspace_explicit=workspace_explicit,
        auto_route=auto_route,
        bell=bell,
        list_limit=_int_setting(limits.get("list"), 50),
        search_limit=_int_setting(limits.get("search"), 100),
        review_limit=_int_setting(limits.get("review_captures"), 10),
        review_max_lines=_int_setting(limits.get("review_lines"), 200),
        review_max_bytes=_int_setting(limits.get("review_bytes"), 32768),
        aliases=aliases,
        routes=routes,
        sources=tuple(sources),
    )
