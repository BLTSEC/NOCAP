"""Configuration and target-routing tests."""

from __future__ import annotations

import pytest

from nocap.config import load_settings
from nocap.routing import (
    _active_root,
    _get_base_dir,
    _get_output_dir,
    _route_label,
    _target_value,
)


def test_user_then_workspace_config_then_environment(tmp_path):
    config_home = tmp_path / "config"
    workspace = tmp_path / "workspace"
    (config_home / "nocap").mkdir(parents=True)
    (workspace / ".nocap").mkdir(parents=True)
    (config_home / "nocap" / "config.toml").write_text(
        f"""\
[capture]
workspace = {str(workspace)!r}
auto_route = false
bell = true

[limits]
review_captures = 8

[routing.aliases]
cme = "nxc"
""",
        encoding="utf-8",
    )
    (workspace / ".nocap" / "config.toml").write_text(
        """\
[capture]
auto_route = true

[limits]
review_captures = 4

[routing.tools]
nxc = "ad"
""",
        encoding="utf-8",
    )

    settings = load_settings(
        environ={
            "XDG_CONFIG_HOME": str(config_home),
            "NOCAP_AUTO": "0",
            "NOCAP_BELL": "0",
        },
        cwd=tmp_path,
    )

    assert settings.workspace == workspace.resolve()
    assert settings.auto_route is False
    assert settings.bell is False
    assert settings.review_limit == 4
    assert settings.aliases == {"cme": "nxc"}
    assert settings.routes == {"nxc": "ad"}
    assert len(settings.sources) == 2


def test_target_must_stay_inside_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NOCAP_WORKSPACE", str(workspace))
    monkeypatch.setenv("TACMUX_TARGET", "../escape")

    with pytest.raises(ValueError, match="relative path"):
        _get_base_dir()


def test_tacmux_target_routes_capture(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    (workspace / "acme" / "internal").mkdir(parents=True)
    monkeypatch.setenv("NOCAP_WORKSPACE", str(workspace))
    monkeypatch.setenv("TACMUX_TARGET", "acme/internal")

    assert _get_output_dir("recon") == workspace / "acme" / "internal" / "recon"


def test_tacmux_route_prefix_keeps_one_active_root(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    (workspace / "captures").mkdir(parents=True)
    monkeypatch.setenv("NOCAP_WORKSPACE", str(workspace))
    monkeypatch.setenv("TACMUX_TARGET", "captures")
    monkeypatch.setenv("NOCAP_ROUTE_PREFIX", "WEB01")

    assert _active_root() == workspace / "captures"
    assert _get_output_dir("recon") == workspace / "captures/WEB01/recon"
    assert _route_label("recon") == "WEB01/recon"


def test_tacmux_route_prefix_rejects_escape(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    (workspace / "captures").mkdir(parents=True)
    monkeypatch.setenv("NOCAP_WORKSPACE", str(workspace))
    monkeypatch.setenv("TACMUX_TARGET", "captures")
    monkeypatch.setenv("NOCAP_ROUTE_PREFIX", "../escape")

    with pytest.raises(ValueError, match="NOCAP_ROUTE_PREFIX"):
        _get_output_dir("recon")


def test_invalid_toml_reports_its_path(tmp_path):
    config = tmp_path / "config" / "nocap" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text("[capture\n", encoding="utf-8")

    with pytest.raises(ValueError, match=str(config)):
        load_settings(environ={"XDG_CONFIG_HOME": str(tmp_path / "config")}, cwd=tmp_path)


def test_dot_subdir_means_active_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _get_output_dir(".") == tmp_path


def test_target_precedence_and_source(monkeypatch):
    monkeypatch.setenv("TACMUX_TARGET", "current")
    monkeypatch.setenv("LOADOUT_TARGET", "ignored")
    monkeypatch.setenv("TARGET", "raw")
    assert _target_value() == ("current", "TACMUX_TARGET")

    monkeypatch.delenv("TACMUX_TARGET")
    assert _target_value() == ("raw", "TARGET")


def test_legacy_target_inputs_are_ignored(monkeypatch):
    monkeypatch.setenv("TMUX", "1")
    monkeypatch.setenv("LOADOUT_TARGET", "legacy")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return type("Result", (), {"returncode": 1, "stdout": ""})()

    monkeypatch.setattr("nocap.routing.subprocess.run", fake_run)

    assert _target_value() == ("", "")
    assert calls == [["tmux", "show-environment", "TACMUX_TARGET"]]
