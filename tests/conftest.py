"""Shared test isolation."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_nocap_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    for name in (
        "NOCAP_WORKSPACE",
        "NOCAP_AUTO",
        "NOCAP_BELL",
        "TACMUX_TARGET",
        "TARGET",
        "TMUX",
    ):
        monkeypatch.delenv(name, raising=False)
