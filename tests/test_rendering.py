"""Tests for ANSI stripping and VT100 line-buffer rendering."""

from nocap.rendering import _clean_rendered, _strip_ansi, _vt100_render


def test_strip_ansi_removes_color_sequences():
    assert _strip_ansi("\033[31mred\033[0m") == "red"


def test_vt100_render_resolves_carriage_return_updates():
    assert _vt100_render("progress 10%\rprogress 20%\n") == "progress 20%"


def test_clean_rendered_collapses_repeated_lines():
    assert _clean_rendered("same\nsame\nsame\n") == "same\n  [×3]\n"
