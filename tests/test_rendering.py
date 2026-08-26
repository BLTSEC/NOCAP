"""Tests for ANSI stripping and VT100 line-buffer rendering."""

import nocap.rendering as rendering
from nocap.rendering import _clean_rendered, _strip_ansi, _vt100_render


def test_strip_ansi_removes_color_sequences():
    assert _strip_ansi("\033[31mred\033[0m") == "red"


def test_vt100_render_resolves_carriage_return_updates():
    assert _vt100_render("progress 10%\rprogress 20%\n") == "progress 20%"


def test_clean_rendered_collapses_repeated_lines():
    assert _clean_rendered("same\nsame\nsame\n") == "same\n  [×3]\n"


def test_vt100_render_expands_tabs_and_keeps_sparse_lines():
    assert _vt100_render("a\tb\n\nnext\n") == "a       b\n\nnext"


def test_default_render_does_not_deduplicate_evidence():
    assert _vt100_render("same\nsame\nsame\n") == "same\nsame\nsame"


def test_compact_restores_prompt_padding_and_animation_cleanup():
    first = "[Aug 26, 2026 - 10:00:00 (CDT)] one"
    second = "[Aug 26, 2026 - 10:01:00 (CDT)] two"
    text = first + second + "\n~\n~\n~\n.\n..\n.\n..\n.\n..\nkept\n"

    assert _clean_rendered(text) == first + "\n" + second + "\nkept\n"


def test_compact_removes_repeated_terminal_redraw_blocks():
    block = "one\ntwo\nthree\nfour\nfive\n"
    assert _clean_rendered(block * 2) == block


def test_default_render_keeps_content_compact_may_drop():
    text = "~\n~\n~\n.\n..\n.\n..\n.\n..\n"
    assert _vt100_render(text) == text.rstrip("\n")


def test_quitting_pager_early_does_not_raise(tmp_path, monkeypatch):
    capture = tmp_path / "capture.txt"
    capture.write_text("line\n", encoding="utf-8")

    class ClosedInput:
        def write(self, value):
            raise BrokenPipeError

        def close(self):
            raise BrokenPipeError

    class Pager:
        stdin = ClosedInput()

        def wait(self):
            return 0

    monkeypatch.setattr(rendering.shutil, "which", lambda command: "/usr/bin/less")
    monkeypatch.setattr(rendering.subprocess, "Popen", lambda *args, **kwargs: Pager())

    rendering._view_file(capture, paging=True)
