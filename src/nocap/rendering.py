"""Streaming terminal cleanup and capture viewing."""

from __future__ import annotations

import codecs
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

_ANSI_RE = re.compile(r"\x1b\[[?!0-9;]*[a-zA-Z]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_PROMPT_TIMESTAMP_RE = re.compile(
    r"\[[A-Z][a-z]{2} \d{2}, \d{4} - \d{2}:\d{2}:\d{2} \([A-Z]{2,5}\)\]"
)
_VT100_COL_CAP = 500


def _strip_ansi(text: str) -> str:
    """Remove common CSI and OSC escape sequences from *text*."""
    return _ANSI_RE.sub("", _OSC_RE.sub("", text))


class _VT100Stream:
    def __init__(self) -> None:
        self.buf: list[str] = []
        self.pos = 0
        self.mode = "text"
        self.escape = ""
        self.osc_esc = False

    def _line(self) -> str:
        value = "".join(self.buf).rstrip()
        self.buf = []
        self.pos = 0
        return value

    def _csi(self, value: str) -> None:
        if not value:
            return
        final = value[-1]
        params_text = value[:-1].lstrip("?")
        try:
            params = [int(item) if item else 0 for item in params_text.split(";")]
        except ValueError:
            params = [0]
        amount = params[0] if params else 0
        if final == "D":
            self.pos = max(0, self.pos - (amount or 1))
        elif final == "C":
            self.pos = min(self.pos + (amount or 1), _VT100_COL_CAP)
        elif final == "G":
            self.pos = min(max(0, (amount or 1) - 1), _VT100_COL_CAP)
        elif final == "K":
            if amount == 0:
                self.buf = self.buf[: self.pos]
            elif amount == 1:
                if self.pos > len(self.buf):
                    self.buf.extend([" "] * (self.pos - len(self.buf)))
                for index in range(min(self.pos + 1, len(self.buf))):
                    self.buf[index] = " "
            elif amount == 2:
                self.buf = []
                self.pos = 0
        elif final == "J" and amount in {0, 2}:
            self.buf = self.buf[: self.pos] if amount == 0 else []
            if amount == 2:
                self.pos = 0

    def feed(self, text: str) -> list[str]:
        lines: list[str] = []
        for ch in text:
            if self.mode == "osc":
                if ch == "\x07" or (self.osc_esc and ch == "\\"):
                    self.mode = "text"
                    self.osc_esc = False
                else:
                    self.osc_esc = ch == "\x1b"
                continue
            if self.mode == "esc":
                if ch == "[":
                    self.mode = "csi"
                    self.escape = ""
                elif ch == "]":
                    self.mode = "osc"
                    self.osc_esc = False
                else:
                    self.mode = "text"
                continue
            if self.mode == "csi":
                self.escape += ch
                if "@" <= ch <= "~":
                    self._csi(self.escape)
                    self.escape = ""
                    self.mode = "text"
                elif len(self.escape) > 64:
                    self.escape = ""
                    self.mode = "text"
                continue

            if ch == "\x1b":
                self.mode = "esc"
            elif ch == "\n":
                lines.append(self._line())
            elif ch == "\r":
                self.pos = 0
            elif ch == "\x08":
                self.pos = max(0, self.pos - 1)
            elif ch == "\t":
                next_stop = min(((self.pos // 8) + 1) * 8, _VT100_COL_CAP)
                if next_stop > len(self.buf):
                    self.buf.extend([" "] * (next_stop - len(self.buf)))
                self.pos = next_stop
            elif ord(ch) < 0x20 or ch == "\x7f":
                continue
            else:
                if self.pos < len(self.buf):
                    self.buf[self.pos] = ch
                else:
                    if self.pos > len(self.buf):
                        self.buf.extend([" "] * (self.pos - len(self.buf)))
                    self.buf.append(ch)
                self.pos += 1
        return lines

    def finish(self) -> list[str]:
        return [self._line()] if self.buf else []


def _iter_rendered_lines(path: Path, *, chunk_size: int = 65536) -> Iterator[str]:
    renderer = _VT100Stream()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            for line in renderer.feed(decoder.decode(chunk)):
                yield line
    tail = decoder.decode(b"", final=True)
    for line in renderer.feed(tail):
        yield line
    yield from renderer.finish()


def _vt100_render(data: str) -> str:
    renderer = _VT100Stream()
    lines = renderer.feed(data)
    lines.extend(renderer.finish())
    return "\n".join(lines)


def _deduplicate_blocks(lines: list[str]) -> list[str]:
    """Keep one copy of consecutively repeated terminal redraw blocks."""
    if len(lines) < 10:
        return lines
    result: list[str] = []
    index = 0
    while index < len(lines):
        max_size = min(60, (len(lines) - index) // 2)
        block_size = repetitions = 0
        for size in range(max_size, 4, -1):
            if lines[index] != lines[index + size]:
                continue
            if lines[index : index + size] != lines[index + size : index + 2 * size]:
                continue
            block_size = size
            repetitions = 2
            cursor = index + 2 * size
            while (
                cursor + size <= len(lines)
                and lines[cursor : cursor + size] == lines[index : index + size]
            ):
                repetitions += 1
                cursor += size
            break
        if block_size:
            result.extend(lines[index : index + block_size])
            index += block_size * repetitions
        else:
            result.append(lines[index])
            index += 1
    return result


def _clean_rendered(text: str) -> str:
    """Apply lossy prompt, padding, animation, and repetition cleanup."""
    expanded: list[str] = []
    for line in text.split("\n"):
        timestamps = list(_PROMPT_TIMESTAMP_RE.finditer(line))
        if len(timestamps) < 2:
            expanded.append(line)
            continue
        start = 0
        for timestamp in timestamps[1:]:
            expanded.append(line[start : timestamp.start()].rstrip())
            start = timestamp.start()
        expanded.append(line[start:])

    without_padding: list[str] = []
    index = 0
    while index < len(expanded):
        end = index + 1
        if expanded[index].strip() == "~":
            while end < len(expanded) and expanded[end].strip() == "~":
                end += 1
            if end - index < 3:
                without_padding.extend(expanded[index:end])
            index = end
            continue
        without_padding.append(expanded[index])
        index += 1

    without_animation: list[str] = []
    index = 0
    while index < len(without_padding):
        if sum(not char.isspace() for char in without_padding[index]) > 3:
            without_animation.append(without_padding[index])
            index += 1
            continue
        end = index + 1
        while (
            end < len(without_padding)
            and sum(not char.isspace() for char in without_padding[end]) <= 3
        ):
            end += 1
        if end - index < 6:
            without_animation.extend(without_padding[index:end])
        index = end

    lines = _deduplicate_blocks(without_animation)
    compacted: list[str] = []
    index = 0
    while index < len(lines):
        end = index + 1
        while end < len(lines) and lines[end] == lines[index]:
            end += 1
        count = end - index
        compacted.append(lines[index])
        if count >= 3:
            compacted.append(f"  [×{count}]")
        elif count == 2:
            compacted.append(lines[index])
        index = end

    result: list[str] = []
    index = 0
    while index < len(compacted):
        if compacted[index].strip():
            result.append(compacted[index])
            index += 1
            continue
        end = index + 1
        while end < len(compacted) and not compacted[end].strip():
            end += 1
        result.extend(compacted[index : index + 1] if end - index >= 3 else compacted[index:end])
        index = end
    return "\n".join(result)


def _render_capture(path: Path, *, compact: bool = False) -> str:
    rendered = "\n".join(_iter_rendered_lines(path))
    return _clean_rendered(rendered) if compact else rendered


def _bounded_render(
    path: Path,
    *,
    max_lines: int,
    max_bytes: int,
    skip_lines: int = 0,
) -> tuple[str, bool]:
    lines: list[str] = []
    used = 0
    truncated = False
    for index, line in enumerate(_iter_rendered_lines(path)):
        if index < skip_lines:
            continue
        encoded = (line + "\n").encode("utf-8", errors="replace")
        if len(lines) >= max_lines or used + len(encoded) > max_bytes:
            truncated = True
            break
        lines.append(line)
        used += len(encoded)
    return "\n".join(lines), truncated


def _write_rendered(path: Path, stream, *, compact: bool = False) -> None:
    if compact:
        text = _render_capture(path, compact=True)
        stream.write(text)
        if text and not text.endswith("\n"):
            stream.write("\n")
        return
    wrote = False
    for line in _iter_rendered_lines(path):
        stream.write(line + "\n")
        wrote = True
    if wrote:
        stream.flush()


def _view_file(path: Path, *, paging: bool = False, compact: bool = False) -> None:
    if paging and shutil.which("less"):
        proc = subprocess.Popen(["less", "-R"], stdin=subprocess.PIPE, text=True)
        assert proc.stdin is not None
        try:
            try:
                _write_rendered(path, proc.stdin, compact=compact)
            except BrokenPipeError:
                # Exiting the pager early is a normal operator action.
                pass
        finally:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass
        proc.wait()
    else:
        _write_rendered(path, sys.stdout, compact=compact)
