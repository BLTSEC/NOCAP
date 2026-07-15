"""VT100 cleanup and rendered capture viewing for NOCAP."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

_ANSI_RE = re.compile(r"\x1b\[[?!0-9;]*[a-zA-Z]")
_RE_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_RE_CSI = re.compile(r"\x1b\[([0-9;?]*)([A-Za-z])")
_RE_ESC_MISC = re.compile(r"\x1b[^[\]]")
_VT100_COL_CAP = 500


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from *text*."""
    return _ANSI_RE.sub("", text)


def _vt100_render(data: str) -> str:
    """Emulate a VT100 line buffer to resolve \\r, cursor movement, and erase
    sequences, then strip all remaining ANSI codes.  Returns clean plain text."""
    data = _RE_OSC.sub("", data)
    data = _RE_ESC_MISC.sub("", data)

    lines: list[str] = []
    buf: list[str] = []
    pos = 0
    i = 0
    n = len(data)

    while i < n:
        ch = data[i]

        if ch == "\n":
            lines.append("".join(buf).rstrip())
            buf, pos = [], 0
            i += 1
            continue

        if ch == "\r":
            pos = 0
            i += 1
            continue

        if ch == "\x08":
            if pos > 0:
                pos -= 1
            i += 1
            continue

        if ch == "\x1b" and i + 1 < n and data[i + 1] == "[":
            m = _RE_CSI.match(data, i)
            if m:
                params_str, final = m.group(1), m.group(2)
                clean = params_str.lstrip("?")
                try:
                    params = [int(x) if x else 0 for x in clean.split(";")]
                except ValueError:
                    params = [0]

                if final == "D":
                    pos = max(0, pos - (params[0] or 1))
                elif final == "C":
                    pos = min(pos + (params[0] or 1), _VT100_COL_CAP)
                elif final == "G":
                    pos = min(max(0, (params[0] or 1) - 1), _VT100_COL_CAP)
                elif final == "K":
                    p = params[0]
                    if p == 0:
                        buf = buf[:pos]
                    elif p == 1:
                        buf = [" "] * pos + buf[pos:]
                    elif p == 2:
                        buf, pos = [], 0
                elif final == "J":
                    buf = buf[:pos]

                i = m.end()
                continue
            else:
                i += 1
                continue

        if ch == "\x1b":
            i += 1
            continue

        if ord(ch) < 0x20 or ch == "\x7f":
            i += 1
            continue

        # printable character
        if pos < len(buf):
            buf[pos] = ch
        else:
            if pos > len(buf):
                buf.extend([" "] * (pos - len(buf)))
            buf.append(ch)
        pos += 1
        i += 1

    if buf:
        lines.append("".join(buf).rstrip())

    return "\n".join(lines)


def _clean_rendered(text: str) -> str:
    """Post-process rendered output: collapse progress-bar spam, repeated
    blocks, and excessive blank lines."""
    lines = text.split("\n")

    # ── Strip animation artifacts (runs of ≥6 near-empty lines) ───────────
    cleaned: list[str] = []
    i = 0
    while i < len(lines):
        nws = sum(1 for c in lines[i] if not c.isspace())
        if nws <= 3:
            j = i
            while j < len(lines) and sum(1 for c in lines[j] if not c.isspace()) <= 3:
                j += 1
            if j - i >= 6:
                i = j
                continue
            cleaned.extend(lines[i:j])
            i = j
        else:
            cleaned.append(lines[i])
            i += 1
    lines = cleaned

    # ── Collapse 3+ consecutive identical lines → one + [×N] ─────────────
    deduped: list[str] = []
    i = 0
    while i < len(lines):
        j = i + 1
        while j < len(lines) and lines[j] == lines[i]:
            j += 1
        deduped.append(lines[i])
        count = j - i
        if count >= 3:
            deduped.append(f"  [\u00d7{count}]")
        elif count == 2:
            deduped.append(lines[i])
        i = j
    lines = deduped

    # ── Collapse 3+ consecutive blank lines → 1 ──────────────────────────
    result: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == "":
            j = i
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            if j - i >= 3:
                result.append("")
            else:
                result.extend(lines[i:j])
            i = j
        else:
            result.append(lines[i])
            i += 1

    return "\n".join(result)


def _render_capture(path: Path) -> str:
    """Read a capture file and return clean plain text."""
    raw = path.read_bytes().decode("utf-8", errors="replace")
    return _clean_rendered(_vt100_render(raw))


def _view_file(path: Path, *, paging: bool = False) -> None:
    """Display *path* rendered through the VT100 cleaner, with optional paging."""
    rendered = _render_capture(path)
    if paging:
        if shutil.which("less"):
            proc = subprocess.Popen(["less", "-R"], stdin=subprocess.PIPE)
            proc.communicate(input=rendered.encode())
        else:
            sys.stdout.write(rendered)
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
