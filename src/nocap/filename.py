"""Filename generation and atomic output-file allocation for NOCAP."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from nocap.tools import SKIP_FLAGS

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d+)?$")
_IP6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d+)?$")
_URL_RE = re.compile(r"^https?://")
_NUM_RE = re.compile(r"^\d+(,\d+)*$")
_HOSTLIKE_RE = re.compile(r"^[A-Za-z0-9.-]+$")

_COMMON_FILE_EXTS = frozenset({
    "7z", "bak", "cfg", "conf", "config", "csv", "db", "dll", "doc",
    "docx", "exe", "gz", "html", "ini", "jar", "json", "key", "log",
    "lst", "md", "pdf", "pem", "php", "ps1", "py", "sh", "sql", "sqlite",
    "tar", "tgz", "toml", "txt", "xml", "yaml", "yml", "zip",
})

_STEM_MAX_LEN = 60
_PART_MAX_LEN = 15
_HOST_LABEL_MAX_LEN = 12
_NOTE_MAX_LEN = 20


def _build_filename(cmd: list[str], note: str = "") -> str:
    """Derive a descriptive filename stem from a command + args list."""
    syntax_parts: list[str] = []
    context_parts: list[str] = []
    skip_next = False
    prev_flag = ""

    def _sanitize_part(value: str, max_len: int = _PART_MAX_LEN) -> str:
        clean = re.sub(r"^-+", "", value)
        clean = re.sub(r"[^a-zA-Z0-9_-]", "", clean)
        return clean[:max_len]

    # Unlike argument parts, the tool name used to be copied verbatim.  That
    # allowed whitespace/control characters and produced awkward double
    # extensions for tools such as ``script.py``.
    tool = _sanitize_part(Path(cmd[0]).name, max_len=_STEM_MAX_LEN) or "command"

    def _extract_host_label(value: str) -> str:
        if (
            not value
            or value.startswith("/")
            or "/" in value
            or "=" in value
            or _IP_RE.match(value)
            or _IP6_RE.match(value)
            or _URL_RE.match(value)
            or not _HOSTLIKE_RE.match(value)
            or "." not in value
        ):
            return ""

        labels = [part for part in value.split(".") if part]
        if len(labels) < 2:
            return ""

        if labels[-1].lower() in _COMMON_FILE_EXTS:
            return ""

        return _sanitize_part(labels[0], max_len=_HOST_LABEL_MAX_LEN)

    def _extract_url_label(value: str) -> str:
        if not _URL_RE.match(value):
            return ""

        try:
            host = urlsplit(value).hostname or ""
        except ValueError:
            # Malformed user input (most commonly an incomplete IPv6 URL)
            # should never prevent the wrapped command from running.
            return ""

        if not host or _IP_RE.match(host) or _IP6_RE.match(host):
            return ""

        return _extract_host_label(host)

    def _collapse_context(parts: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for part in parts:
            if part and part not in seen:
                seen.add(part)
                deduped.append(part)

        if len(deduped) <= 2:
            return deduped

        return [deduped[0], f"plus{len(deduped) - 1}"]

    def _joined_len(parts: list[str]) -> int:
        if not parts:
            return 0
        return sum(len(part) for part in parts) + (len(parts) - 1)

    for arg in cmd[1:]:
        if skip_next:
            if prev_flag in ("-u", "--url"):
                label = _extract_url_label(arg)
                if label:
                    context_parts.append(label)
            elif prev_flag in ("-d", "--domain"):
                label = _extract_host_label(arg)
                if label:
                    context_parts.append(label)
            skip_next = False
            prev_flag = ""
            continue

        if _IP_RE.match(arg):
            continue
        if _IP6_RE.match(arg):
            continue
        if not arg.startswith("-"):
            label = _extract_url_label(arg)
            if label:
                context_parts.append(label)
                continue
        if _URL_RE.match(arg):
            continue
        if arg.startswith("/"):
            continue
        if "=" in arg:
            _, _, val = arg.partition("=")
            if val.startswith("/") or val.startswith("./"):
                continue
        if not arg.startswith("-"):
            label = _extract_host_label(arg)
            if label:
                context_parts.append(label)
                continue
        if not arg.startswith("-") and "." in arg:
            continue
        if _NUM_RE.match(arg):
            continue
        if arg in SKIP_FLAGS:
            prev_flag = arg
            skip_next = True
            continue

        clean = _sanitize_part(arg)
        if clean:
            syntax_parts.append(clean)

    parts: list[str] = [tool]
    note_sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", note) if note else ""
    if note_sanitized and len(note_sanitized) > _NOTE_MAX_LEN:
        print(f"\033[33mnocap: note truncated to {_NOTE_MAX_LEN} chars: "
              f"{note_sanitized[:_NOTE_MAX_LEN]}\033[0m", file=sys.stderr)
    note_clean = note_sanitized[:_NOTE_MAX_LEN]
    context_parts = _collapse_context(context_parts)

    reserved_note = (1 + len(note_clean)) if note_clean else 0
    reserved_context = _joined_len(context_parts) + (1 if context_parts else 0)

    for part in syntax_parts:
        if _joined_len(parts + [part]) + reserved_context + reserved_note <= _STEM_MAX_LEN:
            parts.append(part)

    for part in context_parts:
        if _joined_len(parts + [part]) + reserved_note <= _STEM_MAX_LEN:
            parts.append(part)

    if note_clean and _joined_len(parts + [note_clean]) <= _STEM_MAX_LEN:
        parts.append(note_clean)

    name = "_".join(parts)
    name = re.sub(r"_+", "_", name).rstrip("_")[:_STEM_MAX_LEN]
    return name or tool


def _compute_outfile(outdir: Path, stem: str) -> Path:
    """Return the path that _claim_outfile would create (no filesystem write).
    Used for dry-run mode only — not race-safe."""
    candidate = outdir / f"{stem}.txt"
    if not candidate.exists():
        return candidate
    n = 2
    while (outdir / f"{stem}_{n}.txt").exists():
        n += 1
    return outdir / f"{stem}_{n}.txt"


def _claim_outfile(outdir: Path, stem: str) -> Path:
    """Atomically create and return a unique output file path.

    Uses O_CREAT | O_EXCL to guarantee no two concurrent cap invocations
    claim the same filename (eliminates the TOCTOU race in a plain exists-check).
    """
    candidate = outdir / f"{stem}.txt"
    n = 2
    while True:
        try:
            fd = os.open(str(candidate), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            return candidate
        except FileExistsError:
            candidate = outdir / f"{stem}_{n}.txt"
            n += 1
