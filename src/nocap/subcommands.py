"""NOCAP subcommands, metadata lifecycle, and tmux scrollback helpers."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections import deque
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TextIO

from nocap.config import Settings, load_settings
from nocap.filename import (
    _build_filename,
    _claim_outfile,
    _normalize_command,
)
from nocap.metadata import (
    COMMAND_PREFIX,
    DATE_PREFIX,
    HEADER_SEPARATOR,
    SCHEMA_VERSION,
    abandon_record,
    assert_safe_output_path,
    capture_path,
    create_record,
    delete_capture,
    export_records,
    finalize_record,
    find_capture_files,
    is_capture_file,
    load_records,
    metadata_status,
    prune_tombstones,
    record_for_path,
    rename_capture,
    resolve_record,
    retained_records,
    sync_records,
    tag_record,
    verify_record,
)
from nocap.rendering import _bounded_render, _strip_ansi, _view_file
from nocap.routing import (
    _active_root,
    _ensure_contained,
    _get_output_dir,
    _route_label,
    _target_value,
)
from nocap.tools import route_for_tool

_SUMMARY_PATTERNS: dict[str, re.Pattern[str]] = {
    "passwords": re.compile(
        r"(?:password|passwd|pass(?:word)?|pwd|secret|credential)\s*[:=]\s*\S+"
        r"|\[\+\]\s+\S+\\\S+:\S+|login:\s*\S+.*password:\s*\S+",
        re.IGNORECASE,
    ),
    "hashes": re.compile(
        r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"
        r"|(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"
        r"|(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"
        r"|(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"
    ),
    "users": re.compile(r"(?:username|user|login|account|uid)\s*[:=]\s*\S+", re.IGNORECASE),
    "emails": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "ports": re.compile(r"\d+/(?:tcp|udp)\s+open"),
    "vulns": re.compile(
        r"CVE-\d{4}-\d+|vulnerable|exploitable|(?:severity|risk):\s*(?:critical|high)",
        re.IGNORECASE,
    ),
    "urls": re.compile(r"https?://[^\s'\"<>]+"),
}

_CACHE_HOME = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")).expanduser()
_LAST_FILE = _CACHE_HOME / "nocap" / "last"
_READ_CHUNK = 65536
_PROMPT_GLYPH_RE = re.compile(
    r"^[╭╰┌└├┬┼]|^[❯➜›»](?:\s|$)|^[$#%>](?:\s|$)"
)
_BASIC_PROMPT_RE = re.compile(
    r"^(?:\([^\r\n)]+\)\s*)?(?:\[[^\r\n\]]+\]|"
    r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+(?:[^\r\n$#%>]*)?)[$#%>](?:\s|$)"
)


def _fail(message: str, code: int = 1) -> None:
    print(f"nocap: {message}", file=sys.stderr)
    raise SystemExit(code)


def _settings() -> Settings:
    try:
        return load_settings()
    except ValueError as exc:
        _fail(str(exc), 2)
    raise AssertionError


def _root(settings: Settings | None = None) -> Path:
    try:
        return _active_root(settings or _settings())
    except ValueError as exc:
        _fail(str(exc), 2)
    raise AssertionError


def _sync_quiet(root: Path) -> None:
    try:
        sync_records(root)
    except (OSError, ValueError) as exc:
        print(f"nocap: warning: metadata sync failed: {exc}", file=sys.stderr)


def _in_tmux() -> bool:
    return bool(os.environ.get("TMUX"))


def _tmux_scrollback() -> str:
    try:
        result = subprocess.run(
            ["tmux", "capture-pane", "-p", "-S", "-", "-E", "-"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("tmux executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("tmux capture-pane timed out") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise RuntimeError(f"tmux capture-pane failed: {detail}")
    return result.stdout


def _last_command_from_history() -> str | None:
    shell = Path(os.environ.get("SHELL", "/bin/sh")).name
    default = Path.home() / (".zsh_history" if shell == "zsh" else ".bash_history")
    path = Path(os.environ.get("HISTFILE", default))
    if not path.is_file():
        return None
    try:
        with path.open("rb") as fh:
            try:
                fh.seek(-min(path.stat().st_size, 1024 * 1024), os.SEEK_END)
            except OSError:
                fh.seek(0)
            text = fh.read().decode("utf-8", errors="surrogateescape")
    except OSError:
        return None
    for line in reversed(text.splitlines()):
        command = line.split(";", 1)[1].strip() if line.startswith(": ") and ";" in line else line.strip()
        if command and command != "cap grab" and not command.startswith("cap grab "):
            return command
    return None


def _is_prompt_line(line: str) -> bool:
    clean = _strip_ansi(line).strip()
    return bool(_PROMPT_GLYPH_RE.search(clean) or _BASIC_PROMPT_RE.search(clean))


def _starts_new_prompt(line: str) -> bool:
    clean = _strip_ansi(line).strip()
    return bool(clean and (_PROMPT_GLYPH_RE.search(clean) or _BASIC_PROMPT_RE.search(clean)))


def _looks_like_prompt_command(clean_line: str, command: str) -> bool:
    position = clean_line.find(command)
    return position >= 0 and _starts_new_prompt(clean_line[:position])


def _extract_output(scrollback: str, command: str) -> str:
    lines = scrollback.split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and "cap grab" in lines[-1]:
        lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and _is_prompt_line(lines[-1]):
        lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()

    clean = [_strip_ansi(line) for line in lines]
    command_index = next(
        (index for index in range(len(clean) - 1, -1, -1) if command in clean[index] and _looks_like_prompt_command(clean[index], command)),
        None,
    )
    if command_index is None:
        command_index = next((index for index in range(len(clean) - 1, -1, -1) if command in clean[index]), None)

    if command_index is not None:
        end = next((index for index in range(command_index + 1, len(lines)) if _starts_new_prompt(lines[index])), len(lines))
        output = lines[command_index + 1 : end]
    else:
        prompt_index = next((index for index in range(len(clean) - 1, -1, -1) if _starts_new_prompt(clean[index])), None)
        output = lines[prompt_index + 1 :] if prompt_index is not None else lines
    while output and not output[0].strip():
        output.pop(0)
    while output and not output[-1].strip():
        output.pop()
    return "\n".join(output)


def _pointer_path() -> Path | None:
    if _LAST_FILE.is_symlink():
        _fail("last-file pointer is a symlink — refusing")
    if not _LAST_FILE.exists():
        return None
    try:
        path = Path(_LAST_FILE.read_text(encoding="utf-8", errors="surrogateescape").strip())
    except (OSError, UnicodeError) as exc:
        _fail(f"cannot read last-file pointer: {exc}")
    return path


def _last_path(root: Path) -> Path:
    pointer = _pointer_path()
    if pointer is not None and not pointer.is_symlink() and pointer.is_file():
        try:
            contained = pointer.resolve(strict=False).is_relative_to(root.resolve(strict=False))
        except OSError:
            contained = False
        if contained:
            record = record_for_path(root, pointer)
            if record is not None and record.get("status") != "deleted":
                return pointer.resolve(strict=False)
    for record in retained_records(root):
        path = capture_path(root, record)
        if path.is_file() and not path.is_symlink():
            _remember_last(path)
            return path
    _LAST_FILE.unlink(missing_ok=True)
    _fail(f"no captures in active target: {root}")
    raise AssertionError


def _remember_last(path: Path) -> bool:
    tmp = _LAST_FILE.parent / f".{_LAST_FILE.name}.{os.getpid()}.tmp"
    try:
        _LAST_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(str(path.resolve()).encode("utf-8", errors="surrogateescape"))
        os.replace(tmp, _LAST_FILE)
    except OSError as exc:
        print(f"nocap: warning: cannot update last-file pointer: {exc}", file=sys.stderr)
        return False
    finally:
        tmp.unlink(missing_ok=True)
    return True


def _advance_last(root: Path) -> None:
    records = retained_records(root)
    for record in records:
        path = capture_path(root, record)
        if path.is_file():
            _remember_last(path)
            return
    _LAST_FILE.unlink(missing_ok=True)


def _write_capture_header(fh: TextIO, command: str) -> None:
    date = datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Z %Y")
    display_command = command.replace("\r", r"\r").replace("\n", r"\n")
    fh.write(f"{COMMAND_PREFIX}{display_command}\n{DATE_PREFIX}{date}\n{HEADER_SEPARATOR}\n")


def _is_capture_file(path: Path) -> bool:
    return is_capture_file(path)


def _find_capture_files(root: Path) -> list[Path]:
    return find_capture_files(root)


def _count_lines(path: Path) -> int:
    try:
        with path.open("rb") as fh:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(_READ_CHUNK), b""))
    except OSError:
        return 0


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024 or unit == "T":
            return f"{int(value)}B" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}T"


def _record_for_selector(root: Path, selector: str | None = None) -> dict[str, Any]:
    _sync_quiet(root)
    if selector:
        try:
            return resolve_record(root, selector)
        except ValueError as exc:
            _fail(str(exc))
    path = _last_path(root)
    record = record_for_path(root, path)
    if record is None:
        _sync_quiet(root)
        record = record_for_path(root, path)
    if record is None:
        _fail(f"last capture is outside the active target: {path}")
    return record


def _require_no_args(name: str, args: list[str] | None) -> None:
    if args:
        print(f"nocap: {name} does not accept arguments", file=sys.stderr)
        print(f"  tip: use `cap -- {name} ...` to capture the {name} command", file=sys.stderr)
        raise SystemExit(2)


def _route_for(cmd: list[str], settings: Settings) -> tuple[list[str], str, str]:
    normalized = _normalize_command(cmd, settings.aliases)
    tool = Path(normalized[0]).name if normalized else ""
    route = settings.routes.get(tool)
    if route is None:
        route = route_for_tool(tool, normalized[1:])
    return normalized, tool, route


def _cmd_last(args: list[str] | None = None) -> None:
    _require_no_args("last", args)
    root = _root()
    _sync_quiet(root)
    print(_last_path(root))


def _path_view_parser(name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"cap {name}", allow_abbrev=False)
    parser.add_argument("selector", nargs="?")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="apply lossy padding, animation, and repetition cleanup",
    )
    return parser


def _view_selector(selector: str | None, *, compact: bool = False, paging: bool = False) -> None:
    if selector and Path(selector).expanduser().is_file():
        path = Path(selector).expanduser()
    elif selector:
        root = _root()
        path = capture_path(root, _record_for_selector(root, selector))
    else:
        root = _root()
        _sync_quiet(root)
        path = _last_path(root)
    _view_file(path, paging=paging, compact=compact)


def _cmd_cat(args: list[str] | None = None) -> None:
    ns = _path_view_parser("cat").parse_args(args or [])
    _view_selector(ns.selector, compact=ns.compact)


def _cmd_render(args: list[str] | None = None) -> None:
    ns = _path_view_parser("render").parse_args(args or [])
    _view_selector(ns.selector, compact=ns.compact)


def _cmd_tail(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap tail", allow_abbrev=False)
    parser.add_argument("selector", nargs="?")
    ns = parser.parse_args(args or [])
    root = _root()
    _sync_quiet(root)
    path = capture_path(root, _record_for_selector(root, ns.selector)) if ns.selector else _last_path(root)
    subprocess.run(["tail", "-n", "+1", "-f", str(path)])


def _cmd_open(args: list[str] | None = None) -> None:
    ns = _path_view_parser("open").parse_args(args or [])
    if ns.selector:
        root = _root()
        path = capture_path(root, _record_for_selector(root, ns.selector))
    else:
        root = _root()
        _sync_quiet(root)
        path = _last_path(root)
    editor = os.environ.get("EDITOR", "").strip()
    if editor:
        try:
            command = shlex.split(editor)
        except ValueError as exc:
            _fail(f"invalid $EDITOR: {exc}")
        if command:
            subprocess.run(command + [str(path)])
            return
    _view_file(path, paging=True, compact=ns.compact)


def _fzf_select(
    root: Path,
    records: list[dict[str, Any]],
    *,
    multi: bool,
    prompt: str,
    header: str = "",
) -> list[dict[str, Any]]:
    if not shutil.which("fzf"):
        _fail("fzf is required for this selector; use `cap ls` for a non-interactive listing")
    lines = []
    by_id = {str(record["id"]): record for record in records}
    for record in records:
        started = str(record.get("started_at", ""))[:19]
        lines.append(f"{record['id']}\t{started}\t{record.get('status', '')}\t{record.get('path', '')}")
    command = [
        "fzf",
        "--ansi",
        "--delimiter=\t",
        "--with-nth=2..",
        f"--prompt={prompt} > ",
        "--preview=cap render {1}",
        "--preview-window=right:65%:wrap",
    ]
    if multi:
        command.extend(["--multi", "--bind=tab:toggle+down"])
    if header:
        command.append(f"--header={header}")
    result = subprocess.run(command, input="\n".join(lines), text=True, capture_output=True)
    if result.returncode not in {0, 1, 130}:
        _fail(result.stderr.strip() or "fzf failed")
    selected: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        record = by_id.get(line.split("\t", 1)[0])
        if record:
            selected.append(record)
    return selected


def _confirm_delete(records: list[dict[str, Any]]) -> bool:
    print("Delete these captures?", file=sys.stderr)
    for record in records:
        print(f"  {record.get('path')}", file=sys.stderr)
    try:
        answer = input("Type 'delete' to confirm: ")
    except EOFError:
        return False
    return answer.strip().lower() == "delete"


def _cmd_rm(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap rm", allow_abbrev=False)
    parser.add_argument("selector", nargs="?")
    parser.add_argument("--pick", action="store_true")
    ns = parser.parse_args(args or [])
    root = _root()
    _sync_quiet(root)
    if ns.pick:
        if ns.selector:
            _fail("rm --pick does not accept a selector", 2)
        records = retained_records(root)
        protected = sum(record.get("status") in {"running", "deleting"} for record in records)
        records = [record for record in records if record.get("status") not in {"running", "deleting"}]
        header = f"{protected} active capture(s) excluded" if protected else ""
        selected = _fzf_select(root, records, multi=True, prompt="remove", header=header)
        if not selected or not _confirm_delete(selected):
            print("nocap: deletion cancelled", file=sys.stderr)
            return
    else:
        selected = [_record_for_selector(root, ns.selector)]
    for record in selected:
        path = capture_path(root, record)
        try:
            delete_capture(root, record)
        except (OSError, ValueError) as exc:
            _fail(str(exc))
        print(f"[rm] {path}", file=sys.stderr)
    _advance_last(root)


def _record_rows(root: Path, records: list[dict[str, Any]]) -> list[tuple[str, str, str, str, str]]:
    rows = []
    for record in records:
        path = capture_path(root, record)
        started = str(record.get("started_at", ""))[:16].replace("T", " ")
        status = str(record.get("status", ""))
        size = _format_size(int(record.get("size_bytes") or 0))
        route = str(record.get("route") or "-")
        rows.append((started, status, size, route, str(record.get("path", path))))
    return rows


def _list_records(
    root: Path,
    records: list[dict[str, Any]],
    *,
    subdir: str | None,
    tag: str | None,
    status: str | None,
    limit: int | None,
) -> list[dict[str, Any]]:
    if subdir:
        try:
            scope = _ensure_contained(root, Path(subdir), label="subdir")
        except ValueError as exc:
            _fail(str(exc), 2)
        relative = scope.relative_to(root)
        if relative != Path("."):
            prefix = relative.as_posix().rstrip("/") + "/"
            records = [
                record
                for record in records
                if str(record.get("path", "")).startswith(prefix)
            ]
    if tag:
        records = [record for record in records if tag.lower() in record.get("tags", [])]
    if status:
        records = [record for record in records if record.get("status") == status]
    return records if limit is None else records[:limit]


def _cmd_ls(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap ls", allow_abbrev=False)
    parser.add_argument("subdir", nargs="?")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--tag")
    parser.add_argument("--status")
    parser.add_argument("--include-deleted", action="store_true")
    parser.add_argument("--json", action="store_true")
    ns = parser.parse_args(args or [])
    if ns.status == "deleted" and not ns.include_deleted:
        _fail("--status deleted requires --include-deleted", 2)
    settings = _settings()
    root = _root(settings)
    _sync_quiet(root)
    limit = None if ns.all else settings.list_limit
    records = _list_records(
        root,
        retained_records(root, include_deleted=ns.include_deleted),
        subdir=ns.subdir,
        tag=ns.tag,
        status=ns.status,
        limit=None if limit is None else limit + 1,
    )
    truncated = limit is not None and len(records) > limit
    if truncated:
        records = records[:limit]
    if ns.json:
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "root": str(root),
                    "limit": limit,
                    "truncated": truncated,
                    "captures": records,
                },
                indent=2,
            )
        )
        return
    if not records:
        _fail(f"no captures in {root}")
    print(f"  {root}")
    print(f"{'STARTED':16}  {'STATUS':11}  {'SIZE':>7}  {'ROUTE':14}  CAPTURE")
    for started, status, size, route, path in _record_rows(root, records):
        print(f"{started:16}  {status:11}  {size:>7}  {route:14}  {path}")
    if truncated:
        print(f"nocap: result limit reached ({limit}); use --all to continue", file=sys.stderr)


def _cmd_browse(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap browse", allow_abbrev=False)
    parser.add_argument("subdir", nargs="?")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--tag")
    parser.add_argument("--status")
    parser.add_argument("--print", dest="print_path", action="store_true")
    ns = parser.parse_args(args or [])
    settings = _settings()
    root = _root(settings)
    _sync_quiet(root)
    limit = None if ns.all else settings.list_limit
    records = _list_records(
        root,
        retained_records(root),
        subdir=ns.subdir,
        tag=ns.tag,
        status=ns.status,
        limit=None if limit is None else limit + 1,
    )
    truncated = limit is not None and len(records) > limit
    if truncated:
        records = records[:limit]
    if not records:
        _fail(f"no captures in {root}")
    header = f"showing {limit}; use --all for every capture" if truncated else ""
    if truncated:
        print(f"nocap: result limit reached ({limit}); use --all to continue", file=sys.stderr)
    selected = _fzf_select(root, records, multi=False, prompt="captures", header=header)
    if selected:
        path = capture_path(root, selected[0])
        if ns.print_path:
            print(path)
        else:
            _view_file(path, paging=True)


def _search_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cap search", allow_abbrev=False)
    parser.add_argument("query", nargs="?")
    parser.add_argument("--regex", action="store_true")
    parser.add_argument("--kind", choices=sorted(_SUMMARY_PATTERNS))
    parser.add_argument("--context", type=int, default=0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def _cmd_search(args: list[str] | None = None) -> None:
    ns = _search_parser().parse_args(args or [])
    if not ns.query and not ns.kind:
        _fail("search requires QUERY or --kind", 2)
    if ns.context < 0:
        _fail("context must be non-negative", 2)
    if ns.limit is not None and ns.limit <= 0:
        _fail("limit must be positive", 2)
    if ns.kind:
        pattern = _SUMMARY_PATTERNS[ns.kind]
        label = ns.kind
    elif ns.regex:
        try:
            pattern = re.compile(ns.query, re.IGNORECASE)
        except re.error as exc:
            _fail(f"invalid regex: {exc}", 2)
        label = ns.query
    else:
        pattern = re.compile(re.escape(ns.query), re.IGNORECASE)
        label = ns.query
    settings = _settings()
    root = _root(settings)
    _sync_quiet(root)
    limit = None if ns.all else (ns.limit or settings.search_limit)
    scan_limit = None if limit is None else limit + 1
    results: list[dict[str, Any]] = []
    for record in retained_records(root):
        path = capture_path(root, record)
        if not path.is_file():
            continue
        try:
            matches = _search_file_matches(path, pattern, ns.context)
            for match in matches:
                results.append({"capture_id": record["id"], "path": record["path"], **match})
                if scan_limit is not None and len(results) >= scan_limit:
                    break
        except OSError:
            continue
        if scan_limit is not None and len(results) >= scan_limit:
            break
    truncated = limit is not None and len(results) > limit
    if truncated:
        results = results[:limit]
    if ns.json:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "query": label, "matches": results}, indent=2))
    else:
        for result in results:
            if not ns.context:
                print(f"{result['path']}:{result['line']}: {result['match']}")
                continue
            print(f"-- {result['path']}:{result['line']} --")
            for offset, value in enumerate(result["context"]):
                line_number = result["context_start"] + offset
                marker = ">" if line_number == result["line"] else " "
                print(f"{marker} {line_number:6}: {value}")
    if not results:
        _fail(f"no matches for '{label}'")
    if truncated:
        print(f"nocap: result limit reached ({limit}); use --all to continue", file=sys.stderr)


def _search_file_matches(
    path: Path,
    pattern: re.Pattern[str],
    context: int,
) -> Iterator[dict[str, Any]]:
    before: deque[tuple[int, str]] = deque(maxlen=context)
    pending: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_number, raw in enumerate(fh, 1):
            clean = _strip_ansi(raw.rstrip("\r\n"))
            ready: list[dict[str, Any]] = []
            for item in pending:
                item["after"].append(clean)
                if len(item["after"]) >= context:
                    ready.append(item)
            for item in ready:
                pending.remove(item)
                yield {
                    "line": item["line"],
                    "match": item["match"],
                    "context_start": item["context_start"],
                    "context": item["before"] + [item["match"]] + item["after"],
                }
            if pattern.search(clean):
                previous = [value for _, value in before]
                item = {
                    "line": line_number,
                    "match": clean,
                    "context_start": line_number - len(previous),
                    "before": previous,
                    "after": [],
                }
                if context:
                    pending.append(item)
                else:
                    yield {"line": line_number, "match": clean, "context_start": line_number, "context": [clean]}
            before.append((line_number, clean))
    for item in pending:
        yield {
            "line": item["line"],
            "match": item["match"],
            "context_start": item["context_start"],
            "context": item["before"] + [item["match"]] + item["after"],
        }


def _parse_since(value: str) -> datetime:
    match = re.fullmatch(r"(\d+)([mhdw])", value.strip().lower())
    if not match:
        raise ValueError("duration must look like 30m, 2h, 7d, or 2w")
    amount = int(match.group(1))
    if amount <= 0:
        raise ValueError("duration must be positive")
    delta = {"m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount), "w": timedelta(weeks=amount)}[match.group(2)]
    return datetime.now(timezone.utc) - delta


def _filter_records(records: list[dict[str, Any]], ns: Any) -> list[dict[str, Any]]:
    if getattr(ns, "tag", None):
        records = [record for record in records if ns.tag.lower() in record.get("tags", [])]
    if getattr(ns, "tool", None):
        records = [record for record in records if record.get("effective_tool") == ns.tool]
    if getattr(ns, "status", None):
        records = [record for record in records if record.get("status") == ns.status]
    if getattr(ns, "since", None):
        try:
            cutoff = _parse_since(ns.since)
        except ValueError as exc:
            _fail(str(exc), 2)
        filtered = []
        for record in records:
            try:
                started = datetime.fromisoformat(str(record.get("started_at", "")).replace("Z", "+00:00"))
            except ValueError:
                continue
            if started >= cutoff:
                filtered.append(record)
        records = filtered
    return records


def _md_escape(value: Any) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _md_code(value: Any) -> str:
    text = str(value if value is not None else "").replace("\n", " ").replace("|", "\\|")
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(1, longest + 1)
    padding = " " if text.startswith(("`", " ")) or text.endswith(("`", " ")) else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def _timeline_markdown(records: list[dict[str, Any]]) -> str:
    lines = [
        "| # | Time (UTC) | Status | Tool | Duration | Command | Capture | Tags |",
        "|---:|---|---|---|---:|---|---|---|",
    ]
    for number, record in enumerate(records, 1):
        duration = "" if record.get("duration_ms") is None else f"{int(record['duration_ms']) / 1000:.1f}s"
        tags = ", ".join(record.get("tags", []))
        lines.append(
            f"| {number} | {_md_escape(str(record.get('started_at', ''))[:19])} | "
            f"{_md_escape(record.get('status'))} | {_md_escape(record.get('effective_tool'))} | "
            f"{duration} | {_md_code(record.get('command', ''))} | "
            f"{_md_code(record.get('path'))} | {_md_escape(tags)} |"
        )
    return "\n".join(lines) + "\n"


def _cmd_timeline(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap timeline", allow_abbrev=False)
    parser.add_argument("--include-deleted", action="store_true")
    parser.add_argument("--format", choices=("table", "md", "json"), default="table")
    parser.add_argument("--tag")
    parser.add_argument("--tool")
    parser.add_argument("--status")
    parser.add_argument("--since")
    ns = parser.parse_args(args or [])
    root = _root()
    _sync_quiet(root)
    records = _filter_records(retained_records(root, include_deleted=ns.include_deleted), ns)
    records.reverse()
    if ns.format == "json":
        print(json.dumps({"schema_version": SCHEMA_VERSION, "root": str(root), "captures": records}, indent=2))
    elif ns.format == "md":
        print(_timeline_markdown(records), end="")
    else:
        for record in records:
            duration = "-" if record.get("duration_ms") is None else f"{int(record['duration_ms']) / 1000:.1f}s"
            print(
                f"{str(record.get('started_at', ''))[:19]}  {str(record.get('status', '')):11}  "
                f"{duration:>8}  {str(record.get('effective_tool', '')):18}  {record.get('path', '')}"
            )


def _cmd_inspect(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap inspect", allow_abbrev=False)
    parser.add_argument("selector", nargs="?")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--json", action="store_true")
    ns = parser.parse_args(args or [])
    root = _root()
    record = _record_for_selector(root, ns.selector)
    result = dict(record)
    if ns.verify:
        ok, detail = verify_record(root, record)
        result["integrity"] = {"ok": ok, "detail": detail}
    if ns.json:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "capture": result}, indent=2))
        return
    for key in ("id", "path", "status", "source", "effective_tool", "route", "started_at", "finished_at", "duration_ms", "exit_code", "sha256", "tags", "command"):
        print(f"{key:16} {result.get(key)}")
    if "integrity" in result:
        print(f"{'integrity':16} {'ok' if result['integrity']['ok'] else result['integrity']['detail']}")


def _cmd_tag(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap tag", allow_abbrev=False)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("add", "remove"):
        child = sub.add_parser(action)
        child.add_argument("tags", nargs="+")
        child.add_argument("--capture")
    child = sub.add_parser("list")
    child.add_argument("--capture")
    ns = parser.parse_args(args or [])
    root = _root()
    record = _record_for_selector(root, ns.capture)
    if ns.action == "list":
        for tag in record.get("tags", []):
            print(tag)
        return
    updated = tag_record(root, record, ns.tags, remove=ns.action == "remove")
    print(" ".join(updated.get("tags", [])))


def _sanitize_label(value: str) -> str:
    value = Path(value).stem
    value = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-_")
    value = re.sub(r"[-_]{2,}", "-", value)
    if not value:
        _fail("rename label has no usable characters", 2)
    return value[:60]


def _cmd_rename(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap rename", allow_abbrev=False)
    parser.add_argument("label")
    parser.add_argument("selector", nargs="?")
    ns = parser.parse_args(args or [])
    root = _root()
    record = _record_for_selector(root, ns.selector)
    old_path = capture_path(root, record)
    was_last = False
    if _LAST_FILE.is_file() and not _LAST_FILE.is_symlink():
        try:
            was_last = old_path == Path(_LAST_FILE.read_text(encoding="utf-8").strip())
        except OSError:
            pass
    stem = _sanitize_label(ns.label)
    target = _claim_outfile(old_path.parent, stem)
    try:
        rename_capture(root, record, target)
    except (OSError, ValueError) as exc:
        try:
            if old_path.is_file() and target.is_file() and target.stat().st_size == 0:
                target.unlink()
        except OSError:
            pass
        _fail(f"rename failed: {exc}")
    if was_last:
        _remember_last(target)
    print(target)


def _fence_for(text: str) -> str:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _review_markdown(
    root: Path,
    records: list[dict[str, Any]],
    *,
    metadata_only: bool,
    max_lines: int,
    max_bytes: int,
) -> str:
    lines = [
        "# NOCAP Review Packet",
        "",
        "> **Sensitive:** This file contains executed command provenance and may contain raw findings or credentials.",
        "",
        f"- Target root: `{root}`",
        f"- Generated: `{datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}`",
        f"- Captures: `{len(records)}`",
        "",
        "## Timeline",
        "",
        _timeline_markdown(records).rstrip(),
    ]
    if metadata_only:
        return "\n".join(lines) + "\n"
    lines.extend(["", "## Evidence"])
    for number, record in enumerate(records, 1):
        path = capture_path(root, record)
        if not path.is_file():
            continue
        rendered, truncated = _bounded_render(
            path, max_lines=max_lines, max_bytes=max_bytes, skip_lines=3
        )
        fence = _fence_for(rendered)
        lines.extend(
            [
                "",
                f"### {number}. {record.get('path')}",
                "",
                f"- ID: {_md_code(record.get('id'))}; status: {_md_code(record.get('status'))}; SHA-256: {_md_code(record.get('sha256'))}",
                "",
                fence + "text",
                rendered,
                fence,
            ]
        )
        if truncated:
            lines.append(f"\n_Output truncated at {max_lines} lines or {max_bytes} bytes; inspect `{record.get('path')}` for the raw capture._")
    return "\n".join(lines) + "\n"


def _cmd_review(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap review", allow_abbrev=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--pick", action="store_true")
    group.add_argument("--last", type=int)
    group.add_argument("--since")
    parser.add_argument("--tag")
    parser.add_argument("-o", "--output")
    parser.add_argument("--metadata-only", action="store_true")
    parser.add_argument("--max-lines", type=int)
    parser.add_argument("--max-bytes", type=int)
    ns = parser.parse_args(args or [])
    if ns.max_lines is not None and ns.max_lines <= 0:
        _fail("--max-lines must be positive", 2)
    if ns.max_bytes is not None and ns.max_bytes <= 0:
        _fail("--max-bytes must be positive", 2)
    settings = _settings()
    root = _root(settings)
    _sync_quiet(root)
    records = retained_records(root)
    if ns.tag:
        records = [record for record in records if ns.tag.lower() in record.get("tags", [])]
    if ns.since:
        records = _filter_records(records, ns)
    if ns.pick:
        records = _fzf_select(root, records, multi=True, prompt="review")
    else:
        count = ns.last if ns.last is not None else settings.review_limit
        if count <= 0:
            _fail("--last must be positive", 2)
        records = records[:count]
    records.sort(key=lambda record: str(record.get("started_at") or ""))
    text = _review_markdown(
        root,
        records,
        metadata_only=ns.metadata_only,
        max_lines=ns.max_lines or settings.review_max_lines,
        max_bytes=ns.max_bytes or settings.review_max_bytes,
    )
    if ns.output:
        try:
            output = assert_safe_output_path(root, Path(ns.output).expanduser())
            output.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(
                output,
                os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                os.fchmod(fh.fileno(), 0o600)
                fh.write(text)
        except (OSError, ValueError) as exc:
            _fail(f"cannot write review packet: {exc}")
        print(output)
    else:
        print(text, end="")


def _cmd_meta(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap meta", allow_abbrev=False)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("status")
    sync = sub.add_parser("sync")
    sync.add_argument("--repair-stale", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("selector", nargs="?")
    export = sub.add_parser("export")
    export.add_argument("path", nargs="?")
    prune = sub.add_parser("prune")
    prune.add_argument("--yes", action="store_true")
    ns = parser.parse_args(args or [])
    root = _root()
    if ns.action == "status":
        print(json.dumps(metadata_status(root), indent=2))
    elif ns.action == "sync":
        print(json.dumps(sync_records(root, repair_stale=ns.repair_stale), indent=2))
    elif ns.action == "verify":
        _sync_quiet(root)
        _, errors = load_records(root)
        records = [_record_for_selector(root, ns.selector)] if ns.selector else retained_records(root)
        failed = bool(errors)
        for path, detail in errors:
            print(f"FAIL  {path}  malformed: {detail}")
        for record in records:
            try:
                ok, detail = verify_record(root, record)
            except (OSError, ValueError) as exc:
                ok, detail = False, str(exc)
            print(f"{'ok' if ok else 'FAIL':4}  {record.get('path')}  {detail}")
            failed = failed or not ok
        if failed:
            raise SystemExit(1)
    elif ns.action == "export":
        try:
            count = export_records(root, Path(ns.path).expanduser() if ns.path else None)
        except (OSError, ValueError) as exc:
            _fail(str(exc))
        if ns.path:
            print(f"exported {count} records to {ns.path}")
    elif ns.action == "prune":
        try:
            paths = prune_tombstones(root, apply=ns.yes)
        except (OSError, ValueError) as exc:
            _fail(str(exc))
        for path in paths:
            print(path)
        print(f"{'pruned' if ns.yes else 'would prune'} {len(paths)} tombstones", file=sys.stderr)


def _cmd_status(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cap status", allow_abbrev=False)
    parser.add_argument("--json", action="store_true")
    ns = parser.parse_args(args or [])
    settings = _settings()
    root = _root(settings)
    target, target_source = _target_value()
    result = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(settings.workspace),
        "active_root": str(root),
        "config_sources": [str(path) for path in settings.sources],
        "auto_route": settings.auto_route,
        "tmux": _in_tmux(),
        "tacmux_target": os.environ.get("TACMUX_TARGET", ""),
        "target": target,
        "target_source": target_source,
        "metadata": metadata_status(root),
    }
    if ns.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"workspace       {result['workspace']}")
        print(f"active root     {result['active_root']}")
        print(f"target          {result['target'] or '-'}")
        print(f"target source   {result['target_source'] or '-'}")
        print(f"captures        {result['metadata']['records']}")
        issues = (
            result["metadata"]["missing"]
            + result["metadata"]["stale_running"]
            + result["metadata"]["orphaned_captures"]
            + result["metadata"]["malformed_records"]
            + result["metadata"]["pending_deletes"]
            + result["metadata"]["incomplete_records"]
            + result["metadata"]["duplicate_active_paths"]
        )
        print(f"metadata issues {issues}")



def _cmd_update(args: list[str] | None = None) -> None:
    _require_no_args("update", args)
    if not shutil.which("pipx"):
        _fail("pipx not found — install pipx or update manually")
    raise SystemExit(subprocess.run(["pipx", "upgrade", "nocap"]).returncode)


def _cmd_summary(args: list[str] | None = None) -> None:
    if args and len(args) > 1:
        _fail("summary accepts at most one keyword or regex; quote patterns containing spaces", 2)
    keyword = args[0] if args else ""
    if keyword:
        if keyword.lower() in _SUMMARY_PATTERNS:
            _cmd_search(["--kind", keyword.lower(), "--all"])
            return
        try:
            re.compile(keyword)
        except re.error:
            _cmd_search([keyword, "--all"])
        else:
            _cmd_search(["--regex", keyword, "--all"])
        return

    root = _root()
    _sync_quiet(root)
    rows: list[tuple[str, int, str, str]] = []
    for record in retained_records(root):
        path = capture_path(root, record)
        if not path.is_file():
            continue
        try:
            stat_result = path.stat()
        except OSError:
            continue
        rows.append(
            (
                datetime.fromtimestamp(stat_result.st_mtime).strftime("%Y-%m-%d %H:%M"),
                _count_lines(path),
                _format_size(stat_result.st_size),
                str(record.get("path", path)),
            )
        )
    if not rows:
        _fail(f"no captures in {root}")
    line_width = max(len(str(row[1])) for row in rows)
    size_width = max(len(row[2]) for row in rows)
    for mtime, lines, size, path in rows:
        print(f"{mtime}  {lines:{line_width}} lines  {size:{size_width}}  {path}")


def _build_grab_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cap grab", allow_abbrev=False)
    parser.add_argument("-n", "--note", default="", metavar="LABEL")
    parser.add_argument("-s", "--subdir", default="", metavar="NAME")
    parser.add_argument("-a", "--auto", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


_GRAB_PARSER = _build_grab_parser()


def _cmd_grab(args: list[str] | None = None) -> None:
    ns = _GRAB_PARSER.parse_args(args or [])
    if not _in_tmux():
        _fail("cap grab requires tmux; use `cap <command>` for live capture")
    explicit = ns.command[1:] if ns.command[:1] == ["--"] else ns.command
    if explicit:
        command = shlex.join(explicit)
        cmd = explicit
    else:
        command = _last_command_from_history()
        if not command:
            _fail("could not detect the last command; pass it explicitly")
        try:
            cmd = shlex.split(command)
        except ValueError as exc:
            _fail(f"cannot parse shell history command: {exc}")
    try:
        output = _extract_output(_tmux_scrollback(), command)
    except RuntimeError as exc:
        _fail(str(exc))
    if not output:
        _fail(f"no output found for: {command}")
    settings = _settings()
    _, tool, inferred = _route_for(cmd, settings)
    subdir = ns.subdir or (inferred if ns.auto or settings.auto_route else "")
    if subdir and Path(subdir).parts in {(), (".",)}:
        subdir = ""
    try:
        root = _root(settings)
        outdir = _get_output_dir(subdir, settings)
    except ValueError as exc:
        _fail(str(exc), 2)
    outdir.mkdir(parents=True, exist_ok=True)
    stem = _build_filename(cmd, note=ns.note, aliases=settings.aliases)
    outfile = _claim_outfile(outdir, stem)
    try:
        record = create_record(
            root,
            outfile,
            command=command,
            original_tool=Path(cmd[0]).name,
            effective_tool=tool,
            route=_route_label(subdir),
            source="grab",
        )
    except (OSError, ValueError) as exc:
        outfile.unlink(missing_ok=True)
        _fail(f"cannot create metadata record: {exc}")
    try:
        with outfile.open("w", encoding="utf-8", errors="backslashreplace") as fh:
            _write_capture_header(fh, command)
            fh.write(output)
            if not output.endswith("\n"):
                fh.write("\n")
    except OSError as exc:
        try:
            abandon_record(root, record)
        except (OSError, ValueError) as cleanup_exc:
            print(f"nocap: warning: cannot discard pending metadata: {cleanup_exc}", file=sys.stderr)
        outfile.unlink(missing_ok=True)
        _fail(f"cannot write capture: {exc}")
    try:
        finalize_record(root, record, outfile, exit_code=None, duration_ms=None, status="unknown")
    except (OSError, ValueError) as exc:
        print(f"nocap: warning: cannot finalize metadata: {exc}", file=sys.stderr)
    _remember_last(outfile)
    print(f"[grab] {outfile}", file=sys.stderr)


_DISPATCH: dict[str, Callable[[list[str]], None]] = {
    "last": _cmd_last,
    "cat": _cmd_cat,
    "tail": _cmd_tail,
    "open": _cmd_open,
    "rm": _cmd_rm,
    "summary": _cmd_summary,
    "render": _cmd_render,
    "grab": _cmd_grab,
    "update": _cmd_update,
    "ls": _cmd_ls,
    "browse": _cmd_browse,
    "search": _cmd_search,
    "timeline": _cmd_timeline,
    "inspect": _cmd_inspect,
    "tag": _cmd_tag,
    "rename": _cmd_rename,
    "review": _cmd_review,
    "meta": _cmd_meta,
    "status": _cmd_status,
}
