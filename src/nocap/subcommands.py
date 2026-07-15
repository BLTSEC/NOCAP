"""NOCAP subcommands, capture discovery, and tmux scrollback helpers."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable, TextIO

from nocap.filename import _build_filename, _claim_outfile
from nocap.rendering import _render_capture, _strip_ansi, _view_file
from nocap.routing import _get_base_dir, _get_output_dir
from nocap.tools import TOOL_SUBDIRS

_SUMMARY_PATTERNS: dict[str, re.Pattern[str]] = {
    "passwords": re.compile(
        r"(?:password|passwd|pass(?:word)?|pwd|secret|credential)\s*[:=]\s*\S+"
        r"|\[\+\]\s+\S+\\\S+:\S+"          # netexec/CME:  [+] CORP\user:pass
        r"|login:\s*\S+.*password:\s*\S+",  # hydra output
        re.IGNORECASE,
    ),
    "hashes": re.compile(
        r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"                      # NTLM  LM:NT
        r"|(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"     # MD5
        r"|(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"     # SHA1
        r"|(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])",    # SHA256
    ),
    "users": re.compile(
        r"(?:username|user|login|account|uid)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    "emails": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    ),
    "ports": re.compile(
        r"\d+/(?:tcp|udp)\s+open"
    ),
    "vulns": re.compile(
        r"CVE-\d{4}-\d+|vulnerable|exploitable|(?:severity|risk):\s*(?:critical|high)",
        re.IGNORECASE,
    ),
    "urls": re.compile(
        r"https?://[^\s'\"<>]+"
    ),
}

_CACHE_HOME = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")).expanduser()
_LAST_FILE = _CACHE_HOME / "nocap" / "last"
_READ_CHUNK = 65536
_HEADER_LINE_MAX = 65536
_COMMAND_PREFIX = "Command: "
_DATE_PREFIX = "Date:    "
_HEADER_SEPARATOR = "---"
_PROMPT_GLYPH_RE = re.compile(
    r"^[╭╰┌└├┬┼]"            # box-drawing prompts (p10k, oh-my-posh)
    r"|^[❯➜›»](?:\s|$)"      # compact prompts (starship, custom themes)
    r"|^[$#%>](?:\s|$)"      # minimal sh/root prompts
)

_BASIC_PROMPT_RE = re.compile(
    r"^(?:\([^\r\n)]+\)\s*)?"       # optional virtualenv prefix
    r"(?:\[[^\r\n\]]+\]|"           # [user@host path]$ style
    r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+(?:[^\r\n$#%>]*)?)"
    r"[$#%>](?:\s|$)"
)


def _in_tmux() -> bool:
    """Return True if running inside a tmux session."""
    return bool(os.environ.get("TMUX"))


def _tmux_scrollback() -> str:
    """Capture the full tmux pane scrollback as a string."""
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
    """Read the last command from the user's shell history that isn't `cap grab`.

    Supports zsh extended history format (`: timestamp:0;command`) and
    bash plain-line format.  Returns None if the history can't be read.
    """
    shell = Path(os.environ.get("SHELL", "/bin/sh")).name

    if shell == "zsh":
        hist_path = Path(os.environ.get("HISTFILE", Path.home() / ".zsh_history"))
    else:
        hist_path = Path(os.environ.get("HISTFILE", Path.home() / ".bash_history"))

    if not hist_path.is_file():
        return None

    try:
        raw = hist_path.read_bytes()
        # zsh uses a mix of UTF-8 and meta-encoded bytes; surrogateescape
        # preserves undecodable bytes without silent corruption
        text = raw.decode("utf-8", errors="surrogateescape")
    except (OSError, UnicodeDecodeError):
        return None

    lines = text.splitlines()

    # Walk backwards to find the last non-`cap grab` command
    for line in reversed(lines):
        # zsh extended format: `: <timestamp>:0;<command>`
        if line.startswith(": ") and ";" in line:
            cmd = line.split(";", 1)[1].strip()
        else:
            cmd = line.strip()

        if not cmd:
            continue
        # Skip the `cap grab` invocation itself (with any flags/args)
        if cmd == "cap grab" or cmd.startswith("cap grab "):
            continue
        return cmd

    return None


def _is_prompt_line(line: str) -> bool:
    """Return True if *line* looks like shell prompt decoration."""
    clean = _strip_ansi(line).strip()
    return bool(_PROMPT_GLYPH_RE.search(clean) or _BASIC_PROMPT_RE.search(clean))


def _starts_new_prompt(line: str) -> bool:
    """Return True if *line* looks like the start of a new command prompt.

    Catches multi-line prompts (box-drawing chars), common prompt suffixes,
    and basic ``user@host:path$`` patterns.
    """
    clean = _strip_ansi(line).strip()
    if not clean:
        return False
    return bool(_PROMPT_GLYPH_RE.search(clean) or _BASIC_PROMPT_RE.search(clean))


def _looks_like_prompt_command(clean_line: str, command: str) -> bool:
    """Return True if *clean_line* looks like a prompt that ran *command*."""
    pos = clean_line.find(command)
    if pos < 0:
        return False
    prefix = clean_line[:pos]
    return _starts_new_prompt(prefix)


def _extract_output(scrollback: str, command: str) -> str:
    """Extract the output of *command* from tmux scrollback text.

    Searches backward for a line containing the command string, then returns
    everything between that line (exclusive) and the end, trimming trailing
    blanks and the ``cap grab`` invocation line.
    """
    lines = scrollback.split("\n")

    # Strip trailing empty lines and the `cap grab` invocation
    while lines and lines[-1].strip() == "":
        lines.pop()
    # Remove trailing prompt / `cap grab` line(s)
    while lines and ("cap grab" in lines[-1]):
        lines.pop()
    while lines and lines[-1].strip() == "":
        lines.pop()
    # Strip trailing prompt decoration lines (multi-line prompts like p10k,
    # starship, oh-my-posh use box-drawing chars; also catch common suffixes)
    while lines and _is_prompt_line(lines[-1]):
        lines.pop()
    while lines and lines[-1].strip() == "":
        lines.pop()

    # Build ANSI-clean versions for searching (raw lines kept for output)
    clean_lines = [_strip_ansi(l) for l in lines]

    # Search backward for the command line.  Prefer lines that look like a
    # shell prompt followed by the command, so we don't accidentally match
    # an output line that happens to contain the command string.
    cmd_idx = None
    for i in range(len(clean_lines) - 1, -1, -1):
        cl = clean_lines[i]
        if command not in cl:
            continue
        if _looks_like_prompt_command(cl, command):
            cmd_idx = i
            break
    # If no prompt-style match found, fall back to plain substring match
    if cmd_idx is None:
        for i in range(len(clean_lines) - 1, -1, -1):
            if command in clean_lines[i]:
                cmd_idx = i
                break

    if cmd_idx is not None:
        # Find where the output ends — the next prompt after the command
        end_idx = len(lines)
        for i in range(cmd_idx + 1, len(lines)):
            if _starts_new_prompt(lines[i]):
                end_idx = i
                break
        output_lines = lines[cmd_idx + 1 : end_idx]
    else:
        # Fallback: couldn't find the command — grab everything after the
        # last prompt-like line.
        prompt_idx = None
        for i in range(len(clean_lines) - 1, -1, -1):
            if _starts_new_prompt(clean_lines[i]):
                prompt_idx = i
                break
        if prompt_idx is not None:
            output_lines = lines[prompt_idx + 1:]
        else:
            # Last resort: return everything
            output_lines = lines

    # Strip leading/trailing blank lines from extracted output
    while output_lines and output_lines[0].strip() == "":
        output_lines.pop(0)
    while output_lines and output_lines[-1].strip() == "":
        output_lines.pop()

    return "\n".join(output_lines)


def _last_path() -> Path:
    """Return the path of the last captured file, or exit with an error."""
    if _LAST_FILE.is_symlink():
        print("nocap: last-file pointer is a symlink — refusing", file=sys.stderr)
        sys.exit(1)
    if not _LAST_FILE.exists():
        print("nocap: no captures yet", file=sys.stderr)
        sys.exit(1)
    try:
        path = Path(
            _LAST_FILE.read_text(encoding="utf-8", errors="surrogateescape").strip()
        )
    except (OSError, UnicodeError) as exc:
        print(f"nocap: cannot read last-file pointer: {exc}", file=sys.stderr)
        sys.exit(1)
    if path.is_symlink():
        print("nocap: last capture path is a symlink — refusing", file=sys.stderr)
        sys.exit(1)
    if not path.is_file():
        print(f"nocap: last capture no longer exists: {path}", file=sys.stderr)
        sys.exit(1)
    return path


def _remember_last(path: Path) -> bool:
    """Atomically store an absolute last-capture path with private permissions.

    Last-file tracking is a convenience and must not turn a successful capture
    into a failure when the cache directory is read-only.
    """
    tmp = _LAST_FILE.parent / f".{_LAST_FILE.name}.{os.getpid()}.tmp"
    try:
        _LAST_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = str(path.resolve()).encode("utf-8", errors="surrogateescape")
        fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, _LAST_FILE)
    except OSError as exc:
        print(f"nocap: warning: cannot update last-file pointer: {exc}", file=sys.stderr)
        return False
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    return True


def _require_no_args(name: str, args: list[str] | None) -> None:
    """Reject ignored arguments so destructive subcommands stay unambiguous."""
    if args:
        print(f"nocap: {name} does not accept arguments", file=sys.stderr)
        print(f"  tip: use `cap -- {name} ...` to capture the {name} command", file=sys.stderr)
        sys.exit(2)


def _cmd_last(args: list[str] | None = None) -> None:
    """Print the path of the last captured file."""
    _require_no_args("last", args)
    print(_last_path())


def _cmd_cat(args: list[str] | None = None) -> None:
    """Dump the last captured file to stdout."""
    _require_no_args("cat", args)
    _view_file(_last_path())


def _cmd_tail(args: list[str] | None = None) -> None:
    """Follow the last captured file from the beginning."""
    _require_no_args("tail", args)
    path = _last_path()
    subprocess.run(["tail", "-n", "+1", "-f", str(path)])


def _cmd_open(args: list[str] | None = None) -> None:
    """Open the last captured file in the best available viewer."""
    _require_no_args("open", args)
    path = _last_path()
    editor = os.environ.get("EDITOR", "").strip()
    if editor:
        try:
            editor_cmd = shlex.split(editor)
        except ValueError as exc:
            print(f"nocap: invalid $EDITOR: {exc}", file=sys.stderr)
            sys.exit(1)
        if not editor_cmd:
            _view_file(path, paging=True)
            return
        subprocess.run(editor_cmd + [str(path)])
    else:
        _view_file(path, paging=True)


def _cmd_rm(args: list[str] | None = None) -> None:
    """Delete the last captured file."""
    _require_no_args("rm", args)
    path = _last_path()
    path.unlink(missing_ok=True)
    _LAST_FILE.unlink(missing_ok=True)
    print(f"\033[90m[rm] {path}\033[0m", file=sys.stderr)


def _count_lines(path: Path) -> int:
    """Count newlines in *path* using chunked reads to avoid reading the whole
    file into memory at once (important for large scan outputs)."""
    try:
        with path.open("rb") as fh:
            return sum(
                chunk.count(b"\n")
                for chunk in iter(lambda: fh.read(_READ_CHUNK), b"")
            )
    except OSError:
        return 0


def _format_size(size: int) -> str:
    """Format a byte count compactly for summary and list output."""
    value = float(size)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024 or unit == "T":
            return f"{int(value)}B" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}T"


def _write_capture_header(fh: TextIO, command: str) -> None:
    """Write the canonical three-line NOCAP header."""
    date = datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Z %Y")
    fh.write(f"{_COMMAND_PREFIX}{command}\n")
    fh.write(f"{_DATE_PREFIX}{date}\n")
    fh.write(f"{_HEADER_SEPARATOR}\n")


def _is_capture_file(path: Path) -> bool:
    """Return whether *path* begins with a NOCAP capture header.

    Only the three header lines are read, with a per-line cap so an unrelated
    file with an extremely long first line cannot cause unbounded allocation.
    """
    try:
        with path.open("rb") as fh:
            command = fh.readline(_HEADER_LINE_MAX)
            date = fh.readline(_HEADER_LINE_MAX)
            separator = fh.readline(_HEADER_LINE_MAX)
    except OSError:
        return False

    return (
        command.startswith(_COMMAND_PREFIX.encode())
        and date.startswith(_DATE_PREFIX.encode())
        and separator.rstrip(b"\r\n") == _HEADER_SEPARATOR.encode()
    )


def _find_capture_files(root: Path) -> list[Path]:
    """Find actual NOCAP captures below *root*, newest first."""
    captures: list[tuple[float, Path]] = []
    for path in root.rglob("*.txt"):
        if not _is_capture_file(path):
            continue
        try:
            captures.append((path.stat().st_mtime, path))
        except OSError:
            continue
    captures.sort(key=lambda item: item[0], reverse=True)
    return [path for _, path in captures]


def _cmd_summary(args: list[str] | None = None) -> None:
    """Print a compact summary table, or search captures for a keyword/pattern."""
    if args and len(args) > 1:
        print("nocap: summary accepts at most one keyword or regex", file=sys.stderr)
        print("  tip: quote patterns containing spaces", file=sys.stderr)
        sys.exit(2)
    keyword = (args[0] if args else "")
    base = _get_base_dir() or Path.cwd()
    files = _find_capture_files(base)
    if not files:
        print(f"nocap: no captures in {base}", file=sys.stderr)
        sys.exit(1)

    # ── table mode (no keyword) ───────────────────────────────────────────────
    if not keyword:
        rows = []
        for f in files:
            stat = f.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            size_str = _format_size(stat.st_size)
            lines = _count_lines(f)
            try:
                rel = str(f.relative_to(base))
            except ValueError:
                rel = str(f)
            rows.append((mtime, lines, size_str, rel))

        line_w = max(len(str(r[1])) for r in rows)
        size_w = max(len(r[2]) for r in rows)
        for mtime, lines, size_str, rel in rows:
            print(f"\033[90m{mtime}\033[0m  {lines:{line_w}} lines  {size_str:{size_w}}  {rel}")
        return

    # ── search mode ───────────────────────────────────────────────────────────
    pattern = _SUMMARY_PATTERNS.get(keyword.lower())
    if pattern is None:
        try:
            pattern = re.compile(keyword, re.IGNORECASE)
        except re.error:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)

    found_any = False
    for f in files:
        try:
            rel = str(f.relative_to(base))
        except ValueError:
            rel = str(f)

        matches: list[str] = []
        try:
            with f.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    clean = _strip_ansi(line.rstrip("\r\n"))
                    if pattern.search(clean):
                        matches.append(clean)
        except OSError:
            continue

        if matches:
            found_any = True
            print(f"\033[33m{rel}\033[0m")
            for m in matches:
                print(f"  {m}")
            print()

    if not found_any:
        print(f"nocap: no matches for '{keyword}'", file=sys.stderr)
        sys.exit(1)


def _cmd_update(args: list[str] | None = None) -> None:
    """Upgrade nocap using the source recorded by pipx."""
    _require_no_args("update", args)
    if not shutil.which("pipx"):
        print("nocap: pipx not found — install pipx or update manually", file=sys.stderr)
        sys.exit(1)
    sys.exit(subprocess.run(["pipx", "upgrade", "nocap"]).returncode)


def _cmd_render(args: list[str] | None = None) -> None:
    """Render a capture file (or the last capture) through the VT100 cleaner."""
    if args and len(args) > 1:
        print("nocap: render accepts at most one file", file=sys.stderr)
        sys.exit(2)
    if args:
        path = Path(args[0])
    else:
        path = _last_path()
    if not path.is_file():
        print(f"nocap: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(_render_capture(path))
    sys.stdout.flush()


def _build_grab_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cap grab", add_help=False, allow_abbrev=False)
    p.add_argument("-n", "--note", default="", metavar="LABEL")
    p.add_argument("-s", "--subdir", default="", metavar="NAME")
    p.add_argument("-a", "--auto", action="store_true", default=False)
    p.add_argument("command", nargs=argparse.REMAINDER)
    return p


_GRAB_PARSER = _build_grab_parser()


def _cmd_grab(args: list[str] | None = None) -> None:
    """Retroactively capture the last command's output from tmux scrollback."""
    if not _in_tmux():
        print("nocap: cap grab requires tmux (need scrollback buffer)", file=sys.stderr)
        print("  tip: use `cap <command>` next time to capture live", file=sys.stderr)
        sys.exit(1)

    # Parse grab-specific flags; remaining positional args = explicit command.
    grab_args = list(args) if args else []
    try:
        ns = _GRAB_PARSER.parse_args(grab_args)
    except SystemExit:
        print("nocap: invalid flags for cap grab", file=sys.stderr)
        sys.exit(2)

    explicit_cmd = ns.command  # remaining positional args after flags
    if explicit_cmd[:1] == ["--"]:
        explicit_cmd = explicit_cmd[1:]
    note = ns.note
    subdir = ns.subdir

    _env_auto = os.environ.get("NOCAP_AUTO", "").strip().lower()
    auto = ns.auto or (bool(_env_auto) and _env_auto not in ("0", "false", "no"))

    # Determine the command string
    if explicit_cmd:
        command_str = " ".join(explicit_cmd)
        cmd_list = explicit_cmd
    else:
        command_str = _last_command_from_history()
        if not command_str:
            print("nocap: couldn't detect last command from shell history", file=sys.stderr)
            print("  usage: cap grab [options] <command...>", file=sys.stderr)
            sys.exit(1)
        try:
            cmd_list = shlex.split(command_str)
        except ValueError as exc:
            print(f"nocap: cannot parse command from shell history: {exc}", file=sys.stderr)
            print("  usage: cap grab [options] <command...>", file=sys.stderr)
            sys.exit(1)

    # Capture tmux scrollback
    try:
        scrollback = _tmux_scrollback()
    except RuntimeError as exc:
        print(f"nocap: {exc}", file=sys.stderr)
        sys.exit(1)

    # Extract the output
    output = _extract_output(scrollback, command_str)
    if not output:
        print(f"\033[33mnocap: no output found for: {command_str}\033[0m", file=sys.stderr)
        sys.exit(1)

    # Auto-route subdir if requested
    if auto and not subdir and cmd_list:
        tool = Path(cmd_list[0]).name
        subdir = TOOL_SUBDIRS.get(tool, "")

    # Resolve output directory
    try:
        outdir = _get_output_dir(subdir)
    except ValueError as exc:
        print(f"nocap: invalid subdir: {exc}", file=sys.stderr)
        sys.exit(2)

    outdir.mkdir(parents=True, exist_ok=True)

    # Build filename and claim output file
    stem = _build_filename(cmd_list, note=note)
    outfile = _claim_outfile(outdir, stem)

    # Write header + output (same format as live captures)
    with outfile.open("w", encoding="utf-8", errors="backslashreplace") as f:
        _write_capture_header(f, command_str)
        if output:
            f.write(output)
            if not output.endswith("\n"):
                f.write("\n")

    # Track as last capture
    _remember_last(outfile)

    print(f"\033[90m[grab] → {outfile}\033[0m", file=sys.stderr)


def _cmd_ls(args: list[str] | None = None) -> None:
    """List captures for the current engagement, optionally scoped to a subdir."""
    if args and len(args) > 1:
        print("nocap: ls accepts at most one subdir", file=sys.stderr)
        sys.exit(2)
    subdir = (args[0] if args else "")
    base = _get_base_dir() or Path.cwd()
    search_dir = base / subdir if subdir else base

    if not search_dir.exists():
        print(f"nocap: directory not found: {search_dir}", file=sys.stderr)
        sys.exit(1)

    files = _find_capture_files(search_dir)
    if not files:
        print(f"nocap: no captures in {search_dir}", file=sys.stderr)
        sys.exit(1)

    # Build relative paths and metadata for display
    rows: list[tuple[str, int, str, str, Path]] = []  # (mtime, lines, size_str, rel, abs)
    for f in files:
        stat = f.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        size_str = _format_size(stat.st_size)
        lines = _count_lines(f)
        try:
            rel = str(f.relative_to(base))
        except ValueError:
            rel = str(f)
        rows.append((mtime, lines, size_str, rel, f))

    if shutil.which("fzf"):
        rel_list = "\n".join(rel for _, _, _, rel, _ in rows)
        # Render capture through VT100 cleaner for preview
        preview_cmd = (
            f"cap render {shlex.quote(str(base))}/{{}}"
        )
        subprocess.run(
            ["fzf",
             "--header", f"  {base}",
             "--preview", preview_cmd,
             "--preview-window=right:70%:wrap",
             "--ansi"],
            input=rel_list,
            text=True,
        )
    else:
        line_w = max(len(str(r[1])) for r in rows)
        size_w = max(len(r[2]) for r in rows)
        print(f"\033[90m  {base}\033[0m")
        for mtime, lines, size_str, rel, _ in rows:
            print(f"\033[90m{mtime}\033[0m  {lines:{line_w}} lines  {size_str:{size_w}}  {rel}")


_DISPATCH: dict[str, Callable[[list[str]], None]] = {
    "last":    _cmd_last,
    "cat":     _cmd_cat,
    "tail":    _cmd_tail,
    "open":    _cmd_open,
    "rm":      _cmd_rm,
    "summary": _cmd_summary,
    "render":  _cmd_render,
    "grab":    _cmd_grab,
    "update":  _cmd_update,
    "ls":      _cmd_ls,
}
