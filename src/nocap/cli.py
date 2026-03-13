#!/usr/bin/env python3
"""nocap — Capture tool output. No cap.

Zero-dependency CLI that runs any command and saves output to an
auto-named file with smart engagement directory routing.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import termios
import tty
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable

from nocap.tools import SKIP_FLAGS, SUBDIRS, TOOL_SUBDIRS

__all__ = ["main"]

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

_IP_RE  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d+)?$")
_IP6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d+)?$")
_URL_RE = re.compile(r"^https?://")
_NUM_RE = re.compile(r"^\d+(,\d+)*$")

# Strip ANSI escape codes for clean text matching in summary search
_ANSI_RE = re.compile(r"\x1b\[[?!0-9;]*[a-zA-Z]")

# VT100 rendering helpers (for cleaning raw PTY captures)
_RE_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_RE_CSI = re.compile(r"\x1b\[([0-9;?]*)([A-Za-z])")
_RE_ESC_MISC = re.compile(r"\x1b[^[\]]")

# Named smart patterns for `cap summary <keyword>`
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

_LAST_FILE = Path.home() / ".cache" / "nocap" / "last"

# ---------------------------------------------------------------------------
# tmux / scrollback helpers (for `cap grab`)
# ---------------------------------------------------------------------------

def _in_tmux() -> bool:
    """Return True if running inside a tmux session."""
    return bool(os.environ.get("TMUX"))


def _tmux_scrollback() -> str:
    """Capture the full tmux pane scrollback as a string."""
    result = subprocess.run(
        ["tmux", "capture-pane", "-p", "-S", "-", "-E", "-"],
        capture_output=True, text=True, timeout=5,
    )
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
        # zsh uses a mix of UTF-8 and meta-encoded bytes; best-effort decode
        text = raw.decode("utf-8", errors="replace")
    except Exception:
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


_PROMPT_LINE_RE = re.compile(
    r"^[╭╰┌└├┬┼]"            # box-drawing start (p10k, starship, oh-my-posh)
    r"|[❯➜›»\$#%>]\s*$"      # common prompt-end suffixes
)

# Detects basic single-line prompts: user@host:path$ , root#, etc.
_BASIC_PROMPT_RE = re.compile(r"[@:~].*[$#%>]\s")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from *text*."""
    return _ANSI_RE.sub("", text)


def _is_prompt_line(line: str) -> bool:
    """Return True if *line* looks like shell prompt decoration."""
    clean = _strip_ansi(line).strip()
    return bool(_PROMPT_LINE_RE.search(clean))


def _starts_new_prompt(line: str) -> bool:
    """Return True if *line* looks like the start of a new command prompt.

    Catches multi-line prompts (box-drawing chars), common prompt suffixes,
    and basic ``user@host:path$`` patterns.
    """
    clean = _strip_ansi(line).strip()
    if not clean:
        return False
    if _PROMPT_LINE_RE.search(clean):
        return True
    if _BASIC_PROMPT_RE.search(clean):
        return True
    return False


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
    # shell prompt (contain $ # % > or box-drawing chars) followed by the
    # command, so we don't accidentally match an output line.
    _PROMPT_CHARS = {"$", "#", "%", ">", "╰", "╭", "❯", "➜"}
    cmd_idx = None
    for i in range(len(clean_lines) - 1, -1, -1):
        cl = clean_lines[i]
        if command not in cl:
            continue
        # Check if this looks like a prompt line: a prompt char appears
        # before the command string in the line
        pos = cl.find(command)
        prefix = cl[:pos]
        if any(ch in prefix for ch in _PROMPT_CHARS):
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
        # last prompt-like line (line ending with $ or # or >)
        prompt_idx = None
        for i in range(len(lines) - 1, -1, -1):
            stripped = lines[i].rstrip()
            if stripped and stripped[-1] in ("$", "#", ">"):
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

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

def _get_version() -> str:
    try:
        from importlib.metadata import version
        return version("nocap")
    except Exception:
        from nocap import __version__
        return __version__

# ---------------------------------------------------------------------------
# Engagement directory resolution
# ---------------------------------------------------------------------------

def _get_base_dir() -> Path | None:
    """Return /workspace/<target> (or $NOCAP_WORKSPACE/<target>) from $TARGET
    or the active tmux session name, else None.

    Returns None if the workspace root does not exist so callers fall back to
    cwd gracefully instead of crashing on read-only or missing mounts.
    """
    workspace = Path(os.environ.get("NOCAP_WORKSPACE", "/workspace").rstrip("/"))

    # Bail out early if the workspace root isn't accessible
    if not workspace.is_dir():
        return None

    target = os.environ.get("TARGET", "").strip()
    if target:
        return workspace / target

    try:
        result = subprocess.run(
            ["tmux", "display-message", "-p", "#S"],
            capture_output=True, text=True, timeout=2,
        )
        sess = result.stdout.strip()
        if sess.startswith("op_"):
            tgt = sess.removeprefix("op_").replace("_", ".")
            return workspace / tgt
    except Exception:
        pass

    return None

# ---------------------------------------------------------------------------
# Filename generation
# ---------------------------------------------------------------------------

def _build_filename(cmd: list[str], note: str = "") -> str:
    """Derive a descriptive filename stem from a command + args list."""
    tool = Path(cmd[0]).name
    parts: list[str] = [tool]
    skip_next = False

    for arg in cmd[1:]:
        if skip_next:
            skip_next = False
            continue

        if _IP_RE.match(arg):
            continue
        if _IP6_RE.match(arg):
            continue
        if _URL_RE.match(arg):
            continue
        if arg.startswith("/"):
            continue
        if "=" in arg:
            _, _, val = arg.partition("=")
            if val.startswith("/") or val.startswith("./"):
                continue
        if not arg.startswith("-") and "." in arg:
            continue
        if _NUM_RE.match(arg):
            continue
        if arg in SKIP_FLAGS:
            skip_next = True
            continue

        clean = re.sub(r"^-+", "", arg)
        clean = re.sub(r"[^a-zA-Z0-9_-]", "", clean)
        clean = clean[:15]
        if clean:
            parts.append(clean)

    if note:
        note_clean = re.sub(r"[^a-zA-Z0-9_-]", "", note)[:20]
        if note_clean:
            parts.append(note_clean)

    name = "_".join(parts)
    name = re.sub(r"_+", "_", name).rstrip("_")[:60]
    return name or tool

# ---------------------------------------------------------------------------
# Output file resolution
# ---------------------------------------------------------------------------

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
            fd = os.open(str(candidate), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.close(fd)
            return candidate
        except FileExistsError:
            candidate = outdir / f"{stem}_{n}.txt"
            n += 1

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------

def _term_size() -> tuple[int, int]:
    try:
        ts = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\x00" * 8)
        rows, cols = struct.unpack_from("HH", ts)
        if rows > 0 and cols > 0:
            return rows, cols
    except Exception:
        pass
    return 24, 80


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    try:
        ws = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, ws)
    except Exception:
        pass


@contextmanager
def _raw_terminal(fd: int):
    """Context manager: put *fd* in raw mode, restore on exit."""
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

# ---------------------------------------------------------------------------
# PTY-based execution
# ---------------------------------------------------------------------------

def _parent_io_loop(
    master_fd: int,
    stdin_fd: int,
    is_tty: bool,
    logf,
) -> None:
    """Forward PTY output to stdout/logfile; forward stdin to the PTY."""
    watch_fds = [master_fd, stdin_fd] if is_tty else [master_fd]
    while True:
        try:
            r, _, _ = select.select(watch_fds, [], [], 0.05)
        except (ValueError, OSError):
            break

        if master_fd in r:
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            logf.write(data)
            logf.flush()

        if is_tty and stdin_fd in r:
            try:
                data = os.read(stdin_fd, 4096)
            except OSError:
                break
            if data:
                os.write(master_fd, data)


def _run_pty(cmd: list[str], outfile: Path) -> int:
    """Execute *cmd* under a PTY, appending all output to *outfile* while
    also echoing to stdout in real time.  Returns the child's exit code.

    Running under a PTY means tools that detect TTY (nmap, gobuster, etc.)
    emit colours and progress bars as expected.
    """
    import pty

    rows, cols = _term_size()
    master_fd, slave_fd = pty.openpty()
    _set_winsize(slave_fd, rows, cols)

    # If the command isn't a binary on PATH, wrap it in the user's shell
    # so that shell functions and aliases (e.g. from .zshrc) are available.
    if not shutil.which(cmd[0]):
        shell = os.environ.get("SHELL", "/bin/sh")
        cmd = [shell, "-ic", " ".join(shlex.quote(c) for c in cmd)]

    pid = os.fork()

    if pid == 0:
        # ── child ────────────────────────────────────────────────────────────
        try:
            os.close(master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            for fd in (0, 1, 2):
                os.dup2(slave_fd, fd)
            if slave_fd > 2:
                os.close(slave_fd)
            os.execvp(cmd[0], cmd)
        except FileNotFoundError:
            sys.stderr.write(f"nocap: command not found: {cmd[0]}\n")
        except Exception:
            pass
        os._exit(127)

    # ── parent ───────────────────────────────────────────────────────────────
    os.close(slave_fd)

    # Propagate terminal resize events to the child
    def _sigwinch(sig: int, frame: object) -> None:  # noqa: ARG001
        r, c = _term_size()
        _set_winsize(master_fd, r, c)
        try:
            os.kill(pid, signal.SIGWINCH)
        except ProcessLookupError:
            pass

    old_sigwinch = signal.signal(signal.SIGWINCH, _sigwinch)

    stdin_fd = sys.stdin.fileno()
    is_tty = sys.stdin.isatty()
    exit_code = 0

    try:
        with outfile.open("ab") as logf:
            if is_tty:
                with _raw_terminal(stdin_fd):
                    _parent_io_loop(master_fd, stdin_fd, is_tty, logf)
            else:
                _parent_io_loop(master_fd, stdin_fd, is_tty, logf)
    finally:
        os.close(master_fd)
        signal.signal(signal.SIGWINCH, old_sigwinch)
        try:
            _, status = os.waitpid(pid, 0)
            exit_code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            pass

    return exit_code

# ---------------------------------------------------------------------------
# VT100 renderer — clean raw PTY captures into readable plain text
# ---------------------------------------------------------------------------

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
                    pos += params[0] or 1
                elif final == "G":
                    pos = max(0, (params[0] or 1) - 1)
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


# ---------------------------------------------------------------------------
# Shared viewer helper
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Last-file helpers
# ---------------------------------------------------------------------------

def _last_path() -> Path:
    """Return the path of the last captured file, or exit with an error."""
    if _LAST_FILE.is_symlink():
        print("nocap: last-file pointer is a symlink — refusing", file=sys.stderr)
        sys.exit(1)
    if not _LAST_FILE.exists():
        print("nocap: no captures yet", file=sys.stderr)
        sys.exit(1)
    path = Path(_LAST_FILE.read_text().strip())
    if not path.exists():
        print(f"nocap: last capture no longer exists: {path}", file=sys.stderr)
        sys.exit(1)
    return path

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def _cmd_last(_: list[str] | None = None) -> None:
    """Print the path of the last captured file."""
    print(_last_path())


def _cmd_cat(_: list[str] | None = None) -> None:
    """Dump the last captured file to stdout."""
    _view_file(_last_path())


def _cmd_tail(_: list[str] | None = None) -> None:
    """Follow the last captured file from the beginning."""
    path = _last_path()
    subprocess.run(["tail", "-n", "+1", "-f", str(path)])


def _cmd_open(_: list[str] | None = None) -> None:
    """Open the last captured file in the best available viewer."""
    path = _last_path()
    editor = os.environ.get("EDITOR", "").strip()
    if editor:
        subprocess.run(shlex.split(editor) + [str(path)])
    else:
        _view_file(path, paging=True)


def _cmd_rm(_: list[str] | None = None) -> None:
    """Delete the last captured file."""
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
                for chunk in iter(lambda: fh.read(65536), b"")
            )
    except Exception:
        return 0


def _cmd_summary(args: list[str] | None = None) -> None:
    """Print a compact summary table, or search captures for a keyword/pattern."""
    keyword = (args[0] if args else "")
    base = _get_base_dir() or Path.cwd()
    files = sorted(base.rglob("*.txt"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not files:
        print(f"nocap: no captures in {base}", file=sys.stderr)
        sys.exit(1)

    # ── table mode (no keyword) ───────────────────────────────────────────────
    if not keyword:
        rows = []
        for f in files:
            stat = f.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            size = stat.st_size
            size_str = f"{size / 1024:.1f}K" if size >= 1024 else f"{size}B"
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
                    clean = _ANSI_RE.sub("", line.rstrip("\r\n"))
                    if pattern.search(clean):
                        matches.append(clean)
        except Exception:
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


def _cmd_update(_: list[str] | None = None) -> None:
    """Re-install nocap from GitHub via pipx."""
    if not shutil.which("pipx"):
        print("nocap: pipx not found — install pipx or update manually", file=sys.stderr)
        sys.exit(1)
    sys.exit(subprocess.run([
        "pipx", "install", "--force",
        "git+https://github.com/BLTSEC/NOCAP.git",
    ]).returncode)


def _cmd_render(args: list[str] | None = None) -> None:
    """Render a capture file (or the last capture) through the VT100 cleaner."""
    if args:
        path = Path(args[0])
    else:
        path = _last_path()
    if not path.exists():
        print(f"nocap: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(_render_capture(path))
    sys.stdout.flush()


def _cmd_grab(args: list[str] | None = None) -> None:
    """Retroactively capture the last command's output from tmux scrollback."""
    if not _in_tmux():
        print("nocap: cap grab requires tmux (need scrollback buffer)", file=sys.stderr)
        print("  tip: use `cap <command>` next time to capture live", file=sys.stderr)
        sys.exit(1)

    # Parse nocap flags from args (-n, -s, -a) — reuse the main parser
    # but only extract our flags; remaining positional args = explicit command
    grab_args = list(args) if args else []
    try:
        ns = _PARSER.parse_args(grab_args)
    except SystemExit:
        print("nocap: invalid flags for cap grab", file=sys.stderr)
        sys.exit(2)

    explicit_cmd = ns.command  # remaining positional args after flags
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
        cmd_list = shlex.split(command_str)

    # Capture tmux scrollback
    scrollback = _tmux_scrollback()

    # Extract the output
    output = _extract_output(scrollback, command_str)
    if not output:
        print(f"\033[33mnocap: warning: no output found for: {command_str}\033[0m", file=sys.stderr)

    # Auto-route subdir if requested
    if auto and not subdir and cmd_list:
        tool = Path(cmd_list[0]).name
        subdir = TOOL_SUBDIRS.get(tool, "")

    # Resolve output directory
    base_dir = _get_base_dir()
    if base_dir and subdir:
        outdir = base_dir / subdir
    elif base_dir:
        outdir = base_dir
    elif subdir:
        outdir = Path.cwd() / subdir
    else:
        outdir = Path.cwd()

    outdir.mkdir(parents=True, exist_ok=True)

    # Build filename and claim output file
    stem = _build_filename(cmd_list, note=note)
    outfile = _claim_outfile(outdir, stem)

    # Write header + output (same format as live captures)
    with outfile.open("w") as f:
        f.write(f"Command: {command_str}\n")
        f.write(f"Date:    {datetime.now().astimezone().strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
        f.write("---\n")
        if output:
            f.write(output)
            if not output.endswith("\n"):
                f.write("\n")

    # Track as last capture
    _LAST_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LAST_FILE.write_text(str(outfile))

    print(f"\033[90m[grab] → {outfile}\033[0m", file=sys.stderr)


def _cmd_ls(args: list[str] | None = None) -> None:
    """List captures for the current engagement, optionally scoped to a subdir."""
    subdir = (args[0] if args else "")
    base = _get_base_dir() or Path.cwd()
    search_dir = base / subdir if subdir else base

    if not search_dir.exists():
        print(f"nocap: directory not found: {search_dir}", file=sys.stderr)
        sys.exit(1)

    files = sorted(
        search_dir.rglob("*.txt"),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )
    if not files:
        print(f"nocap: no captures in {search_dir}", file=sys.stderr)
        sys.exit(1)

    # Build relative paths and metadata for display
    rows: list[tuple[str, int, str, str, Path]] = []  # (mtime, lines, size_str, rel, abs)
    for f in files:
        stat = f.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        size = stat.st_size
        size_str = f"{size / 1024:.1f}K" if size >= 1024 else f"{size}B"
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

# ---------------------------------------------------------------------------
# Subcommand dispatch table
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cap", add_help=False, allow_abbrev=False)
    p.add_argument("-h", "--help", action="store_true", default=False)
    p.add_argument("-V", "-v", "--version", action="store_true", default=False)
    p.add_argument("-n", "--note", default="", metavar="LABEL",
                   help="Append a custom label to the output filename")
    p.add_argument("-s", "--subdir", default="", metavar="NAME",
                   help="Write to a custom subdir (created if needed)")
    p.add_argument("-a", "--auto", action="store_true", default=False,
                   help="Auto-route to subdir based on tool name")
    p.add_argument("-D", "--dry-run", dest="dry_run", action="store_true",
                   default=False, help="Show where output would go without running")
    p.add_argument("command", nargs=argparse.REMAINDER)
    return p


# Module-level parser instance (importable for tests)
_PARSER = _build_parser()

# ---------------------------------------------------------------------------
# Usage string
# ---------------------------------------------------------------------------

USAGE = """\
NOCAP — Capture tool output. No cap.

Usage:
  cap [options] [subdir] <command> [args...]
  cap grab [options] [command...]
  cap last | cat | tail | open | rm | summary
  cap ls [subdir]
  cap update
  cap --help | --version

Options:
  -n, --note <label>    Append a custom label to the output filename
  -s, --subdir <name>   Write to a custom subdir (created if needed)
  -a, --auto            Auto-route to subdir based on tool name (opt-in)
  -D, --dry-run         Show where output would go without running

Subcommands:
  last                  Print path of the last captured file
  cat                   Dump last capture to stdout (bat or cat)
  tail                  Follow last capture from the start (tail -f)
  open                  Open last capture in $EDITOR / bat / less / cat
  rm                    Delete the last captured file
  summary [keyword]     Table of all captures, or search across them.
                        Named patterns: passwords, hashes, users, emails,
                        ports, vulns, urls  — or any literal keyword / regex.
  grab [command...]     Retroactively capture the last command's output from
                        tmux scrollback. Auto-detects from shell history or
                        accepts an explicit command. Supports -n, -s, -a.
  ls [subdir]           Browse captures interactively (fzf) or list them.
                        Accepts any subdir name, not just built-in ones.
  update                Update nocap to the latest version via pipx

Environment:
  NOCAP_AUTO=1          Enable --auto routing by default (no flag needed)
  NOCAP_WORKSPACE=path  Override the base workspace directory (default: /workspace)

Subdirs:
  recon, loot, exploitation, screenshots, notes

Examples:
  cap nmap -sCV 10.10.10.5
  cap recon gobuster dir -u http://10.10.10.5 -w /wordlist.txt
  cap -n after-creds nmap -sCV 10.10.10.5
  cap --auto nmap -sCV 10.10.10.5
  cap -D feroxbuster -u http://10.10.10.5
  cap grab
  cap grab -n initial nmap -sCV 10.10.10.5
  cap last
  cap ls
  cap ls recon
  cap ls pivoting
  cat $(cap last)

Routing (priority order):
  1. $TARGET env var         → $NOCAP_WORKSPACE/$TARGET/<subdir>/
  2. tmux op_* session       → $NOCAP_WORKSPACE/<target>/<subdir>/
  3. Fallback                → ./<subdir>/  (current working directory)

Auto-routing (--auto / -a):
  Infers subdir from tool name. Explicit subdir always takes precedence.
  recon/      nmap, rustscan, masscan, autorecon, gobuster, feroxbuster,
              ffuf, wfuzz, dirsearch, nuclei, httpx, http, curl, wget,
              whatweb, nikto, gospider, cariddi, searchsploit, trufflehog,
              gitleaks, git-dumper, wpscan, amass, subfinder, dnsx, dig,
              whois, kerbrute, netexec, smbmap, enum4linux-ng, ldapsearch,
              bloodhound-python, theHarvester, spiderfoot, recon-ng, bbot,
              katana, arp-scan, zmap, airodump-ng, kismet, …
  screenshots/ eyewitness, gowitness, aquatone, webscreenshot
  loot/       hashcat, john, hydra, medusa, legba, ncrack, aircrack-ng,
              hcxpcapngtool, volatility, volatility3, binwalk, foremost,
              steghide, stegseek, exiftool, zsteg, pypykatz, lsassy,
              donpapi, dploot, gosecretsdump, nth, haiti, …
  exploitation/ msfconsole, msfvenom, sliver-server, ps-empire, havoc,
              pwncat-cs, ligolo-ng, chisel, socat, sqlmap, weevely,
              evil-winrm, mitm6, coercer, certipy, bloodyAD, dalfox,
              commix, tplmap, ghauri, jwt_tool, swaks, psexec.py,
              wmiexec.py, smbexec.py, secretsdump.py, GetNPUsers.py,
              GetUserSPNs.py, ntlmrelayx.py, xsstrike, …
"""

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    try:
        _main(argv)
    except KeyboardInterrupt:
        sys.exit(130)


def _main(argv: list[str] | None = None) -> None:
    raw = list(argv) if argv is not None else sys.argv[1:]

    if not raw:
        print(USAGE)
        sys.exit(0)

    # Fast-path: dispatch known subcommands before flag parsing so that
    # subcommand names are never mistaken for a tool to run.
    if raw[0] in _DISPATCH:
        _DISPATCH[raw[0]](raw[1:])
        return

    # Parse nocap-specific flags.
    # nargs=REMAINDER means that once the parser encounters the first
    # positional argument (the tool name), everything that follows —
    # including option-like strings — is captured verbatim in ns.command.
    # This ensures that flags intended for the child process are never
    # accidentally consumed by nocap's own parser.
    try:
        ns = _PARSER.parse_args(raw)
    except SystemExit:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    if ns.help:
        print(USAGE)
        sys.exit(0)

    if ns.version:
        print(f"nocap {_get_version()}")
        sys.exit(0)

    # Resolve NOCAP_AUTO env var; explicit -a flag takes priority
    _env_auto = os.environ.get("NOCAP_AUTO", "").strip().lower()
    auto = ns.auto or (bool(_env_auto) and _env_auto not in ("0", "false", "no"))

    cmd: list[str] = ns.command
    subdir: str = ns.subdir

    # Optional predefined engagement subdir as first positional arg
    if not subdir and cmd and cmd[0] in SUBDIRS:
        subdir = cmd[0]
        cmd = cmd[1:]

    if not cmd:
        print("nocap: error: no command specified\n", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        sys.exit(1)

    # Auto tool→subdir routing (only when --auto is set and no explicit subdir)
    if auto and not subdir:
        tool = Path(cmd[0]).name
        subdir = TOOL_SUBDIRS.get(tool, "")

    # Resolve output directory
    base_dir = _get_base_dir()
    if base_dir and subdir:
        outdir = base_dir / subdir
    elif base_dir:
        outdir = base_dir
    elif subdir:
        outdir = Path.cwd() / subdir
    else:
        outdir = Path.cwd()

    outdir.mkdir(parents=True, exist_ok=True)

    stem = _build_filename(cmd, note=ns.note)

    if ns.dry_run:
        outfile = _compute_outfile(outdir, stem)
        print(f"\033[90m[dry] → {outfile}\033[0m")
        sys.exit(0)

    # Atomically claim the output file (eliminates the TOCTOU race)
    outfile = _claim_outfile(outdir, stem)

    # Write file header (overwrites the empty placeholder created above)
    with outfile.open("w") as f:
        f.write(f"Command: {' '.join(cmd)}\n")
        f.write(f"Date:    {datetime.now().astimezone().strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
        f.write("---\n")

    print(f"\033[90m[cap] → {outfile}\033[0m", file=sys.stderr)

    start = datetime.now()
    exit_code = _run_pty(cmd, outfile)
    elapsed = (datetime.now() - start).total_seconds()

    # Track last captured file for `cap last`
    _LAST_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LAST_FILE.write_text(str(outfile))

    # Bell — audible/visual alert that the command has finished
    sys.stderr.write("\a")
    sys.stderr.flush()

    # Completion status: ✓/✗ + elapsed time
    if exit_code == 0:
        mark = "\033[32m✓\033[0m"
    else:
        mark = f"\033[31m✗ {exit_code}\033[0m"
    sys.stderr.write(f"\033[90m[{mark}\033[90m] {outfile.name}  ({elapsed:.1f}s)\033[0m\n")
    sys.stderr.flush()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
