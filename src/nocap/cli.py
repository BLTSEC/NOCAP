#!/usr/bin/env python3
"""nocap — Capture tool output. No cap.

Zero-dependency CLI that runs any command and saves output to an
auto-named file with smart engagement directory routing.
"""

from __future__ import annotations

import fcntl
import os
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import tty
from datetime import datetime
from pathlib import Path

__all__ = ["main"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUBDIRS = frozenset({"recon", "loot", "exploitation", "screenshots"})

# Flags whose *next* token is a value to be consumed (not added to filename)
SKIP_FLAGS = frozenset({
    "-w", "--wordlist",
    "-u", "--url",
    "-o", "--output",
    "-oN", "-oX", "-oA", "-oG", "-oS", "-oJ",
    "-T", "--timeout",
    "--threads", "-t",
    "--rate",
    "-H", "--header",
    "-d", "--domain",
    "-f", "--file", "--hash-file",
    "-mc", "-fc",
    "-p",
})

_IP_RE  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d+)?$")
_URL_RE = re.compile(r"^https?://")
_NUM_RE = re.compile(r"^\d+(,\d+)*$")

# ---------------------------------------------------------------------------
# Engagement directory resolution
# ---------------------------------------------------------------------------

def _get_base_dir() -> Path | None:
    """Return /workspace/<target> from $TARGET or active tmux session, else None."""
    target = os.environ.get("TARGET", "").strip()
    if target:
        return Path("/workspace") / target

    try:
        result = subprocess.run(
            ["tmux", "display-message", "-p", "#S"],
            capture_output=True, text=True, timeout=2,
        )
        sess = result.stdout.strip()
        if sess.startswith("pentest_"):
            tgt = sess.removeprefix("pentest_").replace("_", ".")
            return Path("/workspace") / tgt
    except Exception:
        pass

    return None

# ---------------------------------------------------------------------------
# Filename generation
# ---------------------------------------------------------------------------

def _build_filename(cmd: list[str]) -> str:
    """Derive a descriptive filename stem from a command + args list."""
    tool = Path(cmd[0]).name
    parts: list[str] = [tool]
    skip_next = False

    for arg in cmd[1:]:
        if skip_next:
            skip_next = False
            continue

        # IPv4 addresses (with optional CIDR)
        if _IP_RE.match(arg):
            continue
        # HTTP/S URLs
        if _URL_RE.match(arg):
            continue
        # Absolute paths
        if arg.startswith("/"):
            continue
        # key=path assignments (e.g. RHOSTS=192.168.1.1, module=./local.py)
        if "=" in arg:
            _, _, val = arg.partition("=")
            if val.startswith("/") or val.startswith("./"):
                continue
        # Dotted non-flag tokens (hostnames, filenames like wordlist.txt)
        if not arg.startswith("-") and "." in arg:
            continue
        # Pure numbers or port lists (80, 443, 80,443)
        if _NUM_RE.match(arg):
            continue
        # Flags that consume the next token as a value
        if arg in SKIP_FLAGS:
            skip_next = True
            continue

        clean = re.sub(r"^-+", "", arg)                # strip leading dashes
        clean = re.sub(r"[^a-zA-Z0-9_-]", "", clean)  # keep safe chars only
        clean = clean[:15]
        if clean:
            parts.append(clean)

    name = "_".join(parts)
    name = re.sub(r"_+", "_", name).rstrip("_")[:60]
    return name or tool

# ---------------------------------------------------------------------------
# Output file resolution
# ---------------------------------------------------------------------------

def _resolve_outfile(outdir: Path, stem: str) -> Path:
    """Return outdir/stem.txt, auto-incrementing suffix on collision."""
    candidate = outdir / f"{stem}.txt"
    if not candidate.exists():
        return candidate
    n = 2
    while True:
        candidate = outdir / f"{stem}_{n}.txt"
        if not candidate.exists():
            return candidate
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

# ---------------------------------------------------------------------------
# PTY-based execution
# ---------------------------------------------------------------------------

def _run_pty(cmd: list[str], outfile: Path) -> int:
    """
    Execute *cmd* under a PTY, appending all output to *outfile* while
    also echoing to stdout in real time.  Returns the child's exit code.

    Running under a PTY means tools that detect TTY (nmap, gobuster, etc.)
    emit colours and progress bars as expected.
    """
    import pty

    rows, cols = _term_size()
    master_fd, slave_fd = pty.openpty()
    _set_winsize(slave_fd, rows, cols)

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

    # Put our terminal in raw mode so Ctrl+C/Ctrl+Z pass through to the child
    # via the PTY line discipline rather than being intercepted by our process.
    if is_tty:
        old_term = termios.tcgetattr(stdin_fd)
        tty.setraw(stdin_fd)

    try:
        with outfile.open("ab") as logf:
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

    finally:
        if is_tty:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_term)
        os.close(master_fd)
        signal.signal(signal.SIGWINCH, old_sigwinch)
        try:
            _, status = os.waitpid(pid, 0)
            exit_code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            pass

    return exit_code

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

USAGE = """\
NOCAP — Capture tool output. No cap.

Usage:
  cap [recon|loot|exploitation|screenshots] <command> [args...]
  cap --help | --version

Examples:
  cap nmap -sCV 10.10.10.5
  cap recon gobuster dir -u http://10.10.10.5 -w /wordlist.txt
  cap loot hashcat -m 1000 hashes.txt /wordlist.txt
  cap netexec smb 10.10.10.5 -u admin -p password
  cap feroxbuster -u http://10.10.10.5 -x php,html

Routing (priority order):
  1. $TARGET env var   → /workspace/$TARGET/<subdir>/
  2. tmux pentest_*    → /workspace/<target>/<subdir>/
  3. Fallback          → ./<subdir>/  (current working directory)

Output filename is derived from the command and meaningful flags.
IPs, URLs, paths, wordlists, and numeric values are stripped automatically.
Collisions auto-increment: nmap_sCV.txt → nmap_sCV_2.txt → nmap_sCV_3.txt

Every output file starts with a header:
  Command: nmap -sCV 10.10.10.5
  Date:    Fri Feb 20 14:30:52 EST 2026
  ---
  <output follows>
"""


def main(argv: list[str] | None = None) -> None:
    args = list(argv) if argv is not None else sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        sys.exit(0)

    if args[0] in ("-V", "--version"):
        from nocap import __version__
        print(f"nocap {__version__}")
        sys.exit(0)

    # Optional engagement subdir as first positional arg
    subdir = ""
    if args[0] in SUBDIRS:
        subdir = args[0]
        args = args[1:]

    if not args:
        print("nocap: error: no command specified\n", file=sys.stderr)
        print(USAGE)
        sys.exit(1)

    cmd = args

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

    # Build filename and resolve collisions
    stem = _build_filename(cmd)
    outfile = _resolve_outfile(outdir, stem)

    # Write file header
    with outfile.open("w") as f:
        f.write(f"Command: {' '.join(cmd)}\n")
        f.write(f"Date:    {datetime.now().astimezone().strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
        f.write("---\n")

    print(f"\033[90m[cap] → {outfile}\033[0m", file=sys.stderr)

    exit_code = _run_pty(cmd, outfile)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
