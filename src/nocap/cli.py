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
    or the active tmux session name, else None."""
    workspace = os.environ.get("NOCAP_WORKSPACE", "/workspace").rstrip("/")

    target = os.environ.get("TARGET", "").strip()
    if target:
        return Path(workspace) / target

    try:
        result = subprocess.run(
            ["tmux", "display-message", "-p", "#S"],
            capture_output=True, text=True, timeout=2,
        )
        sess = result.stdout.strip()
        if sess.startswith("pentest_"):
            tgt = sess.removeprefix("pentest_").replace("_", ".")
            return Path(workspace) / tgt
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
# Shared viewer helper
# ---------------------------------------------------------------------------

def _view_file(path: Path, *, paging: bool = False) -> None:
    """Display *path* using the best available viewer."""
    if paging:
        if shutil.which("bat"):
            subprocess.run(["bat", "--paging=always", "--color=always", str(path)])
        elif shutil.which("less"):
            subprocess.run(["less", "-R", str(path)])
        else:
            subprocess.run(["cat", str(path)])
    else:
        if shutil.which("bat"):
            subprocess.run(["bat", "--paging=never", "--color=always", "--style=plain", str(path)])
        else:
            subprocess.run(["cat", str(path)])

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
    return Path(_LAST_FILE.read_text().strip())

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

    file_list = "\n".join(str(f) for f in files)

    if shutil.which("fzf"):
        preview_cmd = "bat --color=always {} 2>/dev/null || cat {}"
        subprocess.run(
            ["fzf", "--preview", preview_cmd, "--preview-window=right:70%:wrap", "--ansi"],
            input=file_list,
            text=True,
        )
    else:
        for f in files:
            size = f.stat().st_size
            mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"{mtime}  {size:>8}  {f}")

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
  cap last
  cap ls
  cap ls recon
  cap ls pivoting
  cat $(cap last)

Routing (priority order):
  1. $TARGET env var         → $NOCAP_WORKSPACE/$TARGET/<subdir>/
  2. tmux pentest_* session  → $NOCAP_WORKSPACE/<target>/<subdir>/
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
