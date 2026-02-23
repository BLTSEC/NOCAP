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
import shutil
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

SUBDIRS = frozenset({"recon", "loot", "exploitation", "screenshots", "notes"})

# Auto tool→subdir routing (opt-in via --auto / -a)
TOOL_SUBDIRS: dict[str, str] = {
    # ── recon: network scanning & port discovery ─────────────────────────────
    "nmap": "recon",
    "nmap-parse-output": "recon",
    "rustscan": "recon",
    "masscan": "recon",
    "autorecon": "recon",
    "udpx": "recon",
    "divideandscan": "recon",
    "naabu": "recon",
    "netdiscover": "recon",
    "fping": "recon",
    # recon: web fuzzing & directory brute-force
    "gobuster": "recon",
    "feroxbuster": "recon",
    "ffuf": "recon",
    "wfuzz": "recon",
    "dirsearch": "recon",
    "dirb": "recon",
    "arjun": "recon",
    "kr": "recon",            # kiterunner
    "wuzz": "recon",
    # recon: web fingerprinting & active scanning
    "whatweb": "recon",
    "nikto": "recon",
    "nuclei": "recon",
    "httpx": "recon",
    "httprobe": "recon",
    "hakrawler": "recon",
    "katana": "recon",
    "gau": "recon",
    "bbot": "recon",
    "uncover": "recon",
    "chaos": "recon",
    "alterx": "recon",
    "hakrevdns": "recon",
    "jsluice": "recon",
    "linkfinder": "recon",
    "robotstester": "recon",
    "patator": "recon",
    "ssh-audit": "recon",
    # recon: CMS scanners
    "wpscan": "recon",
    "wpprobe": "recon",
    "joomscan": "recon",
    "droopescan": "recon",
    "drupwn": "recon",
    "cmsmap": "recon",
    "moodlescan": "recon",
    # recon: SSL/TLS & web infra
    "testssl": "recon",
    "sslscan": "recon",
    "wafw00f": "recon",
    "cors_scan": "recon",
    # recon: DNS & subdomain enumeration
    "dnsx": "recon",
    "massdns": "recon",
    "shuffledns": "recon",
    "fierce": "recon",
    "amass": "recon",
    "subfinder": "recon",
    "sublist3r": "recon",
    "findomain": "recon",
    "assetfinder": "recon",
    "dnsenum": "recon",
    "dnsrecon": "recon",
    "dnschef": "recon",
    "waybackurls": "recon",
    # recon: SMB / RPC / LDAP enumeration
    "enum4linux": "recon",
    "enum4linux-ng": "recon",
    "ldapsearch": "recon",
    "smbclient": "recon",
    "smbmap": "recon",
    "smbclientng": "recon",
    "rpcclient": "recon",
    "windapsearch": "recon",
    "ldeep": "recon",
    "pywerview": "recon",
    "godap": "recon",
    "manspider": "recon",
    "msprobe": "recon",
    "adidnsdump": "recon",
    "daclsearch": "recon",
    "nbtscan": "recon",
    "smtp-user-enum": "recon",
    "scrtdnsdump": "recon",
    "pysnaffler": "recon",
    # recon: SNMP & NFS
    "snmpwalk": "recon",
    "snmpenum": "recon",
    "onesixtyone": "recon",
    "showmount": "recon",
    # recon: Kerberos, AD & BloodHound collection
    "kerbrute": "recon",
    "netexec": "recon",
    "crackmapexec": "recon",
    "sprayhound": "recon",
    "smartbrute": "recon",
    "ldapdomaindump": "recon",
    "bloodhound-python": "recon",
    "rusthound": "recon",
    "rusthound-ce": "recon",
    # recon: OSINT
    "theHarvester": "recon",
    "recon-ng": "recon",
    "spiderfoot": "recon",
    "finalrecon": "recon",
    "maltego": "recon",
    "sherlock": "recon",
    "maigret": "recon",
    "holehe": "recon",
    "ghunt": "recon",
    "phoneinfoga": "recon",
    "censys": "recon",
    "GitFive": "recon",
    "photon": "recon",
    # recon: cloud
    "scout": "recon",          # ScoutSuite
    "cloudsplaining": "recon",
    "prowler": "recon",
    "cloudmapper.py": "recon",
    # recon: WiFi passive discovery
    "bettercap": "recon",
    "hcxdumptool": "recon",
    # ── screenshots ───────────────────────────────────────────────────────────
    "eyewitness": "screenshots",
    "EyeWitness": "screenshots",
    "gowitness": "screenshots",
    # ── loot: password cracking ───────────────────────────────────────────────
    "hashcat": "loot",
    "john": "loot",
    "hydra": "loot",
    "medusa": "loot",
    "legba": "loot",
    "fcrackzip": "loot",
    "pdfcrack": "loot",
    "nth": "loot",             # name-that-hash
    "haiti": "loot",
    "pkcrack": "loot",
    # loot: credential dumping & extraction
    "pypykatz": "loot",
    "lsassy": "loot",
    "DonPAPI": "loot",
    "donpapi": "loot",
    "gosecretsdump": "loot",
    "dploot": "loot",
    "masky": "loot",
    "crackhound": "loot",
    "keytabextract": "loot",
    "PCredz": "loot",
    "firefox_decrypt": "loot",
    # ── exploitation: frameworks & C2 ────────────────────────────────────────
    "msfconsole": "exploitation",
    "msfvenom": "exploitation",
    "msfdb": "exploitation",
    "routersploit": "exploitation",
    "sliver-server": "exploitation",
    "sliver-client": "exploitation",
    "ps-empire": "exploitation",
    "havoc": "exploitation",
    "Villain.py": "exploitation",
    "pwncat-vl": "exploitation",
    # exploitation: web
    "sqlmap": "exploitation",
    "weevely": "exploitation",
    "xsstrike": "exploitation",
    "nosqlmap": "exploitation",
    "gopherus": "exploitation",
    "ssrfmap": "exploitation",
    "bolt": "exploitation",
    "kadimus": "exploitation",
    "fuxploider": "exploitation",
    "ysoserial": "exploitation",
    "phpggc": "exploitation",
    "jdwp-shellifier": "exploitation",
    "byp4xx": "exploitation",
    "h2csmuggler": "exploitation",
    "smuggler": "exploitation",
    "tomcatWarDeployer": "exploitation",
    "clusterd": "exploitation",
    "token-exploiter": "exploitation",
    "XXEinjector": "exploitation",
    "php_filter_chain_generator": "exploitation",
    # exploitation: AD / Windows
    "evil-winrm": "exploitation",
    "evil-winrm-py": "exploitation",
    "mitm6": "exploitation",
    "ntlmrelayx.py": "exploitation",
    "krbrelayx.py": "exploitation",
    "aclpwn": "exploitation",
    "coercer": "exploitation",
    "petitpotam.py": "exploitation",
    "dfscoerce.py": "exploitation",
    "shadowcoerce.py": "exploitation",
    "pywhisker": "exploitation",
    "targetedKerberoast.py": "exploitation",
    "bloodyAD": "exploitation",
    "autobloody": "exploitation",
    "gpoddity": "exploitation",
    "goexec": "exploitation",
    "remotemonologue.py": "exploitation",
    "sccmhunter.py": "exploitation",
    "pxethief": "exploitation",
    "pre2k": "exploitation",
    "passthecert.py": "exploitation",
    "certipy": "exploitation",
    "noPac.py": "exploitation",
    "privexchange.py": "exploitation",
    "ms14-068.py": "exploitation",
    "zerologon-exploit": "exploitation",
    "abuseACL": "exploitation",
    "sccmsecrets.py": "exploitation",
    "pywsus.py": "exploitation",
    "pygpoabuse.py": "exploitation",
}

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
_IP6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d+)?$")
_URL_RE = re.compile(r"^https?://")
_NUM_RE = re.compile(r"^\d+(,\d+)*$")

_LAST_FILE = Path("/tmp/.nocap_last")

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

def _build_filename(cmd: list[str], note: str = "") -> str:
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
        # IPv6 addresses
        if _IP6_RE.match(arg):
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
# Subcommands
# ---------------------------------------------------------------------------

def _cmd_last() -> None:
    """Print the path of the last captured file."""
    if _LAST_FILE.exists():
        print(_LAST_FILE.read_text().strip())
    else:
        print("nocap: no captures yet", file=sys.stderr)
        sys.exit(1)


def _cmd_ls(subdir: str = "") -> None:
    """List captures for the current engagement, optionally scoped to a subdir."""
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
# CLI entry point
# ---------------------------------------------------------------------------

USAGE = """\
NOCAP — Capture tool output. No cap.

Usage:
  cap [options] [subdir] <command> [args...]
  cap last
  cap ls [subdir]
  cap --help | --version

Options:
  -n, --note <label>    Append a custom label to the output filename
  -s, --subdir <name>   Write to a custom subdir (created if needed)
  -a, --auto            Auto-route to subdir based on tool name (opt-in)
  -D, --dry-run         Show where output would go without running

Subcommands:
  last                  Print path of the last captured file
  ls [subdir]           Browse captures interactively (fzf) or list them

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
  cat $(cap last)

Routing (priority order):
  1. $TARGET env var   → /workspace/$TARGET/<subdir>/
  2. tmux pentest_*    → /workspace/<target>/<subdir>/
  3. Fallback          → ./<subdir>/  (current working directory)

Auto-routing (--auto / -a):
  Infers subdir from tool name. Explicit subdir always takes precedence.
  recon/      nmap, rustscan, masscan, autorecon, gobuster, feroxbuster,
              ffuf, wfuzz, dirsearch, nuclei, httpx, whatweb, nikto,
              wpscan, amass, subfinder, dnsx, kerbrute, netexec, smbmap,
              enum4linux-ng, ldapsearch, bloodhound-python, theHarvester,
              spiderfoot, recon-ng, bbot, katana, …
  screenshots/ eyewitness, gowitness
  loot/       hashcat, john, hydra, medusa, legba, pypykatz, lsassy,
              donpapi, dploot, gosecretsdump, nth, haiti, …
  exploitation/ msfconsole, msfvenom, sliver-server, ps-empire, havoc,
              sqlmap, weevely, evil-winrm, mitm6, coercer, certipy,
              bloodyAD, ntlmrelayx.py, xsstrike, …
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

    # Subcommands
    if args[0] == "last":
        _cmd_last()
        return

    if args[0] == "ls":
        subdir_arg = args[1] if len(args) > 1 and args[1] in SUBDIRS else ""
        _cmd_ls(subdir_arg)
        return

    # Parse nocap-specific flags (must come before subdir / command)
    note = ""
    auto_route = False
    dry_run = False
    subdir = ""

    while args:
        if args[0] in ("-n", "--note") and len(args) > 1:
            note = args[1]
            args = args[2:]
        elif args[0] in ("-a", "--auto"):
            auto_route = True
            args = args[1:]
        elif args[0] in ("-D", "--dry-run"):
            dry_run = True
            args = args[1:]
        elif args[0] in ("-s", "--subdir") and len(args) > 1:
            subdir = args[1]
            args = args[2:]
        else:
            break

    # Optional predefined engagement subdir as first positional arg
    if not subdir and args and args[0] in SUBDIRS:
        subdir = args[0]
        args = args[1:]

    if not args:
        print("nocap: error: no command specified\n", file=sys.stderr)
        print(USAGE)
        sys.exit(1)

    cmd = args

    # Auto tool→subdir routing (only when --auto is set and no explicit subdir)
    if auto_route and not subdir:
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

    # Build filename and resolve collisions
    stem = _build_filename(cmd, note=note)
    outfile = _resolve_outfile(outdir, stem)

    if dry_run:
        print(f"\033[90m[dry] → {outfile}\033[0m")
        sys.exit(0)

    # Write file header
    with outfile.open("w") as f:
        f.write(f"Command: {' '.join(cmd)}\n")
        f.write(f"Date:    {datetime.now().astimezone().strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
        f.write("---\n")

    print(f"\033[90m[cap] → {outfile}\033[0m", file=sys.stderr)

    exit_code = _run_pty(cmd, outfile)

    # Track last captured file for `cap last`
    _LAST_FILE.write_text(str(outfile))

    # Bell — audible/visual alert that the command has finished
    sys.stderr.write("\a")
    sys.stderr.flush()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
