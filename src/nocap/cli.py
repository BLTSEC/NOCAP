#!/usr/bin/env python3
"""NOCAP command-line parsing and live-capture orchestration."""

from __future__ import annotations

import argparse
import os
import shlex
import sys
import time
from pathlib import Path

from nocap.filename import _build_filename, _claim_outfile, _compute_outfile
from nocap.pty import _run_pty
from nocap.routing import _get_output_dir
from nocap.subcommands import _DISPATCH, _remember_last, _write_capture_header
from nocap.tools import SUBDIRS, TOOL_SUBDIRS

__all__ = ["main"]


def _get_version() -> str:
    try:
        from importlib.metadata import version
        return version("nocap")
    except (ImportError, ModuleNotFoundError):
        from nocap import __version__
        return __version__


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


_PARSER = _build_parser()


USAGE = """\
NOCAP — Capture tool output. No cap.

Usage:
  cap [options] [subdir] <command> [args...]
  cap [options] -- <command matching a subcommand> [args...]
  cap grab [options] [command...]
  cap last | cat | tail | open | rm | summary | render
  cap ls [subdir]
  cap update
  cap --help | --version

Options:
  -n, --note <label>    Append a custom label to the output filename
  -s, --subdir <name>   Write to a custom subdir (created if needed)
  -a, --auto            Auto-route to subdir based on tool name (opt-in)
  -D, --dry-run         Show where output would go without running
  --                    Capture a command named like a NOCAP subcommand

Subcommands:
  last                  Print path of the last captured file
  cat                   Dump last capture to stdout as clean rendered text
  tail                  Follow last capture from the start (tail -f)
  open                  Open last capture in $EDITOR or rendered through less
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
  LOADOUT_TARGET=name   Prefer a normalized engagement directory name over $TARGET
  XDG_CACHE_HOME=path   Override the cache root for the last-capture pointer

Subdirs:
  recon, loot, exploitation, screenshots, notes

Examples:
  cap nmap -sCV 10.10.10.5
  cap recon gobuster dir -u http://10.10.10.5 -w /wordlist.txt
  cap -n after-creds nmap -sCV 10.10.10.5
  cap --auto nmap -sCV 10.10.10.5
  cap -D feroxbuster -u http://10.10.10.5
  cap -- ls -la
  cap grab
  cap grab -n initial nmap -sCV 10.10.10.5
  cap last
  cap ls
  cap ls recon
  cap ls pivoting
  cat $(cap last)

Routing (priority order):
  1. $LOADOUT_TARGET         → $NOCAP_WORKSPACE/$LOADOUT_TARGET/<subdir>/
  2. $TARGET env var         → $NOCAP_WORKSPACE/$TARGET/<subdir>/
  3. tmux op_* session       → $NOCAP_WORKSPACE/<target>/<subdir>/
  4. Fallback                → ./<subdir>/  (current working directory)

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
    if cmd[:1] == ["--"]:
        cmd = cmd[1:]
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
    try:
        outdir = _get_output_dir(subdir)
    except ValueError as exc:
        print(f"nocap: invalid subdir: {exc}", file=sys.stderr)
        sys.exit(2)

    stem = _build_filename(cmd, note=ns.note)

    if ns.dry_run:
        outfile = _compute_outfile(outdir, stem)
        print(f"\033[90m[dry] → {outfile}\033[0m")
        sys.exit(0)

    outdir.mkdir(parents=True, exist_ok=True)

    # Atomically claim the output file (eliminates the TOCTOU race)
    outfile = _claim_outfile(outdir, stem)

    # Write file header (overwrites the empty placeholder created above)
    with outfile.open("w", encoding="utf-8", errors="backslashreplace") as f:
        _write_capture_header(f, shlex.join(cmd))

    print(f"\033[90m[cap] → {outfile}\033[0m", file=sys.stderr)

    start = time.monotonic()
    exit_code = _run_pty(cmd, outfile)
    elapsed = time.monotonic() - start

    # Track last captured file for `cap last`
    _remember_last(outfile)

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
