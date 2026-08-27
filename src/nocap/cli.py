"""NOCAP command-line parsing and live-capture orchestration."""

from __future__ import annotations

import argparse
import shlex
import sys
import time
from pathlib import Path
from typing import Any

from nocap.config import Settings, load_settings
from nocap.filename import (
    _build_filename,
    _claim_outfile,
    _compute_outfile,
    _normalize_command,
)
from nocap.metadata import abandon_record, create_record, finalize_record
from nocap.pty import _run_pty
from nocap.routing import _active_root, _get_output_dir
from nocap.subcommands import _DISPATCH, _remember_last, _write_capture_header
from nocap.tools import SUBDIRS, route_for_tool

__all__ = ["main"]


def _get_version() -> str:
    try:
        from importlib.metadata import version

        return version("nocap")
    except (ImportError, ModuleNotFoundError):
        from nocap import __version__

        return __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cap", add_help=False, allow_abbrev=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-V", "-v", "--version", action="store_true")
    parser.add_argument("-n", "--note", default="", metavar="LABEL")
    parser.add_argument("-s", "--subdir", default="", metavar="NAME")
    parser.add_argument("-a", "--auto", action="store_true")
    parser.add_argument("-D", "--dry-run", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


_PARSER = _build_parser()


USAGE = """\
NOCAP — keep the terminal output that matters.

Usage:
  cap [options] [-s SUBDIR] <command> [args...]
  cap -- <command matching a cap subcommand> [args...]
  cap <subcommand> [args...]

Capture options:
  -n, --note LABEL       Add a filename label
  -s, --subdir NAME      Write below the active target root
  -a, --auto             Route by the effective wrapped tool
  -D, --dry-run          Print the destination without writing
  -q, --quiet            Suppress NOCAP status lines

Find and view:
  last                   Print the last capture path
  cat|render [CAPTURE]   Render safely; --compact applies lossy cleanup
  open|tail [CAPTURE]    Page/edit or follow a capture
  ls [SUBDIR]            List captures (bounded by config)
  browse [SUBDIR]        Select and page with fzf; --print returns its path
  summary [PATTERN]      File table or regex-first compatibility search
  search QUERY           Search retained captures
  timeline               Execution order; --format table|md|json

Manage:
  rm [CAPTURE]           Delete raw output and retain a tombstone
  rm --pick              Select captures with fzf, then confirm
  rename LABEL [CAPTURE] Rename without changing capture identity
  tag add|remove|list    Manage capture tags
  inspect [CAPTURE]      Show metadata; use --verify or --json
  review                 Build a bounded local Markdown packet
  meta status|sync|verify|export|prune
  status                 Show routing and metadata health
  grab [command...]      Capture the last tmux command's scrollback
  logs                   Delegate session logs to TACMUX
  update                 Upgrade the pipx installation

CAPTURE may be an ID prefix or a path below the active target. Deleted
captures are hidden unless a command explicitly offers --include-deleted.

Config: $XDG_CONFIG_HOME/nocap/config.toml and <workspace>/.nocap/config.toml
Target: TACMUX_TARGET, tmux TACMUX_TARGET, LOADOUT_TARGET (legacy), then TARGET
"""


def _fail(message: str, code: int = 2) -> None:
    print(f"nocap: {message}", file=sys.stderr)
    raise SystemExit(code)


def _settings() -> Settings:
    try:
        return load_settings()
    except ValueError as exc:
        _fail(str(exc))
    raise AssertionError


def _route_for(cmd: list[str], settings: Settings) -> tuple[str, str]:
    normalized = _normalize_command(cmd, settings.aliases)
    effective = Path(normalized[0]).name if normalized else ""
    route = settings.routes.get(effective)
    return effective, route if route is not None else route_for_tool(
        effective, normalized[1:]
    )


def _status(message: str, *, quiet: bool) -> None:
    if not quiet:
        print(message, file=sys.stderr)


def _finalize_safely(
    root: Path,
    record: dict[str, Any],
    outfile: Path,
    *,
    exit_code: int | None,
    duration_ms: int,
    status: str | None = None,
) -> None:
    try:
        finalize_record(
            root,
            record,
            outfile,
            exit_code=exit_code,
            duration_ms=duration_ms,
            status=status,
        )
    except (OSError, ValueError) as exc:
        print(f"nocap: warning: cannot finalize metadata: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    try:
        _main(argv)
    except KeyboardInterrupt:
        raise SystemExit(130) from None


def _main(argv: list[str] | None = None) -> None:
    raw = list(argv) if argv is not None else sys.argv[1:]
    if not raw:
        print(USAGE)
        raise SystemExit(0)

    # Dispatch first. `cap -- ls ...` remains the escape hatch.
    if raw[0] in _DISPATCH:
        _DISPATCH[raw[0]](raw[1:])
        return

    try:
        ns = _PARSER.parse_args(raw)
    except SystemExit:
        raise SystemExit(2) from None

    if ns.help:
        print(USAGE)
        raise SystemExit(0)
    if ns.version:
        print(f"nocap {_get_version()}")
        raise SystemExit(0)

    cmd: list[str] = ns.command
    if cmd[:1] == ["--"]:
        cmd = cmd[1:]
    subdir: str = ns.subdir
    if not subdir and cmd and cmd[0] in SUBDIRS:
        subdir = cmd.pop(0)
    if not cmd:
        _fail("no command specified", 1)

    settings = _settings()
    effective_tool, inferred_route = _route_for(cmd, settings)
    if not subdir and (ns.auto or settings.auto_route):
        subdir = inferred_route
    if subdir and Path(subdir).parts in {(), (".",)}:
        subdir = ""

    try:
        root = _active_root(settings)
        outdir = _get_output_dir(subdir, settings)
    except ValueError as exc:
        _fail(str(exc))

    stem = _build_filename(cmd, note=ns.note, aliases=settings.aliases)
    if ns.dry_run:
        print(_compute_outfile(outdir, stem))
        raise SystemExit(0)

    outdir.mkdir(parents=True, exist_ok=True)
    outfile = _claim_outfile(outdir, stem)
    command = shlex.join(cmd)
    try:
        record = create_record(
            root,
            outfile,
            command=command,
            original_tool=Path(cmd[0]).name,
            effective_tool=effective_tool,
            route=subdir,
            source="live",
        )
    except (OSError, ValueError) as exc:
        outfile.unlink(missing_ok=True)
        _fail(f"cannot create metadata record: {exc}")

    try:
        with outfile.open("w", encoding="utf-8", errors="backslashreplace") as fh:
            _write_capture_header(fh, command)
    except OSError as exc:
        try:
            abandon_record(root, record)
        except (OSError, ValueError) as cleanup_exc:
            print(f"nocap: warning: cannot discard pending metadata: {cleanup_exc}", file=sys.stderr)
        outfile.unlink(missing_ok=True)
        _fail(f"cannot write capture header: {exc}")

    _status(f"[cap] {outfile}", quiet=ns.quiet)
    started = time.monotonic()
    try:
        exit_code = _run_pty(cmd, outfile)
    except BaseException:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        _finalize_safely(
            root, record, outfile, exit_code=None, duration_ms=elapsed_ms, status="interrupted"
        )
        _remember_last(outfile)
        raise

    elapsed_ms = round((time.monotonic() - started) * 1000)
    _finalize_safely(root, record, outfile, exit_code=exit_code, duration_ms=elapsed_ms)
    _remember_last(outfile)

    if settings.bell and not ns.quiet:
        sys.stderr.write("\a")
    mark = "ok" if exit_code == 0 else f"exit {exit_code}"
    _status(f"[{mark}] {outfile.name} ({elapsed_ms / 1000:.1f}s)", quiet=ns.quiet)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
