"""Filename generation and atomic output-file allocation for NOCAP."""

from __future__ import annotations

import os
import re
import shlex
import sys
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from nocap.tools import SKIP_FLAGS

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d+)?$")
_IP6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d+)?$")
_URL_RE = re.compile(r"^https?://")
_NUM_RE = re.compile(r"^\d+(,\d+)*$")
_HOSTLIKE_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_COMMON_FILE_EXTS = frozenset({
    "7z", "bak", "cfg", "conf", "config", "csv", "db", "dll", "doc",
    "docx", "exe", "gz", "html", "ini", "jar", "json", "key", "log",
    "lst", "md", "pdf", "pem", "php", "ps1", "py", "sh", "sql", "sqlite",
    "tar", "tgz", "toml", "txt", "xml", "yaml", "yml", "zip",
})
_SCRIPT_EXTS = frozenset({".bash", ".pl", ".ps1", ".py", ".pyw", ".rb", ".sh", ".zsh"})

_STEM_MAX_LEN = 60
_PART_MAX_LEN = 15
_HOST_LABEL_MAX_LEN = 12
_NOTE_MAX_LEN = 20

_SHELLS = {"bash", "dash", "fish", "ksh", "sh", "zsh"}
_PYTHONS = {"python", "python3", "python3.11", "python3.12", "python3.13", "python3.14"}
_PROXY_WRAPPERS = {"proxychains", "proxychains4", "proxychains-ng"}
_SENSITIVE_VALUE_FLAGS = {
    "-aeskey",
    "-hashes",
    "-key",
    "-pass",
    "-password",
    "-secret",
    "-token",
    "--aes-key",
    "--aeskey",
    "--api-key",
    "--auth",
    "--authorization",
    "--bearer",
    "--credential",
    "--credentials",
    "--hash",
    "--hashes",
    "--key",
    "--pass",
    "--password",
    "--pfx-pass",
    "--secret",
    "--token",
    "--user",
    "--username",
}
_SENSITIVE_SHORT_FLAGS = frozenset({"-U", "-P", "-L", "-l"})
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?:pass(?:word)?|pwd|secret|token|auth(?:orization)?|api[_-]?key|hash(?:es)?|user(?:name)?|credential(?:s)?)",
    re.IGNORECASE,
)
_SENSITIVE_FLAG_COMPONENT_RE = re.compile(
    r"(?:^|[-_])(?:auth(?:orization)?|bearer|cookie|credential(?:s)?|hash(?:es)?|"
    r"key|login|pass(?:word)?|secret|session|token|user(?:name)?)(?:$|[-_])",
    re.IGNORECASE,
)
_CODE_VALUE_FLAGS = frozenset(
    {"-c", "--command", "-e", "--eval", "-x", "-X", "--encoded-command"}
)
_ATTACHED_VALUE_FLAGS = ("-u", "-U", "-p", "-H", "-w", "-o", "-f")
_SAFE_ATTACHED_SWITCHES = frozenset({"-Pn"})
_NXC_PROTOCOLS = {
    "ftp", "ldap", "mssql", "nfs", "rdp", "smb", "ssh", "vnc", "winrm", "wmi",
}
_NXC_ACTIONS = {
    "--admin-count": "admin-count",
    "--continue-on-success": "continue",
    "--disks": "disks",
    "--shares": "shares",
    "--users": "users",
    "--groups": "groups",
    "--interfaces": "interfaces",
    "--loggedon-users": "loggedon",
    "--password-not-required": "no-password",
    "--pass-pol": "passpol",
    "--qwinsta": "qwinsta",
    "--query": "query",
    "--reg-sessions": "sessions",
    "--rid-brute": "rid-brute",
    "--sam": "sam",
    "--lsa": "lsa",
    "--dpapi": "dpapi",
    "--gen-relay-list": "signing",
    "--local-auth": "local-auth",
    "--trusted-for-delegation": "delegation",
}
_HYDRA_SERVICES = frozenset(
    {
        "ftp", "http-get", "http-head", "http-post", "http-get-form", "http-post-form",
        "https-get", "https-head", "https-post", "https-get-form", "https-post-form",
        "imap", "ldap2", "ldap3", "mssql", "mysql", "pop3", "rdp", "redis", "smb",
        "smtp", "snmp", "ssh", "telnet", "vnc", "winrm",
    }
)


def _drop_env_assignments(args: list[str]) -> list[str]:
    index = 0
    while index < len(args) and _ENV_ASSIGNMENT_RE.match(args[index]):
        index += 1
    return args[index:]


def _is_sensitive_flag(value: str) -> bool:
    name = value.partition("=")[0]
    lowered = name.lower()
    return lowered in _SENSITIVE_VALUE_FLAGS or bool(
        _SENSITIVE_FLAG_COMPONENT_RE.search(lowered.lstrip("-"))
    )


def _skip_options(
    args: list[str],
    *,
    consuming: frozenset[str] = frozenset(),
) -> list[str]:
    i = 0
    while i < len(args):
        value = args[i]
        if value == "--":
            return args[i + 1 :]
        if not value.startswith("-"):
            return args[i:]
        if value in consuming:
            i += 2
        else:
            i += 1
    return []


def _normalize_command(
    cmd: list[str],
    aliases: Mapping[str, str] | None = None,
) -> list[str]:
    """Return the effective command used for naming and auto-routing.

    This never changes the command that is executed or written to evidence.
    """
    current = list(cmd)
    aliases = aliases or {}

    for _ in range(8):
        current = _drop_env_assignments(current)
        if not current:
            break
        tool = Path(current[0]).name

        alias = aliases.get(tool)
        if alias:
            current[0] = alias
            tool = Path(alias).name

        if tool == "sudo":
            reduced = _skip_options(
                current[1:],
                consuming=frozenset(
                    {
                        "-u", "--user", "-g", "--group", "-h", "--host",
                        "-C", "-D", "--chdir", "-R", "-T",
                    }
                ),
            )
            reduced = _drop_env_assignments(reduced)
        elif tool == "env":
            args = _skip_options(current[1:], consuming=frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}))
            while args and "=" in args[0] and not args[0].startswith("="):
                args = args[1:]
            reduced = args
        elif tool == "timeout":
            args = _skip_options(current[1:], consuming=frozenset({"-k", "--kill-after", "-s", "--signal"}))
            reduced = args[1:] if args else []  # discard duration
        elif tool in _PROXY_WRAPPERS:
            reduced = _skip_options(current[1:], consuming=frozenset({"-f", "--config"}))
        elif tool == "faketime":
            file_mode = "-f" in current[1:]
            args = _skip_options(current[1:], consuming=frozenset({"-f"}))
            reduced = args if file_mode else (args[1:] if len(args) > 1 else [])
        elif tool == "uv" and current[1:2] == ["run"]:
            reduced = _skip_options(current[2:], consuming=frozenset({"--directory", "--project", "--python", "--with"}))
        elif tool in _SHELLS:
            try:
                flag_index = next(
                    i
                    for i, value in enumerate(current[1:], 1)
                    if value == "-c"
                    or (
                        value.startswith("-")
                        and not value.startswith("--")
                        and "c" in value[1:]
                    )
                )
            except StopIteration:
                reduced = []
            else:
                payload_index = flag_index + 1
                if payload_index >= len(current):
                    reduced = []
                else:
                    try:
                        parsed = shlex.split(current[payload_index])
                        parsed = _drop_env_assignments(parsed)
                        while parsed and parsed[0] in {"command", "exec", "nohup"}:
                            parsed = _skip_options(parsed[1:])
                            parsed = _drop_env_assignments(parsed)
                        # The payload is arbitrary code. It is useful for finding
                        # the effective tool, but never safe filename material.
                        reduced = parsed[:1]
                    except ValueError:
                        reduced = [tool]
        elif tool in _PYTHONS:
            args = current[1:]
            reduced = []
            index = 0
            while index < len(args):
                value = args[index]
                if value == "--":
                    reduced = args[index + 1 :]
                    break
                if value == "-m":
                    reduced = args[index + 1 :]
                    break
                if value == "-c":
                    return [current[0]]
                if value in {"-W", "-X", "--check-hash-based-pycs"}:
                    index += 2
                    continue
                if value.startswith(("-W", "-X", "--check-hash-based-pycs=")):
                    index += 1
                    continue
                if value.startswith("-"):
                    index += 1
                    continue
                reduced = args[index:]
                break
        else:
            break

        if not reduced or reduced == current:
            break
        current = reduced

    if current:
        alias = aliases.get(Path(current[0]).name)
        if alias:
            current[0] = alias
    return current or ["command"]


def _effective_tool(cmd: list[str], aliases: Mapping[str, str] | None = None) -> str:
    normalized = _normalize_command(cmd, aliases)
    return Path(normalized[0]).name if normalized else ""


def _profile_parts(tool: str, args: list[str]) -> list[str]:
    """Extract stable action labels for high-frequency operator tools."""
    parts: list[str] = []
    lowered = [value.lower() for value in args]

    if tool in {"nxc", "netexec", "crackmapexec"}:
        if args and args[0].lower() in _NXC_PROTOCOLS:
            parts.append(args[0].lower())
        for flag, label in _NXC_ACTIONS.items():
            if flag in lowered and label not in parts:
                parts.append(label)
        for module_flag in ("-m", "--module"):
            if module_flag in lowered:
                i = lowered.index(module_flag)
                if i + 1 < len(args):
                    parts.append(args[i + 1].lower())
        if parts[:1] == ["rdp"] and len(parts) == 1:
            parts.append("check")
    elif tool == "rpcclient":
        if "-c" in args:
            i = args.index("-c")
            if i + 1 < len(args):
                try:
                    parts.extend(shlex.split(args[i + 1])[:1])
                except ValueError:
                    pass
    elif tool == "hydra":
        service = next((value.lower() for value in reversed(args) if value.lower() in _HYDRA_SERVICES), "")
        if service:
            parts.append(service)
    elif tool == "dig":
        for value in args:
            upper = value.upper()
            if upper in {"A", "AAAA", "AXFR", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"}:
                parts.append(upper.lower())
                break
    elif tool == "kerbrute" and args:
        action = args[0].lower()
        if action in {"bruteforce", "bruteuser", "passwordspray", "userenum"}:
            parts.append(action)

    return parts


def _profile_skip_indices(tool: str, args: list[str]) -> set[int]:
    """Arguments represented by a tool profile or known to be target noise."""
    skipped: set[int] = set()
    if tool in {"nxc", "netexec", "crackmapexec"} and args:
        if args[0].lower() in _NXC_PROTOCOLS:
            skipped.add(0)
            if len(args) > 1:
                skipped.add(1)
        for index, value in enumerate(args):
            if value.lower() in _NXC_ACTIONS:
                skipped.add(index)
                if value.lower() == "--query" and index + 1 < len(args):
                    skipped.add(index + 1)
            if value in {"-M", "--module"} and index + 1 < len(args):
                skipped.update({index, index + 1})
    elif tool == "rpcclient":
        for index, value in enumerate(args):
            if value in {"-U", "-c"} and index + 1 < len(args):
                skipped.update({index, index + 1})
            elif value == "-N":
                skipped.add(index)
        # rpcclient's remaining positional argument is the server.
        skipped.update(index for index, value in enumerate(args) if not value.startswith("-"))
    elif tool == "dig":
        skipped.update(index for index, value in enumerate(args) if not value.startswith("-") or value.startswith("@"))
    elif tool == "hydra" or (
        tool == "kerbrute"
        and args
        and args[0].lower() in {"bruteforce", "bruteuser", "passwordspray", "userenum"}
    ):
        skipped.update(range(len(args)))
    return skipped


def _build_filename(
    cmd: list[str],
    note: str = "",
    *,
    aliases: Mapping[str, str] | None = None,
) -> str:
    """Derive a descriptive filename stem from a command + args list."""
    cmd = _normalize_command(cmd, aliases)
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
    tool_name = Path(cmd[0]).name
    suffix = Path(tool_name).suffix.lower()
    display_tool = Path(tool_name).stem if suffix in _SCRIPT_EXTS else tool_name
    tool = _sanitize_part(display_tool, max_len=_STEM_MAX_LEN) or "command"

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
        if not labels:
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

    profiled = _profile_parts(tool_name, cmd[1:])
    for part in profiled:
        clean = _sanitize_part(part)
        if clean and clean not in syntax_parts:
            syntax_parts.append(clean)

    profile_skips = _profile_skip_indices(tool_name, cmd[1:])
    for arg_index, arg in enumerate(cmd[1:]):
        if arg_index in profile_skips:
            continue
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

        if not _URL_RE.match(arg) and "@" in arg and not arg.startswith("-"):
            # Positional userinfo is common in SSH and Impacket targets. It
            # can contain a password, so omit the entire token.
            continue

        if arg.startswith("--") and "=" in arg:
            raw_flag, _, _ = arg.partition("=")
            if _is_sensitive_flag(raw_flag):
                continue
            arg = raw_flag

        if not arg.startswith("-") and "=" in arg:
            key, _, assignment_value = arg.partition("=")
            if _SENSITIVE_ASSIGNMENT_RE.search(key):
                continue
            if (
                assignment_value.startswith(("/", "./"))
                or _IP_RE.match(assignment_value)
                or _IP6_RE.match(assignment_value)
            ):
                continue
            arg = key

        if arg not in _SAFE_ATTACHED_SWITCHES and any(
            arg.startswith(flag) and len(arg) > len(flag) for flag in _ATTACHED_VALUE_FLAGS
        ):
            continue

        if arg in _SENSITIVE_SHORT_FLAGS:
            skip_next = True
            prev_flag = arg
            continue

        flag_name = arg.partition("=")[0]
        if _is_sensitive_flag(flag_name):
            if "=" not in arg:
                skip_next = True
                prev_flag = flag_name
            continue

        if flag_name in _CODE_VALUE_FLAGS:
            if "=" not in arg:
                skip_next = True
                prev_flag = flag_name
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
            if clean not in syntax_parts:
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
