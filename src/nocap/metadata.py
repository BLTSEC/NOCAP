"""Private per-capture metadata records.

Raw capture files remain authoritative.  JSON records provide provenance,
status, tags, rename history, and integrity data without rewriting evidence.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import socket
import stat
import tempfile
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
COMMAND_PREFIX = "Command: "
DATE_PREFIX = "Date:    "
HEADER_SEPARATOR = "---"
HEADER_LINE_MAX = 65536
READ_CHUNK = 65536
_STATUSES = frozenset(
    {
        "running", "completed", "failed", "unknown", "interrupted",
        "imported", "missing", "deleting", "deleted",
    }
)
_SOURCES = frozenset({"live", "grab", "imported"})
_TIME_SOURCES = frozenset({"record", "header", "mtime"})
_HEX_64 = frozenset("0123456789abcdef")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _records_dir(root: Path) -> Path:
    return root / ".nocap" / "records"


def _topology_errors(root: Path) -> list[tuple[Path, str]]:
    errors: list[tuple[Path, str]] = []
    meta = root / ".nocap"
    records = _records_dir(root)
    lock = meta / "lock"
    if meta.is_symlink():
        return [(meta, "metadata directory is a symlink")]
    if meta.exists() and not meta.is_dir():
        return [(meta, "metadata path is not a directory")]
    if records.is_symlink():
        errors.append((records, "metadata records directory is a symlink"))
    elif records.exists() and not records.is_dir():
        errors.append((records, "metadata records path is not a directory"))
    if lock.is_symlink():
        errors.append((lock, "metadata lock is a symlink"))
    elif lock.exists() and not lock.is_file():
        errors.append((lock, "metadata lock is not a regular file"))
    return errors


def _record_path(root: Path, record_id: str) -> Path:
    return _records_dir(root) / f"{_canonical_record_id(record_id)}.json"


def _canonical_record_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"invalid capture id: {value!r}") from exc
    canonical = str(parsed)
    if value != canonical:
        raise ValueError(f"capture id is not canonical: {value!r}")
    return canonical


def _ensure_private_dir(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"metadata directory is a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"metadata path is not a private directory: {path}")
    try:
        path.chmod(0o700)
    except OSError:
        pass


@contextmanager
def _metadata_lock(root: Path) -> Iterator[None]:
    meta = root / ".nocap"
    _ensure_private_dir(meta)
    lock_path = meta / "lock"
    if lock_path.is_symlink():
        raise ValueError(f"metadata lock is a symlink: {lock_path}")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"metadata lock is not a regular file: {lock_path}")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _atomic_write(path: Path, record: dict[str, Any]) -> None:
    _ensure_private_dir(path.parent)
    encoded = (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _count_lines(path: Path) -> int:
    try:
        with path.open("rb") as fh:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(READ_CHUNK), b""))
    except OSError:
        return 0


def _relative_path(root: Path, path: Path) -> str:
    resolved_root = root.resolve(strict=False)
    resolved = path.resolve(strict=False)
    if not resolved.is_relative_to(resolved_root):
        raise ValueError(f"capture path escapes active root: {path}")
    return resolved.relative_to(resolved_root).as_posix()


def _capture_header(path: Path) -> tuple[str, str] | None:
    try:
        with path.open("rb") as fh:
            command = fh.readline(HEADER_LINE_MAX)
            date = fh.readline(HEADER_LINE_MAX)
            separator = fh.readline(HEADER_LINE_MAX)
    except OSError:
        return None
    if not (
        command.startswith(COMMAND_PREFIX.encode())
        and date.startswith(DATE_PREFIX.encode())
        and separator.rstrip(b"\r\n") == HEADER_SEPARATOR.encode()
    ):
        return None
    return (
        command[len(COMMAND_PREFIX) :].decode("utf-8", errors="replace").rstrip("\r\n"),
        date[len(DATE_PREFIX) :].decode("utf-8", errors="replace").rstrip("\r\n"),
    )


def is_capture_file(path: Path) -> bool:
    return _capture_header(path) is not None


def find_capture_files(root: Path) -> list[Path]:
    captures: list[tuple[float, Path]] = []
    resolved_root = root.resolve(strict=False)
    try:
        iterator = root.rglob("*.txt")
    except OSError:
        return []
    for path in iterator:
        if ".nocap" in path.parts or not is_capture_file(path):
            continue
        try:
            if not path.resolve(strict=False).is_relative_to(resolved_root):
                continue
            captures.append((path.stat().st_mtime, path))
        except OSError:
            continue
    captures.sort(key=lambda item: item[0], reverse=True)
    return [path for _, path in captures]


def _parse_legacy_date(value: str, fallback: Path) -> tuple[str, str]:
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            raise ValueError("legacy date has no timezone")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), "header"
    except (TypeError, ValueError):
        try:
            ts = fallback.stat().st_mtime
        except OSError:
            ts = datetime.now(timezone.utc).timestamp()
        return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z"), "mtime"


def create_record(
    root: Path,
    capture: Path,
    *,
    command: str,
    original_tool: str,
    effective_tool: str,
    route: str,
    source: str,
) -> dict[str, Any]:
    record_id = str(uuid.uuid4())
    relative_path = _relative_path(root, capture)
    owned = source in {"live", "grab"}
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": record_id,
        "path": relative_path,
        "command": command,
        "command_sha256": _sha256_bytes(command.encode("utf-8", errors="surrogateescape")),
        "original_tool": original_tool,
        "effective_tool": effective_tool,
        "route": route,
        "source": source,
        "status": "running" if owned else "imported",
        "started_at": _utc_now(),
        "started_at_source": "record",
        "finished_at": None,
        "duration_ms": None,
        "exit_code": None,
        "size_bytes": None,
        "line_count": None,
        "sha256": None,
        "tags": [],
        "renames": [],
        "deleted_at": None,
        "delete_started_at": None,
        "delete_previous_status": None,
        "owner": {"pid": os.getpid(), "host": socket.gethostname()} if owned else None,
    }
    with _metadata_lock(root):
        records, errors = load_records(root)
        if errors:
            path, detail = errors[0]
            raise ValueError(f"cannot create record with malformed metadata {path}: {detail}")
        active = [
            current
            for current in records
            if current.get("path") == relative_path and current.get("status") != "deleted"
        ]
        if len(active) > 1:
            raise ValueError(f"capture path has multiple active records: {relative_path}")
        if active:
            current = active[0]
            if current.get("source") != "imported" or source == "imported":
                raise ValueError(f"capture path already has an active record: {relative_path}")
            try:
                same_file = current.get("sha256") == _sha256_file(capture)
            except OSError:
                same_file = False
            if not same_file or current.get("command_sha256") != record["command_sha256"]:
                raise ValueError(f"capture path already has an active record: {relative_path}")
            # A concurrent sync may have imported the header before an older
            # caller created its live record. Claim that identity rather than
            # creating a second active record for the same path.
            record["id"] = current["id"]
            record["tags"] = list(current.get("tags", []))
            record["renames"] = list(current.get("renames", []))
        _atomic_write(_record_path(root, str(record["id"])), record)
    return record


def abandon_record(root: Path, record: dict[str, Any]) -> None:
    """Remove a pending record that failed before capture output began."""
    with _metadata_lock(root):
        current = _current_record_locked(root, str(record["id"]))
        owner = current.get("owner") or {}
        if current.get("status") != "running" or owner.get("pid") != os.getpid():
            raise ValueError(f"cannot abandon capture record in {current.get('status')} state")
        capture_path(root, current).unlink(missing_ok=True)
        _record_path(root, str(current["id"])).unlink()


def _current_record_locked(root: Path, record_id: str) -> dict[str, Any]:
    path = _record_path(root, record_id)
    try:
        return _load_record(root, path)
    except FileNotFoundError as exc:
        raise ValueError(f"capture record no longer exists: {record_id}") from exc


def finalize_record(
    root: Path,
    record: dict[str, Any],
    capture: Path,
    *,
    exit_code: int | None,
    duration_ms: int | None,
    status: str | None = None,
) -> dict[str, Any]:
    with _metadata_lock(root):
        updated = _current_record_locked(root, str(record["id"]))
        if updated.get("status") in {"deleting", "deleted"}:
            raise ValueError(f"cannot finalize capture in {updated.get('status')} state: {updated['id']}")
        current_capture = capture_path(root, updated)
        updated["finished_at"] = _utc_now()
        updated["duration_ms"] = duration_ms
        updated["exit_code"] = exit_code
        updated["status"] = status or (
            "unknown" if exit_code is None else ("completed" if exit_code == 0 else "failed")
        )
        updated["owner"] = None
        try:
            capture_stat = current_capture.stat()
            updated["size_bytes"] = capture_stat.st_size
            updated["line_count"] = _count_lines(current_capture)
            updated["sha256"] = _sha256_file(current_capture)
        except OSError:
            updated["status"] = "missing"
        _validate_record(root, updated)
        _atomic_write(_record_path(root, str(updated["id"])), updated)
    return updated


def _validate_record(root: Path, value: dict[str, Any], *, source: Path | None = None) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise ValueError("record must be a JSON object with an id")
    record_id = _canonical_record_id(value["id"])
    if source is not None and source.name != f"{record_id}.json":
        raise ValueError(f"record filename does not match id {record_id}")
    raw_path = value.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("record path must be a non-empty string")
    relative = _relative_path(root, root / raw_path)
    if relative != raw_path:
        raise ValueError(f"record path is not canonical: {raw_path!r}")

    schema = value.get("schema_version")
    if type(schema) is not int or schema != SCHEMA_VERSION:
        raise ValueError(f"unsupported metadata schema version: {schema!r}")

    def require_string(name: str, *, allow_empty: bool = True) -> str:
        item = value.get(name)
        if not isinstance(item, str) or (not allow_empty and not item):
            raise ValueError(f"record {name} must be {'a non-empty' if not allow_empty else 'a'} string")
        return item

    def require_optional_int(name: str) -> None:
        item = value.get(name)
        if item is not None and (type(item) is not int or item < 0):
            raise ValueError(f"record {name} must be null or a non-negative integer")

    def require_time(name: str, *, optional: bool = False) -> None:
        item = value.get(name)
        if optional and item is None:
            return
        if not isinstance(item, str) or not item:
            raise ValueError(f"record {name} must be {'null or ' if optional else ''}an ISO timestamp")
        try:
            parsed = datetime.fromisoformat(item.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"record {name} is not an ISO timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError(f"record {name} must include a timezone")

    command = require_string("command")
    command_hash = require_string("command_sha256", allow_empty=False)
    if len(command_hash) != 64 or any(ch not in _HEX_64 for ch in command_hash):
        raise ValueError("record command_sha256 must be a lowercase SHA-256 digest")
    if command_hash != _sha256_bytes(command.encode("utf-8", errors="surrogateescape")):
        raise ValueError("record command_sha256 does not match command")
    for name in ("original_tool", "effective_tool", "route"):
        require_string(name)
    if value.get("source") not in _SOURCES:
        raise ValueError(f"record source is invalid: {value.get('source')!r}")
    if value.get("status") not in _STATUSES:
        raise ValueError(f"record status is invalid: {value.get('status')!r}")
    if value.get("started_at_source") not in _TIME_SOURCES:
        raise ValueError(f"record started_at_source is invalid: {value.get('started_at_source')!r}")
    require_time("started_at")
    for name in ("finished_at", "deleted_at", "delete_started_at"):
        require_time(name, optional=True)
    for name in ("duration_ms", "size_bytes", "line_count"):
        require_optional_int(name)
    exit_code = value.get("exit_code")
    if exit_code is not None and type(exit_code) is not int:
        raise ValueError("record exit_code must be null or an integer")
    digest = value.get("sha256")
    if digest is not None and (
        not isinstance(digest, str) or len(digest) != 64 or any(ch not in _HEX_64 for ch in digest)
    ):
        raise ValueError("record sha256 must be null or a lowercase SHA-256 digest")
    tags = value.get("tags")
    if not isinstance(tags, list) or any(not isinstance(tag, str) or not tag for tag in tags):
        raise ValueError("record tags must be a list of non-empty strings")
    renames = value.get("renames")
    if not isinstance(renames, list):
        raise ValueError("record renames must be a list")
    for rename in renames:
        if not isinstance(rename, dict):
            raise ValueError("record rename entries must be objects")
        for name in ("old_path", "new_path"):
            path_value = rename.get(name)
            if not isinstance(path_value, str) or _relative_path(root, root / path_value) != path_value:
                raise ValueError(f"record rename {name} is invalid")
        if not isinstance(rename.get("source"), str) or not rename["source"]:
            raise ValueError("record rename source must be a non-empty string")
        renamed_at = rename.get("renamed_at")
        if not isinstance(renamed_at, str):
            raise ValueError("record rename renamed_at must be an ISO timestamp")
        try:
            renamed = datetime.fromisoformat(renamed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("record rename renamed_at is not an ISO timestamp") from exc
        if renamed.tzinfo is None:
            raise ValueError("record rename renamed_at must include a timezone")
    previous = value.get("delete_previous_status")
    if previous is not None and previous not in _STATUSES - {"deleted", "deleting"}:
        raise ValueError("record delete_previous_status is invalid")
    owner = value.get("owner")
    if owner is not None:
        if not isinstance(owner, dict) or type(owner.get("pid")) is not int or owner["pid"] <= 0:
            raise ValueError("record owner must contain a positive integer pid")
        if not isinstance(owner.get("host"), str) or not owner["host"]:
            raise ValueError("record owner must contain a non-empty host")


def _load_record(root: Path, path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError("record file is a symlink")
    with path.open("r", encoding="utf-8") as fh:
        value = json.load(fh)
    _validate_record(root, value, source=path)
    return value


def load_records(root: Path) -> tuple[list[dict[str, Any]], list[tuple[Path, str]]]:
    records: list[dict[str, Any]] = []
    errors: list[tuple[Path, str]] = []
    topology = _topology_errors(root)
    if topology:
        return records, topology
    directory = _records_dir(root)
    if not directory.exists():
        return records, errors
    for path in sorted(directory.glob("*.json")):
        try:
            records.append(_load_record(root, path))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append((path, str(exc)))
    return records, errors


def _record_capture(root: Path, record: dict[str, Any]) -> Path:
    return root / str(record.get("path", ""))


def _duplicate_active_paths(records: Sequence[dict[str, Any]]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for record in records:
        if record.get("status") == "deleted":
            continue
        path = str(record.get("path", ""))
        if path in seen:
            duplicates.add(path)
        seen.add(path)
    return duplicates


def sync_records(root: Path, *, repair_stale: bool = False) -> dict[str, int]:
    """Import unrecorded captures and optionally repair stale running records."""
    imported = relinked = repaired = recovered_deletes = 0
    topology = _topology_errors(root)
    if topology:
        path, detail = topology[0]
        raise ValueError(f"invalid metadata topology {path}: {detail}")
    if not _records_dir(root).is_dir() and not find_capture_files(root):
        return {"imported": 0, "relinked": 0, "repaired": 0, "recovered_deletes": 0}
    with _metadata_lock(root):
        records, errors = load_records(root)
        if errors:
            path, detail = errors[0]
            raise ValueError(f"cannot sync malformed metadata {path}: {detail}")
        duplicate_paths = _duplicate_active_paths(records)
        if duplicate_paths:
            raise ValueError(
                f"cannot sync duplicate active capture path: {min(duplicate_paths)}"
            )

        for record in records:
            if record.get("status") != "deleting":
                continue
            capture = _record_capture(root, record)
            if capture.is_file():
                previous = record.get("delete_previous_status")
                record["status"] = (
                    previous
                    if isinstance(previous, str) and previous not in {"deleted", "deleting"}
                    else "completed"
                )
                record["delete_started_at"] = None
                record["delete_previous_status"] = None
            else:
                record["status"] = "deleted"
                record["deleted_at"] = record.get("deleted_at") or _utc_now()
                record["owner"] = None
            _atomic_write(_record_path(root, str(record["id"])), record)
            recovered_deletes += 1

        by_path = {
            str(record.get("path", "")): record
            for record in records
            if record.get("status") != "deleted"
        }
        by_hash: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            digest = record.get("sha256")
            if digest and record.get("status") != "deleted":
                by_hash.setdefault(str(digest), []).append(record)
        for capture in find_capture_files(root):
            rel = _relative_path(root, capture)
            if rel in by_path:
                continue
            try:
                digest = _sha256_file(capture)
            except OSError:
                continue
            missing_matches = []
            for candidate in by_hash.get(digest, []):
                try:
                    old_capture = capture_path(root, candidate)
                except ValueError:
                    continue
                if not old_capture.is_file():
                    missing_matches.append(candidate)
            if len(missing_matches) == 1:
                existing = missing_matches[0]
                old = str(existing.get("path", ""))
                existing["path"] = rel
                existing.setdefault("renames", []).append(
                    {"old_path": old, "new_path": rel, "renamed_at": _utc_now(), "source": "sync"}
                )
                _atomic_write(_record_path(root, str(existing["id"])), existing)
                by_path[rel] = existing
                relinked += 1
                continue
            header = _capture_header(capture)
            if header is None:
                continue
            command, date_text = header
            started, time_source = _parse_legacy_date(date_text, capture)
            try:
                stat = capture.stat()
            except OSError:
                continue
            record_id = str(uuid.uuid4())
            tool = command.split(maxsplit=1)[0] if command else ""
            record = {
                "schema_version": SCHEMA_VERSION,
                "id": record_id,
                "path": rel,
                "command": command,
                "command_sha256": _sha256_bytes(command.encode("utf-8", errors="replace")),
                "original_tool": Path(tool).name,
                "effective_tool": Path(tool).name,
                "route": capture.parent.relative_to(root).as_posix() if capture.parent != root else "",
                "source": "imported",
                "status": "imported",
                "started_at": started,
                "started_at_source": time_source,
                "finished_at": None,
                "duration_ms": None,
                "exit_code": None,
                "size_bytes": stat.st_size,
                "line_count": _count_lines(capture),
                "sha256": digest,
                "tags": [],
                "renames": [],
                "deleted_at": None,
                "delete_started_at": None,
                "delete_previous_status": None,
                "owner": None,
            }
            _atomic_write(_record_path(root, record_id), record)
            by_path[rel] = record
            by_hash.setdefault(digest, []).append(record)
            records.append(record)
            imported += 1

        if repair_stale:
            for record in records:
                if record.get("status") != "running":
                    continue
                owner = record.get("owner") or {}
                if owner.get("host") != socket.gethostname():
                    continue
                pid = owner.get("pid")
                alive = False
                if isinstance(pid, int) and pid > 0:
                    try:
                        os.kill(pid, 0)
                        alive = True
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        alive = True
                if alive:
                    continue
                capture = _record_capture(root, record)
                record["status"] = "unknown" if record.get("source") == "grab" else "interrupted"
                record["finished_at"] = _utc_now()
                record["owner"] = None
                if capture.is_file():
                    stat = capture.stat()
                    record["size_bytes"] = stat.st_size
                    record["line_count"] = _count_lines(capture)
                    record["sha256"] = _sha256_file(capture)
                _atomic_write(_record_path(root, str(record["id"])), record)
                repaired += 1

    return {
        "imported": imported,
        "relinked": relinked,
        "repaired": repaired,
        "recovered_deletes": recovered_deletes,
    }


def resolve_record(root: Path, selector: str) -> dict[str, Any]:
    records, _ = load_records(root)
    matches = [record for record in records if str(record.get("id", "")).startswith(selector)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(f"capture id prefix is ambiguous: {selector}")

    candidate = Path(selector).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        rel = _relative_path(root, candidate)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    path_matches = [record for record in records if record.get("path") == rel]
    active_matches = [record for record in path_matches if record.get("status") != "deleted"]
    if len(active_matches) == 1:
        return active_matches[0]
    if len(active_matches) > 1:
        raise ValueError(f"capture path matches multiple active records: {selector}")
    if len(path_matches) == 1:
        return path_matches[0]
    raise ValueError(f"capture not found: {selector}")


def record_for_path(root: Path, capture: Path) -> dict[str, Any] | None:
    try:
        rel = _relative_path(root, capture)
    except ValueError:
        return None
    records, _ = load_records(root)
    matches = [record for record in records if record.get("path") == rel]
    return next((record for record in matches if record.get("status") != "deleted"), None) or (
        matches[0] if matches else None
    )


def retained_records(root: Path, *, include_deleted: bool = False) -> list[dict[str, Any]]:
    records, _ = load_records(root)
    if not include_deleted:
        records = [record for record in records if record.get("status") != "deleted"]
    records.sort(key=lambda record: str(record.get("started_at") or ""), reverse=True)
    return records


def capture_path(root: Path, record: dict[str, Any]) -> Path:
    path = _record_capture(root, record).resolve(strict=False)
    if not path.is_relative_to(root.resolve(strict=False)):
        raise ValueError(f"record path escapes active root: {record.get('path')}")
    return path


def rename_capture(root: Path, record: dict[str, Any], new_path: Path) -> dict[str, Any]:
    rel = _relative_path(root, new_path)
    with _metadata_lock(root):
        current = _current_record_locked(root, str(record["id"]))
        if current.get("status") in {"running", "deleting", "deleted"}:
            raise ValueError(f"cannot rename capture in {current.get('status')} state: {current['id']}")
        old_path = capture_path(root, current)
        moved = False
        try:
            os.replace(old_path, new_path)
            moved = True
            updated = dict(current)
            old_rel = str(updated.get("path", ""))
            updated["path"] = rel
            updated.setdefault("renames", []).append(
                {"old_path": old_rel, "new_path": rel, "renamed_at": _utc_now(), "source": "operator"}
            )
            _atomic_write(_record_path(root, str(updated["id"])), updated)
        except BaseException:
            if moved:
                try:
                    os.replace(new_path, old_path)
                except OSError:
                    # The original metadata still points at the old path. A
                    # later sync can recover the move if rollback also fails.
                    pass
            raise
    return updated


def delete_capture(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    with _metadata_lock(root):
        current = _current_record_locked(root, str(record["id"]))
        if current.get("status") == "running":
            raise ValueError(f"cannot delete running capture: {current.get('id')}")
        if current.get("status") == "deleted":
            raise ValueError(f"capture is already deleted: {current.get('id')}")
        if current.get("status") == "deleting":
            raise ValueError(f"capture deletion is already in progress: {current.get('id')}")
        path = capture_path(root, current)

        deleting = dict(current)
        deleting["delete_previous_status"] = str(current.get("status") or "completed")
        deleting["delete_started_at"] = _utc_now()
        deleting["status"] = "deleting"
        deleting["owner"] = None
        _atomic_write(_record_path(root, str(deleting["id"])), deleting)

        try:
            path.unlink(missing_ok=True)
        except OSError:
            try:
                _atomic_write(_record_path(root, str(current["id"])), dict(current))
            except (OSError, ValueError):
                pass
            raise

        updated = dict(deleting)
        updated["status"] = "deleted"
        updated["deleted_at"] = _utc_now()
        _atomic_write(_record_path(root, str(updated["id"])), updated)
    return updated


def tag_record(root: Path, record: dict[str, Any], tags: Sequence[str], *, remove: bool = False) -> dict[str, Any]:
    normalized = {tag.strip().lower() for tag in tags if tag.strip()}
    with _metadata_lock(root):
        updated = _current_record_locked(root, str(record["id"]))
        current_tags = {str(tag) for tag in updated.get("tags", [])}
        current_tags = current_tags - normalized if remove else current_tags | normalized
        updated["tags"] = sorted(current_tags)
        _validate_record(root, updated)
        _atomic_write(_record_path(root, str(updated["id"])), updated)
    return updated


def verify_record(root: Path, record: dict[str, Any]) -> tuple[bool, str]:
    if record.get("status") == "deleted":
        return False, "deleted"
    path = capture_path(root, record)
    if not path.is_file():
        return False, "missing"
    expected = record.get("sha256")
    if not expected:
        return False, "no recorded hash"
    actual = _sha256_file(path)
    return actual == expected, actual


def metadata_status(root: Path) -> dict[str, Any]:
    records, errors = load_records(root)
    counts: dict[str, int] = {}
    missing = stale = incomplete = 0
    for record in records:
        status = str(record.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
        try:
            path = capture_path(root, record)
        except ValueError:
            if status != "deleted":
                missing += 1
            continue
        if status != "deleted" and not path.is_file():
            missing += 1
        if status in {"completed", "failed", "unknown"} and (
            not record.get("finished_at")
            or record.get("size_bytes") is None
            or record.get("line_count") is None
            or not record.get("sha256")
        ):
            incomplete += 1
        if status == "running":
            owner = record.get("owner") or {}
            if owner.get("host") == socket.gethostname():
                pid = owner.get("pid")
                try:
                    if not isinstance(pid, int) or pid <= 0:
                        stale += 1
                    else:
                        os.kill(pid, 0)
                except ProcessLookupError:
                    stale += 1
                except PermissionError:
                    pass
    recorded_paths = {
        str(record.get("path", ""))
        for record in records
        if record.get("status") != "deleted"
    }
    orphaned = sum(1 for path in find_capture_files(root) if _relative_path(root, path) not in recorded_paths)
    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "records": len(records),
        "status_counts": counts,
        "missing": missing,
        "stale_running": stale,
        "incomplete_records": incomplete,
        "duplicate_active_paths": len(_duplicate_active_paths(records)),
        "pending_deletes": counts.get("deleting", 0),
        "orphaned_captures": orphaned,
        "malformed_records": len(errors),
    }


def assert_safe_output_path(root: Path, output: Path) -> Path:
    if output.is_symlink():
        raise ValueError(f"output path is a symlink: {output}")
    resolved_root = root.resolve(strict=False)
    resolved = output.resolve(strict=False)
    metadata_root = (resolved_root / ".nocap").resolve(strict=False)
    if resolved == metadata_root or resolved.is_relative_to(metadata_root):
        raise ValueError(f"output path is inside NOCAP metadata: {output}")
    records, errors = load_records(root)
    if errors:
        path, detail = errors[0]
        raise ValueError(f"cannot validate output with malformed metadata {path}: {detail}")
    for record in records:
        if record.get("status") != "deleted" and capture_path(root, record) == resolved:
            raise ValueError(f"output path is a retained capture: {output}")
    if resolved.is_file() and is_capture_file(resolved):
        raise ValueError(f"output path is a NOCAP capture: {output}")
    return resolved


def export_records(root: Path, output: Path | None = None) -> int:
    records, errors = load_records(root)
    if errors:
        path, detail = errors[0]
        raise ValueError(f"cannot export malformed metadata {path}: {detail}")
    lines = "".join(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n" for record in records)
    if output is None:
        print(lines, end="")
        return len(records)
    output = assert_safe_output_path(root, output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        output,
        os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(lines)
    return len(records)


def prune_tombstones(root: Path, *, apply: bool = False) -> list[Path]:
    records, errors = load_records(root)
    if errors:
        path, detail = errors[0]
        raise ValueError(f"cannot prune with malformed metadata {path}: {detail}")
    paths = [_record_path(root, str(record["id"])) for record in records if record.get("status") == "deleted"]
    if not apply:
        return paths
    pruned: list[Path] = []
    with _metadata_lock(root):
        for path in paths:
            try:
                current = _load_record(root, path)
            except FileNotFoundError:
                continue
            if current.get("status") != "deleted":
                continue
            path.unlink()
            pruned.append(path)
    return pruned
