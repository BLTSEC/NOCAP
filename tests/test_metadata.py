"""Capture metadata and lifecycle integration tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import nocap.cli as cli
import nocap.metadata as metadata
import nocap.subcommands as subcommands
from nocap.metadata import (
    capture_path,
    create_record,
    delete_capture,
    export_records,
    load_records,
    metadata_status,
    prune_tombstones,
    rename_capture,
    retained_records,
    sync_records,
    tag_record,
    verify_record,
)


def _capture_once(tmp_path, monkeypatch, *, output: bytes = b"result\n"):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subcommands, "_LAST_FILE", tmp_path / "cache" / "last")

    def fake_run(command: list[str], outfile: Path) -> int:
        with outfile.open("ab") as fh:
            fh.write(output)
        return 0

    monkeypatch.setattr(cli, "_run_pty", fake_run)
    with pytest.raises(SystemExit, match="0"):
        cli._main(["-q", "-a", "sudo", "-n", "nmap", "-sCV", "10.10.10.5"])
    return retained_records(tmp_path)[0]


def test_live_capture_writes_exact_provenance_and_integrity(tmp_path, monkeypatch):
    record = _capture_once(tmp_path, monkeypatch)
    path = capture_path(tmp_path, record)

    assert path == tmp_path / "recon" / "nmap_sCV.txt"
    assert record["command"] == "sudo -n nmap -sCV 10.10.10.5"
    assert record["original_tool"] == "sudo"
    assert record["effective_tool"] == "nmap"
    assert record["route"] == "recon"
    assert record["source"] == "live"
    assert record["status"] == "completed"
    assert record["exit_code"] == 0
    assert record["sha256"]
    assert verify_record(tmp_path, record)[0] is True
    record_file = tmp_path / ".nocap" / "records" / f"{record['id']}.json"
    assert record_file.stat().st_mode & 0o777 == 0o600


def test_rename_delete_timeline_and_prune_lifecycle(tmp_path, monkeypatch, capsys):
    record = _capture_once(tmp_path, monkeypatch)

    subcommands._cmd_rename(["initial-enum", record["id"][:8]])
    renamed = retained_records(tmp_path)[0]
    assert renamed["path"] == "recon/initial-enum.txt"
    assert renamed["renames"][0]["old_path"] == "recon/nmap_sCV.txt"

    subcommands._cmd_rm([renamed["id"][:8]])
    assert retained_records(tmp_path) == []
    deleted = retained_records(tmp_path, include_deleted=True)[0]
    assert deleted["status"] == "deleted"
    assert deleted["deleted_at"]
    assert not capture_path(tmp_path, deleted).exists()

    capsys.readouterr()
    subcommands._cmd_timeline(["--format", "md"])
    assert "initial-enum" not in capsys.readouterr().out
    subcommands._cmd_timeline(["--include-deleted", "--format", "md"])
    assert "initial-enum.txt" in capsys.readouterr().out

    subcommands._cmd_meta(["prune"])
    assert len(load_records(tmp_path)[0]) == 1
    subcommands._cmd_meta(["prune", "--yes"])
    assert load_records(tmp_path)[0] == []


def test_sync_imports_legacy_capture_without_touching_raw_file(tmp_path):
    capture = tmp_path / "recon" / "legacy.txt"
    capture.parent.mkdir()
    capture.write_text(
        "Command: nmap -sCV 10.10.10.5\n"
        "Date:    Wed Jul 15 12:00:00 CDT 2026\n"
        "---\n"
        "22/tcp open ssh\n",
        encoding="utf-8",
    )
    before = capture.read_bytes()

    result = sync_records(tmp_path)
    records, errors = load_records(tmp_path)

    assert result == {"imported": 1, "relinked": 0, "repaired": 0, "recovered_deletes": 0}
    assert errors == []
    assert records[0]["source"] == "imported"
    assert records[0]["started_at_source"] == "header"
    assert records[0]["started_at"] == "2026-07-15T17:00:00Z"
    assert capture.read_bytes() == before


def test_review_packet_is_bounded_and_private(tmp_path, monkeypatch):
    _capture_once(tmp_path, monkeypatch, output=(b"line\n" * 40))
    output = tmp_path / "packet.md"

    subcommands._cmd_review(["--last", "1", "--max-lines", "8", "-o", str(output)])

    text = output.read_text(encoding="utf-8")
    assert "# NOCAP Review Packet" in text
    assert "Output truncated" in text
    assert text.count("Command: sudo -n nmap") == 0
    assert "line" in text
    assert "never calls" not in text
    assert output.stat().st_mode & 0o777 == 0o600


def test_review_has_no_unbounded_mode(capsys):
    with pytest.raises(SystemExit, match="2"):
        subcommands._cmd_review(["--full"])

    assert "unrecognized arguments: --full" in capsys.readouterr().err


def test_metadata_status_counts_orphans(tmp_path):
    capture = tmp_path / "capture.txt"
    capture.write_text(
        "Command: id\nDate:    Wed Jul 15 12:00:00 CDT 2026\n---\nuid=0(root)\n",
        encoding="utf-8",
    )

    status = metadata_status(tmp_path)
    assert status["records"] == 0
    assert status["orphaned_captures"] == 1


def test_running_capture_cannot_be_renamed_or_deleted(tmp_path):
    capture = tmp_path / "running.txt"
    capture.write_text("Command: sleep 10\nDate:    Wed Jul 15 12:00:00 CDT 2026\n---\n", encoding="utf-8")
    record = create_record(
        tmp_path,
        capture,
        command="sleep 10",
        original_tool="sleep",
        effective_tool="sleep",
        route="",
        source="live",
    )

    with pytest.raises(ValueError, match="running"):
        delete_capture(tmp_path, record)
    with pytest.raises(ValueError, match="running"):
        rename_capture(tmp_path, record, tmp_path / "renamed.txt")

    assert capture.is_file()


def test_lifecycle_mutations_reload_canonical_record(tmp_path, monkeypatch):
    stale = _capture_once(tmp_path, monkeypatch)
    tag_record(tmp_path, stale, ["keep"])

    renamed = rename_capture(tmp_path, stale, tmp_path / "recon" / "renamed.txt")

    assert renamed["tags"] == ["keep"]
    assert retained_records(tmp_path)[0]["tags"] == ["keep"]


def test_finalize_preserves_tags_added_to_running_record(tmp_path):
    capture = tmp_path / "running.txt"
    capture.write_text("Command: id\nDate:    Wed Jul 15 12:00:00 CDT 2026\n---\n", encoding="utf-8")
    stale = create_record(
        tmp_path,
        capture,
        command="id",
        original_tool="id",
        effective_tool="id",
        route="",
        source="live",
    )
    tag_record(tmp_path, stale, ["keep"])

    final = metadata.finalize_record(tmp_path, stale, capture, exit_code=0, duration_ms=1)

    assert final["tags"] == ["keep"]


def test_reused_filename_prefers_new_active_record(tmp_path, monkeypatch):
    first = _capture_once(tmp_path, monkeypatch)
    subcommands._cmd_rm([first["id"]])

    second = _capture_once(tmp_path, monkeypatch)
    records = retained_records(tmp_path, include_deleted=True)

    assert second["path"] == first["path"]
    assert len(records) == 2
    assert retained_records(tmp_path) == [second]


def test_last_pointer_is_scoped_to_current_target(tmp_path, monkeypatch, capsys):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    pointer = tmp_path / "cache" / "last"
    monkeypatch.setattr(subcommands, "_LAST_FILE", pointer)

    first_capture = first_root / "first.txt"
    second_capture = second_root / "second.txt"
    for root, capture, command in (
        (first_root, first_capture, "echo first"),
        (second_root, second_capture, "echo second"),
    ):
        capture.write_text(
            f"Command: {command}\nDate:    Wed Jul 15 12:00:00 CDT 2026\n---\n{command}\n",
            encoding="utf-8",
        )
        sync_records(root)

    subcommands._remember_last(first_capture)
    monkeypatch.chdir(second_root)
    subcommands._cmd_last([])

    assert capsys.readouterr().out.strip() == str(second_capture)
    assert Path(pointer.read_text(encoding="utf-8")) == second_capture


def test_rename_metadata_failure_rolls_raw_file_back(tmp_path, monkeypatch):
    record = _capture_once(tmp_path, monkeypatch)
    old_path = capture_path(tmp_path, record)
    before = old_path.read_bytes()
    target = old_path.with_name("renamed.txt")
    target.touch(mode=0o600)

    monkeypatch.setattr(metadata, "_atomic_write", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")))

    with pytest.raises(OSError, match="disk full"):
        rename_capture(tmp_path, record, target)

    assert old_path.read_bytes() == before
    assert not target.exists()
    assert retained_records(tmp_path)[0]["path"] == record["path"]


def test_sync_recovers_rename_when_rollback_also_fails(tmp_path, monkeypatch):
    record = _capture_once(tmp_path, monkeypatch)
    old_path = capture_path(tmp_path, record)
    target = old_path.with_name("moved.txt")
    target.touch(mode=0o600)
    real_replace = metadata.os.replace
    calls = 0

    def replace_then_fail_rollback(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("rollback failed")
        return real_replace(source, destination)

    real_write = metadata._atomic_write
    with monkeypatch.context() as scoped:
        scoped.setattr(metadata.os, "replace", replace_then_fail_rollback)
        scoped.setattr(metadata, "_atomic_write", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError, match="disk full"):
            rename_capture(tmp_path, record, target)

    assert target.is_file()
    assert not old_path.exists()
    assert metadata._atomic_write is real_write
    result = sync_records(tmp_path)
    recovered = retained_records(tmp_path)[0]
    assert result["relinked"] == 1
    assert recovered["id"] == record["id"]
    assert recovered["path"] == "recon/moved.txt"


def test_sync_finishes_delete_after_final_metadata_write_fails(tmp_path, monkeypatch):
    record = _capture_once(tmp_path, monkeypatch)
    raw = capture_path(tmp_path, record)
    real_write = metadata._atomic_write
    writes = 0

    def fail_final_write(path, value):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("disk full")
        return real_write(path, value)

    with monkeypatch.context() as scoped:
        scoped.setattr(metadata, "_atomic_write", fail_final_write)
        with pytest.raises(OSError, match="disk full"):
            delete_capture(tmp_path, record)

    assert not raw.exists()
    assert load_records(tmp_path)[0][0]["status"] == "deleting"
    result = sync_records(tmp_path)
    recovered = retained_records(tmp_path, include_deleted=True)[0]
    assert result["recovered_deletes"] == 1
    assert recovered["status"] == "deleted"
    assert recovered["deleted_at"]


def test_sync_cancels_interrupted_delete_when_raw_still_exists(tmp_path, monkeypatch):
    record = _capture_once(tmp_path, monkeypatch)
    record["delete_previous_status"] = record["status"]
    record["delete_started_at"] = "2026-08-26T00:00:00Z"
    record["status"] = "deleting"
    with metadata._metadata_lock(tmp_path):
        metadata._atomic_write(metadata._record_path(tmp_path, record["id"]), record)

    result = sync_records(tmp_path)
    recovered = retained_records(tmp_path)[0]

    assert result["recovered_deletes"] == 1
    assert recovered["status"] == "completed"
    assert recovered["delete_started_at"] is None


def test_copy_with_same_hash_gets_a_new_identity(tmp_path, monkeypatch):
    record = _capture_once(tmp_path, monkeypatch)
    original = capture_path(tmp_path, record)
    copied = original.with_name("copy.txt")
    shutil.copyfile(original, copied)

    result = sync_records(tmp_path)
    records = retained_records(tmp_path)

    assert result["imported"] == 1
    assert result["relinked"] == 0
    assert len(records) == 2
    assert len({item["id"] for item in records}) == 2


@pytest.mark.parametrize(
    ("filename", "record_id", "record_path"),
    [
        ("not-a-uuid.json", "not-a-uuid", "capture.txt"),
        ("00000000-0000-0000-0000-000000000001.json", "00000000-0000-0000-0000-000000000002", "capture.txt"),
        ("00000000-0000-0000-0000-000000000001.json", "00000000-0000-0000-0000-000000000001", "../escape.txt"),
    ],
)
def test_malformed_record_identity_and_paths_are_visible(tmp_path, filename, record_id, record_path):
    directory = tmp_path / ".nocap" / "records"
    directory.mkdir(parents=True)
    (directory / filename).write_text(json.dumps({"id": record_id, "path": record_path}), encoding="utf-8")

    records, errors = load_records(tmp_path)
    assert records == []
    assert len(errors) == 1
    assert metadata_status(tmp_path)["malformed_records"] == 1
    with pytest.raises(ValueError, match="malformed metadata"):
        export_records(tmp_path)
    with pytest.raises(ValueError, match="malformed metadata"):
        prune_tombstones(tmp_path)


def test_record_field_type_corruption_is_visible_without_command_crashes(tmp_path):
    record_id = "00000000-0000-0000-0000-000000000001"
    directory = tmp_path / ".nocap" / "records"
    directory.mkdir(parents=True)
    (directory / f"{record_id}.json").write_text(
        json.dumps({"schema_version": 1, "id": record_id, "path": "capture.txt", "size_bytes": "bad", "tags": None}),
        encoding="utf-8",
    )

    records, errors = load_records(tmp_path)
    assert records == []
    assert len(errors) == 1
    assert metadata_status(tmp_path)["malformed_records"] == 1


@pytest.mark.parametrize("kind", ["metadata-file", "records-file", "lock-directory"])
def test_invalid_metadata_topology_is_reported_before_empty_sync(tmp_path, kind):
    meta = tmp_path / ".nocap"
    if kind == "metadata-file":
        meta.write_text("bad", encoding="utf-8")
    else:
        meta.mkdir()
        path = meta / ("records" if kind == "records-file" else "lock")
        if kind == "records-file":
            path.write_text("bad", encoding="utf-8")
        else:
            path.mkdir()

    assert metadata_status(tmp_path)["malformed_records"] >= 1
    with pytest.raises(ValueError, match="metadata"):
        sync_records(tmp_path)


def test_meta_verify_export_and_prune_fail_on_malformed_records(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / ".nocap" / "records"
    directory.mkdir(parents=True)
    (directory / "broken.json").write_text("{", encoding="utf-8")

    for command in (["verify"], ["export"], ["prune"]):
        with pytest.raises(SystemExit, match="1"):
            subcommands._cmd_meta(command)

    output = capsys.readouterr()
    assert "malformed" in output.out
    assert "malformed metadata" in output.err


def test_sync_refuses_to_duplicate_capture_with_malformed_metadata(tmp_path):
    capture = tmp_path / "capture.txt"
    capture.write_text(
        "Command: id\nDate:    Wed Jul 15 12:00:00 CDT 2026\n---\nuid=0(root)\n",
        encoding="utf-8",
    )
    directory = tmp_path / ".nocap" / "records"
    directory.mkdir(parents=True)
    broken = directory / "broken.json"
    broken.write_text("{", encoding="utf-8")

    with pytest.raises(ValueError, match="cannot sync malformed metadata"):
        sync_records(tmp_path)

    assert list(directory.iterdir()) == [broken]


@pytest.mark.parametrize("symlink_name", ["records", "lock"])
def test_metadata_refuses_symlinked_internal_paths(tmp_path, symlink_name):
    meta = tmp_path / ".nocap"
    meta.mkdir()
    outside = tmp_path / "outside"
    if symlink_name == "records":
        outside.mkdir()
    else:
        outside.write_text("lock", encoding="utf-8")
    (meta / symlink_name).symlink_to(outside, target_is_directory=symlink_name == "records")
    capture = tmp_path / "capture.txt"
    capture.write_text("Command: id\nDate:    now\n---\nuid=0\n", encoding="utf-8")

    with pytest.raises((OSError, ValueError), match="symlink"):
        create_record(
            tmp_path,
            capture,
            command="id",
            original_tool="id",
            effective_tool="id",
            route="",
            source="grab",
        )


def test_metadata_refuses_symlinked_top_level_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".nocap").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        sync_records(tmp_path)


def test_private_exports_restrict_existing_file_permissions(tmp_path, monkeypatch):
    _capture_once(tmp_path, monkeypatch)
    metadata_export = tmp_path / "metadata.jsonl"
    review_export = tmp_path / "review.md"
    for path in (metadata_export, review_export):
        path.write_text("old", encoding="utf-8")
        path.chmod(0o644)

    export_records(tmp_path, metadata_export)
    subcommands._cmd_review(["--last", "1", "-o", str(review_export)])

    assert metadata_export.stat().st_mode & 0o777 == 0o600
    assert review_export.stat().st_mode & 0o777 == 0o600


def test_exports_never_overwrite_raw_or_orphaned_captures(tmp_path, monkeypatch):
    record = _capture_once(tmp_path, monkeypatch)
    capture = capture_path(tmp_path, record)
    before = capture.read_bytes()

    with pytest.raises(ValueError, match="capture"):
        export_records(tmp_path, capture)
    with pytest.raises(SystemExit, match="1"):
        subcommands._cmd_review(["-o", str(capture)])

    orphan = tmp_path / "orphan.txt"
    orphan.write_text("Command: id\nDate:    Wed Jul 15 12:00:00 CDT 2026\n---\n", encoding="utf-8")
    with pytest.raises(ValueError, match="capture"):
        export_records(tmp_path, orphan)
    assert capture.read_bytes() == before


def test_multiline_command_header_stays_detectable_and_metadata_keeps_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subcommands, "_LAST_FILE", tmp_path / "last")
    monkeypatch.setattr(cli, "_run_pty", lambda command, outfile: 0)
    command = ["bash", "-c", "printf one\nprintf two"]

    with pytest.raises(SystemExit, match="0"):
        cli._main(["-q", *command])

    record = retained_records(tmp_path)[0]
    path = capture_path(tmp_path, record)
    assert metadata.is_capture_file(path)
    assert "\n" in record["command"]
    assert r"\n" in path.read_text(encoding="utf-8").splitlines()[0]


def test_grab_removes_empty_claim_when_metadata_creation_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TMUX", "1")
    monkeypatch.setattr(subcommands, "_LAST_FILE", tmp_path / "cache" / "last")
    monkeypatch.setattr(subcommands, "_tmux_scrollback", lambda: "$ whoami\nroot\n$ cap grab\n")
    monkeypatch.setattr(subcommands, "create_record", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("readonly")))

    with pytest.raises(SystemExit, match="1"):
        subcommands._cmd_grab(["whoami"])

    assert list(tmp_path.glob("*.txt")) == []
    assert not (tmp_path / "cache" / "last").exists()
    assert "cannot create metadata record" in capsys.readouterr().err


def test_sync_and_live_start_share_one_record_for_same_path(tmp_path):
    capture = tmp_path / "capture.txt"
    capture.write_text(
        "Command: nmap -sCV 10.10.10.5\n"
        "Date:    Wed Jul 15 12:00:00 CDT 2026\n"
        "---\n",
        encoding="utf-8",
    )
    sync_records(tmp_path)
    imported = retained_records(tmp_path)[0]

    live = create_record(
        tmp_path,
        capture,
        command="nmap -sCV 10.10.10.5",
        original_tool="nmap",
        effective_tool="nmap",
        route="",
        source="live",
    )
    records = retained_records(tmp_path)

    assert len(records) == 1
    assert live["id"] == imported["id"]
    assert records[0]["source"] == "live"
    assert records[0]["status"] == "running"


def test_grab_finalizes_with_unknown_command_status(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TMUX", "1")
    monkeypatch.setattr(subcommands, "_LAST_FILE", tmp_path / "cache" / "last")
    monkeypatch.setattr(subcommands, "_tmux_scrollback", lambda: "$ whoami\nroot\n$ cap grab\n")

    subcommands._cmd_grab(["whoami"])

    record = retained_records(tmp_path)[0]
    assert record["status"] == "unknown"
    assert record["exit_code"] is None
    assert record["finished_at"]
    assert record["sha256"]
    assert verify_record(tmp_path, record)[0] is True
    assert metadata_status(tmp_path)["incomplete_records"] == 0


def test_failed_grab_finalization_is_detectable_and_repairable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TMUX", "1")
    monkeypatch.setattr(subcommands, "_LAST_FILE", tmp_path / "cache" / "last")
    monkeypatch.setattr(subcommands, "_tmux_scrollback", lambda: "$ whoami\nroot\n$ cap grab\n")
    monkeypatch.setattr(
        subcommands,
        "finalize_record",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    subcommands._cmd_grab(["whoami"])
    assert metadata_status(tmp_path)["status_counts"] == {"running": 1}

    monkeypatch.setattr(metadata.os, "kill", lambda *args: (_ for _ in ()).throw(ProcessLookupError))
    result = sync_records(tmp_path, repair_stale=True)
    record = retained_records(tmp_path)[0]

    assert result["repaired"] == 1
    assert record["status"] == "unknown"
    assert record["sha256"]


def test_completed_record_without_integrity_data_is_reported(tmp_path):
    capture = tmp_path / "capture.txt"
    capture.write_text("Command: id\nDate:    now\n---\n", encoding="utf-8")
    record = create_record(
        tmp_path,
        capture,
        command="id",
        original_tool="id",
        effective_tool="id",
        route="",
        source="grab",
    )
    record["status"] = "completed"
    record["owner"] = None
    with metadata._metadata_lock(tmp_path):
        metadata._atomic_write(metadata._record_path(tmp_path, record["id"]), record)

    assert metadata_status(tmp_path)["incomplete_records"] == 1


def test_duplicate_active_paths_are_reported_and_block_sync(tmp_path):
    capture = tmp_path / "capture.txt"
    capture.write_text("Command: id\nDate:    now\n---\n", encoding="utf-8")
    first = create_record(
        tmp_path,
        capture,
        command="id",
        original_tool="id",
        effective_tool="id",
        route="",
        source="live",
    )
    duplicate = dict(first)
    duplicate["id"] = "00000000-0000-0000-0000-000000000001"
    with metadata._metadata_lock(tmp_path):
        metadata._atomic_write(metadata._record_path(tmp_path, duplicate["id"]), duplicate)

    assert metadata_status(tmp_path)["duplicate_active_paths"] == 1
    with pytest.raises(ValueError, match="duplicate active capture path"):
        sync_records(tmp_path)
