# Metadata lifecycle

NOCAP keeps one JSON record per capture. There is no service to run, database to
vacuum, or migration command required for normal use.

## Layout

```text
target/
├── recon/nmap_sCV.txt
└── .nocap/
    ├── lock
    └── records/<uuid>.json
```

Raw captures are the source of truth. Records are written atomically with mode
`0600`; `.nocap` directories use mode `0700`. The lock serializes concurrent
capture and lifecycle updates. NOCAP refuses symlinked metadata directories,
lock files, malformed UUIDs, mismatched record filenames, and paths that escape
the active target.

## States

| State | Meaning |
|---|---|
| `running` | A live capture or in-progress scrollback grab owns the record |
| `completed` | The command exited zero |
| `failed` | The command exited nonzero |
| `unknown` | Scrollback was captured after execution, so its exit code is unavailable |
| `interrupted` | Capture ended without a normal exit |
| `imported` | `meta sync` discovered an older header-valid capture |
| `missing` | Finalization or status checks could not find the raw file |
| `deleting` | Raw deletion started but its tombstone is not final yet |
| `deleted` | Raw output was removed; the record is a tombstone |

## Routine commands

```bash
cap meta status
cap meta verify
cap meta export /protected/backup/metadata.jsonl
```

Back up raw capture directories and their `.nocap` directory together. JSONL
export is useful for inspection, but it is not a replacement for the individual
records because record IDs and tombstones form the active timeline.

## Import and recovery

`cap meta sync` scans only `.txt` files with NOCAP's `Command:`, `Date:`, and
`---` header. It does not rewrite them. A matching SHA-256 is treated as a move
only when exactly one record has that hash and its recorded path is missing. If
the old path still exists, the new file is a copy and receives a new identity.
Ambiguous hash matches are also imported as new records.

Rename writes are rolled back if their metadata update fails. If both the
metadata update and raw-file rollback fail, `cap meta sync` can relink the lone
moved file without changing its capture ID.

After a hard crash, inspect first:

```bash
cap meta status
cap meta sync --repair-stale
cap meta verify
```

`--repair-stale` changes a local `running` record to `interrupted` only when its
recorded process is no longer alive. It is explicit so a remote or long-running
capture is not guessed dead.

Lifecycle commands reload the current record while holding the metadata lock.
They refuse to rename or delete `running` and `deleting` captures, preventing a
second pane from unlinking or moving evidence while it is still being written.

`cap rm` is two-phase. It first records `deleting`, removes the raw file, and
then records `deleted`. Sync finalizes the tombstone when the raw file is gone,
or restores the previous state when an interrupted deletion left the raw file
in place. Its JSON result reports recovered work in `recovered_deletes`.

Malformed records are counted by `cap meta status`. Sync, verify, export, and
prune fail visibly instead of guessing around them; repair or quarantine the
named JSON file before retrying. `cap grab` creates its record before writing
output and finishes in `unknown` because the original exit code is unavailable.
If finalization is interrupted, `cap meta sync --repair-stale` hashes the raw
capture and restores that state. Review and metadata exports refuse capture
paths, header-valid orphan captures, and paths below `.nocap`.

## Delete and prune

```bash
cap rm <id-or-path>
cap timeline --include-deleted
cap meta prune          # preview record files
cap meta prune --yes    # delete tombstone records
```

Pruning removes history, not raw data: a tombstone's raw file is already gone.
Do not prune until retention and reporting requirements allow the deletion
history to disappear.

Back up raw captures and `.nocap` together before lifecycle maintenance. A
JSONL export is convenient for review, but the per-record files remain the
working metadata store and are required for continued updates.
