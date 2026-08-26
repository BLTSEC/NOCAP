# NOCAP

<p align="center">
  <img src="assets/nocap.jpg" alt="NOCAP banner" width="100%">
</p>

Capture a command once. Keep the raw output, its provenance, and the order in
which it ran.

```bash
cap -a nmap -sCV 10.10.10.5
# /workspace/acme/targets/10.10.10.5/recon/nmap_sCV.txt
```

NOCAP mirrors the command through a PTY and writes the same byte stream to a
private `.txt` file. The capture path uses only Python's standard library.
`fzf`, TACMUX, and a pager or editor are optional integrations. NOCAP has no
model or provider integration.

[Read the NOCAP workflow article](https://bltsec.com/blog/nocap/) ·
[Watch the original NOCAP 1.x demo](https://youtu.be/tUDXFoZIkg4)

## Install

NOCAP requires Python 3.11 or newer.

```bash
pipx install git+https://github.com/BLTSEC/NOCAP.git
```

From a clone:

```bash
pipx install .
```

## Daily use

```bash
cap -a nmap -sCV 10.10.10.5       # route by the effective tool
cap -n after-creds nxc smb dc -u user -p pass --shares
cap -s notes printf '%s\n' 'manual checkpoint'
cap -D -a sudo -n nmap -Pn dc01    # print the destination only
cap -- ls -la                       # capture a command named like a subcommand
```

Naming is deterministic. NOCAP unwraps common launchers such as `sudo`, `env`,
`timeout`, `proxychains`, `faketime`, shell `-c`, `uv run`, and Python modules.
High-frequency tools such as NXC, `rpcclient`, and `dig` get action-oriented
names. Fix an edge case directly with `cap rename`.

## Find, review, and remove

```bash
cap ls
cap browse                         # fzf preview, then page the selection
cap browse --print                 # select and print an absolute path
cap search --kind ports
cap inspect --verify
cap timeline
cap timeline --format md
cap review --last 10 -o review.md
cap rename initial-enum
cap rm                         # remove the last raw capture
cap rm --pick                  # fzf multi-select, then exact confirmation
```

`cap review` creates a local Markdown packet and never transmits it. It includes at most 10 captures
by default and bounds each rendered capture to 200 lines or 32 KiB. Use
`--metadata-only`, `--since 2h`, `--tag`, `--pick`, or explicit limits to narrow
it.

The packet can contain credentials, targets, and findings. Sanitize it with a
tool such as DECON before it crosses an approved processing boundary.

## Evidence model

Raw `.txt` files are authoritative. NOCAP does **not** use a database. Each
capture has a private JSON record at:

```text
<target>/.nocap/records/<uuid>.json
```

The record stores the shell-rendered executed argv, timestamps, exit status, duration,
SHA-256, tags, rename history, route, and deletion state.

```bash
cap meta status
cap meta sync                   # import existing header-valid captures
cap meta verify                 # compare retained files with recorded hashes
cap meta export metadata.jsonl
cap meta prune                  # preview tombstone records
cap meta prune --yes            # remove tombstone records
```

`cap rm` deletes the raw file and keeps its record as a tombstone. Timelines
hide tombstones by default; `cap timeline --include-deleted` shows them.
Interrupted delete metadata and failed rename rollbacks can be reconciled with
`cap meta sync`; deleted raw output cannot be restored. See
[Metadata lifecycle](docs/METADATA.md) for recovery and backup details.
Running captures cannot be renamed or deleted. Review and metadata exports also
refuse to overwrite capture files or anything below `.nocap`.

## Routing

The active target is selected in this order:

1. `TACMUX_TARGET` in the process environment
2. `TACMUX_TARGET` stored in the current tmux session
3. `LOADOUT_TARGET` for NOCAP 1.x compatibility
4. `TARGET`
5. the target encoded by a legacy `op_*` tmux session
6. current directory when no target is set

An explicit workspace or target fails closed if it is missing or escapes the
workspace. Create the target first; operator-loadout and Exegol's `set_target`
helpers do this automatically. NOCAP never silently redirects an explicitly
targeted capture to the current directory.

Configuration loads from the user, then the workspace:

```text
$XDG_CONFIG_HOME/nocap/config.toml
<workspace>/.nocap/config.toml
```

Environment variables override both files. Start with
[`docs/config.example.toml`](docs/config.example.toml).

## Commands

| Command | Purpose |
|---|---|
| `last` | Print the newest retained capture in the current target |
| `cat`, `render` | Render ANSI and cursor updates; `--compact` is explicitly lossy |
| `open`, `tail` | Page/edit or follow a capture; editing raw evidence breaks verification |
| `ls` | Print a deterministic, bounded capture table |
| `browse` | Select with `fzf`; page it or return its absolute path |
| `search` | Bounded literal, regex, or named-pattern search |
| `timeline` | Show retained execution order as a table, Markdown, or JSON |
| `inspect`, `tag`, `rename` | Manage one capture's metadata and path |
| `rm` | Delete raw evidence and leave a tombstone |
| `review` | Export a bounded Markdown review packet |
| `meta` | Sync, verify, export, inspect, or prune metadata |
| `grab` | Recover tmux scrollback; the original exit status is recorded as unknown |
| `logs` | Open TACMUX's session-log browser |
| `update` | Upgrade the pipx installation |

Run `cap --help` or `cap <command> --help` for flags.

## TACMUX and SITREP

TACMUX owns continuous pane `.log` files. NOCAP owns discrete command `.txt`
captures. `cap logs` delegates to TACMUX so the formats do not compete.

SITREP's SQLite file is its working snippet index; it is unrelated to NOCAP
metadata. Source-backed snippets are rebuildable, but pins, manual/imported
snippets, accepted curation, usage history, and deletion exclusions are DB-only
state worth backing up. SITREP can execute a selected snippet through `cap -a`,
after which the capture appears in the same target timeline.

## Migrating from 1.x

- Use Python 3.11 or newer.
- The completion bell is off by default. Set `bell = true` under `[capture]` if
  you want it back.
- Explicit workspaces and targets now fail closed instead of falling back to
  the current directory.
- Run `cap meta sync` once per existing target to create records for older
  header-valid captures. Back up `.nocap` with the raw capture directories.
- Prefer `TACMUX_TARGET`. `LOADOUT_TARGET` is read only for legacy compatibility.
- `cap ls` always lists. Use `cap browse` for `fzf` and `cap browse --print` when
  another shell command needs the selected path. Bounded results say when
  `--all` is required.

## Development

```bash
python3.11 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

The test suite covers PTY behavior, deterministic naming, routing containment,
stream rendering, metadata integrity, tombstones, migration, and review bounds.

## License

[MIT](LICENSE)
