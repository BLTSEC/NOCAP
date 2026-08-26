# NOCAP

<p align="center">
  <img src="assets/nocap.jpg" alt="NOCAP banner" width="100%">
</p>

<p align="center">
  <a href="https://github.com/BLTSEC/NOCAP/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BLTSEC/NOCAP/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/BLTSEC/NOCAP/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/BLTSEC/NOCAP"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
</p>

<p align="center"><strong>PTY-backed command capture with deterministic names, target-aware routing, and local provenance.</strong></p>

<p align="center"><a href="https://bltsec.com/blog/nocap/">Workflow article</a> · <a href="https://youtu.be/tUDXFoZIkg4">Original 1.x demo</a></p>

## Install

NOCAP supports Linux and macOS and requires Python 3.11 or newer.

```bash
pipx install https://github.com/BLTSEC/NOCAP/archive/refs/tags/v2.0.0.zip
cap --version                            # nocap 2.0.0
```

From a clone, run `pipx install .`. A pinned installation stays on its selected
tag when `cap update` runs. Move releases explicitly:

```bash
pipx install --force https://github.com/BLTSEC/NOCAP/archive/refs/tags/vX.Y.Z.zip
```

## Start in 60 seconds

With no target configured, NOCAP uses the current directory:

```bash
mkdir -p ~/engagements/acme
cd ~/engagements/acme

cap -a nmap -sCV 10.10.10.5
cap ls
cap timeline
```

`-a` routes by the effective tool:

```text
~/engagements/acme/
├── recon/nmap_sCV.txt
└── .nocap/records/<uuid>.json
```

The `.txt` file contains a short command/date header followed by the PTY stream.
The JSON record tracks identity, timing, status, route, hash, tags, renames, and
deletion state.

## Daily workflow

```bash
# Capture
cap -a nmap -sCV "$TARGET"
cap -a -n after-creds nxc smb dc -u user -p pass --shares
cap -s notes printf '%s\n' 'manual checkpoint'
cap -D -a sudo -n nmap -Pn dc01       # print the destination only
cap -- ls -la                          # capture a command named "ls"
# Find and inspect
cap last
cap ls
cap browse                             # fzf preview and selection
cap browse --print                     # selected absolute path
cap search --kind ports
cap inspect --verify
# Curate and export
cap tag add foothold
cap rename initial-enum
cap timeline --format md
cap review --last 10 -o review.md
# Remove
cap rm                                 # immediately remove the last capture
cap rm --pick                          # multi-select, then confirm
```

Review packets are local Markdown files. The default includes 10 captures and
limits each rendered excerpt to 200 lines or 32 KiB. Inspect it before sharing.

## How it works

| Concern | Behavior |
|---|---|
| Capture | Mirrors the live PTY to a `.txt` file created with mode `0600`. |
| Naming | Unwraps launchers such as `sudo`, `env`, `proxychains`, shell `-c`, `uv run`, and Python modules; collisions get numeric suffixes. |
| Routing | `-a` routes by effective tool. Target precedence is environment `TACMUX_TARGET`, tmux `TACMUX_TARGET`, legacy `LOADOUT_TARGET`, `TARGET`, legacy `op_*`, then the current directory. |
| Safety | Explicit workspaces and targets must exist and remain inside the workspace. Invalid targets never fall back to the current directory. |
| Metadata | Stores one private JSON record per capture under `.nocap/records`; there is no database or daemon. |
| Integrity | Records SHA-256 and file size. Verify with `cap inspect --verify` or `cap meta verify`. |
| Deletion | Removes the raw file and retains a tombstone, hidden unless `--include-deleted` is used. |

Use `cap meta status`, `sync`, `verify`, `export`, and `prune` to maintain the
record set. Back up captures and `.nocap` together. The
[metadata lifecycle guide](docs/METADATA.md) covers recovery and retention.

## Command map

| Area | Commands |
|---|---|
| Capture | `cap [options] <command>`, `grab` |
| Find | `last`, `ls`, `browse`, `search`, `summary` |
| View | `cat`, `render`, `open`, `tail`; `--compact` is explicitly lossy |
| Manage | `inspect`, `tag`, `rename`, `rm` |
| History | `timeline`, `review` |
| Health | `status`, `meta status|sync|verify|export|prune` |
| Integrations | `logs`, `update` |

Capture selectors accept an ID prefix or a path below the active target. Where
a selector is optional, omitting it uses the newest retained capture in that
target. Run `cap --help` or `cap <command> --help` for flags.

## Configuration

Configuration loads from the user file and then the active workspace file:

```text
$XDG_CONFIG_HOME/nocap/config.toml
<workspace>/.nocap/config.toml
```

```toml
[capture]
auto_route = true
bell = false
```

`NOCAP_WORKSPACE`, `NOCAP_AUTO`, and `NOCAP_BELL` override the workspace,
automatic routing, and bell settings. See
[`docs/config.example.toml`](docs/config.example.toml) for routes, aliases, and
bounded list, search, and review limits.

## Integrations

| Tool | Role |
|---|---|
| [TACMUX](https://github.com/BLTSEC/TACMUX) | Supplies target context and continuous pane logs. `cap logs` opens its browser. |
| `fzf` | Enables `browse`, `rm --pick`, and `review --pick`. |

<details>
<summary>Upgrading from NOCAP 1.x</summary>

Use Python 3.11 or newer, then run `cap meta sync` once in each existing target.
Back up raw captures and `.nocap` together. Prefer `TACMUX_TARGET`;
`LOADOUT_TARGET` remains a compatibility input. Explicit targets now fail
closed, and `cap ls` lists instead of opening `fzf`; use `cap browse` to select.
</details>

<details>
<summary>Development</summary>

```bash
python3.11 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

</details>

## License

[MIT](LICENSE)
