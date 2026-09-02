# Changelog

## Unreleased

## 2.3.0 — 2026-09-02

### Added

- `NOCAP_ROUTE_PREFIX` places automatically routed captures below one validated,
  relative prefix while retaining a single metadata root. TACMUX uses it to
  group files by target without fragmenting the engagement timeline.
- Capture metadata records the complete prefixed route for live and `grab`
  captures.

## 2.2.0 — 2026-09-01

Removes obsolete TACMUX v1 compatibility and makes the current evidence
boundary explicit.

### Removed

- `cap logs`. Use `cap browse` for selected NOCAP captures and TACMUX
  **Documents** for continuous pane logs and routed evidence.
- The legacy `LOADOUT_TARGET` routing input. Export `TACMUX_TARGET` instead.
- Target recovery from legacy `op_*` tmux session names. Set explicit
  TACMUX/NOCAP context, or use `TARGET` for standalone routing.

### Unchanged

- Capture files and `.nocap` metadata remain ordinary local files.
- Explicit workspaces still fail closed.
- `cap meta sync` remains the supported reconciliation step after copying
  older captures.

## 2.1.0 — 2026-08-27

Aligns automatic routing with the phase of work.

### Changed

- Routes NetExec, Certipy, and Kerbrute by action instead of tool name alone.
- Sends credential attacks to `exploitation` and credential acquisition or
  dumps to `loot`.
- Applies launcher normalization and configured route overrides before
  built-in action routing.
- Explicit `-s` routes still take precedence. TACMUX continues to own
  continuous `logs`.

### Added

- `reports` as a positional phase directory; `notes` remains available.
- Route coverage for wrapped commands and common AD workflows.

## 2.0.0 — 2026-08-26

Turns captured terminal output into a small local evidence history.

### Added

- Capture tracking with stable IDs, hashes, tags, rename/delete history, and
  lifecycle commands.
- `cap timeline`, bounded Markdown review packets, and JSON/Markdown metadata
  exports.
- Privacy-safe filenames, target-aware routing, and configurable tool aliases
  and routes.

### Changed

- `cap ls` is the bounded non-interactive list and `cap browse` the fzf picker.
- Default rendering stays non-lossy; `--compact` enables intentional
  ANSI/backspace cleanup.
- Intelligence stays local: no AI provider, model, upload path, or inference
  dependency.
