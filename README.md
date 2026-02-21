# NOCAP

<p align="center">
  <img src="assets/nocap.jpg" alt="nocap" width="600">
</p>

> **N**o-overhead **C**apture. **A**utomatic **P**ath routing.
> *Capture tool output. No cap.*

NOCAP is a zero-dependency command capture wrapper built for security operators.
Drop it in front of any tool and it handles the rest: smart file naming, engagement
directory routing, collision avoidance, live TTY output, bell notifications, and
interactive capture browsing. No more `| tee recon/nmap-sCV.txt` one-liners.

```bash
# $TARGET set or pentest_* tmux session active → routes to /workspace/<target>/
cap nmap -sCV 10.10.10.5
# → /workspace/10.10.10.5/nmap_sCV.txt

# No engagement context → writes to current directory
cap nmap -sCV 10.10.10.5
# → ./nmap_sCV.txt
```

---

## Install

```bash
pipx install git+https://github.com/BLTSEC/NOCAP.git
```

Or directly from source:

```bash
git clone https://github.com/BLTSEC/nocap
pipx install ./nocap
```

---

## Usage

```
cap [options] [subdir] <command> [args...]
cap last
cap ls [subdir]
```

### Options

| Flag | Description |
|---|---|
| `-n`, `--note <label>` | Append a custom label to the output filename |
| `-s`, `--subdir <name>` | Write to a custom subdir (created if needed) |
| `-a`, `--auto` | Auto-route to subdir based on tool name (opt-in) |
| `-D`, `--dry-run` | Show where output would go without running |

### Subcommands

| Command | Description |
|---|---|
| `cap last` | Print the path of the last captured file |
| `cap ls [subdir]` | Browse captures interactively (fzf) or list them |

---

## Examples

```bash
# Basic capture — output goes to cwd by default
cap nmap -sCV 10.10.10.5

# Explicit subdir
cap recon gobuster dir -u http://10.10.10.5 -w /wordlist.txt
cap loot hashcat -m 1000 hashes.txt /wordlist.txt

# Custom subdir (created automatically if it doesn't exist)
cap -s pivoting ping -c 4 192.168.1.1
cap -s ad-enum bloodhound-python -u user -p pass -d corp.local

# Add a note to distinguish runs with the same flags
cap -n after-creds nmap -sCV 10.10.10.5
cap -n authenticated feroxbuster -u http://10.10.10.5 -x php,html

# Auto-routing: infers subdir from the tool name
cap --auto nmap -sCV 10.10.10.5       # → recon/nmap_sCV.txt
cap --auto hashcat -m 1000 h.txt wl   # → loot/hashcat_m_1000.txt

# Preview routing without running
cap -D feroxbuster -u http://10.10.10.5

# Reference the last captured file
cap last
cat $(cap last)
cp $(cap last) ~/report/
grep -i password $(cap last)

# Browse captures
cap ls             # all captures for current target
cap ls recon       # scoped to recon/
```

---

## Smart Routing

NOCAP resolves your engagement directory automatically — no configuration needed.

| Priority | Condition | Output location |
|---|---|---|
| 1 | `$TARGET` env var is set | `/workspace/$TARGET/<subdir>/` |
| 2 | Active tmux session named `pentest_*` | `/workspace/<target>/<subdir>/` |
| 3 | Fallback | `./<subdir>/` (current directory) |

Set `TARGET` manually for non-tmux workflows:

```bash
export TARGET=10.10.10.5
cap nmap -sCV 10.10.10.5
# → /workspace/10.10.10.5/nmap_sCV.txt
```

---

## Auto-Subdir Routing

With `--auto` / `-a`, NOCAP infers the engagement subdir from the tool name.
Default behavior (without the flag) writes to cwd — no routing is applied.

```bash
cap --auto nmap -sCV 10.10.10.5
# → /workspace/10.10.10.5/recon/nmap_sCV.txt

cap --auto hashcat -m 1000 hashes.txt /wl.txt
# → /workspace/10.10.10.5/loot/hashcat_m_1000.txt
```

An explicit subdir always takes precedence over `--auto`:

```bash
cap -a notes nmap -sCV 10.10.10.5
# → /workspace/10.10.10.5/notes/nmap_sCV.txt
```

**Tool→subdir map:**

| Subdir | Tools |
|---|---|
| `recon` | nmap, rustscan, masscan, gobuster, feroxbuster, ffuf, wfuzz, whatweb, nikto, enum4linux, ldapsearch, dnsx, subfinder, amass, kerbrute, netexec, crackmapexec, smbclient, rpcclient, snmpwalk, showmount, wpscan, sqlmap, dirsearch, onesixtyone, dnsrecon |
| `loot` | hashcat, john, hydra, medusa |
| `exploitation` | msfconsole, msfvenom |

---

## `cap last`

Prints the path of the most recently captured file. Compose naturally with other tools:

```bash
cat $(cap last)
grep -i password $(cap last)
cp $(cap last) ~/report/evidence.txt
```

---

## `cap ls`

Lists all captures for the current engagement. Uses **fzf** with file preview if
available (falls back to a plain listing if not). Preview uses **bat** for syntax
highlighting when installed, otherwise **cat**.

```bash
cap ls             # all files under current engagement dir, newest first
cap ls recon       # scoped to recon/ subdir
```

---

## Auto-Named Output

NOCAP derives a clean filename from your command. IPs (v4 and v6), URLs, absolute
paths, wordlists, hostnames, and numeric values are stripped automatically.
Meaningful flags and subcommands become the filename.

| Command | Output file |
|---|---|
| `cap nmap -sCV 10.10.10.5` | `nmap_sCV.txt` |
| `cap nmap -p- --min-rate 5000 10.10.10.5` | `nmap_p-_min-rate.txt` |
| `cap gobuster dir -u http://10.10.10.5 -w /wl.txt` | `gobuster_dir.txt` |
| `cap netexec smb 10.10.10.5 -u admin -p pass` | `netexec_smb.txt` |
| `cap feroxbuster -u http://10.10.10.5 -x php,html` | `feroxbuster_x_phphtml.txt` |
| `cap loot hashcat -m 1000 hashes.txt /wl.txt` | `loot/hashcat_m_1000.txt` |
| `cap -n after-creds nmap -sCV 10.10.10.5` | `nmap_sCV_after-creds.txt` |

Collisions are resolved automatically:

```
nmap_sCV.txt → nmap_sCV_2.txt → nmap_sCV_3.txt
```

IPv6 addresses are stripped just like IPv4:

```bash
cap nmap -sCV dead:beef::1
# → nmap_sCV.txt
```

---

## File Header

Every output file starts with a structured header:

```
Command: nmap -sCV 10.10.10.5
Date:    Fri Feb 20 14:30:52 EST 2026
---
Starting Nmap 7.94 ...
```

---

## TTY Preserved

NOCAP runs commands under a PTY so tools behave exactly as they would in a
normal terminal — colours, progress bars, and interactive prompts all work.

---

## Bell Notification

NOCAP fires a bell (`\a`) when a command completes, so you can task-switch freely
in tmux and get notified when a long scan finishes.

---

## Zero Dependencies

Standard library only. Python 3.9+. No third-party packages required.
(`cap ls` optionally uses **fzf** and **bat** if they are on your PATH.)

---

## Engagement Directory Structure

NOCAP integrates with the standard engagement layout:

```
/workspace/<target>/
├── recon/           ← nmap, gobuster, feroxbuster output
├── exploitation/    ← payloads, custom scripts
├── loot/            ← hashes, creds, exfiltrated files
├── screenshots/     ← evidence
└── notes/           ← operator notes
```

---

*Built for operators who move fast and document everything.*
