# NOCAP

<p align="center">
  <img src="assets/nocap.jpg" alt="nocap" width="600">
</p>

> **N**o-overhead **C**apture. **A**utomatic **P**ath routing.
> *Capture tool output. No cap.*

NOCAP is a zero-dependency command capture wrapper built for security operators.
Drop it in front of any tool — NOCAP handles smart file naming, engagement directory
routing, collision avoidance, and live output. You stay focused on the objective.

```
cap nmap -sCV 10.10.10.5
# → /workspace/10.10.10.5/recon/nmap_sCV.txt
```

---

## Install

```bash
pipx install nocap
```

Or with pip:

```bash
pip install nocap
```

Or directly from source:

```bash
git clone https://github.com/BLTSEC/nocap
pipx install ./nocap
```

---

## Usage

```
cap [recon|loot|exploitation|screenshots] <command> [args...]
```

The subdir argument is optional. Without it, output goes to the engagement root
(or current directory if no engagement context is detected).

### Examples

```bash
cap nmap -sCV 10.10.10.5
cap nmap -p- --min-rate 5000 10.10.10.5

cap recon gobuster dir -u http://10.10.10.5 -w /wordlist.txt
cap recon feroxbuster -u http://10.10.10.5 -x php,html

cap netexec smb 10.10.10.5 -u admin -p password
cap netexec smb 10.10.10.5 --shares

cap loot hashcat -m 1000 hashes.txt /wordlist.txt
cap loot john --wordlist=/wordlist.txt hashes.txt
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

## Auto-Named Output

NOCAP derives a clean filename from your command. IPs, URLs, absolute paths,
wordlists, hostnames, and numeric values are stripped automatically. Meaningful
flags and subcommands become the filename.

| Command | Output file |
|---|---|
| `cap nmap -sCV 10.10.10.5` | `nmap_sCV.txt` |
| `cap nmap -p- --min-rate 5000 10.10.10.5` | `nmap_p-_min-rate.txt` |
| `cap gobuster dir -u http://10.10.10.5 -w /wl.txt` | `gobuster_dir.txt` |
| `cap netexec smb 10.10.10.5 -u admin -p pass` | `netexec_smb.txt` |
| `cap feroxbuster -u http://10.10.10.5 -x php,html` | `feroxbuster_x_phphtml.txt` |
| `cap loot hashcat -m 1000 hashes.txt /wl.txt` | `loot/hashcat_m_1000.txt` |

Collisions are resolved automatically:

```
nmap_sCV.txt → nmap_sCV_2.txt → nmap_sCV_3.txt
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

## Zero Dependencies

Standard library only. Python 3.9+. No third-party packages required.

---

## Engagement Directory Structure

NOCAP integrates with the standard engagement layout:

```
/workspace/<target>/
├── recon/           ← nmap, gobuster, feroxbuster output
├── exploitation/    ← payloads, custom scripts
├── loot/            ← hashes, creds, exfiltrated files
└── screenshots/     ← evidence
```

---

*Built for operators who move fast and document everything.*
