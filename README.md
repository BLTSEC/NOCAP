# NOCAP

<p align="center">
  <img src="assets/nocap.jpg" alt="nocap" width="600">
</p>

> **N**o-overhead **C**apture. **A**utomatic **P**ath routing.
> *Capture tool output. No cap.*

NOCAP is a zero-dependency command capture wrapper built for security operators.
Drop it in front of any tool and it handles the rest: smart file naming, engagement
directory routing, auto subdir routing, collision avoidance, live TTY output,
completion status with elapsed time, and interactive capture browsing.
No more `| tee recon/nmap-sCV.txt` one-liners.

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
cap last | cat | tail | open | rm | summary
cap ls [subdir]
cap update
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
| `cap cat` | Dump last capture to stdout (`bat` or `cat`) |
| `cap tail` | Follow last capture from the start — useful while a scan runs in another pane |
| `cap open` | Open last capture in `$EDITOR`, then `bat`, `less -R`, or `cat` |
| `cap rm` | Delete the last captured file |
| `cap summary` | Compact table of all captures: timestamp, line count, size, path |
| `cap ls [subdir]` | Browse captures interactively (fzf) or list them |
| `cap update` | Update nocap to the latest version via pipx |

### Environment

| Variable | Description |
|---|---|
| `NOCAP_AUTO=1` | Enable `--auto` subdir routing by default without the flag |

---

## Examples

```bash
# Basic capture — output goes to cwd by default
cap nmap -sCV 10.10.10.5

# Explicit subdir
cap recon gobuster dir -u http://10.10.10.5 -w /wordlist.txt
cap loot hashcat -m 1000 hashes.txt /wordlist.txt

# Custom subdir (created automatically if it doesn't exist)
cap -s pivoting chisel client 10.10.14.5:8080 R:socks
cap -s ad-enum bloodhound-python -u user -p pass -d corp.local

# Add a note to distinguish runs with the same flags
cap -n after-creds nmap -sCV 10.10.10.5
cap -n authenticated feroxbuster -u http://10.10.10.5 -x php,html

# Auto-routing: infers subdir from the tool name
cap --auto nmap -sCV 10.10.10.5       # → recon/nmap_sCV.txt
cap --auto hashcat -m 1000 h.txt wl   # → loot/hashcat_m_1000.txt
cap --auto msfconsole                 # → exploitation/msfconsole.txt

# NOCAP_AUTO=1: make auto-routing the default, no flag needed
export NOCAP_AUTO=1
cap nmap -sCV 10.10.10.5             # → recon/ automatically

# Preview routing without running
cap -D feroxbuster -u http://10.10.10.5

# Work with the last captured file
cap last                             # print the path
cap cat                              # dump to stdout
cap tail                             # follow live — watch a scan from another pane
cap open                             # open in $EDITOR / bat / less
cap rm                               # delete it
grep -i password $(cap last)
cp $(cap last) ~/report/evidence.txt

# Engagement overview
cap summary                          # timestamp, lines, size, path for all captures
cap ls                               # interactive fzf browser
cap ls recon                         # scoped to recon/

# Update to latest
cap update
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

Set `NOCAP_AUTO=1` to make auto-routing the default for every capture without
typing the flag:

```bash
export NOCAP_AUTO=1
cap nmap -sCV 10.10.10.5       # → recon/ automatically
cap hashcat -m 1000 h.txt wl   # → loot/ automatically
```

Add it to your shell profile (`.zshrc`, `.bashrc`) or Exegol's shell init to
make it permanent.

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
| `recon` | **Network:** nmap, rustscan, masscan, autorecon, naabu, udpx, netdiscover, fping |
| | **Web fuzzing:** gobuster, feroxbuster, ffuf, wfuzz, dirsearch, dirb, arjun, kr |
| | **Web scanning:** whatweb, nikto, nuclei, httpx, httprobe, hakrawler, katana, gau, bbot, uncover, patator, ssh-audit |
| | **CMS:** wpscan, wpprobe, joomscan, droopescan, drupwn, cmsmap, moodlescan |
| | **SSL/TLS:** testssl, sslscan, wafw00f, cors_scan |
| | **DNS/Subdomain:** dnsx, amass, subfinder, sublist3r, findomain, assetfinder, massdns, shuffledns, fierce, dnsenum, dnsrecon, dnschef, waybackurls |
| | **SMB/LDAP/AD:** enum4linux, enum4linux-ng, ldapsearch, smbclient, smbmap, smbclientng, rpcclient, windapsearch, ldeep, pywerview, godap, manspider, msprobe, adidnsdump, daclsearch, nbtscan, smtp-user-enum, pysnaffler |
| | **SNMP/NFS:** snmpwalk, onesixtyone, showmount |
| | **Kerberos/AD collection:** kerbrute, netexec, crackmapexec, sprayhound, smartbrute, ldapdomaindump, bloodhound-python, rusthound, rusthound-ce |
| | **OSINT:** theHarvester, recon-ng, spiderfoot, sherlock, maigret, holehe, ghunt, phoneinfoga, censys, GitFive, photon, finalrecon, maltego |
| | **Cloud:** scout, cloudsplaining, prowler, cloudmapper.py |
| | **WiFi:** bettercap, hcxdumptool |
| `screenshots` | eyewitness, EyeWitness, gowitness |
| `loot` | **Cracking:** hashcat, john, hydra, medusa, legba, fcrackzip, pdfcrack, nth, haiti, pkcrack |
| | **Dumping:** pypykatz, lsassy, donpapi, gosecretsdump, dploot, masky, crackhound, keytabextract, PCredz, firefox_decrypt |
| `exploitation` | **C2/Frameworks:** msfconsole, msfvenom, msfdb, sliver-server, sliver-client, ps-empire, havoc, Villain.py, pwncat-vl, routersploit |
| | **Web:** sqlmap, weevely, xsstrike, nosqlmap, gopherus, ssrfmap, ysoserial, phpggc, XXEinjector, php_filter_chain_generator, jdwp-shellifier, byp4xx, h2csmuggler, smuggler, tomcatWarDeployer, clusterd, token-exploiter |
| | **AD/Windows:** evil-winrm, evil-winrm-py, mitm6, ntlmrelayx.py, krbrelayx.py, aclpwn, coercer, petitpotam.py, dfscoerce.py, shadowcoerce.py, pywhisker, targetedKerberoast.py, bloodyAD, autobloody, gpoddity, goexec, certipy, noPac.py, pre2k, passthecert.py, sccmhunter.py, pxethief, remotemonologue.py |

---

## `cap last` / `cat` / `tail` / `open` / `rm`

All last-file subcommands operate on the most recently captured file.

```bash
cap last                    # print the path
cap cat                     # dump to stdout (bat or cat)
cap tail                    # follow from the start — watch a running scan
cap open                    # open in $EDITOR / bat / less -R / cat
cap rm                      # delete the capture

# Compose last with other tools
grep -i password $(cap last)
cp $(cap last) ~/report/evidence.txt
```

`cap open` picks the best available viewer in order: `$EDITOR` → `bat` → `less -R` → `cat`.

---

## `cap summary`

Prints a compact table of all captures for the current engagement — timestamp, line count, size, and relative path:

```
2026-02-23 14:32  1234 lines   45.2K  recon/nmap_sCV.txt
2026-02-23 14:28   892 lines   28.1K  recon/gobuster_dir.txt
2026-02-23 13:55   310 lines    9.8K  loot/hashcat_m_1000.txt
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

## Updating

```bash
cap update
```

Re-installs nocap from the latest commit on GitHub using `pipx install --force`.
Requires pipx (the same tool used to install nocap).

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

## Completion Status

When a command finishes, NOCAP prints a one-line summary with exit status and elapsed time:

```
[✓] nmap_sCV.txt  (12.3s)
[✗ 1] feroxbuster_x_php.txt  (0.4s)
```

A bell (`\a`) also fires on completion so you can task-switch in tmux and get
notified when a long scan finishes.

---

## Zero Dependencies

Standard library only. Python 3.9+. No third-party packages required.
Optional enhancements if present on your PATH:

| Tool | Used by |
|---|---|
| **fzf** | `cap ls` — interactive file browser with preview |
| **bat** | `cap cat`, `cap open`, `cap ls` preview — syntax-aware output |
| **less** | `cap open` — fallback pager if bat is not installed |

---

## Engagement Directory Structure

NOCAP integrates with the standard engagement layout:

```
/workspace/<target>/
├── recon/           ← scanning, enumeration, OSINT output
├── exploitation/    ← C2 sessions, payloads, AD attacks
├── loot/            ← cracked hashes, dumped credentials
├── screenshots/     ← eyewitness, gowitness output
└── notes/           ← operator notes
```

---

*Built for operators who move fast and document everything.*
