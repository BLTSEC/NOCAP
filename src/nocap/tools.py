"""Tool→subdir routing table and related constants for NOCAP."""

from __future__ import annotations

from collections.abc import Sequence

SUBDIRS = frozenset(
    {"recon", "exploitation", "loot", "screenshots", "reports", "notes"}
)

# Flags whose *next* token is a value to be consumed (not added to filename)
SKIP_FLAGS = frozenset({
    "-w", "--wordlist",
    "-u", "--url",
    "-o", "--output",
    "-oN", "-oX", "-oA", "-oG", "-oS", "-oJ",
    "-T", "--timeout",
    "--threads", "-t",
    "--rate",
    "-H", "--header",
    "-d", "--domain",
    "-f", "--file", "--hash-file",
    "-mc", "-fc",
    "-p",
})

# Auto tool→subdir routing (opt-in via --auto / -a)
TOOL_SUBDIRS: dict[str, str] = {
    # ── recon: network scanning & port discovery ─────────────────────────────
    "nmap": "recon",
    "nmap-parse-output": "recon",
    "rustscan": "recon",
    "masscan": "recon",
    "autorecon": "recon",
    "udpx": "recon",
    "divideandscan": "recon",
    "naabu": "recon",
    "netdiscover": "recon",
    "fping": "recon",
    "arp-scan": "recon",
    "zmap": "recon",
    "unicornscan": "recon",
    # recon: web fuzzing & directory brute-force
    "gobuster": "recon",
    "feroxbuster": "recon",
    "ffuf": "recon",
    "wfuzz": "recon",
    "dirsearch": "recon",
    "dirb": "recon",
    "arjun": "recon",
    "kr": "recon",            # kiterunner
    "wuzz": "recon",
    # recon: web fingerprinting & active scanning
    "whatweb": "recon",
    "nikto": "recon",
    "nuclei": "recon",
    "httpx": "recon",
    "httprobe": "recon",
    "http": "recon",            # httpie
    "curl": "recon",
    "wget": "recon",
    "hakrawler": "recon",
    "katana": "recon",
    "gau": "recon",
    "bbot": "recon",
    "uncover": "recon",
    "chaos": "recon",
    "alterx": "recon",
    "hakrevdns": "recon",
    "jsluice": "recon",
    "linkfinder": "recon",
    "robotstester": "recon",
    "ssh-audit": "recon",
    "gospider": "recon",
    "cariddi": "recon",
    "searchsploit": "recon",
    "trufflehog": "recon",
    "gitleaks": "recon",
    "git-dumper": "recon",
    # recon: CMS scanners
    "wpscan": "recon",
    "wpprobe": "recon",
    "joomscan": "recon",
    "droopescan": "recon",
    "drupwn": "recon",
    "cmsmap": "recon",
    "moodlescan": "recon",
    # recon: SSL/TLS & web infra
    "testssl": "recon",
    "sslscan": "recon",
    "wafw00f": "recon",
    "cors_scan": "recon",
    # recon: DNS & subdomain enumeration
    "dnsx": "recon",
    "massdns": "recon",
    "shuffledns": "recon",
    "fierce": "recon",
    "amass": "recon",
    "subfinder": "recon",
    "sublist3r": "recon",
    "findomain": "recon",
    "assetfinder": "recon",
    "dnsenum": "recon",
    "dnsrecon": "recon",
    "dnschef": "recon",
    "waybackurls": "recon",
    "dig": "recon",
    "whois": "recon",
    # recon: SMB / RPC / LDAP enumeration
    "enum4linux": "recon",
    "enum4linux-ng": "recon",
    "ldapsearch": "recon",
    "smbclient": "recon",
    "smbmap": "recon",
    "smbclientng": "recon",
    "rpcclient": "recon",
    "windapsearch": "recon",
    "ldeep": "recon",
    "pywerview": "recon",
    "godap": "recon",
    "manspider": "recon",
    "msprobe": "recon",
    "adidnsdump": "recon",
    "daclsearch": "recon",
    "nbtscan": "recon",
    "smtp-user-enum": "recon",
    "scrtdnsdump": "recon",
    "pysnaffler": "recon",
    # recon: SNMP & NFS
    "snmpwalk": "recon",
    "snmpenum": "recon",
    "onesixtyone": "recon",
    "showmount": "recon",
    # recon: Kerberos, AD & BloodHound collection
    "kerbrute": "recon",
    "netexec": "recon",
    "nxc": "recon",
    "crackmapexec": "recon",
    "cme": "recon",
    "ldapdomaindump": "recon",
    "bloodhound-python": "recon",
    "rusthound": "recon",
    "rusthound-ce": "recon",
    # recon: OSINT
    "theHarvester": "recon",
    "recon-ng": "recon",
    "spiderfoot": "recon",
    "finalrecon": "recon",
    "maltego": "recon",
    "sherlock": "recon",
    "maigret": "recon",
    "holehe": "recon",
    "ghunt": "recon",
    "phoneinfoga": "recon",
    "censys": "recon",
    "GitFive": "recon",
    "photon": "recon",
    # recon: cloud
    "scout": "recon",          # ScoutSuite
    "cloudsplaining": "recon",
    "prowler": "recon",
    "cloudmapper.py": "recon",
    # recon: WiFi passive discovery
    "bettercap": "recon",
    "hcxdumptool": "recon",
    "airodump-ng": "recon",
    "kismet": "recon",
    # ── screenshots ───────────────────────────────────────────────────────────
    "eyewitness": "screenshots",
    "EyeWitness": "screenshots",
    "gowitness": "screenshots",
    "aquatone": "screenshots",
    "webscreenshot": "screenshots",
    # ── loot: password cracking ───────────────────────────────────────────────
    "hashcat": "loot",
    "john": "loot",
    "fcrackzip": "loot",
    "pdfcrack": "loot",
    "nth": "loot",             # name-that-hash
    "haiti": "loot",
    "pkcrack": "loot",
    "aircrack-ng": "loot",
    "hcxpcapngtool": "loot",
    # loot: forensics & steganography
    "volatility": "loot",
    "volatility3": "loot",
    "binwalk": "loot",
    "foremost": "loot",
    "steghide": "loot",
    "stegseek": "loot",
    "exiftool": "loot",
    "zsteg": "loot",
    # loot: credential dumping & extraction
    "pypykatz": "loot",
    "lsassy": "loot",
    "DonPAPI": "loot",
    "donpapi": "loot",
    "gosecretsdump": "loot",
    "dploot": "loot",
    "masky": "loot",
    "crackhound": "loot",
    "keytabextract": "loot",
    "PCredz": "loot",
    "firefox_decrypt": "loot",
    "secretsdump.py": "loot",
    "GetNPUsers.py": "loot",
    "GetUserSPNs.py": "loot",
    # ── exploitation: frameworks & C2 ────────────────────────────────────────
    "msfconsole": "exploitation",
    "msfvenom": "exploitation",
    "msfdb": "exploitation",
    "routersploit": "exploitation",
    "sliver-server": "exploitation",
    "sliver-client": "exploitation",
    "ps-empire": "exploitation",
    "havoc": "exploitation",
    "Villain.py": "exploitation",
    "pwncat-vl": "exploitation",
    "pwncat-cs": "exploitation",
    # exploitation: online credential attacks
    "hydra": "exploitation",
    "legba": "exploitation",
    "medusa": "exploitation",
    "ncrack": "exploitation",
    "patator": "exploitation",
    "smartbrute": "exploitation",
    "sprayhound": "exploitation",
    # exploitation: tunneling & pivoting
    "ligolo-ng": "exploitation",
    "chisel": "exploitation",
    "socat": "exploitation",
    # exploitation: web
    "sqlmap": "exploitation",
    "weevely": "exploitation",
    "xsstrike": "exploitation",
    "nosqlmap": "exploitation",
    "gopherus": "exploitation",
    "ssrfmap": "exploitation",
    "bolt": "exploitation",
    "kadimus": "exploitation",
    "fuxploider": "exploitation",
    "ysoserial": "exploitation",
    "phpggc": "exploitation",
    "jdwp-shellifier": "exploitation",
    "byp4xx": "exploitation",
    "h2csmuggler": "exploitation",
    "smuggler": "exploitation",
    "tomcatWarDeployer": "exploitation",
    "clusterd": "exploitation",
    "token-exploiter": "exploitation",
    "XXEinjector": "exploitation",
    "php_filter_chain_generator": "exploitation",
    "dalfox": "exploitation",
    "commix": "exploitation",
    "tplmap": "exploitation",
    "ghauri": "exploitation",
    "jwt_tool": "exploitation",
    "swaks": "exploitation",
    # exploitation: AD / Windows
    "evil-winrm": "exploitation",
    "evil-winrm-py": "exploitation",
    "mitm6": "exploitation",
    "ntlmrelayx.py": "exploitation",
    "krbrelayx.py": "exploitation",
    "aclpwn": "exploitation",
    "coercer": "exploitation",
    "petitpotam.py": "exploitation",
    "dfscoerce.py": "exploitation",
    "shadowcoerce.py": "exploitation",
    "pywhisker": "exploitation",
    "targetedKerberoast.py": "exploitation",
    "bloodyAD": "exploitation",
    "autobloody": "exploitation",
    "gpoddity": "exploitation",
    "goexec": "exploitation",
    "remotemonologue.py": "exploitation",
    "sccmhunter.py": "exploitation",
    "pxethief": "exploitation",
    "pre2k": "exploitation",
    "passthecert.py": "exploitation",
    "certipy": "exploitation",
    "certipy-ad": "exploitation",
    "noPac.py": "exploitation",
    "privexchange.py": "exploitation",
    "ms14-068.py": "exploitation",
    "zerologon-exploit": "exploitation",
    "abuseACL": "exploitation",
    "sccmsecrets.py": "exploitation",
    "pywsus.py": "exploitation",
    "pygpoabuse.py": "exploitation",
    # exploitation: impacket lateral movement
    "psexec.py": "exploitation",
    "wmiexec.py": "exploitation",
    "smbexec.py": "exploitation",
    "atexec.py": "exploitation",
    "dcomexec.py": "exploitation",
}


_NXC_TOOLS = frozenset({"cme", "crackmapexec", "netexec", "nxc"})
_NXC_LOOT_FLAGS = frozenset(
    {"--dpapi", "--get-file", "--lsa", "--ntds", "--sam"}
)
_NXC_EXEC_FLAGS = frozenset({"-x", "-X", "--exec-method", "--put-file"})
_NXC_LOOT_MODULES = frozenset(
    {
        "donpapi",
        "firefox",
        "handlekatz",
        "lsassy",
        "masky",
        "mobaxterm",
        "mremoteng",
        "nanodump",
        "procdump",
        "putty",
        "rdcman",
        "spider_plus",
        "teams_localdb",
        "veeam",
        "wifi",
        "winscp",
    }
)
_NXC_RECON_MODULES = frozenset(
    {
        "adcs",
        "daclread",
        "find-computer",
        "laps",
        "ldap-checker",
        "maq",
        "pso",
        "spooler",
        "subnets",
        "user-desc",
        "wcc",
        "webdav",
    }
)
_CERTIPY_RECON_ACTIONS = frozenset({"find", "parse"})
_CERTIPY_LOOT_ACTIONS = frozenset({"cert"})
_CERTIPY_EXPLOIT_ACTIONS = frozenset(
    {
        "account",
        "auth",
        "ca",
        "forge",
        "relay",
        "req",
        "shadow",
        "template",
    }
)
_KERBRUTE_RECON_ACTIONS = frozenset({"userenum"})
_KERBRUTE_EXPLOIT_ACTIONS = frozenset(
    {"bruteforce", "bruteuser", "passwordspray"}
)


def _nxc_modules(args: Sequence[str]) -> list[str]:
    modules: list[str] = []
    for index, value in enumerate(args):
        lowered = value.lower()
        if lowered.startswith("--module="):
            modules.append(value.partition("=")[2].lower())
        elif value == "-M" or lowered == "--module":
            if index + 1 < len(args):
                modules.append(args[index + 1].lower())
    return modules


def _nxc_route(args: Sequence[str]) -> str:
    """Route NetExec-family actions by the artifact an operator keeps."""
    lowered = {value.lower() for value in args}
    modules = _nxc_modules(args)

    if lowered & _NXC_LOOT_FLAGS or any(
        module in _NXC_LOOT_MODULES for module in modules
    ):
        return "loot"
    if any(value in _NXC_EXEC_FLAGS for value in args):
        return "exploitation"
    if modules:
        if all(
            module.startswith("enum_") or module in _NXC_RECON_MODULES
            for module in modules
        ):
            return "recon"
        return "exploitation"
    return "recon"


def _first_action(args: Sequence[str], actions: frozenset[str]) -> str:
    return next((value.lower() for value in args if value.lower() in actions), "")


def route_for_tool(tool: str, args: Sequence[str]) -> str:
    """Return the built-in route for a normalized tool invocation."""
    if tool in _NXC_TOOLS:
        return _nxc_route(args)

    if tool in {"certipy", "certipy-ad"}:
        action = _first_action(
            args,
            _CERTIPY_RECON_ACTIONS
            | _CERTIPY_LOOT_ACTIONS
            | _CERTIPY_EXPLOIT_ACTIONS,
        )
        if action in _CERTIPY_RECON_ACTIONS:
            return "recon"
        if action in _CERTIPY_LOOT_ACTIONS:
            return "loot"
        if action in _CERTIPY_EXPLOIT_ACTIONS:
            return "exploitation"

    if tool == "kerbrute":
        action = _first_action(
            args, _KERBRUTE_RECON_ACTIONS | _KERBRUTE_EXPLOIT_ACTIONS
        )
        if action in _KERBRUTE_RECON_ACTIONS:
            return "recon"
        if action in _KERBRUTE_EXPLOIT_ACTIONS:
            return "exploitation"

    return TOOL_SUBDIRS.get(tool, "")
