"""Tests for _build_filename — pure logic, no subprocess or filesystem needed."""

import pytest

from nocap.filename import _build_filename, _effective_tool

# ---------------------------------------------------------------------------
# Basic tool name extraction
# ---------------------------------------------------------------------------

def test_tool_only():
    assert _build_filename(["nmap"]) == "nmap"


def test_tool_with_flag():
    assert _build_filename(["nmap", "-sCV"]) == "nmap_sCV"


def test_tool_with_subcommand():
    assert _build_filename(["gobuster", "dir"]) == "gobuster_dir"


def test_tool_name_sanitised():
    assert _build_filename(["/tmp/my tool.py"]) == "mytool"


def test_tool_name_with_no_safe_characters_uses_fallback():
    assert _build_filename(["🔥"]) == "command"


# ---------------------------------------------------------------------------
# IP / URL / path stripping
# ---------------------------------------------------------------------------

def test_ipv4_stripped():
    assert _build_filename(["nmap", "-sCV", "10.10.10.5"]) == "nmap_sCV"


def test_ipv4_cidr_stripped():
    assert _build_filename(["nmap", "-sP", "10.10.10.0/24"]) == "nmap_sP"


def test_ipv6_stripped():
    assert _build_filename(["nmap", "-sCV", "dead:beef::1"]) == "nmap_sCV"


def test_url_stripped():
    result = _build_filename(["gobuster", "dir", "-u", "http://10.10.10.5", "-w", "/wl.txt"])
    assert result == "gobuster_dir"


def test_url_hostname_added_as_context():
    result = _build_filename(["gobuster", "dir", "-u", "https://portal.example.local/login", "-w", "/wl.txt"])
    assert result == "gobuster_dir_portal"


def test_malformed_ipv6_url_does_not_crash():
    assert _build_filename(["curl", "http://["]) == "curl"


def test_absolute_path_stripped():
    result = _build_filename(["hashcat", "-m", "1000", "/path/to/hashes.txt"])
    assert "/path" not in result
    assert "hashes" not in result


def test_hostname_label_added():
    # Dotted hostnames become concise target labels
    result = _build_filename(["nmap", "-sCV", "target.htb"])
    assert result == "nmap_sCV_target"


def test_multiple_hostnames_kept_concisely():
    result = _build_filename([
        "nmap", "-Pn", "-sT", "-sV",
        "castelblack.north.sevenkingdoms.local",
        "winterfell.north.sevenkingdoms.local",
    ])
    assert result == "nmap_Pn_sT_sV_castelblack_winterfell"


def test_many_hostnames_collapsed():
    result = _build_filename([
        "nmap",
        "castelblack.north.sevenkingdoms.local",
        "winterfell.north.sevenkingdoms.local",
        "kingslanding.crownlands.sevenkingdoms.local",
    ])
    assert result == "nmap_castelblack_plus2"


def test_relative_filename_not_treated_as_target():
    result = _build_filename(["hashcat", "-m", "1000", "hashes.txt", "/wl.txt"])
    assert "hashes" not in result
    assert result == "hashcat_m"


# ---------------------------------------------------------------------------
# Numeric stripping
# ---------------------------------------------------------------------------

def test_number_stripped():
    # Pure numeric args stripped
    result = _build_filename(["nmap", "--min-rate", "5000"])
    assert "5000" not in result
    assert result == "nmap_min-rate"


def test_port_list_stripped():
    # Comma-separated port list stripped
    result = _build_filename(["nmap", "--open", "80,443,8080"])
    assert "80" not in result
    assert result == "nmap_open"


# ---------------------------------------------------------------------------
# SKIP_FLAGS: flags that consume the next token
# ---------------------------------------------------------------------------

def test_skip_flag_wordlist():
    result = _build_filename(["gobuster", "dir", "-w", "/path/to/wordlist.txt"])
    assert "wordlist" not in result
    assert result == "gobuster_dir"


def test_skip_flag_output():
    result = _build_filename(["nmap", "-sCV", "-oN", "out.txt", "10.10.10.5"])
    assert "out" not in result
    assert result == "nmap_sCV"


def test_skip_flag_port():
    # -p consumes next; 80 would also match _NUM_RE but should be gone either way
    result = _build_filename(["nmap", "-p", "80", "10.10.10.5"])
    assert "80" not in result


def test_skip_flag_threads():
    result = _build_filename(["ffuf", "-w", "/wl.txt", "-t", "50"])
    assert "50" not in result
    assert result == "ffuf"


# ---------------------------------------------------------------------------
# Note appending
# ---------------------------------------------------------------------------

def test_note_appended():
    result = _build_filename(["nmap", "-sCV"], note="after-creds")
    assert result == "nmap_sCV_after-creds"


def test_note_empty():
    result = _build_filename(["nmap", "-sCV"], note="")
    assert result == "nmap_sCV"


def test_note_sanitised():
    # Special chars stripped from note
    result = _build_filename(["nmap"], note="my note/here!")
    assert "/" not in result
    assert "!" not in result
    assert "mynotehere" in result


def test_note_preserved_with_context():
    result = _build_filename(
        ["nmap", "-Pn", "-sT", "-sV", "castelblack.north.sevenkingdoms.local"],
        note="after-creds",
    )
    assert result == "nmap_Pn_sT_sV_castelblack_after-creds"


# ---------------------------------------------------------------------------
# Length and deduplication
# ---------------------------------------------------------------------------

def test_flag_part_truncated():
    long_flag = "--" + "x" * 30
    result = _build_filename(["tool", long_flag])
    parts = result.split("_")
    # Each flag part capped at 15 chars
    assert all(len(p) <= 15 for p in parts[1:])


def test_total_stem_truncated():
    # Many flags → stem capped at 60 chars
    flags = [f"--flag{i}" for i in range(20)]
    result = _build_filename(["tool"] + flags)
    assert len(result) <= 60


def test_consecutive_underscores_collapsed():
    result = _build_filename(["tool", "-a", "10.10.10.5", "-b"])
    assert "__" not in result


# ---------------------------------------------------------------------------
# key=value assignments
# ---------------------------------------------------------------------------

def test_key_path_assignment_stripped():
    result = _build_filename(["msfconsole", "RHOSTS=192.168.1.1"])
    # value is an IP, so the whole arg is skipped
    assert "RHOSTS" not in result
    assert result == "msfconsole"


def test_key_value_non_path_kept():
    # key=value where value is not a path/IP — currently the whole arg is
    # kept if it doesn't match path heuristics
    result = _build_filename(["tool", "MODE=active"])
    # 'MODE=active' has '=' but value doesn't start with / or ./
    # so it falls through to normal processing; '=' is stripped by sanitize
    # The test just confirms it doesn't crash
    assert isinstance(result, str)
    assert len(result) > 0


def test_sudo_wrapper_uses_effective_tool():
    assert _build_filename(["sudo", "-n", "nmap", "-sCV", "10.10.10.5"]) == "nmap_sCV"


def test_env_wrapper_skips_assignments():
    assert _build_filename(["env", "DEBUG=1", "nmap", "-Pn", "target.htb"]) == "nmap_Pn_target"


def test_shell_wrapper_ignores_long_options_before_command_flag():
    assert _build_filename(["bash", "--norc", "-c", "nmap -sCV 10.10.10.5"]) == "nmap"


def test_python_module_uses_module_as_effective_tool():
    assert _build_filename(["python3", "-m", "http.server", "8000"]) == "httpserver"


def test_configured_alias_is_used_for_naming():
    assert _build_filename(["cme", "smb", "dc01.corp.local", "--shares"], aliases={"cme": "nxc"}) == "nxc_smb_shares"


def test_nxc_profile_drops_single_label_target_and_names_action():
    command = ["nxc", "smb", "TPM-DC", "-u", "guest", "-p", "", "--pass-pol"]
    assert _build_filename(command) == "nxc_smb_passpol"


def test_rpcclient_profile_keeps_action_not_credentials_or_target():
    command = ["rpcclient", "-U", "", "-N", "TPM-DC", "-c", "enumdomusers"]
    assert _build_filename(command) == "rpcclient_enumdomusers"


def test_dig_profile_keeps_record_type_not_server_or_target():
    command = ["dig", "SRV", "_ldap._tcp.example.com", "@TPM-DC"]
    assert _build_filename(command) == "dig_srv"


@pytest.mark.parametrize("value", [".", "..", "..."])
def test_dot_only_arguments_never_crash_filename_generation(value):
    assert _build_filename(["printf", value]).startswith("printf")


def test_python_interpreter_flags_are_unwrapped():
    assert _build_filename(["python3", "-u", "scanner.py", "--shares"]) == "scanner_shares"
    assert _effective_tool(["python3", "-I", "-m", "http.server", "8000"]) == "http.server"


def test_common_script_suffix_is_not_part_of_filename():
    assert _build_filename(["secretsdump.py", "CORP/admin@dc01"]) == "secretsdump"


def test_sudo_long_chdir_is_unwrapped():
    assert _effective_tool(["sudo", "--chdir", "/tmp", "nmap", "-Pn", "target.htb"]) == "nmap"


@pytest.mark.parametrize(
    "credential_args",
    [
        ["--username", "administrator"],
        ["--password", "SuperSecret123!"],
        ["--hash", "aad3b435b51404eeaad3b435b51404ee:deadbeef"],
        ["--password=SuperSecret123!"],
        ["--hash=deadbeef"],
    ],
)
def test_long_credentials_never_enter_filenames(credential_args):
    result = _build_filename(["nxc", "smb", "dc01.corp.local", *credential_args, "--shares"])
    lowered = result.lower()
    assert "administrator" not in lowered
    assert "supersecret" not in lowered
    assert "deadbeef" not in lowered
    assert "password" not in lowered
    assert "hash" not in lowered


@pytest.mark.parametrize(
    "command",
    [
        ["ssh", "user:SuperSecret@dc01"],
        ["secretsdump.py", "CORP/admin:SuperSecret@dc01"],
        ["mysql", "-uadmin", "-pSuperSecret", "dc01"],
        ["curl", "--authorization=BearerSuperSecret", "https://portal.example.local"],
        ["secretsdump.py", "-hashes", "aad3b435:SuperSecret", "CORP/admin@dc01"],
        ["tool", "-U", "SuperSecret", "dc01"],
        ["tool", "TOKEN=SuperSecret"],
        ["python3", "-c", 'print("SuperSecret")'],
    ],
)
def test_positional_attached_and_code_credentials_never_enter_filenames(command):
    assert "supersecret" not in _build_filename(command).lower()


@pytest.mark.parametrize(
    "command",
    [
        ["sudo", "PASSWORD=SuperSecret123", "nmap", "-sCV", "10.10.10.5"],
        ["sudo", "-E", "API_TOKEN=abcDEF987", "nmap", "-sCV", "10.10.10.5"],
        ["bash", "-c", "PASSWORD=SuperSecret123 nmap -sCV 10.10.10.5"],
        ["bash", "-lc", "API_TOKEN=abcDEF987 exec nmap -sCV 10.10.10.5"],
        ["curl", "--oauth2-bearer", "SuperSecret123", "https://portal.example.local"],
        ["aws", "sts", "get-caller-identity", "--session-token", "SuperSecret123"],
        ["kerbrute", "passwordspray", "corp.local", "users.txt", "SuperSecret123!"],
    ],
)
def test_wrapper_flag_and_positional_credentials_never_enter_filenames(command):
    lowered = _build_filename(command).lower()
    assert "supersecret" not in lowered
    assert "abcdef987" not in lowered


def test_password_spray_profile_keeps_only_the_action():
    command = ["kerbrute", "passwordspray", "corp.local", "users.txt", "SuperSecret123!"]
    assert _build_filename(command) == "kerbrute_passwordspray"


def test_nmap_pn_is_not_treated_as_an_attached_password():
    assert _build_filename(["nmap", "-Pn", "target.htb"]) == "nmap_Pn_target"


def test_malformed_rpcclient_action_never_breaks_naming():
    assert _build_filename(["rpcclient", "-c", "'", "dc01"]) == "rpcclient"


def test_faketime_file_mode_keeps_the_effective_tool():
    assert _build_filename(["faketime", "-f", "stamp.txt", "nmap", "-Pn", "target.htb"]) == "nmap_Pn_target"


@pytest.mark.parametrize("service", ["smb", "https-post-form"])
def test_hydra_profile_keeps_only_service(service):
    result = _build_filename(
        ["hydra", "-L", "resources/users.txt", "-P", "resources/passwords.txt", "dc01", service]
    )
    assert result == f"hydra_{service}"
