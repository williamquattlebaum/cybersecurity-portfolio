#!/usr/bin/env python3
"""
💀 CHAOS MODE — Controlled Attack Simulation
Runs randomized red team scenarios from Kali → Windows endpoint.
Generates real Wazuh + Suricata alerts. Keeps the lab alive.

Usage:
  python3 chaos.py            # one random scenario
  python3 chaos.py --all      # run all scenarios sequentially
  python3 chaos.py --schedule # run random scenario every 6h (daemon)
  python3 chaos.py --list     # list scenarios
"""

import subprocess
import random
import time
import argparse
import json
from datetime import datetime

KALI_HOST    = "192.168.x.x"
WIN_TARGET   = "192.168.x.x"
SSH_KEY      = "/root/.ssh/proxmox_key"
PROXMOX_HOST = "192.168.x.x"
LOG_FILE     = "/root/.openclaw/workspace/memory/chaos-log.json"

def kali(cmd, timeout=60):
    """Run a command on Kali via Proxmox SSH jump."""
    try:
        result = subprocess.run(
            ["ssh", "-i", SSH_KEY,
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=10",
             "-o", "ProxyJump=root@192.168.x.x",
             f"root@{KALI_HOST}", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), -1

def proxmox_ssh(cmd, timeout=15):
    try:
        result = subprocess.run(
            ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             f"root@{PROXMOX_HOST}", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except:
        return ""

def log_run(scenario_name, output, alerts_before, alerts_after):
    entry = {
        "ts": datetime.now().isoformat(),
        "scenario": scenario_name,
        "target": WIN_TARGET,
        "alerts_generated": alerts_after - alerts_before,
        "output_summary": output[:500]
    }
    try:
        try:
            with open(LOG_FILE) as f:
                log = json.load(f)
        except:
            log = []
        log.append(entry)
        with open(LOG_FILE, 'w') as f:
            json.dump(log[-100:], f, indent=2)  # keep last 100
    except:
        pass
    return entry

def get_alert_count():
    """Count current Wazuh alerts for today."""
    raw = subprocess.run(
        ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
         f"root@192.168.x.x",
         "wc -l /var/ossec/logs/alerts/2026/Mar/ossec-alerts-30.json 2>/dev/null || echo 0"],
        capture_output=True, text=True, timeout=10
    ).stdout.strip().split()[0]
    try:
        return int(raw)
    except:
        return 0

def check_kali_reachable():
    out = proxmox_ssh(f"nc -zv {KALI_HOST} 22 2>&1 | head -1")
    return "succeeded" in out.lower() or "open" in out.lower()

# ─── Scenarios ────────────────────────────────────────────────────────────────

SCENARIOS = {}

def scenario(name, mitre, desc):
    def decorator(fn):
        SCENARIOS[name] = {"fn": fn, "mitre": mitre, "desc": desc}
        return fn
    return decorator


@scenario("port_scan_stealth", "T1046", "Stealth SYN scan — enumerate open ports on Windows target")
def port_scan_stealth():
    print(f"  [*] Running stealth port scan against {WIN_TARGET}...")
    out, rc = kali(f"nmap -sS -T2 -p 22,80,135,139,443,445,3389,5985,8080 {WIN_TARGET} 2>/dev/null", timeout=90)
    open_ports = [l for l in out.split('\n') if 'open' in l]
    return f"Found {len(open_ports)} open ports: {', '.join(open_ports[:5])}"


@scenario("port_scan_aggressive", "T1046", "Aggressive full port scan with service/version detection")
def port_scan_aggressive():
    print(f"  [*] Running aggressive scan against {WIN_TARGET}...")
    out, rc = kali(f"nmap -sV -T4 -p 135,139,445,3389,5985 {WIN_TARGET} 2>/dev/null", timeout=120)
    lines = [l for l in out.split('\n') if 'open' in l or 'filtered' in l]
    return f"Services detected: {len(lines)} | {' | '.join(lines[:3])}"


@scenario("smb_enum", "T1135", "SMB share enumeration via smbclient")
def smb_enum():
    print(f"  [*] Enumerating SMB shares on {WIN_TARGET}...")
    out, rc = kali(f"smbclient -L //{WIN_TARGET} -N 2>/dev/null | head -20", timeout=30)
    return f"SMB output: {out[:200]}"


@scenario("winrm_brute", "T1021.006", "WinRM brute force with common password list")
def winrm_brute():
    print(f"  [*] WinRM brute force against {WIN_TARGET}...")
    passwords = "Admin123!\\nPassword1\\nWelcome1\\nAdmin2023\\nP@ssw0rd\\nWazuhLab2025!"
    out, rc = kali(
        f"echo -e '{passwords}' > /tmp/pass.txt && "
        f"hydra -l Administrator -P /tmp/pass.txt {WIN_TARGET} winrm -t 3 -W 2 2>/dev/null | tail -5",
        timeout=60
    )
    return f"Brute result: {out[:200]}"


@scenario("rdp_brute", "T1021.001", "RDP brute force attempt")
def rdp_brute():
    print(f"  [*] RDP brute force against {WIN_TARGET}:3389...")
    out, rc = kali(
        f"hydra -l Administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt "
        f"-t 4 -W 3 rdp://{WIN_TARGET} 2>/dev/null | tail -5",
        timeout=90
    )
    return f"RDP brute: {out[:200]}"


@scenario("os_fingerprint", "T1082", "OS and system info fingerprinting")
def os_fingerprint():
    print(f"  [*] OS fingerprinting {WIN_TARGET}...")
    out, rc = kali(f"nmap -O --osscan-guess {WIN_TARGET} 2>/dev/null | grep -E 'OS:|Running:|CPE' | head -5", timeout=60)
    return f"OS fingerprint: {out[:200]}"


@scenario("vuln_scan", "T1190", "NSE vulnerability scan (smb-vuln, ms17-010)")
def vuln_scan():
    print(f"  [*] Running vuln scripts against {WIN_TARGET}...")
    out, rc = kali(
        f"nmap --script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode "
        f"-p 445 {WIN_TARGET} 2>/dev/null | head -20",
        timeout=90
    )
    return f"Vuln scan: {out[:300]}"


@scenario("ping_sweep", "T1018", "Network host discovery sweep")
def ping_sweep():
    print(f"  [*] Ping sweep of 192.168.x.x/24...")
    out, rc = kali(f"nmap -sn 192.168.x.x/24 2>/dev/null | grep 'report for' | head -15", timeout=60)
    hosts = out.count('report for')
    return f"Discovered {hosts} live hosts"


@scenario("smb_brute", "T1110", "SMB credential brute force")
def smb_brute():
    print(f"  [*] SMB brute force against {WIN_TARGET}...")
    out, rc = kali(
        f"hydra -l Administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt "
        f"-t 3 smb://{WIN_TARGET} 2>/dev/null | tail -5",
        timeout=90
    )
    return f"SMB brute: {out[:200]}"


# ─── Runner ───────────────────────────────────────────────────────────────────

def run_scenario(name):
    s = SCENARIOS.get(name)
    if not s:
        print(f"Unknown scenario: {name}")
        return

    print(f"\n{'='*60}")
    print(f"  💀 CHAOS MODE — {name}")
    print(f"  MITRE: {s['mitre']} | {s['desc']}")
    print(f"  Target: {WIN_TARGET}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    alerts_before = get_alert_count()
    start = time.time()

    result = s['fn']()
    elapsed = round(time.time() - start, 1)

    time.sleep(3)  # give Wazuh time to ingest
    alerts_after = get_alert_count()
    new_alerts = alerts_after - alerts_before

    print(f"\n  ✓ Done in {elapsed}s")
    print(f"  Result: {result}")
    print(f"  New Wazuh alerts generated: {new_alerts}")

    entry = log_run(name, result, alerts_before, alerts_after)
    print(f"  Logged to: {LOG_FILE}")
    return entry


def run_all():
    print(f"🔥 Running ALL {len(SCENARIOS)} scenarios against {WIN_TARGET}")
    print("  Press Ctrl+C to abort\n")
    results = []
    for i, name in enumerate(SCENARIOS.keys()):
        print(f"\n[{i+1}/{len(SCENARIOS)}]", end="")
        entry = run_scenario(name)
        results.append(entry)
        if i < len(SCENARIOS) - 1:
            delay = random.randint(5, 15)
            print(f"  Waiting {delay}s before next scenario...")
            time.sleep(delay)
    print(f"\n\n{'='*60}")
    print(f"  ALL DONE — {len(results)} scenarios run")
    total_alerts = sum(r.get('alerts_generated', 0) for r in results if r)
    print(f"  Total Wazuh alerts generated: {total_alerts}")
    return results


def run_scheduled(interval_hours=6):
    print(f"⏰ Chaos scheduler: random scenario every {interval_hours}h")
    print("  Press Ctrl+C to stop\n")
    while True:
        name = random.choice(list(SCENARIOS.keys()))
        print(f"\n[{datetime.now().strftime('%H:%M')}] Scheduled run: {name}")
        run_scenario(name)
        sleep_secs = interval_hours * 3600 + random.randint(-1800, 1800)
        next_run = datetime.fromtimestamp(time.time() + sleep_secs)
        print(f"  Next run at: {next_run.strftime('%Y-%m-%d %H:%M')}")
        time.sleep(sleep_secs)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chaos Mode — Lab Attack Simulator")
    parser.add_argument("--all", action="store_true", help="Run all scenarios")
    parser.add_argument("--schedule", action="store_true", help="Run on schedule (every 6h)")
    parser.add_argument("--list", action="store_true", help="List scenarios")
    parser.add_argument("--run", metavar="NAME", help="Run specific scenario by name")
    parser.add_argument("--hours", type=int, default=6, help="Hours between scheduled runs")
    args = parser.parse_args()

    if args.list:
        print(f"\n{'Name':<22} {'MITRE':<10} Description")
        print("-" * 70)
        for name, s in SCENARIOS.items():
            print(f"  {name:<20} {s['mitre']:<10} {s['desc']}")
        print()

    elif args.run:
        if not check_kali_reachable():
            print(f"⚠️  Kali ({KALI_HOST}) unreachable via Proxmox. Is the VM running?")
            exit(1)
        run_scenario(args.run)

    elif args.all:
        if not check_kali_reachable():
            print(f"⚠️  Kali ({KALI_HOST}) unreachable via Proxmox. Is the VM running?")
            exit(1)
        run_all()

    elif args.schedule:
        if not check_kali_reachable():
            print(f"⚠️  Kali ({KALI_HOST}) unreachable via Proxmox. Is the VM running?")
            exit(1)
        run_scheduled(args.hours)

    else:
        # Default: run one random scenario
        if not check_kali_reachable():
            print(f"⚠️  Kali ({KALI_HOST}) unreachable via Proxmox. Is the VM running?")
            exit(1)
        name = random.choice(list(SCENARIOS.keys()))
        run_scenario(name)
