#!/usr/bin/env python3
"""
☀️ MORNING LAB DIGEST
Reads overnight activity and sends a one-paragraph Telegram summary.
Designed to run at 7am daily via OpenClaw cron.
"""

import subprocess
import json
import gzip
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

SSH_KEY       = "/root/.ssh/proxmox_key"
WAZUH_HOST    = "192.168.x.x"
PROXMOX_HOST  = "192.168.x.x"
CHAOS_LOG     = "/root/.openclaw/workspace/memory/chaos-log.json"

def ssh(host, cmd, timeout=10):
    try:
        r = subprocess.run(
            ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5", f"root@{host}", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except:
        return ""

FETCH_OVERNIGHT = r"""
import json, gzip, os
from datetime import datetime, timedelta
cutoff = datetime.now() - timedelta(hours=10)
base = '/var/ossec/logs/alerts'
alerts = []
for year in sorted(os.listdir(base)):
    yp = os.path.join(base, year)
    if not os.path.isdir(yp): continue
    for month in sorted(os.listdir(yp)):
        mp = os.path.join(yp, month)
        if not os.path.isdir(mp): continue
        for fname in sorted(os.listdir(mp)):
            if not (fname.endswith('.json') or fname.endswith('.json.gz')): continue
            fp = os.path.join(mp, fname)
            try:
                fh = gzip.open(fp, 'rt') if fname.endswith('.gz') else open(fp)
                for line in fh:
                    line = line.strip()
                    if not line: continue
                    try:
                        a = json.loads(line)
                        ts_str = a.get('timestamp','')[:19]
                        ts = datetime.fromisoformat(ts_str)
                        if ts < cutoff: continue
                        alerts.append({
                            'ts': ts_str,
                            'lvl': a.get('rule',{}).get('level', 0),
                            'desc': a.get('rule',{}).get('description',''),
                            'agent': a.get('agent',{}).get('name','?'),
                        })
                    except: pass
                fh.close()
            except: pass
print(json.dumps(alerts))
"""

def fetch_overnight_alerts():
    try:
        r = subprocess.run(
            ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=10", f"root@{WAZUH_HOST}", "python3 -"],
            input=FETCH_OVERNIGHT,
            capture_output=True, text=True, timeout=30
        )
        return json.loads(r.stdout.strip()) if r.stdout.strip() else []
    except:
        return []

def get_vm_status():
    raw = ssh(PROXMOX_HOST, "pvesh get /nodes/pve/qemu --output-format json 2>/dev/null")
    raw_ct = ssh(PROXMOX_HOST, "pvesh get /nodes/pve/lxc --output-format json 2>/dev/null")
    vms = []
    try:
        for v in json.loads(raw):
            vms.append((v['name'], v['status']))
    except: pass
    try:
        for c in json.loads(raw_ct):
            vms.append((c['name'], c['status']))
    except: pass
    return vms

def get_chaos_overnight():
    try:
        with open(CHAOS_LOG) as f:
            log = json.load(f)
        cutoff = (datetime.now() - timedelta(hours=10)).isoformat()
        overnight = [e for e in log if e.get('ts', '') >= cutoff]
        return overnight
    except:
        return []

def get_disk_usage():
    raw = ssh(WAZUH_HOST, "df -h / | awk 'NR==2{print $5}'")
    return raw.strip() if raw else "?"

def build_digest():
    now = datetime.now()
    greeting = "Good morning" if now.hour < 12 else "Morning"
    day = now.strftime("%A")

    alerts = fetch_overnight_alerts()
    vms = get_vm_status()
    chaos_runs = get_chaos_overnight()
    disk = get_disk_usage()

    # Alert breakdown
    total_alerts = len(alerts)
    high_alerts = [a for a in alerts if a['lvl'] >= 10]
    med_alerts  = [a for a in alerts if 7 <= a['lvl'] < 10]

    # VM health
    down_vms = [name for name, status in vms if status != 'running']
    all_up = len(down_vms) == 0

    # Chaos summary
    chaos_str = ""
    if chaos_runs:
        total_new_alerts = sum(r.get('alerts_generated', 0) for r in chaos_runs)
        scenarios = [r['scenario'] for r in chaos_runs]
        chaos_str = f"Chaos mode ran {len(chaos_runs)} scenario(s) overnight ({', '.join(scenarios[:3])}), generating {total_new_alerts} alerts. "

    # Build message
    lines = [f"☀️ {greeting}, William. {day} lab report:\n"]

    # VM status
    if all_up:
        lines.append(f"✅ All {len(vms)} VMs running")
    else:
        lines.append(f"⚠️ VMs down: {', '.join(down_vms)}")

    # Disk
    disk_int = int(disk.replace('%','')) if disk.replace('%','').isdigit() else 0
    disk_icon = "🔴" if disk_int >= 85 else "🟡" if disk_int >= 70 else "🟢"
    lines.append(f"{disk_icon} Wazuh disk: {disk}")

    # Alerts overnight
    if total_alerts == 0:
        lines.append(f"🔕 No Wazuh alerts overnight")
    elif high_alerts:
        lines.append(f"🚨 {total_alerts} alerts ({len(high_alerts)} high-severity) — check the war room")
    else:
        lines.append(f"📋 {total_alerts} alerts overnight ({len(med_alerts)} medium, rest low)")

    # Chaos
    if chaos_str:
        lines.append(f"💀 {chaos_str.strip()}")

    # Sign off
    lines.append(f"\nRun `python3 scripts/ir-generator.py` to auto-generate IRs from overnight data.")

    return "\n".join(lines)


if __name__ == "__main__":
    digest = build_digest()
    print(digest)

    # If --send flag, deliver via OpenClaw message tool
    if "--send" in sys.argv:
        import subprocess
        # Write to temp file for OpenClaw to pick up
        with open("/tmp/digest-msg.txt", "w") as f:
            f.write(digest)
        print("\n[digest written to /tmp/digest-msg.txt]")
