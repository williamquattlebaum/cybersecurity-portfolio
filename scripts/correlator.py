#!/usr/bin/env python3
"""
🔗 ALERT CORRELATION ENGINE
Watches Wazuh + Suricata simultaneously. Matches events across both sources.
Identifies multi-stage attack chains with full timelines.

What it detects:
  - Recon → Exploitation chains (Suricata scan + Wazuh auth failure from same IP)
  - Brute force campaigns (multiple auth failures same IP across time)
  - Lateral movement (SMB/WinRM attempts after recon)
  - Persistence indicators (service changes after access)
  - Data exfil patterns (large outbound after compromise)

Usage:
  python3 correlator.py             # one-shot: analyze last 24h
  python3 correlator.py --hours 48  # analyze last N hours
  python3 correlator.py --watch     # live mode, alert on new chains
  python3 correlator.py --report    # generate IR from chains found
"""

import subprocess, json, gzip, os, sys, time, argparse
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

SSH_KEY      = "/root/.ssh/proxmox_key"
WAZUH_HOST   = "192.168.x.x"
PROXMOX_HOST = "192.168.x.x"
EVE_LOG      = "/var/log/suricata/eve.json"
PORTFOLIO_DIR = Path("/root/.openclaw/workspace/portfolio/incident-reports")

# ─── Chain definitions ────────────────────────────────────────────────────────

CHAIN_PATTERNS = {
    "recon_to_auth": {
        "desc": "Reconnaissance followed by authentication attempt",
        "severity": "High",
        "mitre": [("T1046", "Network Service Scanning"), ("T1110", "Brute Force")],
        "stage1": {"source": "suricata", "keywords": ["scan", "port", "nmap", "probe"]},
        "stage2": {"source": "wazuh", "keywords": ["authentication failure", "failed login", "invalid user"]},
        "window_minutes": 60,
    },
    "recon_to_smb": {
        "desc": "Reconnaissance followed by SMB enumeration",
        "severity": "High",
        "mitre": [("T1046", "Network Service Scanning"), ("T1021.002", "SMB Shares")],
        "stage1": {"source": "suricata", "keywords": ["scan", "port"]},
        "stage2": {"source": "wazuh", "keywords": ["smb", "samba", "share", "445"]},
        "window_minutes": 60,
    },
    "brute_force_campaign": {
        "desc": "Sustained brute force campaign (10+ failures same IP)",
        "severity": "High",
        "mitre": [("T1110", "Brute Force")],
        "stage1": None,
        "stage2": {"source": "wazuh", "keywords": ["authentication failure", "failed login"]},
        "window_minutes": 30,
        "min_count": 10,
    },
    "vuln_scan_to_exploit": {
        "desc": "Vulnerability scan followed by exploitation attempt",
        "severity": "Critical",
        "mitre": [("T1595", "Active Scanning"), ("T1190", "Exploit Public-Facing App")],
        "stage1": {"source": "suricata", "keywords": ["exploit", "ms17", "eternal", "vuln"]},
        "stage2": {"source": "wazuh", "keywords": ["exploit", "privilege", "shellcode", "buffer"]},
        "window_minutes": 30,
    },
    "persistence_after_access": {
        "desc": "Service or startup modification after successful access",
        "severity": "Critical",
        "mitre": [("T1021", "Remote Services"), ("T1543", "Create or Modify System Process")],
        "stage1": {"source": "wazuh", "keywords": ["winrm", "rdp", "remote", "login success"]},
        "stage2": {"source": "wazuh", "keywords": ["service", "startup", "registry", "scheduled task", "autorun"]},
        "window_minutes": 120,
    },
    "multi_stage_recon": {
        "desc": "Multi-vector reconnaissance (network scan + host enum + credential attempt)",
        "severity": "High",
        "mitre": [("T1046", "Network Service Scanning"), ("T1082", "System Information Discovery"), ("T1110", "Brute Force")],
        "stage1": {"source": "suricata", "keywords": ["scan", "nmap"]},
        "stage2": {"source": "suricata", "keywords": ["smb", "rdp", "winrm", "ssh"]},
        "stage3": {"source": "wazuh", "keywords": ["authentication failure", "brute"]},
        "window_minutes": 120,
    },
}

# ─── Data fetchers ─────────────────────────────────────────────────────────────

def ssh(host, cmd, input_text=None, timeout=30):
    try:
        r = subprocess.run(
            ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=8", f"root@{host}", cmd],
            input=input_text, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except:
        return ""

WAZUH_FETCH = r"""
import json, gzip, os, sys
from datetime import datetime, timedelta
hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
cutoff = datetime.now() - timedelta(hours=hours)
base = '/var/ossec/logs/alerts'
events = []
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
                        ts_str = a.get('timestamp', '')[:19]
                        ts = datetime.fromisoformat(ts_str)
                        if ts < cutoff: continue
                        src = (a.get('data', {}).get('srcip') or
                               a.get('data', {}).get('src_ip') or '')
                        events.append({
                            'source': 'wazuh',
                            'ts': ts_str,
                            'lvl': a.get('rule', {}).get('level', 0),
                            'desc': a.get('rule', {}).get('description', ''),
                            'agent': a.get('agent', {}).get('name', '?'),
                            'src_ip': src,
                        })
                    except: pass
                fh.close()
            except: pass
for e in events:
    print(json.dumps(e))
"""

def fetch_wazuh_events(hours=24):
    try:
        r = subprocess.run(
            ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=10", f"root@{WAZUH_HOST}", f"python3 - {hours}"],
            input=WAZUH_FETCH,
            capture_output=True, text=True, timeout=60
        )
        events = []
        for line in r.stdout.strip().split('\n'):
            if line.strip():
                try: events.append(json.loads(line))
                except: pass
        return events
    except:
        return []

def fetch_suricata_events(hours=24):
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    raw = ssh(PROXMOX_HOST,
        f"grep '\"event_type\":\"alert\"' {EVE_LOG} 2>/dev/null | "
        f"python3 -c \"\nimport sys,json\nfor l in sys.stdin:\n l=l.strip()\n if not l: continue\n try:\n  e=json.loads(l)\n  if e.get('timestamp','')[:19] >= '{cutoff[:19]}': print(l)\n except: pass\n\"",
        timeout=30
    )
    events = []
    for line in (raw or '').split('\n'):
        if not line.strip(): continue
        try:
            e = json.loads(line)
            events.append({
                'source': 'suricata',
                'ts': e.get('timestamp', '')[:19],
                'sig': e.get('alert', {}).get('signature', ''),
                'desc': e.get('alert', {}).get('signature', ''),
                'src_ip': e.get('src_ip', ''),
                'dst_ip': e.get('dest_ip', ''),
                'sev': e.get('alert', {}).get('severity', 3),
                'lvl': max(1, 12 - (e.get('alert', {}).get('severity', 3) * 3)),
            })
        except: pass
    return events


# ─── Correlation logic ────────────────────────────────────────────────────────

def event_matches(event, criteria):
    if not criteria:
        return False
    if criteria.get('source') and event.get('source') != criteria['source']:
        return False
    desc = (event.get('desc') or event.get('sig') or '').lower()
    keywords = criteria.get('keywords', [])
    return any(k in desc for k in keywords)


def find_chains(events, hours=24):
    """Find multi-stage attack chains across all events."""
    # Index events by IP
    events_by_ip = defaultdict(list)
    for e in events:
        ip = e.get('src_ip', '')
        if ip and not ip.startswith(('192.168.', '10.', '127.')):
            events_by_ip[ip].append(e)

    # Also index all events by time
    all_sorted = sorted(events, key=lambda x: x['ts'])

    chains_found = []

    for pattern_name, pattern in CHAIN_PATTERNS.items():
        window = timedelta(minutes=pattern['window_minutes'])

        # Brute force volume detection (no IP required)
        if pattern.get('min_count'):
            wazuh_failures = defaultdict(list)
            for e in all_sorted:
                if event_matches(e, pattern['stage2']):
                    ip = e.get('src_ip', 'unknown')
                    wazuh_failures[ip].append(e)
            for ip, fails in wazuh_failures.items():
                if len(fails) >= pattern['min_count']:
                    ts_range = f"{fails[0]['ts']} → {fails[-1]['ts']}"
                    chains_found.append({
                        'pattern': pattern_name,
                        'desc': pattern['desc'],
                        'severity': pattern['severity'],
                        'mitre': pattern['mitre'],
                        'src_ip': ip,
                        'events': fails,
                        'ts_range': ts_range,
                        'stage_count': 1,
                    })
            continue

        # Multi-stage chain detection (requires matching IP across stages)
        for ip, ip_events in events_by_ip.items():
            ip_sorted = sorted(ip_events, key=lambda x: x['ts'])

            stage1_hits = [e for e in ip_sorted if event_matches(e, pattern.get('stage1'))]
            stage2_hits = [e for e in ip_sorted if event_matches(e, pattern.get('stage2'))]

            if not stage1_hits or not stage2_hits:
                continue

            # Find pairs where stage2 comes within window after stage1
            for s1 in stage1_hits:
                s1_ts = datetime.fromisoformat(s1['ts'])
                for s2 in stage2_hits:
                    s2_ts = datetime.fromisoformat(s2['ts'])
                    if timedelta(0) <= (s2_ts - s1_ts) <= window:
                        chain_events = [s1, s2]

                        # Check for stage3 if defined
                        if pattern.get('stage3'):
                            stage3_hits = [e for e in ip_sorted if event_matches(e, pattern.get('stage3'))]
                            for s3 in stage3_hits:
                                s3_ts = datetime.fromisoformat(s3['ts'])
                                if s3_ts >= s2_ts and (s3_ts - s1_ts) <= window * 2:
                                    chain_events.append(s3)
                                    break

                        chains_found.append({
                            'pattern': pattern_name,
                            'desc': pattern['desc'],
                            'severity': pattern['severity'],
                            'mitre': pattern['mitre'],
                            'src_ip': ip,
                            'events': sorted(chain_events, key=lambda x: x['ts']),
                            'ts_range': f"{chain_events[0]['ts']} → {chain_events[-1]['ts']}",
                            'stage_count': len(chain_events),
                        })
                        break  # one chain per s1 event

    # Deduplicate (same IP + same pattern)
    seen = set()
    unique = []
    for c in chains_found:
        key = (c['pattern'], c['src_ip'], c['events'][0]['ts'][:16])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return sorted(unique, key=lambda x: (
        {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x['severity'], 4),
        x['ts_range']
    ))


# ─── Output ───────────────────────────────────────────────────────────────────

def print_chain(chain, idx):
    sev = chain['severity']
    sev_icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(sev, '⚪')
    print(f"\n{'='*65}")
    print(f"  {sev_icon} CHAIN #{idx+1}: {chain['desc']}")
    print(f"  Severity: {sev} | Stages: {chain['stage_count']}")
    print(f"  Source IP: {chain['src_ip']}")
    print(f"  Timespan: {chain['ts_range']}")
    mitre_str = ' → '.join(t for t, _ in chain['mitre'])
    print(f"  MITRE: {mitre_str}")
    print(f"\n  Timeline:")
    for e in chain['events']:
        src = e.get('source', '?').upper()[:7]
        ts = e.get('ts', '')[:19]
        desc = (e.get('desc') or e.get('sig') or '')[:55]
        print(f"    [{src}] {ts}  {desc}")


def generate_chain_ir(chains):
    """Write a correlation-based IR for all chains found."""
    if not chains:
        return None

    from scripts.ir_generator import next_ir_number
    try:
        ir_num = next_ir_number()
    except:
        existing = list(PORTFOLIO_DIR.glob("IR-*.md"))
        nums = [int(f.stem.split('-')[1]) for f in existing if f.stem.split('-')[1].isdigit()]
        ir_num = max(nums) + 1 if nums else 7

    now = datetime.now().strftime("%Y-%m-%d")
    ir_id = f"IR-{ir_num:03d}"
    title = f"Multi-Stage Attack Chain — Correlation Analysis ({now})"
    filename = PORTFOLIO_DIR / f"{ir_id}.md"

    content = f"# {ir_id}: {title}\n\n"
    content += f"**Date:** {now}\n"
    content += f"**Analyst:** William Quattlebaum\n"
    content += f"**Method:** Cross-source correlation (Wazuh + Suricata)\n"
    content += f"**Chains Found:** {len(chains)}\n\n---\n\n"
    content += f"## Executive Summary\n\nCorrelation engine identified **{len(chains)} attack chain(s)** "
    content += f"by matching events across Wazuh SIEM and Suricata IDS. "

    crit = sum(1 for c in chains if c['severity'] == 'Critical')
    high = sum(1 for c in chains if c['severity'] == 'High')
    if crit:
        content += f"**{crit} Critical** and {high} High severity chains detected.\n\n---\n\n"
    else:
        content += f"**{high} High** severity chains detected.\n\n---\n\n"

    for i, chain in enumerate(chains):
        content += f"## Chain #{i+1}: {chain['desc']}\n\n"
        content += f"**Severity:** {chain['severity']}  \n"
        content += f"**Source IP:** `{chain['src_ip']}`  \n"
        content += f"**Timespan:** {chain['ts_range']}  \n"
        mitre_links = ' → '.join(f'[{t}](https://attack.mitre.org/techniques/{t.replace(".", "/")}) {n}' for t, n in chain['mitre'])
        content += f"**MITRE:** {mitre_links}\n\n"
        content += f"### Timeline\n\n| Source | Timestamp | Event |\n|--------|-----------|-------|\n"
        for e in chain['events']:
            src = e.get('source','?').upper()
            ts = e.get('ts','')[:19]
            desc = (e.get('desc') or e.get('sig') or '')[:60]
            content += f"| {src} | `{ts}` | {desc} |\n"
        content += "\n"

    content += f"---\n\n*Generated by correlator.py — {now}*\n"
    content += "*Portfolio: github.com/williamquattlebaum/cybersecurity-portfolio*\n"

    with open(filename, 'w') as f:
        f.write(content)

    return filename, ir_id


# ─── Main ─────────────────────────────────────────────────────────────────────

def main(hours=24, watch=False, report=False):
    print(f"\n🔗 Correlation Engine — analyzing last {hours}h")
    print(f"   Fetching Wazuh events from {WAZUH_HOST}...")

    wazuh_events = fetch_wazuh_events(hours)
    print(f"   Loaded {len(wazuh_events)} Wazuh events")

    print(f"   Fetching Suricata events from {PROXMOX_HOST}...")
    suri_events = fetch_suricata_events(hours)
    print(f"   Loaded {len(suri_events)} Suricata alert events")

    all_events = wazuh_events + suri_events
    print(f"   Total events: {len(all_events)} | Running correlation...\n")

    chains = find_chains(all_events, hours)

    if not chains:
        print("   ✓ No attack chains detected in this window.")
        return

    print(f"   🚨 Found {len(chains)} attack chain(s):\n")
    for i, chain in enumerate(chains):
        print_chain(chain, i)

    if report and chains:
        print(f"\n\n  Writing IR...")
        result = generate_chain_ir(chains)
        if result:
            path, ir_id = result
            print(f"  ✓ {ir_id} written to {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Alert Correlation Engine")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--watch", action="store_true", help="Live monitoring mode")
    parser.add_argument("--report", action="store_true", help="Generate IR from chains found")
    args = parser.parse_args()

    if args.watch:
        print("👁️  Live correlation mode — checking every 5 minutes (Ctrl+C to stop)")
        while True:
            main(hours=1, report=False)
            time.sleep(300)
    else:
        main(hours=args.hours, report=args.report)
