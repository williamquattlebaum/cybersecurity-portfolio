#!/usr/bin/env python3
"""
🐝 THEHIVE AUTO-CASE CREATOR
Reads Wazuh alert clusters (from ir-generator logic) and automatically
opens cases in TheHive with full timelines, MITRE tags, and severity.

Usage:
  python3 thehive-integration.py              # check for new cases to create
  python3 thehive-integration.py --hours 24   # scan last N hours
  python3 thehive-integration.py --test        # test TheHive connectivity
  python3 thehive-integration.py --list        # list existing cases
"""

import subprocess, json, gzip, os, sys, requests, argparse
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

SSH_KEY      = "/root/.ssh/proxmox_key"
WAZUH_HOST   = "192.168.x.x"
THEHIVE_URL  = "http://192.168.x.x:9000"
THEHIVE_KEY  = "lPOB5YMxg5Qm8UMhtjrMp0HMqCEchtOr"
STATE_FILE   = Path("/root/.openclaw/workspace/memory/thehive-state.json")

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_KEY}",
    "Content-Type": "application/json",
}

# ─── TheHive API helpers ──────────────────────────────────────────────────────

def hive_get(path):
    try:
        r = requests.get(f"{THEHIVE_URL}{path}", headers=HEADERS, timeout=10)
        return r.json() if r.ok else None
    except Exception as e:
        print(f"  [hive_get error] {e}")
        return None

def hive_post(path, data):
    try:
        r = requests.post(f"{THEHIVE_URL}{path}", headers=HEADERS,
                          json=data, timeout=15)
        if r.ok:
            return r.json()
        else:
            print(f"  [hive_post {r.status_code}] {r.text[:200]}")
            return None
    except Exception as e:
        print(f"  [hive_post error] {e}")
        return None

def test_connection():
    result = hive_get("/api/v1/user/current")
    if result:
        print(f"  ✓ Connected to TheHive as: {result.get('login', '?')} ({result.get('name', '?')})")
        return True
    print(f"  ✗ Cannot reach TheHive at {THEHIVE_URL}")
    return False

def list_cases():
    result = hive_post("/api/v1/query", {
        "query": [{"_name": "listCase"}],
        "from": 0, "to": 20
    })
    if not result:
        print("  No cases found or API error")
        return
    print(f"\n  {'#':<6} {'Title':<50} {'Severity':<10} {'Status'}")
    print("  " + "-"*80)
    for case in (result if isinstance(result, list) else []):
        num = case.get('number', '?')
        title = case.get('title', '?')[:48]
        sev = {1:'Low', 2:'Medium', 3:'High', 4:'Critical'}.get(case.get('severity', 2), '?')
        status = case.get('status', '?')
        print(f"  {num:<6} {title:<50} {sev:<10} {status}")

# ─── Severity mapping ─────────────────────────────────────────────────────────

def wazuh_level_to_hive_sev(lvl):
    if lvl >= 12: return 4  # Critical
    if lvl >= 10: return 3  # High
    if lvl >= 7:  return 2  # Medium
    return 1                # Low

SEV_LABELS = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}

MITRE_MAP = {
    "brute force": "T1110", "authentication failure": "T1110", "failed login": "T1110",
    "port scan": "T1046", "nmap": "T1046",
    "smb": "T1021.002", "winrm": "T1021.006", "rdp": "T1021.001",
    "disk": "T1485", "filesystem": "T1485",
    "sca": "T1601", "cis": "T1601",
    "firewall": "T1562.004", "blocked": "T1562",
}

def get_mitre(desc):
    dl = desc.lower()
    for k, v in MITRE_MAP.items():
        if k in dl:
            return v
    return None

# ─── Alert fetcher (same as ir-generator) ─────────────────────────────────────

FETCH_SCRIPT = r"""
import json, gzip, os, sys
from datetime import datetime, timedelta
hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
cutoff = datetime.now() - timedelta(hours=hours)
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
                        ts_str = a.get('timestamp', '')[:19]
                        ts = datetime.fromisoformat(ts_str)
                        if ts < cutoff: continue
                        alerts.append({
                            'ts': ts_str,
                            'lvl': a.get('rule', {}).get('level', 0),
                            'rule_id': a.get('rule', {}).get('id', ''),
                            'desc': a.get('rule', {}).get('description', ''),
                            'agent': a.get('agent', {}).get('name', '?'),
                            'src_ip': a.get('data', {}).get('srcip', ''),
                        })
                    except: pass
                fh.close()
            except: pass
for a in alerts:
    print(json.dumps(a))
"""

def fetch_alerts(hours=24):
    try:
        r = subprocess.run(
            ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=10", f"root@{WAZUH_HOST}", f"python3 - {hours}"],
            input=FETCH_SCRIPT, capture_output=True, text=True, timeout=60
        )
        alerts = []
        for line in r.stdout.strip().split('\n'):
            if line.strip():
                try: alerts.append(json.loads(line))
                except: pass
        return alerts
    except:
        return []

def cluster_alerts(alerts, window_minutes=30, min_count=3):
    sorted_alerts = sorted(alerts, key=lambda a: a['ts'])
    clusters, used = [], set()
    for i, anchor in enumerate(sorted_alerts):
        if i in used: continue
        cluster = [anchor]
        used.add(i)
        anchor_ts = datetime.fromisoformat(anchor['ts'])
        anchor_mitre = get_mitre(anchor['desc'])
        for j, other in enumerate(sorted_alerts[i+1:], start=i+1):
            if j in used: continue
            other_ts = datetime.fromisoformat(other['ts'])
            if (other_ts - anchor_ts).total_seconds() > window_minutes * 60: break
            if other['agent'] == anchor['agent'] and get_mitre(other['desc']) == anchor_mitre:
                cluster.append(other)
                used.add(j)
        max_lvl = max(a['lvl'] for a in cluster)
        if len(cluster) >= min_count or max_lvl >= 10:
            clusters.append(cluster)
    return clusters

# ─── State tracking (avoid duplicate cases) ───────────────────────────────────

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"created_cases": []}

def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def cluster_fingerprint(cluster):
    sorted_c = sorted(cluster, key=lambda a: a['ts'])
    return f"{sorted_c[0]['ts']}|{sorted_c[0]['agent']}|{sorted_c[0]['desc'][:30]}"

# ─── Case creator ─────────────────────────────────────────────────────────────

def create_case(cluster):
    sorted_c = sorted(cluster, key=lambda a: a['ts'])
    first_ts = sorted_c[0]['ts']
    max_lvl = max(a['lvl'] for a in cluster)
    sev = wazuh_level_to_hive_sev(max_lvl)
    agents = list(set(a['agent'] for a in cluster))
    desc_primary = sorted_c[0]['desc']
    mitre = get_mitre(desc_primary)

    # Build title
    if "brute" in desc_primary.lower() or "authentication failure" in desc_primary.lower():
        title = f"Credential Brute Force — {agents[0]}"
    elif "scan" in desc_primary.lower():
        title = f"Network Reconnaissance — {agents[0]}"
    elif "disk" in desc_primary.lower() or "filesystem" in desc_primary.lower():
        title = f"Disk Exhaustion — {agents[0]}"
    elif "smb" in desc_primary.lower():
        title = f"SMB Enumeration — {agents[0]}"
    else:
        title = f"{desc_primary[:45]} — {agents[0]}"

    # Build description markdown
    desc_md = f"""## Wazuh Alert Cluster — Auto-Created

**First seen:** {first_ts}  
**Affected host(s):** {', '.join(agents)}  
**Alert count:** {len(cluster)}  
**Max severity:** Level {max_lvl} ({SEV_LABELS[sev]})  
{"**MITRE:** " + mitre if mitre else ""}

### Alert Timeline

| Timestamp | Level | Agent | Description |
|-----------|-------|-------|-------------|
"""
    for a in sorted_c[:15]:
        desc_md += f"| {a['ts']} | {a['lvl']} | {a['agent']} | {a['desc'][:55]} |\n"

    if len(sorted_c) > 15:
        desc_md += f"\n*...{len(sorted_c)-15} additional alerts*\n"

    desc_md += f"\n---\n*Auto-created by thehive-integration.py — Home SOC Lab*"

    # Tags
    tags = ["wazuh", "auto-created", f"level-{max_lvl}"]
    if mitre:
        tags.append(mitre)
    tags.extend(agents[:2])

    case_data = {
        "title": title,
        "description": desc_md,
        "severity": sev,
        "startDate": int(datetime.fromisoformat(first_ts).timestamp() * 1000),
        "tags": tags,
        "flag": sev >= 3,  # flag high/critical
        "tlp": 2,  # TLP:AMBER
        "pap": 2,
    }

    result = hive_post("/api/v1/case", case_data)
    if result:
        case_num = result.get('number', '?')
        case_id = result.get('_id', '')
        print(f"  ✓ Case #{case_num} created: {title} [{SEV_LABELS[sev]}]")

        # Add observable for source IP if present
        src_ips = list(set(a['src_ip'] for a in cluster if a.get('src_ip')))
        for ip in src_ips[:3]:
            obs_data = {
                "dataType": "ip",
                "data": ip,
                "message": "Source IP from Wazuh alert",
                "tags": ["wazuh", "src-ip"],
                "tlp": 2,
                "ioc": True,
            }
            hive_post(f"/api/v1/case/{case_id}/observable", obs_data)

        return case_num, case_id
    return None, None


# ─── Main ─────────────────────────────────────────────────────────────────────

def main(hours=24):
    print(f"\n🐝 TheHive Integration — scanning last {hours}h for new incidents")

    if not test_connection():
        sys.exit(1)

    print(f"\n  Fetching Wazuh alerts...")
    alerts = fetch_alerts(hours)
    print(f"  Loaded {len(alerts)} alerts")

    if not alerts:
        print("  No alerts to process.")
        return

    clusters = cluster_alerts(alerts)
    print(f"  Found {len(clusters)} incident cluster(s)")

    state = load_state()
    new_cases = 0

    for cluster in clusters:
        fp = cluster_fingerprint(cluster)
        if fp in state['created_cases']:
            print(f"  [skip] Already created case for: {cluster[0]['desc'][:40]}")
            continue

        case_num, case_id = create_case(cluster)
        if case_num:
            state['created_cases'].append(fp)
            new_cases += 1

    save_state(state)
    print(f"\n  Done. {new_cases} new case(s) created in TheHive.")
    if new_cases:
        print(f"  View at: {THEHIVE_URL}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TheHive Auto-Case Creator")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--test", action="store_true", help="Test connectivity only")
    parser.add_argument("--list", action="store_true", help="List existing cases")
    args = parser.parse_args()

    if args.test:
        test_connection()
    elif args.list:
        if test_connection():
            list_cases()
    else:
        main(hours=args.hours)
