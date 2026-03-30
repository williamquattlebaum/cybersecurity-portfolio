#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║         SOC WAR ROOM — BOZO COMMAND CENTER           ║
║         Built for William's Home Lab                 ║
╚══════════════════════════════════════════════════════╝
"""

import subprocess
import json
import time
import re
from datetime import datetime, timezone
from collections import deque

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, DataTable, Label, RichLog
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual import work
from textual.reactive import reactive
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.style import Style
from rich import box

# ─── SSH helpers ──────────────────────────────────────────────────────────────

PROXMOX_HOST = "192.168.x.x"
WAZUH_HOST   = "192.168.x.x"
SSH_KEY      = "/root/.ssh/proxmox_key"

def ssh(host, cmd, timeout=8):
    try:
        result = subprocess.run(
            ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5", f"root@{host}", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception as e:
        return ""

# ─── Data fetchers ────────────────────────────────────────────────────────────

def fetch_vms():
    raw = ssh(PROXMOX_HOST, "pvesh get /nodes/pve/qemu --output-format json 2>/dev/null")
    raw_ct = ssh(PROXMOX_HOST, "pvesh get /nodes/pve/lxc --output-format json 2>/dev/null")
    vms = []
    try:
        for v in json.loads(raw):
            mem_pct = round(v['mem'] / v['maxmem'] * 100) if v.get('maxmem') else 0
            cpu_pct = round(v.get('cpu', 0) * 100, 1)
            uptime_h = v.get('uptime', 0) // 3600
            vms.append({
                "vmid": v['vmid'],
                "name": v['name'],
                "status": v['status'],
                "cpu": cpu_pct,
                "mem": mem_pct,
                "uptime_h": uptime_h,
                "type": "VM"
            })
    except: pass
    try:
        for c in json.loads(raw_ct):
            mem_pct = round(c['mem'] / c['maxmem'] * 100) if c.get('maxmem') else 0
            vms.append({
                "vmid": c['vmid'],
                "name": c['name'],
                "status": c['status'],
                "cpu": round(c.get('cpu', 0) * 100, 1),
                "mem": mem_pct,
                "uptime_h": c.get('uptime', 0) // 3600,
                "type": "CT"
            })
    except: pass
    return sorted(vms, key=lambda x: x['vmid'])


def fetch_wazuh_services():
    raw = ssh(WAZUH_HOST, "systemctl is-active wazuh-manager wazuh-dashboard wazuh-indexer")
    lines = raw.strip().split('\n') if raw else []
    services = ["wazuh-manager", "wazuh-dashboard", "wazuh-indexer"]
    result = {}
    for i, svc in enumerate(services):
        status = lines[i].strip() if i < len(lines) else "unknown"
        result[svc] = status
    return result


WAZUH_ALERT_SCRIPT = r"""
import json, gzip, os, sys
from datetime import datetime
base = '/var/ossec/logs/alerts'
now = datetime.now()
month = now.strftime('%b')
year = str(now.year)
p = os.path.join(base, year, month)
if not os.path.isdir(p):
    sys.exit(0)
files = sorted([f for f in os.listdir(p) if f.endswith('.json') or f.endswith('.json.gz')])
alerts = []
for f in files[-3:]:
    fp = os.path.join(p, f)
    try:
        fh = gzip.open(fp, 'rt') if f.endswith('.gz') else open(fp)
        for line in fh:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except:
                    pass
        fh.close()
    except:
        pass
for a in alerts[-12:]:
    print(json.dumps({
        'ts': a.get('timestamp','')[:19],
        'lvl': a.get('rule',{}).get('level', 0),
        'agent': a.get('agent',{}).get('name','?'),
        'desc': a.get('rule',{}).get('description','?')[:55]
    }))
"""

def fetch_wazuh_alerts(n=12):
    try:
        result = subprocess.run(
            ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5", f"root@{WAZUH_HOST}", "python3 -"],
            input=WAZUH_ALERT_SCRIPT,
            capture_output=True, text=True, timeout=12
        )
        raw = result.stdout.strip()
    except Exception:
        return []
    alerts = []
    for line in raw.split('\n'):
        if not line.strip():
            continue
        try:
            alerts.append(json.loads(line))
        except:
            pass
    return alerts


def fetch_suricata_stats():
    # Count alerts from today's eve.json
    count_raw = ssh(PROXMOX_HOST,
        "grep '\"event_type\":\"alert\"' /var/log/suricata/eve.json 2>/dev/null | wc -l")
    total = int(count_raw.strip()) if count_raw.strip().isdigit() else 0

    # Last 5 real alerts (non-truncated)
    last_raw = ssh(PROXMOX_HOST,
        "grep '\"event_type\":\"alert\"' /var/log/suricata/eve.json 2>/dev/null | "
        "grep -v 'truncated' | grep -v 'AF-PACKET' | tail -5")
    alerts = []
    for line in last_raw.strip().split('\n'):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
            alerts.append({
                "ts": e.get('timestamp', '')[:19],
                "src": e.get('src_ip', '?'),
                "dst": e.get('dest_ip', '?'),
                "sig": e.get('alert', {}).get('signature', '?')[:45],
                "sev": e.get('alert', {}).get('severity', 3)
            })
        except:
            pass
    return total, alerts


def fetch_proxmox_host_stats():
    raw = ssh(PROXMOX_HOST,
        "pvesh get /nodes/pve/status --output-format json 2>/dev/null")
    try:
        d = json.loads(raw)
        cpu = round(d.get('cpu', 0) * 100, 1)
        mem_used = d.get('memory', {}).get('used', 0)
        mem_total = d.get('memory', {}).get('total', 1)
        mem_pct = round(mem_used / mem_total * 100)
        uptime = d.get('uptime', 0) // 3600
        return {"cpu": cpu, "mem": mem_pct, "uptime_h": uptime}
    except:
        return {"cpu": 0, "mem": 0, "uptime_h": 0}


# ─── Widgets ──────────────────────────────────────────────────────────────────

def status_color(status):
    if status in ("running", "active"):
        return "bright_green"
    elif status in ("stopped", "inactive", "failed"):
        return "bright_red"
    return "yellow"


def mem_bar(pct, width=10):
    filled = round(pct / 100 * width)
    if pct >= 90:
        color = "bright_red"
    elif pct >= 70:
        color = "yellow"
    else:
        color = "bright_green"
    bar = "█" * filled + "░" * (width - filled)
    return Text(f"[{bar}] {pct:3}%", style=color)


def cpu_color(pct):
    if pct >= 80:
        return "bright_red"
    elif pct >= 50:
        return "yellow"
    return "bright_cyan"


def alert_level_color(lvl):
    lvl = int(lvl) if str(lvl).isdigit() else 0
    if lvl >= 12:
        return "bright_red"
    elif lvl >= 7:
        return "yellow"
    elif lvl >= 4:
        return "bright_cyan"
    return "white"


def severity_badge(lvl):
    lvl = int(lvl) if str(lvl).isdigit() else 0
    if lvl >= 12:
        return Text("■ CRIT", style="bright_red bold")
    elif lvl >= 10:
        return Text("▲ HIGH", style="red")
    elif lvl >= 7:
        return Text("● MED ", style="yellow")
    elif lvl >= 4:
        return Text("○ LOW ", style="bright_cyan")
    return Text("· INFO", style="dim white")


VM_ICONS = {
    "wazuh-server":   "🛡️",
    "win10-endpoint": "🖥️",
    "kali-attacker":  "💀",
    "splunk-server":  "📊",
    "thehive-server": "🐝",
    "Clawdbot":       "🤡",
}


# ─── App ──────────────────────────────────────────────────────────────────────

class WarRoom(App):
    CSS = """
    Screen {
        background: #0a0a0f;
        color: #c0caf5;
    }
    Header {
        background: #1a1b26;
        color: #7dcfff;
        text-style: bold;
    }
    Footer {
        background: #1a1b26;
        color: #565f89;
    }
    .panel {
        border: solid #3b4261;
        background: #0d1117;
        margin: 0 1;
        padding: 0 1;
    }
    .panel-title {
        color: #7aa2f7;
        text-style: bold;
        padding: 0 1;
    }
    .section-header {
        color: #bb9af7;
        text-style: bold;
    }
    #left-col {
        width: 42;
    }
    #mid-col {
        width: 1fr;
    }
    #right-col {
        width: 45;
    }
    #vm-table {
        height: auto;
    }
    #alert-feed {
        height: 1fr;
        border: solid #3b4261;
        background: #0d1117;
        margin: 0 1;
    }
    #suricata-panel {
        height: auto;
        border: solid #3b4261;
        background: #0d1117;
        margin: 0 1;
        padding: 0 1;
    }
    #host-stats {
        height: auto;
        border: solid #3b4261;
        background: #0d1117;
        margin: 0 1;
        padding: 0 1;
    }
    #clock-panel {
        height: 3;
        border: solid #3b4261;
        background: #0d1117;
        margin: 0 1;
        padding: 0;
        text-align: center;
        content-align: center middle;
        color: #e0af68;
        text-style: bold;
    }
    DataTable {
        background: #0d1117;
        color: #c0caf5;
    }
    DataTable > .datatable--header {
        background: #1a1b26;
        color: #7aa2f7;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #1a1b26;
    }
    """

    TITLE = "🤡 SOC WAR ROOM — BOZO COMMAND CENTER"
    BINDINGS = [("q", "quit", "Quit"), ("r", "refresh", "Refresh")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            # Left column: VM status + host stats
            with Vertical(id="left-col"):
                yield Label("  ◈ PROXMOX HOST", classes="section-header")
                yield Static("Loading...", id="host-stats", classes="panel")
                yield Label("  ◈ VM STATUS", classes="section-header")
                yield DataTable(id="vm-table", classes="panel", show_cursor=False)
            # Middle column: Wazuh alert feed
            with Vertical(id="mid-col"):
                yield Label("  ◈ WAZUH ALERT FEED", classes="section-header")
                yield RichLog(id="alert-feed", highlight=False, markup=True, wrap=True)
            # Right column: Suricata + Wazuh services
            with Vertical(id="right-col"):
                yield Label("  ◈ CLOCK", classes="section-header")
                yield Static("", id="clock-panel", classes="panel")
                yield Label("  ◈ WAZUH SERVICES", classes="section-header")
                yield Static("Loading...", id="wazuh-services", classes="panel")
                yield Label("  ◈ SURICATA IDS", classes="section-header")
                yield Static("Loading...", id="suricata-panel", classes="panel")
                yield Label("  ◈ NETWORK MAP", classes="section-header")
                yield Static("", id="netmap", classes="panel")
        yield Footer()

    def on_mount(self) -> None:
        # Init VM table columns
        table = self.query_one("#vm-table", DataTable)
        table.add_columns("", "Name", "CPU", "RAM", "Up")
        # Initial load
        self.refresh_all()
        # Tick every second for clock
        self.set_interval(1, self.tick_clock)
        # Refresh data every 30s
        self.set_interval(30, self.refresh_all)

    def tick_clock(self):
        now = datetime.now()
        day = now.strftime("%A, %B %d %Y")
        t = now.strftime("%H:%M:%S")
        self.query_one("#clock-panel", Static).update(
            f"[bold bright_yellow]{t}[/]\n[dim]{day}[/]"
        )

    def action_refresh(self):
        self.refresh_all()

    @work(thread=True)
    def refresh_all(self):
        self.app.call_from_thread(self._update_vms)
        self.app.call_from_thread(self._update_wazuh_services)
        self.app.call_from_thread(self._update_alert_feed)
        self.app.call_from_thread(self._update_suricata)
        self.app.call_from_thread(self._update_netmap)
        self.app.call_from_thread(self._update_host_stats)

    def _update_host_stats(self):
        stats = fetch_proxmox_host_stats()
        cpu = stats['cpu']
        mem = stats['mem']
        uptime = stats['uptime_h']
        cpu_col = cpu_color(cpu)

        t = Text()
        t.append(f"  HOST  192.168.x.x\n", style="dim")
        t.append(f"  CPU:  ")
        t.append(f"{cpu:4.1f}%\n", style=cpu_col)
        t.append(f"  RAM:  ")
        mem_col = "bright_red" if mem >= 90 else ("yellow" if mem >= 70 else "bright_green")
        t.append(f"{mem:3}%\n", style=mem_col)
        t.append(f"  UP:   {uptime}h", style="dim")
        self.query_one("#host-stats", Static).update(t)

    def _update_vms(self):
        table = self.query_one("#vm-table", DataTable)
        table.clear()
        vms = fetch_vms()
        for v in vms:
            icon = VM_ICONS.get(v['name'], "💻")
            status = v['status']
            s_color = status_color(status)
            name_text = Text(f"{icon} {v['name']}", style="white")
            cpu_text = Text(f"{v['cpu']:4.1f}%", style=cpu_color(v['cpu']))
            mem_text = mem_bar(v['mem'], width=8)
            up_text = Text(f"{v['uptime_h']}h", style="dim cyan")
            table.add_row(
                Text("●", style=s_color),
                name_text,
                cpu_text,
                mem_text,
                up_text,
            )

    def _update_wazuh_services(self):
        services = fetch_wazuh_services()
        t = Text()
        labels = {
            "wazuh-manager":   "  Manager  ",
            "wazuh-dashboard": "  Dashboard",
            "wazuh-indexer":   "  Indexer  ",
        }
        for svc, label in labels.items():
            status = services.get(svc, "unknown")
            dot_color = "bright_green" if status == "active" else "bright_red"
            status_text = "● ACTIVE" if status == "active" else f"✗ {status.upper()}"
            status_color_val = "bright_green" if status == "active" else "bright_red"
            t.append(f"{label}  ")
            t.append(f"{status_text}\n", style=status_color_val)
        self.query_one("#wazuh-services", Static).update(t)

    def _update_alert_feed(self):
        log = self.query_one("#alert-feed", RichLog)
        log.clear()
        alerts = fetch_wazuh_alerts(12)
        if not alerts:
            log.write(Text("  No recent alerts", style="dim"))
            return
        for a in reversed(alerts):
            lvl = a.get('lvl', 0)
            ts = a.get('ts', '')
            agent = a.get('agent', '?')[:16]
            desc = a.get('desc', '?')
            badge = severity_badge(lvl)
            line = Text()
            line.append(f"  ")
            line.append_text(badge)
            line.append(f"  {ts[11:19]}  ", style="dim cyan")
            line.append(f"{agent:<16}  ", style="bright_blue")
            line.append(desc, style=alert_level_color(lvl))
            log.write(line)

    def _update_suricata(self):
        total, alerts = fetch_suricata_stats()
        t = Text()
        total_col = "bright_red" if total > 100000 else ("yellow" if total > 50000 else "bright_green")
        t.append(f"  Total alerts: ", style="dim")
        t.append(f"{total:,}\n", style=total_col)
        t.append(f"  Interface: vmbr0\n", style="dim")
        t.append(f"\n  ─ Recent IDS Hits ─\n", style="dim #3b4261")
        if alerts:
            for a in alerts[-4:]:
                sev = a.get('sev', 3)
                sev_col = "bright_red" if sev == 1 else ("yellow" if sev == 2 else "dim white")
                t.append(f"  {a['ts'][11:19]}  ", style="dim cyan")
                t.append(f"{a['src']:<15}  ", style="bright_blue")
                t.append(f"{a['sig']}\n", style=sev_col)
        else:
            t.append("  No recent hits\n", style="dim")
        self.query_one("#suricata-panel", Static).update(t)

    def _update_netmap(self):
        map_text = Text()
        map_text.append("  ┌─ HOME LAB ──────────────────┐\n", style="#3b4261")
        map_text.append("  │  ", style="#3b4261")
        map_text.append("192.168.x.x/24", style="bright_white")
        map_text.append("            │\n", style="#3b4261")
        map_text.append("  │                              │\n", style="#3b4261")

        nodes = [
            ("🛡️", ".212", "wazuh-server  "),
            ("📊", ".74 ", "splunk-server "),
            ("🐝", ".75 ", "thehive-server"),
            ("🖥️", ".76 ", "win10-endpoint"),
            ("💀", ".87 ", "kali-attacker "),
            ("🤡", ".20 ", "Clawdbot      "),
        ]
        for icon, ip, name in nodes:
            map_text.append("  │  ", style="#3b4261")
            map_text.append(f"{icon} ")
            map_text.append(f"192.168.1{ip}  ", style="bright_cyan")
            map_text.append(f"{name}", style="dim white")
            map_text.append("│\n", style="#3b4261")

        map_text.append("  └──────────────────────────────┘\n", style="#3b4261")
        map_text.append("  Proxmox: 192.168.x.x\n", style="dim")
        map_text.append("  Router:  192.168.x.x", style="dim")
        self.query_one("#netmap", Static).update(map_text)


if __name__ == "__main__":
    app = WarRoom()
    app.run()
