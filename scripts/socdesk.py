#!/usr/bin/env python3
"""
🖥️ SOC DESK — Unified War Room + Attack Map
Full-screen terminal dashboard for William's home lab.
Left pane: VM status, Wazuh services, alerts
Right pane: Live ASCII world attack map + Suricata feed

Run: python3 socdesk.py
"""

import subprocess, json, gzip, os, time, threading, requests
from datetime import datetime
from collections import deque, defaultdict
from queue import Queue, Empty

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, RichLog, Label, DataTable
from textual.containers import Horizontal, Vertical
from textual import work
from rich.text import Text

# ─── Config ───────────────────────────────────────────────────────────────────
PROXMOX_HOST = "192.168.x.x"
WAZUH_HOST   = "192.168.x.x"
SSH_KEY      = "/root/.ssh/proxmox_key"
EVE_LOG      = "/var/log/suricata/eve.json"

# ─── Map constants ────────────────────────────────────────────────────────────
MAP_ROWS, MAP_COLS = 20, 72
ASCII_WORLD = [
    "                                                                        ",
    "        ##    ########          ######      ##     ###                  ",
    "      #######  ###########    #########   #####  ######                 ",
    "     ######### ############  ##########  ###############                ",
    "   ########### ################################  #########              ",
    "   ########################################### ##########              ",
    "    ###########################################  #######   ###          ",
    "     ##########################################   #####  #####          ",
    "      ########################################        ######            ",
    "       #######################################       #####              ",
    "        ######################################      ####    #           ",
    "         #####################################      ###     #           ",
    "          ###################################                           ",
    "           #################################                            ",
    "            ###############################                             ",
    "             #############################                              ",
    "              ############################                              ",
    "                ########################                                ",
    "                   ##################                                   ",
    "                       ##########                                       ",
]

def latlon_to_xy(lat, lon):
    x = int((lon + 180) / 360 * (MAP_COLS - 1))
    y = int((90 - lat) / 180 * (MAP_ROWS - 1))
    return max(0, min(MAP_COLS-1, x)), max(0, min(MAP_ROWS-1, y))

PRIVATE_RANGES = ['192.168.','10.','172.16.','127.','0.']
def is_private(ip): return any(ip.startswith(r) for r in PRIVATE_RANGES)

geo_cache = {}
def geoip(ip):
    if ip in geo_cache: return geo_cache[ip]
    if is_private(ip): return None
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon",timeout=3)
        d = r.json()
        if d.get('status') == 'success':
            geo_cache[ip] = d
            return d
    except: pass
    return None

def ssh(host, cmd, timeout=8):
    try:
        r = subprocess.run(["ssh","-i",SSH_KEY,"-o","StrictHostKeyChecking=no",
                            "-o","ConnectTimeout=5",f"root@{host}",cmd],
                           capture_output=True,text=True,timeout=timeout)
        return r.stdout.strip()
    except: return ""

WAZUH_ALERT_SCRIPT = r"""
import json,gzip,os,sys
from datetime import datetime
base='/var/ossec/logs/alerts'
now=datetime.now()
month=now.strftime('%b'); year=str(now.year)
p=os.path.join(base,year,month)
if not os.path.isdir(p): sys.exit(0)
files=sorted([f for f in os.listdir(p) if f.endswith('.json') or f.endswith('.json.gz')])
alerts=[]
for f in files[-2:]:
    fp=os.path.join(p,f)
    try:
        fh=gzip.open(fp,'rt') if f.endswith('.gz') else open(fp)
        for line in fh:
            line=line.strip()
            if line:
                try: alerts.append(json.loads(line))
                except: pass
        fh.close()
    except: pass
for a in alerts[-10:]:
    print(json.dumps({'ts':a.get('timestamp','')[:19],'lvl':a.get('rule',{}).get('level',0),
        'agent':a.get('agent',{}).get('name','?'),'desc':a.get('rule',{}).get('description','?')[:52]}))
"""

def fetch_all_data():
    # VMs
    vms = []
    try:
        raw = ssh(PROXMOX_HOST,"pvesh get /nodes/pve/qemu --output-format json 2>/dev/null")
        for v in json.loads(raw):
            vms.append({'name':v['name'],'status':v['status'],
                        'cpu':round(v.get('cpu',0)*100,1),
                        'mem':round(v['mem']/v['maxmem']*100) if v.get('maxmem') else 0,
                        'uptime':v.get('uptime',0)//3600,'type':'VM'})
    except: pass
    try:
        raw = ssh(PROXMOX_HOST,"pvesh get /nodes/pve/lxc --output-format json 2>/dev/null")
        for c in json.loads(raw):
            vms.append({'name':c['name'],'status':c['status'],
                        'cpu':round(c.get('cpu',0)*100,1),
                        'mem':round(c['mem']/c['maxmem']*100) if c.get('maxmem') else 0,
                        'uptime':c.get('uptime',0)//3600,'type':'CT'})
    except: pass

    # Wazuh services
    svc_raw = ssh(WAZUH_HOST,"systemctl is-active wazuh-manager wazuh-dashboard wazuh-indexer")
    services = dict(zip(['manager','dashboard','indexer'],svc_raw.split('\n')[:3]))

    # Wazuh alerts
    alerts = []
    try:
        r = subprocess.run(["ssh","-i",SSH_KEY,"-o","StrictHostKeyChecking=no",
                            "-o","ConnectTimeout=10",f"root@{WAZUH_HOST}","python3 -"],
                           input=WAZUH_ALERT_SCRIPT,capture_output=True,text=True,timeout=15)
        for line in r.stdout.strip().split('\n'):
            if line.strip():
                try: alerts.append(json.loads(line))
                except: pass
    except: pass

    # Suricata count
    suri_count = 0
    raw = ssh(PROXMOX_HOST,"grep '\"event_type\":\"alert\"' /var/log/suricata/eve.json 2>/dev/null | wc -l")
    try: suri_count = int(raw.strip())
    except: pass

    # Host stats
    host = {'cpu':0,'mem':0,'uptime':0}
    try:
        raw = ssh(PROXMOX_HOST,"pvesh get /nodes/pve/status --output-format json 2>/dev/null")
        d = json.loads(raw)
        host = {'cpu':round(d.get('cpu',0)*100,1),
                'mem':round(d['memory']['used']/d['memory']['total']*100),
                'uptime':d.get('uptime',0)//3600}
    except: pass

    return vms, services, alerts, suri_count, host

def tail_suricata(q: Queue):
    cmd=["ssh","-i",SSH_KEY,"-o","StrictHostKeyChecking=no","-o","ConnectTimeout=10",
         "-o","ServerAliveInterval=30",f"root@{PROXMOX_HOST}",f"tail -F {EVE_LOG} 2>/dev/null"]
    try:
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        for line in proc.stdout:
            line=line.strip()
            if not line: continue
            try:
                e=json.loads(line)
                if e.get('event_type')=='alert':
                    src=e.get('src_ip','')
                    if src and not is_private(src):
                        q.put({'ts':e.get('timestamp','')[:19],'src':src,
                               'sig':e.get('alert',{}).get('signature','?')[:42],
                               'sev':e.get('alert',{}).get('severity',3)})
            except: pass
    except: pass

VM_ICONS = {'wazuh-server':'🛡️','win10-endpoint':'🖥️','kali-attacker':'💀',
            'splunk-server':'📊','thehive-server':'🐝','Clawdbot':'🤡'}

def mem_bar(pct,w=8):
    filled=round(pct/100*w)
    col='bright_red' if pct>=90 else 'yellow' if pct>=70 else 'bright_green'
    return Text('█'*filled+'░'*(w-filled)+f' {pct:3}%',style=col)

def flag(code):
    if len(code)!=2: return '🌐'
    return chr(0x1F1E6+ord(code[0])-ord('A'))+chr(0x1F1E6+ord(code[1])-ord('A'))

# ─── App ──────────────────────────────────────────────────────────────────────

class SOCDesk(App):
    CSS = """
    Screen { background: #07090f; color: #c0caf5; }
    Header { background: #0d1117; color: #7dcfff; text-style: bold; }
    Footer { background: #0d1117; color: #565f89; }

    #left { width: 44; border-right: solid #1a2040; padding: 0 1; }
    #right { width: 1fr; }

    .sec { color: #7aa2f7; text-style: bold; margin-top: 1; }

    #vm-table { height: auto; }
    DataTable { background: #07090f; }
    DataTable > .datatable--header { background: #0d1117; color: #7aa2f7; text-style: bold; }
    DataTable > .datatable--cursor { background: #0d1117; }

    #wazuh-svc { height: 5; }
    #wazuh-alerts { height: 1fr; border: solid #1a2040; background: #07090f; margin-top: 1; }

    #map-area { height: 22; background: #07090f; padding: 0 1; }
    #suri-feed { height: 1fr; border-top: solid #1a2040; background: #07090f; }
    #clock-strip { height: 1; color: #e0af68; text-style: bold; padding: 0 1; }
    """

    TITLE = "🤡 SOC DESK — HOME LAB COMMAND CENTER"
    BINDINGS = [("q","quit","Quit"),("r","manual_refresh","Refresh")]

    def __init__(self):
        super().__init__()
        self.eq = Queue()
        self.dots = {}
        self.country_counts = defaultdict(int)
        self.map_total = 0

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="left"):
                yield Label("◈ PROXMOX HOST", classes="sec")
                yield Static("", id="host-stats")
                yield Label("◈ VMs", classes="sec")
                yield DataTable(id="vm-table", show_cursor=False)
                yield Label("◈ WAZUH SERVICES", classes="sec")
                yield Static("", id="wazuh-svc")
                yield Label("◈ RECENT ALERTS", classes="sec")
                yield RichLog(id="wazuh-alerts", highlight=False, markup=True, wrap=True)
            with Vertical(id="right"):
                yield Static("", id="clock-strip")
                yield Static("", id="map-area")
                yield RichLog(id="suri-feed", highlight=False, markup=True, wrap=False)
        yield Footer()

    def on_mount(self):
        t = self.query_one("#vm-table", DataTable)
        t.add_columns("", "Name", "CPU", "RAM", "Up")
        threading.Thread(target=tail_suricata, args=(self.eq,), daemon=True).start()
        self.refresh_static()
        self.set_interval(0.5, self.poll_map)
        self.set_interval(1.0, self.redraw_map)
        self.set_interval(30, self.refresh_static)
        self.set_interval(1, self.tick_clock)

    def tick_clock(self):
        now = datetime.now()
        self.query_one("#clock-strip", Static).update(
            Text(f"  {now.strftime('%H:%M:%S')}  {now.strftime('%A %b %d %Y')}  ◈  IDS hits: {self.map_total:,}", style="#e0af68 bold"))

    def action_manual_refresh(self): self.refresh_static()

    @work(thread=True)
    def refresh_static(self):
        vms, services, alerts, suri_count, host = fetch_all_data()
        self.app.call_from_thread(self._update_host, host)
        self.app.call_from_thread(self._update_vms, vms)
        self.app.call_from_thread(self._update_services, services)
        self.app.call_from_thread(self._update_alerts, alerts)

    def _update_host(self, h):
        t = Text()
        t.append(f"  192.168.x.x  UP:{h['uptime']}h\n", style="dim")
        cpu_col = 'bright_red' if h['cpu']>=80 else 'yellow' if h['cpu']>=50 else 'bright_cyan'
        t.append(f"  CPU: "); t.append(f"{h['cpu']:4.1f}%  ", style=cpu_col)
        mem_col = 'bright_red' if h['mem']>=90 else 'yellow' if h['mem']>=70 else 'bright_green'
        t.append(f"RAM: "); t.append(f"{h['mem']}%", style=mem_col)
        self.query_one("#host-stats", Static).update(t)

    def _update_vms(self, vms):
        tbl = self.query_one("#vm-table", DataTable)
        tbl.clear()
        for v in sorted(vms, key=lambda x: x['name']):
            icon = VM_ICONS.get(v['name'], '💻')
            s_col = 'bright_green' if v['status']=='running' else 'bright_red'
            tbl.add_row(
                Text('●', style=s_col),
                Text(f"{icon} {v['name']}", style='white'),
                Text(f"{v['cpu']:4.1f}%", style='bright_cyan' if v['cpu']<50 else 'yellow'),
                mem_bar(v['mem']),
                Text(f"{v['uptime']}h", style='dim')
            )

    def _update_services(self, svcs):
        t = Text()
        for name, status in svcs.items():
            col = 'bright_green' if status=='active' else 'bright_red'
            dot = '●' if status=='active' else '✗'
            t.append(f"  {dot} wazuh-{name:<12}", style=col)
            t.append(f"  {status}\n", style=col)
        self.query_one("#wazuh-svc", Static).update(t)

    def _update_alerts(self, alerts):
        log = self.query_one("#wazuh-alerts", RichLog)
        log.clear()
        if not alerts:
            log.write(Text("  no recent alerts", style="dim"))
            return
        for a in reversed(alerts):
            lvl = a.get('lvl',0)
            col = 'bright_red' if lvl>=12 else 'red' if lvl>=10 else 'yellow' if lvl>=7 else 'bright_cyan' if lvl>=4 else 'dim white'
            badge = '☠' if lvl>=12 else '▲' if lvl>=10 else '●' if lvl>=7 else '○'
            line = Text()
            line.append(f"  {badge} ", style=col)
            line.append(f"{a.get('ts','')[11:19]} ", style="dim cyan")
            line.append(f"{a.get('agent','?')[:14]:<14} ", style="bright_blue")
            line.append(a.get('desc','?'), style=col)
            log.write(line)

    def poll_map(self):
        processed = 0
        while processed < 5:
            try:
                e = self.eq.get_nowait()
                self.app.call_from_thread(self._resolve_and_plot, e)
                processed += 1
            except Empty:
                break

    @work(thread=True)
    def _resolve_and_plot(self, e):
        self.map_total += 1
        geo = geoip(e['src'])
        if not geo: return
        self.country_counts[geo.get('country','?')] += 1
        x, y = latlon_to_xy(geo['lat'], geo['lon'])
        sev = e['sev']
        char = '☠' if sev==1 else '▲' if sev==2 else '●'
        col  = 'bright_red' if sev==1 else 'red' if sev==2 else 'yellow'
        self.dots[(x,y)] = {'char':char,'col':col,'ttl':10,'geo':geo,'e':e}
        self.app.call_from_thread(self._add_suri_line, e, geo)

    def _add_suri_line(self, e, geo):
        f = self.query_one("#suri-feed", RichLog)
        sev_col = 'bright_red' if e['sev']==1 else 'red' if e['sev']==2 else 'yellow'
        fl = flag(geo.get('countryCode','??'))
        line = Text()
        line.append(f"  {e['ts'][11:19]} ", style="dim cyan")
        line.append(f"{fl} {geo.get('city','?')[:12]:<12} ", style="white")
        line.append(f"{e['src']:<16} ", style="bright_blue")
        line.append(e['sig'], style=sev_col)
        f.write(line)

    def redraw_map(self):
        # Decay dots
        for k in list(self.dots.keys()):
            self.dots[k]['ttl'] -= 1
            if self.dots[k]['ttl'] <= 0:
                del self.dots[k]

        # Home base
        hx, hy = latlon_to_xy(33.8, -84.3)

        out = Text()
        # Top countries strip
        top = sorted(self.country_counts.items(), key=lambda x:-x[1])[:5]
        strip = "  "
        for c, n in top:
            strip += f"{c}: {n}  "
        out.append(strip[:MAP_COLS+2] + "\n", style="dim #3b4261")

        for ry, row in enumerate(ASCII_WORLD):
            out.append("  ")
            for rx, ch in enumerate(row.ljust(MAP_COLS)):
                pos = (rx, ry)
                if pos in self.dots:
                    d = self.dots[pos]
                    ttl = d['ttl']
                    style = f"bold {d['col']}" if ttl>7 else d['col'] if ttl>4 else f"dim {d['col']}"
                    out.append(d['char'], style=style)
                elif rx==hx and ry==hy:
                    out.append('⌂', style="bold bright_green")
                elif ch=='#':
                    out.append('·', style="#1e3a5f")
                else:
                    out.append(' ')
            out.append("\n")

        out.append(f"  ⌂ Decatur GA  |  hits today: {self.map_total:,}  |  geo resolved: {len(self.dots)} active",
                   style="dim #3b4261")
        self.query_one("#map-area", Static).update(out)


if __name__ == "__main__":
    SOCDesk().run()
