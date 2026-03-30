#!/usr/bin/env python3
"""
🌍 LIVE ATTACK MAP — BOZO SOC COMMAND CENTER
Real-time ASCII world map showing Suricata IDS hits by geolocation.
"""

import subprocess
import json
import time
import threading
import requests
from collections import deque, defaultdict
from datetime import datetime
from queue import Queue, Empty

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, RichLog, Label
from textual.containers import Horizontal, Vertical
from textual import work
from rich.text import Text

# ─── Config ───────────────────────────────────────────────────────────────────

PROXMOX_HOST = "192.168.x.x"
SSH_KEY      = "/root/.ssh/proxmox_key"
EVE_LOG      = "/var/log/suricata/eve.json"

# ─── ASCII World Map (equirectangular, 118 wide × 35 tall) ────────────────────
# lat range: +90 (top) to -90 (bottom)
# lon range: -180 (left) to +180 (right)

WORLD_MAP = """\
                                                                                                                      
              . .   .     .ooooo.              .oooooo.                  .ooooo.        .oooooo.                      
           .oooo.  . .   d88' `"Y8            d8P'  `Y8b                d88' `"Y8      d8P'  `Y8b                    
          d8P  `Y8b.     888                 888      888               888            888      888                   
          888   888      888ooooo8  .oooo.   888      888               888ooooo8      888      888                   
          888   888      888    "  `P  )88b  888      888               888    "       888      888                   
          `88bod8P'      888       .oP"888   `88b    d88'               888       o    `88b    d88'                   
          `8oooooo.      o888o      8888"88b   `Y8bood8P'               o888ooooood8     `Y8bood8P'                   
          d"     YD                `8b  d8'                                                                           
          "Y88888P'                 `Y888"                                                                            
                                                                                                                      
           .oooo.   ooo        ooooo oooooooooooo ooooooooo.   ooooo   .oooooo.         .o.                          
          `P  )88b  `88.       .888' `888'     `8 `888   `Y88. `888'  d8P'  `Y8b       .888.                         
           .oP"888   888b     d'888   888          888   .d88'  888  888               .8"888.                        
          d8(  888   8 Y88. .P  888   888oooo8     888ooo88P'   888  888              .8' `888.                       
          88ooo888   8  `888'   888   888    "     888`88b.     888  888             .88ooo8888.                      
               888   8    Y    888   888       o  888  `88b.   888  `88b    ooo    .8'     `888.                      
              o888o o8o        o888o o888ooooood8 o888o  o888o o888o  `Y8bood8P'  o88o     o8888o                     
                                                                                                                      
                         .o.                .o.       ooooo                                                           
                        .888.              .888.      `888'                                                           
                       .8"888.            .8"888.      888                                                            
                      .8' `888.          .8' `888.     888                                                            
                     .88ooo8888.        .88ooo8888.    888                                                            
                    .8'     `888.      .8'     `888.   888       o                                                    
                   o88o     o8888o    o88o     o8888o o888ooooood8                                                    """

# Simple flat ASCII map for plotting (each char = ~1.5° lat, ~3° lon approx)
# We'll use a cleaner map with known dimensions

FLAT_MAP = [
    "                                                                                    ",
    "          .:      .:::.    .::.      ..:         ::.   .::.  .:  .:               ",
    "     .::.:::::  .:::::::::::::::.  .:::::.     :::::::::::: :::::::::.             ",
    "    ::::::::::::::::::::::::::::: ::::::::::::::::::::::::::::::::::::.            ",
    "    :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            ",
    "     :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            ",
    "      :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::             ",
    "      .:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            ",
    "       :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            ",
    "        .:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            ",
    "         .:::::::::::::::::::::::::::::::::::::::::::::::::::::::::.              ",
    "          :::::::::::::::::::::::::::::::::::::::::::::::::::::::.                ",
    "           .:::::::::::::::::::::::::::::::::::::::::::::::::::::.                ",
    "             .::::::::::::::::::::::::::::::::::::::::::::::::::.                 ",
    "              .::::::::::::::::::::::::::::::::::::::::::::::::.                  ",
    "               .::::::::::::::::::::::::::::::::::::::::::::::                    ",
    "                .::::::::::::::::::::::::::::::::::::::::::.                      ",
    "                 .::::::::::::::::::::::::::::::::::::::::                        ",
    "                   .:::::::::::::::::::::::::::::::::::.                          ",
    "                     .::::::::::::::::::::::::::::::.                             ",
    "                       .::::::::::::::::::::::::::.                               ",
    "                          .:::::::::::::::::::::.                                 ",
    "                             .::::::::::::::::.                                   ",
    "                                .::::::::::.                                      ",
]

# Better map with real continent shapes (80 wide x 24 tall)
WORLD = """\
         .....          ...........           ......          .....                     
       .:::::::.       .::::::::::::::..    .::::::::.      .:::::.                    
      .:::::::::.     .::::::::::::::::::::.:::::::::::.   .:::::::::..                
     .:::::::::::.   .::::::::::::::::::::::::::::::::::.  .:::::::::::.               
     ::::::::::::.   :::::::::::::::::::::::::::::::::::::.:::::::::::::               
      :::::::::::.  .:::::::::::::::::::::::::::::::::::::.::::::::::::.               
       .:::::::::.  .::::::::::::::::::::::::::::::::::::::::::::::::::.               
        .:::::::::..:::::::::::::::::::::::::::::::::::::::::::::::::::                
          .::::::::::::::::::::::::::::::::::::::::::::::::::::::::::.                 
            .:::::::::::::::::::::::::::::::::::::::::::::::::::::.                    
             .:::::::::::::::::::::::::::::::::::::::::::::::::::.   .::.              
              .::::::::::::::::::::::::::::::::::::::::::::::::::.  .:::.              
               .::::::::::::::::::::::::::::::::::::::::::::::::.   .:::               
                .:::::::::::::::::::::::::::::::::::::::::::::.      .:.               
                  .::::::::::::::::::::::::::::::::::::::::::                          
                   .::::::::::::::::::::::::::::::::::::::.                            
                     .:::::::::::::::::::::::::::::::::.                               
                       .:::::::::::::::::::::::::::.                                   
                          .::::::::::::::::::::.                                       
                              .::::::::::.                                             """

# Use a proper ASCII world map (80 cols × 23 rows) with equirectangular projection
# lon: -180..+180 maps to col 0..79
# lat: +90..-90 maps to row 0..22

MAP_ROWS = 23
MAP_COLS = 80

# Proper continent-shaped ASCII world map
ASCII_WORLD = [
    "                                                                                ",
    "         ##   ###       ##########          ######      ##     ####            ",
    "       #######        ###############     #########    ###  ########           ",
    "      #########      ##################  ##########  ##############            ",
    "    ########### #### ####################################  #########           ",
    "    ########################################### ########   #########           ",
    "     ##########################################  ######    ########            ",
    "      ##########################################  ####    ########             ",
    "       #########################################  ###    #######              ",
    "        ########################################        ######               ",
    "         ######################################        #####    ##           ",
    "          #####################################       ####      ##           ",
    "           ###################################        ##                     ",
    "            #################################                                ",
    "             ##############################                                  ",
    "              ############################                                   ",
    "               ###########################                                   ",
    "                 ########################                                    ",
    "                   ####################                                      ",
    "                      ##############                                         ",
    "                          ######                                             ",
    "                                                                             ",
    "                                                                             ",
]

def latlon_to_xy(lat, lon):
    """Convert lat/lon to ASCII map x,y coordinates."""
    # Equirectangular projection
    x = int((lon + 180) / 360 * (MAP_COLS - 1))
    y = int((90 - lat) / 180 * (MAP_ROWS - 1))
    x = max(0, min(MAP_COLS - 1, x))
    y = max(0, min(MAP_ROWS - 1, y))
    return x, y


# ─── IP Geo cache ─────────────────────────────────────────────────────────────

geo_cache = {}
geo_queue = Queue()
PRIVATE_RANGES = ['192.168.', '10.', '172.16.', '172.17.', '172.18.',
                  '172.19.', '172.2', '127.', '0.', '::1']

def is_private(ip):
    return any(ip.startswith(r) for r in PRIVATE_RANGES)

def geoip(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    if is_private(ip):
        return None
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp",
                         timeout=3)
        d = r.json()
        if d.get('status') == 'success':
            geo_cache[ip] = d
            return d
    except:
        pass
    return None


# ─── Suricata tail ────────────────────────────────────────────────────────────

def tail_suricata(event_queue: Queue):
    """SSH tail -F suricata eve.json, push alert events to queue."""
    cmd = [
        "ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30",
        f"root@{PROXMOX_HOST}",
        f"tail -F {EVE_LOG} 2>/dev/null"
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if e.get('event_type') == 'alert':
                    src = e.get('src_ip', '')
                    if src and not is_private(src):
                        event_queue.put({
                            'ts': e.get('timestamp', '')[:19],
                            'src': src,
                            'dst': e.get('dest_ip', '?'),
                            'sig': e.get('alert', {}).get('signature', '?')[:50],
                            'sev': e.get('alert', {}).get('severity', 3),
                            'proto': e.get('proto', '?'),
                        })
            except:
                pass
    except Exception as e:
        pass


# ─── App ──────────────────────────────────────────────────────────────────────

class AttackMap(App):
    CSS = """
    Screen {
        background: #050508;
        color: #c0caf5;
    }
    Header {
        background: #0d1117;
        color: #f7768e;
        text-style: bold;
    }
    Footer {
        background: #0d1117;
        color: #565f89;
    }
    #map-panel {
        height: 27;
        border: solid #1a2040;
        background: #070b12;
        margin: 0 1;
        padding: 0 1;
    }
    #bottom-row {
        height: 1fr;
    }
    #feed-panel {
        width: 1fr;
        border: solid #1a2040;
        background: #070b12;
        margin: 0 1;
    }
    #stats-panel {
        width: 36;
        border: solid #1a2040;
        background: #070b12;
        margin: 0 1;
        padding: 0 1;
    }
    """

    TITLE = "🌍 LIVE ATTACK MAP — BOZO SOC"
    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self):
        super().__init__()
        self.event_queue = Queue()
        self.hits = deque(maxlen=200)         # recent hits with geo
        self.active_dots = {}                  # (x,y) -> (char, color, ttl)
        self.country_counts = defaultdict(int)
        self.sig_counts = defaultdict(int)
        self.total_alerts = 0
        self.geo_hits = 0

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="map-panel")
        with Horizontal(id="bottom-row"):
            yield RichLog(id="feed-panel", highlight=False, markup=True, wrap=False)
            yield Static("", id="stats-panel")
        yield Footer()

    def on_mount(self):
        # Start suricata tail in background thread
        t = threading.Thread(target=tail_suricata, args=(self.event_queue,), daemon=True)
        t.start()
        # Poll for new events every 0.5s
        self.set_interval(0.5, self.poll_events)
        # Redraw map every 1s (decay dots)
        self.set_interval(1.0, self.redraw_map)
        # Update stats every 5s
        self.set_interval(5.0, self.update_stats)
        self.redraw_map()
        self.update_stats()

    def poll_events(self):
        processed = 0
        while processed < 10:
            try:
                event = self.event_queue.get_nowait()
                self.process_event(event)
                processed += 1
            except Empty:
                break

    @work(thread=True)
    def process_event(self, event):
        """Resolve geo in thread, then update map."""
        self.total_alerts += 1
        self.sig_counts[event['sig'][:40]] += 1
        geo = geoip(event['src'])
        if geo:
            self.geo_hits += 1
            event['geo'] = geo
            self.country_counts[geo.get('country', '?')] += 1
            x, y = latlon_to_xy(geo['lat'], geo['lon'])
            sev = event['sev']
            if sev == 1:
                char, color = '☠', 'bright_red'
            elif sev == 2:
                char, color = '▲', 'red'
            else:
                char, color = '●', 'yellow'
            self.active_dots[(x, y)] = {'char': char, 'color': color, 'ttl': 8, 'event': event}
            self.hits.appendleft(event)
            self.app.call_from_thread(self.add_feed_line, event, geo)

    def add_feed_line(self, event, geo):
        log = self.query_one("#feed-panel", RichLog)
        sev = event['sev']
        sev_col = 'bright_red' if sev == 1 else ('red' if sev == 2 else 'yellow')
        flag = self._flag(geo.get('countryCode', '??'))
        line = Text()
        line.append(f"  {event['ts'][11:19]}  ", style="dim cyan")
        line.append(f"{flag} {geo.get('city','?'):<14}", style="white")
        line.append(f"  {event['src']:<16}", style="bright_blue")
        line.append(f"  {event['sig'][:42]}", style=sev_col)
        log.write(line)

    def _flag(self, code):
        """Convert country code to flag emoji."""
        if len(code) != 2:
            return "🌐"
        return chr(0x1F1E6 + ord(code[0]) - ord('A')) + chr(0x1F1E6 + ord(code[1]) - ord('A'))

    def redraw_map(self):
        # Decay TTLs
        to_remove = []
        for k in list(self.active_dots.keys()):
            self.active_dots[k]['ttl'] -= 1
            if self.active_dots[k]['ttl'] <= 0:
                to_remove.append(k)
        for k in to_remove:
            del self.active_dots[k]

        # Build map as list of Text rows
        map_rows = [list(row.ljust(MAP_COLS)) for row in ASCII_WORLD]

        # Home base marker (Decatur GA ~ 33.8°N, 84.3°W)
        hx, hy = latlon_to_xy(33.8, -84.3)
        if 0 <= hy < MAP_ROWS and 0 <= hx < MAP_COLS:
            map_rows[hy][hx] = '⌂'

        # Plot active dots
        dot_positions = {}
        for (x, y), dot in self.active_dots.items():
            dot_positions[(x, y)] = dot

        # Render
        output = Text()
        output.append(f"  lon: -180{'':>30}0{'':>30}+180   hits:{self.total_alerts:,}  geo:{self.geo_hits}\n",
                      style="dim #3b4261")

        for row_idx, row in enumerate(map_rows):
            output.append("  ")
            for col_idx, ch in enumerate(row):
                pos = (col_idx, row_idx)
                if pos in dot_positions:
                    dot = dot_positions[pos]
                    ttl = dot['ttl']
                    # Fade based on TTL
                    if ttl > 6:
                        style = f"bold {dot['color']}"
                    elif ttl > 3:
                        style = dot['color']
                    else:
                        style = "dim " + dot['color']
                    output.append(dot['char'], style=style)
                elif col_idx == hx and row_idx == hy:
                    output.append('⌂', style="bold bright_green")
                elif ch == '#':
                    output.append('·', style="#1e3a5f")
                elif ch == '.':
                    output.append('░', style="#0e2040")
                else:
                    output.append(ch, style="dim #0a0a14")
            output.append("\n")

        lat_label = "  lat: +90" + " " * 30 + "0" + " " * 30 + "-90"
        output.append(lat_label, style="dim #3b4261")

        self.query_one("#map-panel", Static).update(output)

    def update_stats(self):
        t = Text()
        now = datetime.now().strftime("%H:%M:%S")
        t.append(f"  ┌─ STATS {now} ─────────┐\n", style="dim #3b4261")
        t.append(f"  │ Total alerts: ", style="dim")
        t.append(f"{self.total_alerts:>7,}", style="bright_yellow")
        t.append(f"        │\n", style="dim #3b4261")
        t.append(f"  │ Geo resolved: ", style="dim")
        pct = round(self.geo_hits / max(self.total_alerts, 1) * 100)
        t.append(f"{self.geo_hits:>7,}", style="bright_cyan")
        t.append(f"  ({pct}%)  │\n", style="dim")
        t.append(f"  ├─ TOP COUNTRIES ──────────┤\n", style="dim #3b4261")

        top_countries = sorted(self.country_counts.items(), key=lambda x: -x[1])[:8]
        for country, count in top_countries:
            bar_len = min(12, int(count / max(1, self.geo_hits) * 12))
            bar = "█" * bar_len
            t.append(f"  │ {country[:16]:<16} ", style="white")
            t.append(f"{bar:<12}", style="bright_red")
            t.append(f" {count:>4}", style="dim")
            t.append(f" │\n", style="dim #3b4261")

        t.append(f"  ├─ TOP SIGNATURES ─────────┤\n", style="dim #3b4261")
        top_sigs = sorted(self.sig_counts.items(), key=lambda x: -x[1])[:5]
        for sig, count in top_sigs:
            t.append(f"  │ ", style="dim #3b4261")
            t.append(f"{sig[:24]:<24}", style="yellow")
            t.append(f" {count:>3}", style="dim")
            t.append(f" │\n", style="dim #3b4261")

        t.append(f"  │                          │\n", style="dim #3b4261")
        t.append(f"  │ ⌂ = 192.168.x.xx (home)  │\n", style="dim")
        t.append(f"  │ ☠ = sev1  ▲ = sev2       │\n", style="dim")
        t.append(f"  │ ● = sev3  dots fade/ttl  │\n", style="dim")
        t.append(f"  └──────────────────────────┘", style="dim #3b4261")

        self.query_one("#stats-panel", Static).update(t)


if __name__ == "__main__":
    print("Connecting to Suricata feed... (q to quit)")
    time.sleep(0.5)
    app = AttackMap()
    app.run()
