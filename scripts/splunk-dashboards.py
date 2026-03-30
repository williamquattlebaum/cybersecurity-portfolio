#!/usr/bin/env python3
"""
📊 SPLUNK DASHBOARD BUILDER
Creates pre-built SOC dashboards in Splunk using the REST API.
Generates SPL queries from your Wazuh data structure and pushes
full dashboards with panels, charts, and tables.

Dashboards created:
  1. SOC Overview — alert counts, top rules, severity breakdown
  2. Threat Hunter — top source IPs, attack patterns, MITRE heatmap
  3. Agent Health — per-agent alert volume, last seen, rule distribution
  4. Compliance — CIS benchmark findings, SCA pass/fail trends

Usage:
  python3 splunk-dashboards.py          # create all dashboards
  python3 splunk-dashboards.py --list   # list existing dashboards
  python3 splunk-dashboards.py --delete # delete our dashboards (clean reinstall)
"""

import requests, json, sys, argparse
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SPLUNK_HOST = "192.168.x.x"
SPLUNK_PORT = 8089
SPLUNK_USER = "admin"
SPLUNK_PASS = "Splunk2026!"
BASE_URL    = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
APP         = "search"  # deploy into search app

# ─── Splunk API helpers ───────────────────────────────────────────────────────

def splunk_get(path, params=None):
    try:
        r = requests.get(f"{BASE_URL}{path}", auth=(SPLUNK_USER, SPLUNK_PASS),
                         params={**(params or {}), "output_mode": "json"},
                         verify=False, timeout=15)
        return r.json() if r.ok else None
    except Exception as e:
        print(f"  [GET error] {e}")
        return None

def splunk_post(path, data):
    try:
        r = requests.post(f"{BASE_URL}{path}", auth=(SPLUNK_USER, SPLUNK_PASS),
                          data={**data, "output_mode": "json"},
                          verify=False, timeout=15)
        return r.json(), r.status_code
    except Exception as e:
        print(f"  [POST error] {e}")
        return None, 0

def splunk_delete(path):
    try:
        r = requests.delete(f"{BASE_URL}{path}", auth=(SPLUNK_USER, SPLUNK_PASS),
                            verify=False, timeout=15)
        return r.status_code
    except:
        return 0

def test_connection():
    result = splunk_get("/services/server/info")
    if result:
        info = result['entry'][0]['content']
        print(f"  ✓ Splunk {info.get('version')} — {info.get('serverName')}")
        return True
    print(f"  ✗ Cannot reach Splunk at {BASE_URL}")
    return False

# ─── Dashboard XML builder ────────────────────────────────────────────────────

def make_dashboard(title, description, panels):
    """Build Splunk Simple XML dashboard."""
    panels_xml = "\n".join(panels)
    return f"""<dashboard version="1.1" theme="dark">
  <label>{title}</label>
  <description>{description}</description>
  <row>
{panels_xml}
  </row>
</dashboard>"""

def single_value_panel(title, spl, color="#53a051"):
    return f"""    <panel>
      <single>
        <title>{title}</title>
        <search><query>{spl}</query><earliest>-24h</earliest><latest>now</latest></search>
        <option name="colorBy">value</option>
        <option name="colorMode">block</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xf1813f","0xdc4e41"]</option>
      </single>
    </panel>"""

def bar_chart_panel(title, spl, earliest="-24h"):
    return f"""    <panel>
      <chart>
        <title>{title}</title>
        <search><query>{spl}</query><earliest>{earliest}</earliest><latest>now</latest></search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.showDataLabels">minmax</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="charting.axisTitleX.visibility">collapsed</option>
        <option name="charting.drilldown">none</option>
        <option name="height">300</option>
      </chart>
    </panel>"""

def pie_chart_panel(title, spl, earliest="-24h"):
    return f"""    <panel>
      <chart>
        <title>{title}</title>
        <search><query>{spl}</query><earliest>{earliest}</earliest><latest>now</latest></search>
        <option name="charting.chart">pie</option>
        <option name="charting.drilldown">none</option>
        <option name="height">300</option>
      </chart>
    </panel>"""

def timechart_panel(title, spl, earliest="-7d"):
    return f"""    <panel>
      <chart>
        <title>{title}</title>
        <search><query>{spl}</query><earliest>{earliest}</earliest><latest>now</latest></search>
        <option name="charting.chart">line</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="charting.axisTitleX.visibility">collapsed</option>
        <option name="charting.drilldown">none</option>
        <option name="height">300</option>
      </chart>
    </panel>"""

def table_panel(title, spl, earliest="-24h"):
    return f"""    <panel>
      <table>
        <title>{title}</title>
        <search><query>{spl}</query><earliest>{earliest}</earliest><latest>now</latest></search>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="totalsRow">false</option>
        <option name="count">15</option>
      </table>
    </panel>"""

# ─── Dashboard definitions ────────────────────────────────────────────────────

def build_soc_overview():
    panels = []

    # Row 1: Single value KPIs
    panels.append("""  <row>""")
    panels.append(single_value_panel("Total Alerts (24h)",
        "search index=main sourcetype=wazuh | stats count"))
    panels.append(single_value_panel("Critical Alerts (lvl 12+)",
        "search index=main sourcetype=wazuh | where rule.level>=12 | stats count"))
    panels.append(single_value_panel("High Alerts (lvl 10-11)",
        "search index=main sourcetype=wazuh | where rule.level&gt;=10 AND rule.level&lt;12 | stats count"))
    panels.append(single_value_panel("Active Agents",
        "search index=main sourcetype=wazuh | stats dc(agent.name) as count"))
    panels.append("""  </row>
  <row>""")

    # Row 2: Alert volume over time
    panels.append(timechart_panel("Alert Volume (7 Days)",
        "search index=main sourcetype=wazuh | timechart span=1h count by rule.level", earliest="-7d"))
    panels.append(pie_chart_panel("Alert Severity Distribution",
        "search index=main sourcetype=wazuh | eval severity=case(rule.level&gt;=12,\"Critical\",rule.level&gt;=10,\"High\",rule.level&gt;=7,\"Medium\",1=1,\"Low\") | stats count by severity"))
    panels.append("""  </row>
  <row>""")

    # Row 3: Top rules + agents
    panels.append(bar_chart_panel("Top 10 Alert Rules",
        "search index=main sourcetype=wazuh | stats count by rule.description | sort -count | head 10"))
    panels.append(table_panel("Recent Critical Alerts",
        "search index=main sourcetype=wazuh rule.level>=10 | table _time agent.name rule.level rule.description | sort -_time | head 10"))
    panels.append("""  </row>""")

    xml = f"""<dashboard version="1.1" theme="dark">
  <label>SOC Overview</label>
  <description>Home SOC Lab — Wazuh Alert Overview Dashboard</description>
  {"".join(panels)}
</dashboard>"""
    return xml


def build_threat_hunter():
    panels = []
    panels.append("""  <row>""")
    panels.append(single_value_panel("Unique Source IPs (24h)",
        "search index=main sourcetype=wazuh data.srcip=* | stats dc(data.srcip) as count"))
    panels.append(single_value_panel("Brute Force Events",
        "search index=main sourcetype=wazuh rule.groups=authentication_failures | stats count"))
    panels.append(single_value_panel("Blocked IPs (Active Response)",
        "search index=main sourcetype=wazuh rule.id=651 | stats count"))
    panels.append("""  </row>
  <row>""")
    panels.append(bar_chart_panel("Top Attacking IPs",
        "search index=main sourcetype=wazuh data.srcip=* | stats count by data.srcip | sort -count | head 10"))
    panels.append(bar_chart_panel("Top MITRE ATT&amp;CK Techniques",
        "search index=main sourcetype=wazuh rule.mitre.technique=* | stats count by rule.mitre.technique | sort -count | head 10"))
    panels.append("""  </row>
  <row>""")
    panels.append(timechart_panel("Authentication Failures Over Time",
        "search index=main sourcetype=wazuh rule.groups=authentication_failures | timechart span=1h count",
        earliest="-7d"))
    panels.append(table_panel("Recent Attack Events",
        "search index=main sourcetype=wazuh rule.level>=7 data.srcip=* | table _time data.srcip agent.name rule.description rule.mitre.technique | sort -_time | head 15"))
    panels.append("""  </row>""")

    xml = f"""<dashboard version="1.1" theme="dark">
  <label>Threat Hunter</label>
  <description>Adversarial activity — source IPs, MITRE techniques, brute force patterns</description>
  {"".join(panels)}
</dashboard>"""
    return xml


def build_agent_health():
    panels = []
    panels.append("""  <row>""")
    panels.append(bar_chart_panel("Alert Volume by Agent",
        "search index=main sourcetype=wazuh | stats count by agent.name | sort -count"))
    panels.append(pie_chart_panel("Alert Distribution by Agent",
        "search index=main sourcetype=wazuh | stats count by agent.name"))
    panels.append("""  </row>
  <row>""")
    panels.append(table_panel("Agent Summary (24h)",
        "search index=main sourcetype=wazuh | stats count min(_time) as first max(_time) as last dc(rule.id) as unique_rules by agent.name | eval last_seen=strftime(last,\"%Y-%m-%d %H:%M\") | table agent.name count unique_rules last_seen | sort -count"))
    panels.append(timechart_panel("Per-Agent Alert Volume (7d)",
        "search index=main sourcetype=wazuh | timechart span=6h count by agent.name",
        earliest="-7d"))
    panels.append("""  </row>""")

    xml = f"""<dashboard version="1.1" theme="dark">
  <label>Agent Health</label>
  <description>Per-agent alert volume, activity, and rule coverage</description>
  {"".join(panels)}
</dashboard>"""
    return xml


def build_compliance():
    panels = []
    panels.append("""  <row>""")
    panels.append(single_value_panel("SCA Checks (Total)",
        "search index=main sourcetype=wazuh rule.groups=sca | stats count"))
    panels.append(single_value_panel("SCA Failures",
        "search index=main sourcetype=wazuh rule.groups=sca data.sca.result=failed | stats count"))
    panels.append(single_value_panel("CIS Benchmark Events",
        "search index=main sourcetype=wazuh rule.description=*CIS* | stats count"))
    panels.append("""  </row>
  <row>""")
    panels.append(bar_chart_panel("Top CIS Failing Controls",
        "search index=main sourcetype=wazuh rule.groups=sca data.sca.result=failed | stats count by data.sca.check.title | sort -count | head 10"))
    panels.append(timechart_panel("SCA Pass vs Fail Over Time",
        "search index=main sourcetype=wazuh rule.groups=sca | timechart span=1d count by data.sca.result",
        earliest="-30d"))
    panels.append("""  </row>
  <row>""")
    panels.append(table_panel("Recent Compliance Violations",
        "search index=main sourcetype=wazuh rule.groups=sca data.sca.result=failed | table _time agent.name data.sca.check.title data.sca.check.reason | sort -_time | head 15"))
    panels.append("""  </row>""")

    xml = f"""<dashboard version="1.1" theme="dark">
  <label>Compliance</label>
  <description>CIS Benchmark and SCA compliance tracking</description>
  {"".join(panels)}
</dashboard>"""
    return xml


# ─── Push to Splunk ───────────────────────────────────────────────────────────

DASHBOARDS = [
    ("soc_overview_bozo",  "SOC Overview",    build_soc_overview),
    ("threat_hunter_bozo", "Threat Hunter",   build_threat_hunter),
    ("agent_health_bozo",  "Agent Health",    build_agent_health),
    ("compliance_bozo",    "Compliance",      build_compliance),
]

def push_dashboard(name, title, xml):
    # Try update first, then create
    result, code = splunk_post(
        f"/servicesNS/admin/{APP}/data/ui/views/{name}",
        {"eai:data": xml}
    )
    if code in (200, 201):
        print(f"  ✓ Updated: {title}")
        return True

    # Create new
    result, code = splunk_post(
        f"/servicesNS/admin/{APP}/data/ui/views",
        {"name": name, "eai:data": xml}
    )
    if code in (200, 201):
        print(f"  ✓ Created: {title}")
        return True

    print(f"  ✗ Failed ({code}): {title}")
    if result:
        msgs = result.get('messages', [])
        for m in msgs:
            print(f"    {m.get('text', '')}")
    return False

def list_dashboards():
    result = splunk_get(f"/servicesNS/admin/{APP}/data/ui/views",
                        {"count": 50, "search": "bozo"})
    if not result:
        print("  No dashboards found")
        return
    entries = result.get('entry', [])
    bozo = [e for e in entries if 'bozo' in e['name']]
    if not bozo:
        print("  No Bozo dashboards found yet — run without --list to create them")
        return
    print(f"\n  {'Name':<30} {'Label'}")
    print("  " + "-"*50)
    for e in bozo:
        label = e['content'].get('label', e['name'])
        print(f"  {e['name']:<30} {label}")

def delete_dashboards():
    for name, title, _ in DASHBOARDS:
        code = splunk_delete(f"/servicesNS/admin/{APP}/data/ui/views/{name}")
        if code in (200, 201, 204):
            print(f"  ✓ Deleted: {title}")
        else:
            print(f"  - Not found or error ({code}): {title}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"\n📊 Splunk Dashboard Builder")

    if not test_connection():
        sys.exit(1)

    print(f"\n  Building and pushing {len(DASHBOARDS)} dashboards...\n")

    success = 0
    for name, title, builder in DASHBOARDS:
        xml = builder()
        if push_dashboard(name, title, xml):
            success += 1

    print(f"\n  {success}/{len(DASHBOARDS)} dashboards deployed.")
    print(f"  View at: http://{SPLUNK_HOST}:8000/en-US/app/{APP}/dashboards")
    print(f"\n  Direct links:")
    for name, title, _ in DASHBOARDS:
        print(f"    {title}: http://{SPLUNK_HOST}:8000/en-US/app/{APP}/{name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Splunk Dashboard Builder")
    parser.add_argument("--list",   action="store_true", help="List existing dashboards")
    parser.add_argument("--delete", action="store_true", help="Delete our dashboards")
    args = parser.parse_args()

    if args.list:
        if test_connection(): list_dashboards()
    elif args.delete:
        if test_connection(): delete_dashboards()
    else:
        main()
