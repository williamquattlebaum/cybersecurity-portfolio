# Incident Report #003 — Suricata IDS Deployment & Network Detection Gap Closure

**Date:** March 2, 2026
**Analyst:** William Quattlebaum
**Type:** Infrastructure Improvement / Detection Engineering
**Status:** Complete

---

## Summary

Following the detection gap identified in Incident Report #002 (port scans not detected by host-based Wazuh agents), deployed Suricata IDS on the Proxmox hypervisor host to provide network-layer visibility across all lab traffic.

---

## Problem Statement

Wazuh is a host-based SIEM — it only sees what the OS sees. During the network reconnaissance simulation (IR #002), nmap port scans against the Windows endpoint generated zero Wazuh alerts because Windows Firewall dropped the packets silently before generating any OS-level events.

**Detection gap:** No network-layer IDS = blind to all network-based attacks.

---

## Solution Architecture

Deployed Suricata directly on the Proxmox hypervisor, monitoring **vmbr0** — the virtual network bridge that connects all VMs to each other and the internet. Every packet traversing the lab passes through this interface.

```
Internet ──► vmbr0 (Proxmox bridge)
                │
                ├── Suricata IDS (inline monitor, all traffic)
                │       └── eve.json alerts
                │               └── Wazuh Agent (proxmox-host, ID: 002)
                │                       └── Wazuh Server → Dashboard
                │
                ├── VM 200: wazuh-server
                ├── VM 201: win10-endpoint
                └── VM 202: kali-attacker (pending)
```

---

## Implementation

**Step 1 — Install Suricata**
```bash
apt-get install -y suricata suricata-update
suricata-update  # loads 48,786 detection rules
```

**Step 2 — Configure interface**
```yaml
# /etc/suricata/suricata.yaml
interface: vmbr0
```

**Step 3 — Deploy Wazuh agent on Proxmox host**
```bash
WAZUH_MANAGER='<wazuh-server>' WAZUH_AGENT_NAME='proxmox-host' \
  apt-get install -y wazuh-agent=4.11.2-1
```

**Step 4 — Wire Suricata logs into Wazuh**
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

**Step 5 — Configure Active Response**
Wazuh configured to auto-block IPs triggering brute force rules (5712, 5763) for 600 seconds via `firewall-drop` command.

---

## Results

- Suricata running with 48,786 active rules ✅
- Wazuh Agent ID 002 (proxmox-host) reporting Active ✅
- Network traffic on vmbr0 fully monitored ✅
- Active response configured — brute force IPs auto-blocked ✅

---

## Detection Capabilities Added

| Attack Type | Before | After |
|---|---|---|
| Port scans | ❌ Not detected | ✅ Suricata rule ET SCAN |
| Brute force (network) | ⚠️ Partial | ✅ Suricata + Wazuh AR |
| Exploit attempts | ❌ Not detected | ✅ Suricata ET EXPLOIT rules |
| Malware C2 traffic | ❌ Not detected | ✅ Suricata ET MALWARE rules |
| Protocol anomalies | ❌ Not detected | ✅ Suricata ET POLICY rules |

---

## Lessons Learned

1. **Defense-in-depth requires both layers** — host-based and network-based detection are complementary, not interchangeable
2. **Hypervisor-level placement is optimal** — monitoring the bridge captures 100% of VM traffic without needing agents on every host
3. **eve.json is the gold standard** — Suricata's JSON output integrates cleanly with any SIEM

---

*Report authored by William Quattlebaum as part of home SOC lab documentation.*
