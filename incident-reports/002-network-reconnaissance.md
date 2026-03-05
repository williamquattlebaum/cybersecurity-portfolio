# Incident Report #002 — Network Reconnaissance & Attack Simulation

**Date:** March 2, 2026  
**Analyst:** William Quattlebaum  
**Severity:** High  
**Status:** Detected & Documented  

---

## Summary

Conducted a controlled red team simulation against the Windows 10 endpoint (DESKTOP-G5P06GA) from the Wazuh server (<wazuh-server>) to test detection capabilities and generate real security events for SOC analyst training.

---

## Attack Timeline

| Time (UTC) | Action | Tool | Target |
|---|---|---|---|
| 05:46 | Aggressive port scan (1-1000) | Nmap -sS -sV -O | <windows-endpoint> |
| 05:47 | RDP brute force simulation | Nmap rdp-brute script | <windows-endpoint>:3389 |
| 05:47 | SMB enumeration | Nmap smb-enum-shares/users | <windows-endpoint>:445 |
| 05:47 | Vulnerability scan | Nmap --script vuln | <windows-endpoint> |

---

## Findings

### Port Scan Results
All 1000 TCP ports on the Windows endpoint returned **filtered** — the Windows Firewall was blocking all inbound connections. This is actually a positive security finding: default Windows 10 firewall provides strong perimeter protection at the host level.

**Open/Filtered ports identified:**
- 135/tcp — Microsoft RPC (filtered)
- 139/tcp — NetBIOS (filtered)
- 445/tcp — SMB/Microsoft-DS (filtered)
- 3389/tcp — RDP/Remote Desktop (filtered)

### SMB Enumeration
SMB port 445 was filtered — no shares enumerable from external host. Windows Defender Firewall blocking lateral movement via SMB.

### Vulnerability Assessment
No exploitable vulnerabilities detected via external scan. Host firewall effectively blocked all vulnerability probes.

### CVE-2011-1002 (Avahi DoS)
Nmap identified a broadcast Avahi service at 224.0.0.251 on the network. Checked for CVE-2011-1002 (NULL UDP packet DoS) — **not vulnerable**.

---

## Wazuh Detection Results

**Alerts generated during simulation:**
- Rule 19007 (level 7) — Multiple CIS Benchmark failures detected on Windows endpoint
- Rule 19004 (level 7) — CIS Benchmark score 32% (below 50% threshold)
- Rule 60106 (level 3) — Windows authentication events logged in real time

**Detection gap identified:** The port scans did not generate Wazuh IDS alerts because:
1. Windows Firewall dropped packets before they reached the OS
2. Wazuh agent monitors Windows Event Logs — network-layer drops don't generate Windows events
3. A network-based IDS (Suricata/Snort) would be needed to detect these scans at the packet level

---

## Lessons Learned

1. **Host-based vs Network-based detection:** Wazuh is a host-based SIEM. It sees what the OS sees. A network IDS like Suricata would catch port scans before they hit the endpoint.

2. **Windows Firewall is your first line of defense:** All ports filtered = attacker gets no useful information. This is correct behavior.

3. **Defense-in-depth gap:** The lab currently has no network-layer IDS. Next step: deploy Suricata on the Proxmox host to monitor all VM traffic.

---

## Recommendations

1. Deploy **Suricata IDS** on Proxmox host to capture network-layer attack signatures
2. Enable **Windows Event ID 5156** (network connection allowed) logging for better visibility
3. Configure **Wazuh active response** to auto-block IPs after repeated scan attempts
4. Add a **Kali Linux VM** as dedicated attack machine for realistic red team exercises

---

*Report authored by William Quattlebaum as part of home SOC lab documentation.*
