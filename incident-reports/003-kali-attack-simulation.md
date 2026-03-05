# Incident Report #003 — Red Team Attack Simulation (Kali Linux)

**Date:** March 5, 2026  
**Analyst:** William Quattlebaum  
**Severity:** High  
**Status:** Documented — Detection Validated  
**Attacker IP:** 192.168.1.87 (kali-attacker VM)  
**Target IP:** 192.168.1.76 (win10-endpoint, DESKTOP-G5P06GA)  

---

## Executive Summary

A controlled red team attack simulation was conducted from a dedicated Kali Linux VM (192.168.1.87) against a Windows 10 endpoint (192.168.1.76) with Windows Defender Firewall disabled. The purpose was to generate realistic attack telemetry, validate detection coverage across the SOC stack, and document attacker TTPs in a controlled environment.

**Key outcome:** Suricata IDS detected attack activity at the network layer in real time. Wazuh SIEM correlated and logged the alerts. This exercise closes the detection gap identified in IR #002 and validates the defense-in-depth architecture.

---

## Lab Architecture

```
[Kali Linux VM]          →      [Windows 10 Endpoint]
192.168.1.87                    192.168.1.76
kali-attacker (VM 202)          win10-endpoint (VM 201)
4GB RAM | 30GB disk             6GB RAM | 32GB disk

↓ All traffic passes through ↓

[Suricata IDS on Proxmox vmbr0]
48,786 active detection rules
↓
[Wazuh SIEM — 192.168.1.73]
Real-time alert correlation
```

---

## Pre-Attack Configuration

| Setting | Value |
|---|---|
| Windows Firewall | **Disabled** (all profiles: Domain, Private, Public) |
| Wazuh Agent | Active on Windows endpoint (Agent ID: 001) |
| Suricata | Running on Proxmox host, monitoring vmbr0 |
| Attack Platform | Kali Linux 2024.x — Nmap 7.95 |

Firewall confirmed off via WinRM:
```
Domain Profile:  State OFF
Private Profile: State OFF
Public Profile:  State OFF
```

---

## Attack Phases & Findings

### Phase 1 — Initial Reconnaissance (TCP SYN Scan, ports 1–1000)

**Tool:** `nmap -sS -T4 -A -p 1-1000 192.168.1.76`

**Ports discovered:**

| Port | Service | Notes |
|---|---|---|
| 135/tcp | msrpc | Windows RPC — lateral movement vector |
| 139/tcp | netbios-ssn | NetBIOS session service |
| 445/tcp | microsoft-ds | SMB — file sharing, pass-the-hash, ransomware |

**OS fingerprinting result:** Microsoft Windows 10 (1709–21H2)  
**NetBIOS hostname:** DESKTOP-G5P06GA  
**MAC:** BC:24:11:7F:FD:ED (Proxmox virtual NIC)  
**SMB signing:** Enabled but not required — relay attacks possible

---

### Phase 2 — Full Port Scan (all 65,535 ports)

**Tool:** `nmap -sS -T4 -p- --min-rate 1000 192.168.1.76`

**Additional ports discovered with firewall down:**

| Port | Service | Notes |
|---|---|---|
| 5040/tcp | unknown | Windows service |
| 5357/tcp | wsdapi | Web Services for Devices — discovery protocol |
| 5985/tcp | wsman | WinRM HTTP — remote management (exploitable) |
| 7680/tcp | pando-pub | BITS/Windows Update delivery |
| 47001/tcp | winrm | WinRM alternate port |
| 49664–49917 | RPC dynamic | Windows RPC ephemeral ports |

**Key finding:** WinRM (port 5985) is exposed. With valid credentials, an attacker has full remote PowerShell access to this machine.

**Comparison to IR #002:** With the firewall enabled, all 1000 ports returned `filtered`. With the firewall disabled, **15 open ports** were exposed — a dramatic expansion of the attack surface.

---

### Phase 3 — SMB Enumeration

**Tool:** `nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode`

**Result:** SMB2 negotiation succeeded. Nmap's SMB1 enumeration scripts generated malformed dialect negotiation requests.

**Suricata detection:**
```
[2026-03-05 08:09:43] Signature 2225005 — SURICATA SMB malformed request dialects
Severity: 3 | Category: Generic Protocol Command Decode
Source: 192.168.1.87:47540 → Destination: 192.168.1.76:445
```
*3 alerts fired for SMB enumeration activity — Suricata caught the probe.*

---

### Phase 4 — Vulnerability Scan

**Tool:** `nmap --script vuln -p 135,139,445`

| CVE Checked | Result |
|---|---|
| MS10-054 (SMB Pool Overflow) | Not vulnerable |
| MS10-061 (Print Spooler RCE) | Could not negotiate — connection error |
| CVE-2012-1182 (Samba RCE) | Could not negotiate |
| CVE-2011-1002 (Avahi DoS) | Not vulnerable |

**Finding:** No critical CVEs exploitable on this target from the tested vectors. System is patched against legacy SMB exploits.

---

### Phase 5 — RDP Assessment

**Tool:** `nmap -p 3389`

**Result:** Port 3389 (RDP) is **closed**. RDP is not enabled on this endpoint — brute force via RDP is not possible from this attack vector.

---

### Phase 6 — WinRM Exposure

**Tool:** `nmap -p 5985 --script http-auth-finder`

**Result:** Port 5985 confirmed open and responding. WinRM with basic auth enabled represents a valid remote code execution path if credentials are obtained.

---

## Alerts Generated

### Suricata (Network Layer — Proxmox vmbr0)

| Time | Signature ID | Description | Source → Dest |
|---|---|---|---|
| 08:09:43 | 2225005 | SURICATA SMB malformed request dialects | 192.168.1.87 → 192.168.1.76:445 |
| 08:09:45 | 2225005 | SURICATA SMB malformed request dialects | 192.168.1.87 → 192.168.1.76:445 |
| 08:09:45 | 2225005 | SURICATA SMB malformed request dialects | 192.168.1.87 → 192.168.1.76:445 |

**Total Suricata alerts from 192.168.1.87:** 28  
**Detection method:** Packet-level signature matching on vmbr0 bridge

### Wazuh (Host + IDS Correlation)

Wazuh correlated Suricata alerts via the proxmox-host agent (Agent ID: 002) and logged them under rule 86601 (Suricata alert forwarding). All IDS alerts are visible in the Wazuh dashboard alongside host-based telemetry.

---

## Comparison: Firewall ON vs OFF

| Metric | IR #002 (Firewall ON) | IR #003 (Firewall OFF) |
|---|---|---|
| Open ports (1–1000) | 0 (all filtered) | 3 (135, 139, 445) |
| Open ports (full scan) | 0 | 15 |
| WinRM exposed | No | Yes |
| Suricata detections | 0 (no traffic) | 28 alerts |
| SMB enumerable | No | Partial |
| OS fingerprint possible | No | Yes (Windows 10) |

---

## Key Findings

1. **Windows Firewall is the primary perimeter defense.** Disabling it exposes 15 ports immediately, including WinRM (full remote code execution) and SMB (ransomware/lateral movement vector).

2. **Suricata detected attack activity that Wazuh alone could not.** SMB probe packets were caught at the network layer by Suricata before reaching the host — validating the defense-in-depth architecture.

3. **WinRM (port 5985) is a critical risk when firewall is disabled.** An attacker with any valid credentials has full PowerShell remote access.

4. **SMB signing not required** — NTLM relay attacks (Responder, ntlmrelayx) are theoretically possible on this network segment.

5. **No critical CVEs exploitable** from the tested attack vectors. System patching is effective.

---

## MITRE ATT&CK Mapping

| Technique | ID | Phase | Tool Used |
|---|---|---|---|
| Network Service Scanning | T1046 | Reconnaissance | Nmap |
| OS Fingerprinting | T1082 | Discovery | Nmap -A |
| SMB/Windows Admin Shares | T1021.002 | Lateral Movement | Nmap SMB scripts |
| Remote Services: WinRM | T1021.006 | Lateral Movement | Detected open |
| Network Share Discovery | T1135 | Discovery | Nmap SMB enum |

---

## Remediation Recommendations

| Priority | Finding | Recommendation |
|---|---|---|
| Critical | Windows Firewall disabled | Re-enable immediately. Whitelist only required ports. |
| High | WinRM exposed on LAN | Restrict WinRM to management IPs only; require HTTPS (5986) |
| High | SMB signing not required | Enable SMB signing via Group Policy to prevent relay attacks |
| Medium | RPC dynamic ports exposed | Restrict RPC port range via registry (49152–49159) |
| Low | NetBIOS (139) active | Disable NetBIOS over TCP/IP if not required |

---

## Detection Architecture — Validated

```
Attack: Kali Linux nmap scan → Windows 10
         ↓
Network Layer: Suricata on vmbr0 → 28 alerts (SMB probes detected)
         ↓
SIEM Layer: Wazuh Agent 002 (proxmox-host) → Correlated & logged
         ↓
Dashboard: Wazuh Dashboard (192.168.1.73) → Visible in real time
```

This confirms the two-layer detection stack (Suricata + Wazuh) is functioning as designed.

---

## Conclusion

This exercise successfully demonstrated that:
- The Kali Linux attack VM is operational and capable of realistic attack simulation
- Suricata IDS detects network-layer attack signatures in real time
- Wazuh SIEM correctly correlates and surfaces those alerts
- Windows Firewall is the critical control preventing attack surface exposure

The detection gap identified in IR #002 (host-only SIEM cannot see network scans) has been closed by the Suricata deployment documented in Project 4.

---

*Report written by: William Quattlebaum | SOC Analyst*  
*Lab: Home SOC | Proxmox VE 9.0.3 | Wazuh 4.11.2 | Suricata 7.0*  
*Date: March 5, 2026*
