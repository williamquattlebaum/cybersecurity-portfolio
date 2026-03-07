# William Quattlebaum
**Cybersecurity Analyst | SOC Analyst**

📍 Lawrenceville, GA | 📧 williamquattlebaum@gmail.com | 📞 770-826-0832  
🔗 [github.com/williamquattlebaum/cybersecurity-portfolio](https://github.com/williamquattlebaum/cybersecurity-portfolio)

---

## Summary

Cybersecurity professional with a B.S. in Cybersecurity from Kennesaw State University and an M.S. in Cybersecurity & Information Assurance in progress at WGU. Hands-on builder and operator of a self-hosted home SOC lab running enterprise-grade security tools on bare metal hardware. Practical experience in SIEM deployment, threat detection, red team simulation, CIS benchmark compliance, and AI-driven SOC automation. Pursuing entry-level SOC Analyst and Security Analyst roles.

---

## Technical Skills

| Domain | Tools & Technologies |
|---|---|
| SIEM | Wazuh 4.11, OpenSearch, alert correlation, SCA |
| Network Security | Suricata 7.0 IDS, Nmap, Wireshark, firewall policy |
| Threat Detection | Wazuh rules, Suricata signatures (48,786 rules), MITRE ATT&CK |
| Penetration Testing | Kali Linux, Nmap, Hydra, SMB enumeration, brute force simulation |
| Compliance | CIS Benchmarks (Windows 10), HIPAA, PCI-DSS v4.0, NIST 800-53 |
| Hypervisor | Proxmox VE 9.0 (QEMU-KVM), VM lifecycle management |
| Operating Systems | Ubuntu 22.04, Windows 10/Server, Kali Linux |
| Scripting | PowerShell, Bash, Python |
| Cloud & Network Design | Azure Sentinel, Azure AD P2, FortiGate NGFW, Cisco, Zero Trust |
| Automation | OpenClaw AI agent, SSH orchestration, cron scheduling |
| Version Control | Git, GitHub |

---

## Certifications

- **CompTIA Security+**
- **Google Cybersecurity Professional Certificate**

---

## Cybersecurity Projects

### Home SOC Lab — Wazuh SIEM + Suricata IDS | *March 2026*
*Proxmox VE | Ubuntu 22.04 | Wazuh 4.11 | Suricata 7.0 | Windows 10*

- Designed and deployed a fully functional SOC lab from scratch on a Dell OptiPlex 7010 using Proxmox as the hypervisor, managing 3 VMs and a management container on 32GB RAM
- Deployed Wazuh all-in-one stack (Manager + Indexer/OpenSearch + Dashboard) via official installer on Ubuntu 22.04; enrolled Windows 10 endpoint as Agent ID 001
- Installed Suricata 7.0 IDS on the Proxmox hypervisor host monitoring all VM-to-VM traffic at the vmbr0 bridge level, loading 48,786 active detection rules via suricata-update
- Integrated Suricata with Wazuh via a dedicated host agent, creating a two-layer detection stack (host-based + network-based) following defense-in-depth architecture
- Provisioned Ubuntu VM using cloud-init for automated deployment; configured SSH key-based authentication across all hosts
- Resolved live disk space issues by resizing LVM thin pool volumes and extending ext4 filesystem online without downtime

### Red Team Simulation & Detection Validation | *March 2026*
*Kali Linux | Nmap 7.95 | Wazuh | Suricata*

- Conducted a controlled red team attack simulation from a dedicated Kali Linux VM (kali-attacker) against a Windows 10 endpoint with Windows Defender Firewall disabled
- Ran multi-phase attack: TCP SYN scan (all 65,535 ports), OS fingerprinting, aggressive SMB enumeration, vulnerability scan (CVE checks), and WinRM exposure assessment
- Discovered 15 open ports with firewall disabled vs. 0 with firewall enabled — documented the attack surface expansion including WinRM (port 5985) exposure
- Suricata IDS fired 28 alerts in real time during the attack, including 3 SMB malformed dialect alerts (Signature 2225005) — validating network-layer detection coverage
- Documented findings as Incident Report #003 with full MITRE ATT&CK mapping (T1046, T1082, T1021.002, T1021.006, T1135) and remediation recommendations

### CIS Benchmark Compliance Remediation | *March 2026*
*PowerShell | Wazuh SCA | Windows 10 | CIS v1.12.0*

- Assessed Windows 10 endpoint against CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0 using Wazuh Security Configuration Assessment (SCA); baseline score: 32%
- Developed and executed a multi-phase PowerShell remediation script via WinRM targeting 100+ failing controls across audit policy, account lockout, password policy, service hardening, firewall logging, and network security settings
- Remediated key findings: disabled 30 unnecessary services (Bluetooth, Xbox, Print Spooler, RDP, ICS, P2P), enforced NTLMv2-only authentication, disabled SMBv1, configured firewall logging on all profiles, enabled process creation command-line logging
- Applied MSS network hardening (IP source routing disabled, ICMP redirects blocked, NTLMv2 minimum session security), IPv6 disabled, UAC hardened, logon banner configured
- Improved compliance score from **32% → 51%+** (ongoing remediation targeting 70%)

### AI-Assisted SOC Automation | *March 2026*
*OpenClaw | Claude Sonnet | Proxmox API | Python | Bash*

- Deployed and configured an AI agent (OpenClaw + Claude) inside a Proxmox LXC container as an always-on SOC assistant, sysadmin, and automation orchestrator
- AI agent performs: VM lifecycle management via SSH, real-time Wazuh service health monitoring, automated SCA rescan orchestration, incident report generation, and GitHub portfolio publishing
- Implemented proactive alerting via Telegram for Wazuh service failures, triggered by scheduled health checks
- Demonstrates practical knowledge of AI integration in SOC workflows, reflecting emerging enterprise security operations practice

### Corporate Network Security Merger Proposal | *March 2026*
*WGU Academic Project | FortiGate NGFW | Cisco | Azure Sentinel | Azure AD P2*

- Designed a secure merged network architecture for two companies with distinct infrastructure environments
- Proposed hardened network topology with 4 segmented VLANs, mapped compliance to HIPAA and PCI-DSS v4.0
- Applied Zero Trust and Defense-in-Depth principles; recommended FortiGate NGFW, Azure Sentinel SIEM, Cisco Umbrella DNS security, and Mimecast email protection

---

## Incident Reports (Selected)

| # | Title | Severity | Outcome |
|---|---|---|---|
| IR-001 | CIS Benchmark Compliance Gap — Windows 10 at 32% | Medium | Remediation in progress → 51%+ |
| IR-002 | Network Recon: 0 alerts with firewall ON | High | Identified SIEM detection gap |
| IR-003 | Kali Red Team: 28 Suricata alerts, 15 open ports | High | Detection gap closed |
| IR-004 | Suricata Deployment & Network-Layer Validation | Medium | Full IDS integration documented |

---

## Education

**Western Governors University** — M.S. Cybersecurity & Information Assurance *(In Progress)*  
Coursework: Security Foundations, Secure Network Design, Cloud Security, Compliance

**Kennesaw State University** — B.S. Cybersecurity  
Coursework: Perimeter Defense, Network Security, Client System Security, Ethical Hacking

---

## Work Experience

**Vehicle Condition Assessor | CarMax, Buford GA** | *Current*
- Systematic inspection and documentation under time constraints — translates directly to methodical security analysis and incident documentation skills
- Customer-facing communication and professional reporting

---

*References available upon request*
