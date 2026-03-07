# William Quattlebaum — Cybersecurity Portfolio

📍 Lawrenceville, GA | 📧 williamquattlebaum@gmail.com | 📞 770-826-0832  
🔗 [github.com/williamquattlebaum/cybersecurity-portfolio](https://github.com/williamquattlebaum/cybersecurity-portfolio)

---

## About Me

Cybersecurity professional with a B.S. in Cybersecurity from Kennesaw State University and a Master's in Cybersecurity & Information Assurance in progress at WGU. I built and operate a self-hosted home SOC lab running enterprise-grade security tools on a Dell OptiPlex 7010 via Proxmox hypervisor.

I take a hands-on approach to learning — everything in this portfolio was built, broken, fixed, and documented by me.

**Certifications:** CompTIA Security+, CompTIA Network+, Google Cybersecurity Professional Certificate

---

## Projects

---

### 🔵 Project 1: Home SOC Lab — Wazuh SIEM Deployment

**Date:** March 2026  
**Tools:** Proxmox VE, Ubuntu 22.04, Wazuh 4.11, OpenSearch, Windows 10, Nmap

#### What I Built
Designed and deployed a fully functional Security Operations Center (SOC) lab from scratch on a Dell OptiPlex 7010 (8GB RAM, 100GB storage) using Proxmox as the hypervisor.

**Infrastructure:**
- **Proxmox VE** hypervisor managing multiple VMs on bare metal hardware
- **Wazuh Server VM** (Ubuntu 22.04, 4GB RAM, 40GB disk) — running Wazuh Manager, Wazuh Indexer (OpenSearch), and Wazuh Dashboard
- **Windows 10 Endpoint VM** (2GB RAM, 32GB disk) — monitored endpoint with Wazuh agent installed and reporting

#### What I Did
- Provisioned Ubuntu VM using cloud-init for automated deployment
- Deployed Wazuh all-in-one stack (manager + indexer + dashboard) via official installer
- Installed VirtIO network and storage drivers on Windows VM for hypervisor compatibility
- Enrolled Windows 10 endpoint as monitored agent (Agent ID: 001, DESKTOP-G5P06GA)
- Resolved disk space issues by live-resizing LVM volumes and extending ext4 filesystem online
- Tuned RAM allocation across VMs to balance SIEM performance vs endpoint availability
- Configured SSH key-based authentication between management hosts

#### What I Found
- **CIS Benchmark Assessment:** Windows 10 endpoint scored **32% compliance** against CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0
- Identified 68% compliance gap — key failures in Windows Update, audit policy, and service hardening
- **Rule 61104:** BITS service startup type changed — flagged as potential malware persistence technique
- Real-time authentication event monitoring via Windows Security Event logs (Event ID 4624)

#### Skills Demonstrated
- Hypervisor administration (Proxmox VE / QEMU-KVM)
- SIEM deployment and configuration (Wazuh)
- Endpoint agent deployment and enrollment
- CIS Benchmark compliance assessment and gap analysis
- Linux server administration and troubleshooting (Ubuntu 22.04)
- LVM disk management and online filesystem resizing
- Cloud-init and VM provisioning automation
- SSH key management and hardening

---

### 🔴 Project 2: Red Team Simulation & Detection Gap Analysis

**Date:** March 2026  
**Tools:** Nmap, Wazuh, Windows Defender Firewall

#### What I Did
Conducted a controlled attack simulation from the Wazuh server against the Windows 10 endpoint to test detection capabilities and identify gaps in the SOC architecture.

**Attacks simulated:**
- Aggressive TCP SYN port scan (ports 1-1000) with OS fingerprinting
- RDP brute force simulation (port 3389)
- SMB enumeration (shares, users, OS discovery)
- Vulnerability scan with CVE detection scripts

#### What I Found
- All 1000 ports returned **filtered** — Windows Defender Firewall blocked all inbound scans
- SMB port 445 non-enumerable from external host — lateral movement blocked at host level
- CVE-2011-1002 (Avahi DoS) checked on network — **not vulnerable**
- **Critical detection gap identified:** Wazuh (host-based SIEM) does not detect network-layer scans — a network IDS (Suricata) is required for packet-level visibility

#### What I Learned
- Difference between host-based detection (Wazuh) vs network-based detection (Suricata/Snort)
- Defense-in-depth: Windows Firewall as first line, SIEM as second line, network IDS as third
- How to conduct gap analysis and document remediation recommendations professionally

**Documented in:** [Incident Report #002](incident-reports/002-network-reconnaissance.md)

---

### 🤖 Project 3: AI-Assisted SOC Automation & Sysadmin Orchestration

**Date:** March 2026  
**Tools:** OpenClaw, Claude AI (Anthropic), Proxmox API, SSH, Python, Bash

#### What I Built
Deployed and configured an AI agent (OpenClaw + Claude Sonnet) inside a Proxmox LXC container to serve as an always-on SOC assistant, sysadmin, and automation orchestrator.

#### What the AI Agent Does

**Infrastructure Management:**
- SSH access to Proxmox host and all VMs
- VM lifecycle management via Proxmox API (create, start, stop, resize, configure)
- Automated disk resizing and filesystem expansion when storage limits hit
- Real-time service health monitoring of Wazuh stack

**Threat Analysis & SOC Operations:**
- Reads and interprets Wazuh alert logs directly from the server
- Identifies high-severity alerts, explains them in plain English, and recommends responses
- Runs controlled attack simulations (Nmap, brute force) to test detection coverage
- Performs detection gap analysis and documents findings as incident reports
- Monitors CIS Benchmark compliance scores and tracks remediation progress

**Security Research:**
- Web research on emerging CVEs, attack techniques, and defensive tools
- Threat intelligence lookups and contextual analysis of alerts
- Generates professional incident reports in structured markdown format

**Portfolio & Documentation:**
- Automatically updates and pushes this portfolio to GitHub after each lab exercise
- Writes incident reports following SOC analyst documentation standards
- Tracks lab progress, open findings, and remediation backlog

**Productivity & Scheduling:**
- Manages a cron-based reminder system tailored to work schedule
- Smart reminders that adapt based on shift times (8-5, 10-7, 12-9, or days off)
- Job application nudges and study reminders delivered via Telegram

#### Why This Matters
Running an AI agent as part of a SOC workflow reflects real-world enterprise practice. Security teams increasingly use AI/ML tools for alert triage, threat hunting, and automated response. Building and operating this system demonstrates:
- Understanding of AI integration in security operations
- Ability to automate repetitive SOC tasks
- Infrastructure-as-code mindset (everything documented, version controlled)
- Practical experience with orchestration and automation pipelines

---

### 🟠 Project 4: Suricata IDS — Network-Layer Threat Detection

**Date:** March 2026  
**Tools:** Suricata 7.0, Wazuh Agent, Proxmox vmbr0

#### What I Built
Deployed Suricata IDS directly on the Proxmox hypervisor host to monitor all VM-to-VM and VM-to-internet traffic at the network bridge level (vmbr0). Integrated with Wazuh SIEM via a dedicated host agent.

#### Architecture
- Suricata runs on the Proxmox host, listening on vmbr0 (the virtual bridge connecting all VMs)
- All traffic between VMs and the internet passes through Suricata before reaching its destination
- Suricata logs alerts to eve.json (structured JSON format)
- Wazuh agent (ID: 002, proxmox-host) ships eve.json to the Wazuh server in real time
- Alerts appear in the Wazuh dashboard alongside endpoint telemetry

#### Rules
- **48,786 active detection rules** loaded via suricata-update
- Covers: malware C2, exploit attempts, port scans, lateral movement, protocol anomalies

#### Why This Matters
This closes the detection gap identified in Incident Report #002. Wazuh alone (host-based) couldn't see network-layer attacks. Suricata provides the network visibility layer — together they form a defense-in-depth detection stack.

---

### 🟣 Project 5: Corporate Network Security Merger Proposal

**Date:** March 2026  
**Type:** Academic Project (WGU)  
**Tools:** FortiGate NGFW, Cisco, Azure Sentinel, Azure AD P2, Azure VPN Gateway, Azure Backup, MS Sentinel, Cisco Umbrella, Sophos, Mimecast

Designed a secure merged network architecture for two companies with distinct infrastructure environments. Identified vulnerabilities, proposed a hardened network topology with 4 segmented VLANs, and mapped compliance to HIPAA and PCI-DSS v4.0. Applied Zero Trust and Defense in Depth principles throughout.

📁 [View Project](./merger-network-proposal/README.md)

---

## Lab Architecture

```
Dell OptiPlex 7010 — Proxmox VE Host (32GB RAM)
├── CT 100: Clawdbot LXC Container (4GB RAM)
│   └── OpenClaw AI Agent — SOC automation, sysadmin, portfolio management
├── VM 200: wazuh-server (Ubuntu 22.04, 8GB RAM, 40GB disk)
│   ├── Wazuh Manager 4.11.2
│   ├── Wazuh Indexer (OpenSearch)
│   └── Wazuh Dashboard
├── VM 201: win10-endpoint (Windows 10, 6GB RAM, 32GB disk)
│   └── Wazuh Agent (ID: 001) — reporting to wazuh-server
└── VM 202: kali-attacker (Kali Linux, 4GB RAM, 30GB disk)
    └── Attack simulation platform — Nmap, Hydra, red team tooling
```

---

## Technical Skills (Hands-On)

| Skill | Tool/Technology | Evidence |
|-------|----------------|---------|
| SIEM | Wazuh 4.11 | Deployed, configured, actively monitoring |
| Hypervisor | Proxmox VE | Managing 3 VMs/containers |
| Log Analysis | Wazuh / OpenSearch | Triaging real alerts daily |
| Endpoint Detection | Wazuh Agent | Windows 10 enrolled and reporting |
| Compliance Assessment | CIS Benchmarks | 32% — remediating |
| Network Scanning | Nmap | Attack simulations conducted |
| Detection Gap Analysis | Manual + Wazuh | Documented in IR #002 |
| Linux Administration | Ubuntu 22.04 | Server management, disk ops |
| AI/Automation | OpenClaw + Claude | SOC orchestration pipeline |
| Scripting | Bash, Python | Automation and tooling |
| Version Control | Git / GitHub | This portfolio |
| VM Provisioning | Cloud-init, QEMU | Automated VM deployment |
| Network Security Design | Cisco, FortiGate, Azure | WGU academic project |
| Compliance Mapping | HIPAA, PCI-DSS v4.0 | WGU academic project |

---

## Incident Reports

| # | Title | Severity | Status |
|---|-------|----------|--------|
| [001](incident-reports/001-cis-benchmark-finding.md) | CIS Benchmark Compliance Gap — Windows 10 | Medium | Open |
| [002](incident-reports/002-network-reconnaissance.md) | Network Reconnaissance & Attack Simulation | High | Documented |
| [003](incident-reports/003-kali-attack-simulation.md) | Kali Red Team Simulation — Firewall Down, Suricata Detection | High | Documented |
| [004](incident-reports/004-suricata-deployment.md) | Suricata IDS Deployment & Network-Layer Detection | Medium | Documented |

---

## Education

**Western Governors University**  
M.S. Cybersecurity and Information Assurance *(In Progress)*  
Coursework: Security Foundations, Secure Network Design, Cloud Security

**Kennesaw State University**  
B.S. Cybersecurity  
Coursework: Perimeter Defense, Network Security, Client System Security

---

## Certifications

- CompTIA Security+
- CompTIA Network+
- Google Cybersecurity Professional Certificate

---

---

### 🟣 Project 6: Splunk SIEM + TheHive IR Platform Deployment

**Date:** March 6, 2026  
**Tools:** Splunk Enterprise 9.3.2, TheHive 5.3, Docker, Cassandra, Elasticsearch

Deployed two enterprise-grade security tools on dedicated Proxmox VMs:

- **Splunk 9.3.2** (VM 203, 192.168.1.74) — industry-standard SIEM for log analysis and dashboards
- **TheHive 5.3** (VM 204, 192.168.1.75) — open-source incident response platform for structured case management (Docker + Cassandra + Elasticsearch)

The lab now has dual-SIEM coverage and a full IR workflow from detection to case closure.

📄 [Full project write-up](projects/splunk-thehive-deployment.md)

---

## Coming Soon

- [x] Kali Linux attack VM — realistic red team exercises ✅
- [x] Windows firewall disabled simulation — Suricata caught 28 alerts ✅
- [x] Splunk SIEM deployment ✅
- [x] TheHive incident response platform ✅
- [ ] CIS Benchmark remediation — target >70% compliance
- [ ] Splunk universal forwarder — ship endpoint logs to Splunk
- [ ] TheHive + Wazuh integration — auto-create cases from alerts
- [ ] TryHackMe SOC Level 1 path completion

---

*Last updated: March 6, 2026 | Maintained by William Quattlebaum*
