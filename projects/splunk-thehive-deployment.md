# Project 6: Splunk SIEM + TheHive IR Platform Deployment

**Date:** March 6, 2026  
**Author:** William Quattlebaum  
**Environment:** Home SOC Lab (Proxmox)

---

## Overview

Expanded the home SOC lab by deploying two enterprise-grade security tools on dedicated VMs:

- **Splunk 9.3.2** — industry-standard SIEM for log aggregation, search, and dashboards
- **TheHive 5.3** — open-source Security Incident Response Platform (SIRP) for case management

Both platforms mirror a real SOC architecture where analysts use a SIEM for detection and a case management platform for structured incident response.

---

## Infrastructure

| VM | IP | Tool | Version | Access |
|----|----|------|---------|--------|
| splunk-server (VM 203) | 192.168.1.74 | Splunk Enterprise | 9.3.2 | http://192.168.1.74:8000 |
| thehive-server (VM 204) | 192.168.1.75 | TheHive | 5.3 | http://192.168.1.75:9000 |

---

## Splunk Deployment

**Specs:** Ubuntu 22.04, 4GB RAM, 40GB disk, 2 vCPUs  
**Version:** Splunk Enterprise 9.3.2

Splunk is the #1 SIEM in enterprise environments. Deploying it hands-on — even in a lab — demonstrates practical familiarity that most entry-level candidates lack. Key capabilities:

- SPL (Search Processing Language) for log analysis and threat hunting
- Custom dashboards and saved searches
- Real-time alerting and correlation rules
- Data ingestion via Universal Forwarder

---

## TheHive Deployment

**Specs:** Ubuntu 22.04, 4GB RAM, 40GB disk, 2 vCPUs  
**Stack:** Docker Compose (TheHive 5.3 + Cassandra 4 + Elasticsearch 7.17)

TheHive provides a structured incident response workflow matching enterprise SOC processes:

- Case creation and lifecycle management
- Task assignment and tracking
- Observable tracking (IPs, hashes, domains, URLs)
- MITRE ATT&CK tagging per case
- Integration-ready with Cortex (automated enrichment) and MISP (threat intel)

### Docker Compose Stack
```
thehive-thehive-1        → port 9000 (web UI)
thehive-cassandra-1      → port 9042 (database backend)
thehive-elasticsearch-1  → port 9200 (search/index)
```

---

## Updated SOC Architecture

```
                    ┌──────────────────────────────────────┐
                    │  Proxmox Host (192.168.1.91)         │
                    │  Suricata IDS (monitoring vmbr0)     │
                    └───────────────┬──────────────────────┘
                                    │ vmbr0 bridge
        ┌───────────────────────────┼──────────────────────────┐
        │                           │                          │
 ┌──────▼──────┐            ┌───────▼──────┐         ┌────────▼─────┐
 │ wazuh-server│            │splunk-server │         │thehive-server│
 │ .73 (SIEM)  │            │ .74 (SIEM)   │         │  .75 (IR)    │
 └─────────────┘            └──────────────┘         └──────────────┘
        │
 ┌──────▼───────────────────────────────────┐
 │            Monitored Endpoints            │
 │  win10-endpoint (.76) + proxmox-host      │
 └───────────────────────────────────────────┘
```

---

## Skills Demonstrated

- VM provisioning on Proxmox (cloud-init, networking)
- Linux server administration (Ubuntu 22.04)
- Docker and Docker Compose deployment
- Enterprise SIEM deployment and operation (Splunk 9.3)
- Incident response platform setup (TheHive 5.3)
- SOC toolchain architecture design
- Multi-tool security stack integration

---

*Part of the William Quattlebaum Cybersecurity Home Lab portfolio.*
