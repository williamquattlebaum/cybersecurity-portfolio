# Incident Report #001 — CIS Benchmark Compliance Gap

**Date:** March 2, 2026  
**Analyst:** William Quattlebaum  
**Severity:** Medium  
**Status:** Open — Remediation In Progress  

---

## Summary

During initial deployment of the home SOC lab, a CIS Benchmark assessment was automatically performed by the Wazuh SIEM on the Windows 10 endpoint (DESKTOP-G5P06GA). The endpoint scored **32%** compliance against the CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0 — significantly below the industry-accepted threshold of 70%.

---

## Detection

- **Tool:** Wazuh SCA (Security Configuration Assessment)
- **Rule:** 19004 — SCA summary score below 50%
- **Agent:** DESKTOP-G5P06GA (<windows-endpoint>)
- **Time:** 2026-03-02 04:45 UTC

---

## Findings

The assessment checked 100 security controls. The endpoint failed 68% of them. Key failure categories:

- **Windows Update:** "Remove access to Pause Updates" feature not enforced (Rule 19007)
- **Feature Updates:** Preview Build and Feature Update receive window not configured to 180+ days
- **Service Configuration:** BITS service startup type changed (Rule 61104) — potential persistence mechanism
- **Audit Policy:** Multiple audit logging controls not enabled
- **User Account Controls:** Several UAC settings below enterprise standards

---

## Risk Assessment

A 32% CIS score means the system has significant attack surface. An attacker who gains access to this endpoint would find:
- Weak audit logging (harder to detect their activity)
- Misconfigured services (potential persistence opportunities)
- Unpatched update channels (vulnerability exposure)

---

## Recommended Remediation

1. Enable Windows Update and configure auto-update policy
2. Enable full audit logging via Group Policy
3. Investigate BITS service change — confirm it was legitimate
4. Apply remaining CIS Benchmark controls incrementally
5. Target: >70% CIS score within 30 days

---

## Lessons Learned

Fresh Windows 10 installations have a very low security baseline out of the box. Enterprises rely on Group Policy and configuration management tools (SCCM, Intune) to enforce these controls at scale. This is why compliance teams and SOC analysts focus heavily on baseline hardening before endpoints are put into production.

---

*Report authored by William Quattlebaum as part of home SOC lab documentation.*
