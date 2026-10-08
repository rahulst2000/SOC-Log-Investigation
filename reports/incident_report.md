# SOC L1 Security Incident Investigation Report

## 1. Executive Summary

This report documents the investigation of simulated SSH authentication activity using a Python-based SOC monitoring and detection workflow.

The analysis identified:

- Repeated authentication failures against a single account.
- Multiple accounts targeted from a single source.
- Authentication failures followed by a successful login.
- Activity from an authorized vulnerability scanner that requires false-positive validation.

The investigation demonstrates an L1 SOC workflow involving detection, triage, severity assessment, false-positive analysis, MITRE ATT&CK mapping, IOC extraction, investigation documentation, and escalation recommendations.

---

# 2. Incident Findings

## Incident 1 — Brute Force

**Source IP:** `10.10.10.50`

**Target Account:** `kali`

**Evidence:** 8 failed SSH authentication attempts occurred between `09:10:01` and `09:10:29`.

**Detection:** `BRUTE_FORCE`

**Severity:** HIGH

**MITRE ATT&CK:** T1110 — Brute Force

**Assessment:** Suspicious repeated authentication activity targeting a single account.

---

## Incident 2 — Password Spraying

**Source IP:** `10.10.10.60`

**Target Accounts:**
- user01
- user02
- user03
- user04
- user05

**Evidence:** Five different accounts were targeted within nine seconds.

**Detection:** `PASSWORD_SPRAYING`

**Severity:** HIGH

**MITRE ATT&CK:** T1110.003 — Password Spraying

**Assessment:** The observed behavior is consistent with password-spraying activity.

---

## Incident 3 — Failure Followed by Successful Login

**Source IP:** `10.10.10.70`

**Target Account:** `kali`

**Evidence:** Three failed authentication attempts were followed by a successful login at `09:20:13`.

**Detection:** `FAILURE_THEN_SUCCESS`

**Severity:** CRITICAL

**MITRE ATT&CK:** T1078 — Valid Accounts

**Assessment:** Potentially higher-risk authentication sequence requiring investigation to determine whether the successful login was legitimate.

---

## Incident 4 — Authorized Vulnerability Scanner

**Source IP:** `10.10.10.100`

**Evidence:** Four failed SSH authentication attempts.

**Context:** The source IP is present in the authorized vulnerability scanner allowlist.

**Assessment:** Potential false-positive candidate.

**L1 Action:** Validate scanner ownership, scan timing, and expected target before closing the alert.

---

# 3. Investigation Indicators

## Source IPs

- `10.10.10.50`
- `10.10.10.60`
- `10.10.10.70`
- `10.10.10.100`
- `192.168.1.21`

## Targeted Accounts

- `kali`
- `user01`
- `user02`
- `user03`
- `user04`
- `user05`

## Destination Port

- `22` — SSH

> These values are investigation indicators. They are not automatically confirmed Indicators of Compromise without additional evidence and validation.

---

# 4. L1 Investigation Actions

For the detected activities, the SOC L1 analyst should:

1. Validate the alert.
2. Review source IP and targeted account information.
3. Check authentication history.
4. Determine whether the source is authorized.
5. Review successful authentication events.
6. Check for additional suspicious activity.
7. Preserve relevant timestamps and indicators.
8. Determine severity and priority.
9. Escalate confirmed or potentially serious incidents to L2.
10. Document investigation findings.

---

# 5. Containment Recommendations

If malicious activity is confirmed:

- Consider blocking the malicious source IP according to organizational policy.
- Review and potentially reset compromised credentials.
- Review account activity for unauthorized access.
- Investigate the affected endpoint or server.
- Apply appropriate SSH security controls.
- Continue monitoring for related authentication attempts.
- Preserve relevant logs and evidence.

For the authorized scanner:

- Verify scanner ownership.
- Confirm the scan schedule.
- Confirm the intended target.
- Document the validation.
- Close the alert as a false positive only after verification.

---

# 6. Overall L1 Assessment

The simulated environment demonstrated three significant authentication behaviors:

1. Brute-force-like activity.
2. Password-spraying-like activity.
3. Failed authentication followed by successful authentication.

The authorized vulnerability scanner activity demonstrates the importance of contextual validation and false-positive analysis before escalation or containment.

The lab demonstrates a complete SOC L1 investigation workflow from security log ingestion through detection, alert generation, triage, investigation, MITRE ATT&CK mapping, indicator extraction, and incident reporting.

---

# 7. Conclusion

This project demonstrates practical SOC L1 capabilities using simulated SSH authentication logs and Python-based analysis.

The project does not claim to represent a production security environment or prove actual compromise. The findings are based on controlled laboratory data designed to demonstrate common SOC investigation scenarios.
