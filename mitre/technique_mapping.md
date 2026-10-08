# MITRE ATT&CK Technique Mapping

## 1. Brute Force

### Observed Behavior
Multiple failed SSH authentication attempts were observed from:
- Source IP: 10.10.10.50
- Target account: kali
- Failed attempts: 8

### ATT&CK Mapping
**T1110 — Brute Force**

The activity is consistent with repeated authentication attempts against the same account.

---

## 2. Password Spraying

### Observed Behavior
Source IP `10.10.10.60` attempted authentication against:
- user01
- user02
- user03
- user04
- user05

### ATT&CK Mapping
**T1110.003 — Password Spraying**

The observed pattern is consistent with attempting authentication against multiple accounts from a single source.

---

## 3. Valid Accounts Investigation

### Observed Behavior
Source IP `10.10.10.70` generated three failed authentication attempts followed by a successful login for account `kali`.

### ATT&CK Mapping
**T1078 — Valid Accounts**

The successful authentication requires investigation to determine whether valid credentials were legitimately used or obtained through malicious activity.

---

## Analyst Note

These mappings represent behavioral alignment with MITRE ATT&CK techniques. The available lab logs alone do not prove attacker intent or account compromise.
