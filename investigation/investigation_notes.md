# SOC L1 Investigation Notes

## Incident 1 — Brute Force

### Source
10.10.10.50

### Target
kali

### Evidence
8 failed SSH authentication attempts occurred within 28 seconds.

### Detection
BRUTE_FORCE

### Initial Severity
HIGH

### Assessment
Suspicious repeated authentication activity targeting a single account.

### L1 Actions
- Validate source IP.
- Review authentication history.
- Check whether the source is authorized.
- Review successful logins for the targeted account.
- Preserve relevant timestamps and source information.
- Escalate if malicious activity is confirmed.

---

## Incident 2 — Password Spraying

### Source
10.10.10.60

### Targets
user01, user02, user03, user04, user05

### Evidence
Five different accounts were targeted within nine seconds.

### Detection
PASSWORD_SPRAYING

### Initial Severity
HIGH

### Assessment
Behavior is consistent with password-spraying activity.

### L1 Actions
- Validate source IP.
- Check whether the source belongs to an authorized security tool.
- Review authentication activity for all targeted accounts.
- Search for successful authentication after failures.
- Escalate confirmed malicious activity.

---

## Incident 3 — Failure Followed by Success

### Source
10.10.10.70

### Target
kali

### Evidence
Three failed authentication attempts were followed by a successful login.

### Detection
FAILURE_THEN_SUCCESS

### Initial Severity
CRITICAL

### Assessment
Potentially higher-risk authentication sequence requiring investigation.

### L1 Actions
- Validate whether the login was expected.
- Identify source ownership.
- Review account activity.
- Review additional authentication events.
- Escalate if unauthorized access is suspected.

---

## Incident 4 — Authorized Scanner

### Source
10.10.10.100

### Evidence
Four failed authentication attempts.

### Context
The source IP is present in the authorized vulnerability scanner allowlist.

### Assessment
Potential false-positive candidate.

### L1 Actions
- Verify scanner ownership.
- Confirm scan timing.
- Confirm expected target.
- Document validation.
- Close as false positive only after validation.
