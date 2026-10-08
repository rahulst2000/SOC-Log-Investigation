# SOC L1 Security Log Analysis & Incident Investigation

## Project Overview

This project demonstrates a practical SOC Level 1 workflow for monitoring and investigating simulated SSH authentication activity.

The project uses Python and Pandas to parse security logs, detect suspicious authentication patterns, generate structured alerts, perform false-positive analysis, extract investigation indicators, map observed behavior to MITRE ATT&CK techniques, and document incident findings.

The project is designed as a controlled security laboratory and does not represent a production SOC environment.

---

## Objectives

- Analyze SSH authentication logs.
- Detect repeated failed authentication attempts.
- Identify brute-force-like behavior.
- Detect password-spraying-like behavior.
- Identify authentication failures followed by successful login.
- Generate structured SOC alerts.
- Perform false-positive analysis.
- Extract investigation indicators.
- Map observed behavior to MITRE ATT&CK.
- Document investigation findings.
- Demonstrate an L1 escalation workflow.

---

## Technologies Used

- Kali Linux
- Python 3
- Pandas
- Linux command line
- SSH authentication logs
- Git
- MITRE ATT&CK

---

## Project Architecture

```text
Simulated SSH Logs
        |
        v
Python Log Parser
        |
        v
Log Analysis
        |
        v
Detection Engine
        |
        v
SOC Alert Manager
        |
        +--------------------+
        |                    |
        v                    v
False Positive        IOC / Investigation
Analysis              Indicator Extraction
        |                    |
        +---------+----------+
                  |
                  v
           Incident Investigation
                  |
                  v
          MITRE ATT&CK Mapping
                  |
                  v
           Incident Report
