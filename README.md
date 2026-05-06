# Embedded System Cybersecurity Risk Assessment Tool

A command-line security assessment tool for embedded systems, built in Python.
Performs CVSS v3.1 vulnerability scoring, security control mapping, and
NIS2 Article 21 regulatory gap analysis on an ARM Cortex-M4 IoT gateway.

---

## What it does

- Scores 6 real embedded system threats using the CVSS v3.1 base score formula
- Maps preventive, detective, and corrective security controls to each risk
- Calculates risk exposure scores based on CVSS score and control coverage
- Checks compliance against 8 NIS2 Article 21(2) requirements
- Generates a colour-coded terminal report with tables, score bars, and summaries

## Threats modelled

| ID    | Threat                                           | Score | Severity |
| ----- | ------------------------------------------------ | ----- | -------- |
| R-001 | Remote Code Execution via Ethernet               | 9.6   | Critical |
| R-003 | Hardcoded Credentials in Firmware                | 9.2   | Critical |
| R-002 | JTAG Firmware Tampering                          | 7.6   | High     |
| R-005 | Privilege Escalation via FreeRTOS Task Isolation | 7.4   | High     |
| R-004 | Man-in-the-Middle Attack on OTA Firmware Update  | 7.1   | High     |
| R-006 | Unauthorised Access via UART Console             | 6.4   | Medium   |

## NIS2 compliance result

- 1/8 Article 21(2) requirements covered (12%)
- 3 complete gaps: incident handling, business continuity, supply chain
- 4 partial: cryptography, vulnerability handling, access control, secure comms

---

## Project structure

main.py — entry point
models.py — data models, enums, CVSS v3.1 scoring engine
risks.py — risk register with controls and CVSS vectors
analysis.py — control mapping and exposure analysis
nis2.py — NIS2 Article 21 gap analysis engine
report.py — colour terminal report generator
requirements.txt — dependencies

## Skills demonstrated

- **CVSS v3.1** — full base score implementation from the official specification
- **Threat modelling** — ARM/RISC-V embedded system attack surface analysis
- **NIS2 compliance** — Article 21(2) gap identification and remediation mapping
- **Python** — dataclasses, enums, type hints, list comprehensions, Counter
- **Security engineering** — control mapping, exposure scoring, risk registers

---

## Setup and run

```bash
# Clone the repository
git clone https://github.com/MM-Robin/embedded-risk-assessment
cd embedded-risk-assessment

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the assessment
python3 main.py
```

## Sample output

========================================================================
EMBEDDED SYSTEM CYBERSECURITY RISK ASSESSMENT TOOL
CVSS v3.1 | NIS2-Aligned | ARM Cortex-M4 IoT Gateway
Author: Mainuddin Monsur Robin | HAW Hamburg
Risk distribution:
Critical : 2
High : 3
Medium : 1
Avg CVSS score : 7.9 / 10.0
NIS2-relevant : 3 risks

---

## Background

Built as a portfolio project to demonstrate applied cybersecurity knowledge
in embedded systems security, regulatory compliance, and Python engineering.
Threat scenarios are based on real vulnerability classes documented in
CVE databases and ENISA embedded security guidelines.
