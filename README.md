<div align="center">

# Embedded System Cybersecurity Risk Assessment Tool

**CVSS v3.1 Scoring · NIS2 Compliance · Threat Modelling · ARM Cortex-M4**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![CVSS](https://img.shields.io/badge/CVSS-v3.1-CC0000?style=flat-square)](https://www.first.org/cvss/)
[![NIS2](https://img.shields.io/badge/Compliance-NIS2%20Art.%2021-004F9F?style=flat-square)]()
[![Domain](https://img.shields.io/badge/Domain-Embedded%20Security-5C2D91?style=flat-square)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

</div>

---

## Overview

A **command-line cybersecurity risk assessment tool** for embedded systems, built in Python. The tool performs **CVSS v3.1 vulnerability scoring**, **security control mapping**, and **NIS2 Article 21 regulatory gap analysis** against a modelled ARM Cortex-M4 IoT gateway.

Threat scenarios are based on real vulnerability classes documented in CVE databases and ENISA embedded security guidelines.

---

## What It Does

```
Input: Embedded System Threat Register (ARM Cortex-M4 IoT Gateway)
         │
         ▼
  CVSS v3.1 Base Score Calculation
         │
         ▼
  Security Control Mapping
  (Preventive · Detective · Corrective)
         │
         ▼
  Risk Exposure Scoring
  (CVSS score × control coverage gap)
         │
         ▼
  NIS2 Article 21(2) Gap Analysis
         │
         ▼
  Colour-Coded Terminal Report
  (Tables · Score bars · Summaries)
```

---

## Threats Modelled

| ID | Threat | CVSS Score | Severity |
|---|---|---|---|
| R-001 | Remote Code Execution via Ethernet | 9.6 | 🔴 Critical |
| R-003 | Hardcoded Credentials in Firmware | 9.2 | 🔴 Critical |
| R-002 | JTAG Firmware Tampering | 7.6 | 🟠 High |
| R-005 | Privilege Escalation via FreeRTOS Task Isolation | 7.4 | 🟠 High |
| R-004 | Man-in-the-Middle Attack on OTA Firmware Update | 7.1 | 🟠 High |
| R-006 | Unauthorised Access via UART Console | 6.4 | 🟡 Medium |

**Average CVSS Score: 7.9 / 10.0**

---

## NIS2 Article 21 Compliance Result

| Result | Detail |
|---|---|
| **Coverage** | 1 / 8 Article 21(2) requirements (12%) |
| **Complete gaps** | Incident handling · Business continuity · Supply chain |
| **Partial coverage** | Cryptography · Vulnerability handling · Access control · Secure comms |

---

## Project Structure

```
embedded-risk-assessment/
│
├── main.py            # Entry point — orchestrates assessment pipeline
├── models.py          # Data models, enums & CVSS v3.1 scoring engine
├── risks.py           # Risk register — threats, controls & CVSS vectors
├── analysis.py        # Control mapping & exposure analysis
├── nis2.py            # NIS2 Article 21 gap analysis engine
├── report.py          # Colour terminal report generator
└── requirements.txt   # Dependencies (colorama, tabulate)
```

---

## Skills Demonstrated

| Area | Detail |
|---|---|
| **CVSS v3.1** | Full base score implementation from the official FIRST specification |
| **Threat Modelling** | ARM/RISC-V embedded system attack surface analysis |
| **NIS2 Compliance** | Article 21(2) gap identification and remediation mapping |
| **Security Engineering** | Control mapping, exposure scoring, risk registers |
| **Python** | Dataclasses, enums, type hints, list comprehensions |

---

## Setup & Run

```bash
# Clone the repository
git clone https://github.com/MM-Robin/embedded-risk-assessment
cd embedded-risk-assessment

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the assessment
python3 main.py
```

---

## Sample Output

```
========================================================================
  EMBEDDED SYSTEM CYBERSECURITY RISK ASSESSMENT TOOL
  CVSS v3.1  |  NIS2-Aligned  |  ARM Cortex-M4 IoT Gateway
  Author: Mainuddin Monsur Robin  |  HAW Hamburg
========================================================================

Risk distribution:
  Critical : 2
  High     : 3
  Medium   : 1

Avg CVSS score  : 7.9 / 10.0
NIS2-relevant   : 3 risks
```

---

## Background

Built as a portfolio project to demonstrate applied cybersecurity knowledge in embedded systems security, regulatory compliance (NIS2), and Python engineering. The threat model targets a realistic ARM Cortex-M4 IoT gateway with Ethernet, JTAG, UART, OTA update, and FreeRTOS-based task isolation.

---

## Author

<div align="center">

**Mainuddin Monsur Robin**
*M.Sc. Information and Communication Engineering — HAW Hamburg*

[![GitHub](https://img.shields.io/badge/GitHub-MM--Robin-181717?style=flat-square&logo=github)](https://github.com/MM-Robin)

</div>
