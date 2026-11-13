# ThreatFlow — Autonomous Phishing Response System

[![Wazuh](https://img.shields.io/badge/Wazuh-4.7.0-blue?logo=wazuh&logoColor=white)](https://wazuh.com)
[![Shuffle](https://img.shields.io/badge/Shuffle-1.3.0-orange?logo=shuffle&logoColor=white)](https://shuffler.io)
[![TheHive](https://img.shields.io/badge/TheHive-5.2-yellow?logo=thehive&logoColor=black)](https://thehive-project.org)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-blue?logo=virustotal&logoColor=white)](https://virustotal.com)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API%20v2-red)](https://www.abuseipdb.com)

---

## Executive Summary

ThreatFlow is a production-grade, fully autonomous Security Orchestration, Automation and Response (SOAR) system built to detect, analyse, and contain phishing threats without human intervention. It integrates Wazuh SIEM for real-time log correlation, Shuffle for workflow orchestration, and TheHive for case management — enriching every alert with live threat intelligence from VirusTotal and AbuseIPDB before executing automated containment actions. Designed for a modern enterprise SOC, ThreatFlow reduces mean-time-to-contain (MTTC) for phishing incidents from hours to under 90 seconds. The entire stack is containerised and deployable with a single `docker-compose up` command.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        THREATFLOW — SYSTEM ARCHITECTURE                 │
└─────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │  DMZ  (Monitored Endpoints)                                          │
  │                                                                      │
  │   ┌───────────────┐    ┌───────────────┐    ┌───────────────┐       │
  │   │  Windows Host │    │  Linux Server │    │  Mail Gateway │       │
  │   │  + Sysmon     │    │  + Wazuh Agt  │    │  + Wazuh Agt  │       │
  │   └──────┬────────┘    └──────┬────────┘    └──────┬────────┘       │
  └──────────┼─────────────────── ┼ ─────────────────── ┼ ───────────────┘
             │  Wazuh Agent       │  Encrypted           │  Log Stream
             │  (1514/UDP)        │  Comms               │
  ┌──────────▼────────────────────▼──────────────────────▼───────────────┐
  │  SOC ZONE                                                             │
  │                                                                       │
  │   ┌─────────────────────────────────────┐                            │
  │   │         WAZUH MANAGER               │                            │
  │   │   Rules Engine · Decoder · Alerts   │  :1514/UDP  :55000/REST    │
  │   └──────────────────┬──────────────────┘                            │
  │                      │ Webhook (phishing rule hit)                   │
  │   ┌──────────────────▼──────────────────┐                            │
  │   │         SHUFFLE SOAR                │  :3001                     │
  │   │   Workflow Engine · App Integrations│                            │
  │   │   ┌─────────┐  ┌──────────────────┐│                            │
  │   │   │ Enrich  │  │ Contain & Notify ││                            │
  │   │   │ VT · AIP│  │ FW Block · Email ││                            │
  │   │   └────┬────┘  └────────┬─────────┘│                            │
  │   └────────┼────────────────┼───────────┘                            │
  │            │ Case Data       │ Actions                               │
  │   ┌────────▼────────┐       │                                        │
  │   │   THEHIVE 5     │       │  :9000                                 │
  │   │   Case Manager  │       │                                        │
  │   │   + Cortex      │       │                                        │
  │   └─────────────────┘       │                                        │
  │                             │                                        │
  │   ┌─────────────────────────▼──────────────┐                        │
  │   │  THREAT INTELLIGENCE (External APIs)   │                        │
  │   │   VirusTotal API v3  │  AbuseIPDB v2   │                        │
  │   └────────────────────────────────────────┘                        │
  └───────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │  MANAGEMENT ZONE                                                     │
  │   Wazuh Dashboard :443  │  Kibana/OpenSearch :5601  │  Portainer    │
  └──────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

> **Prerequisites:** Docker ≥ 24.0, Docker Compose v2, 16 GB RAM, 4 vCPU

```bash
# 1. Clone the repository
git clone https://github.com/your-org/threatflow-soar.git
cd threatflow-soar

# 2. Copy and configure environment variables
cp .env.example .env
# Edit .env — set API keys for VirusTotal, AbuseIPDB, and TheHive

# 3. Launch the full stack
docker-compose up -d

# 4. Verify all services are healthy
docker-compose ps
./scripts/healthcheck.sh

# 5. Access the dashboards
#   Wazuh Dashboard  → https://localhost:443   (admin / <WAZUH_PASSWORD>)
#   TheHive          → http://localhost:9000    (admin@thehive.local / secret)
#   Shuffle          → http://localhost:3001
```

---

## Components

| Tool                | Role                                       | Version | Port(s)                        |
| ------------------- | ------------------------------------------ | ------- | ------------------------------ |
| **Wazuh Manager**   | SIEM – log collection, rule-based alerting | 4.7.0   | 1514/UDP, 1515/TCP, 55000/REST |
| **Wazuh Indexer**   | OpenSearch-based log storage and search    | 4.7.0   | 9200, 9300                     |
| **Wazuh Dashboard** | Kibana-style analytics UI                  | 4.7.0   | 443                            |
| **Shuffle SOAR**    | Workflow orchestration, app integrations   | 1.3.0   | 3001                           |
| **TheHive**         | Case & incident management                 | 5.2     | 9000                           |
| **Cortex**          | Observable analysis and response actions   | 3.1     | 9001                           |
| **Cassandra**       | TheHive backend database                   | 4.1     | 9042                           |
| **Elasticsearch**   | Cortex / TheHive indexing                  | 7.17    | 9200                           |
| **VirusTotal**      | File/URL/IP threat intelligence (API)      | v3      | External HTTPS                 |
| **AbuseIPDB**       | IP reputation scoring (API)                | v2      | External HTTPS                 |
| **Sysmon**          | Windows endpoint telemetry                 | 15.0    | — (agent-side)                 |
| **Python Scripts**  | Custom enrichment & automation scripts     | 3.11    | —                              |

---

## Directory Structure

```
ThreatFlow Autonomous Phishing Response System/
├── README.md                        ← This file
├── LICENSE
├── .env.example                     ← Environment variable template
├── docker-compose.yml               ← Full stack orchestration
│
├── docs/
│   ├── ARCHITECTURE.md              ← Mermaid diagrams & data flow
│   └── DEPLOYMENT_GUIDE.md         ← Full installation walkthrough
│
├── wazuh/
│   ├── config/
│   │   ├── ossec.conf               ← Wazuh manager configuration
│   │   └── local_rules.xml          ← Custom phishing detection rules
│   └── decoders/
│       └── phishing_decoder.xml     ← Custom log decoders
│
├── shuffle/
│   ├── workflows/
│   │   └── phishing_response.json   ← Exported Shuffle workflow
│   └── apps/
│       └── threatflow_custom_app/   ← Custom Shuffle app definitions
│
├── thehive/
│   ├── config/
│   │   └── application.conf         ← TheHive configuration
│   └── templates/
│       └── phishing_case_template.json ← Case template
│
├── scripts/
│   ├── enrich_ioc.py                ← VirusTotal + AbuseIPDB enrichment
│   ├── create_thehive_case.py       ← Automated case creation
│   ├── block_ip.py                  ← Firewall containment action
│   ├── healthcheck.sh               ← Stack health verification
│   └── simulate_phishing.py         ← Red-team test payload generator
│
├── sysmon/
│   └── sysmonconfig.xml             ← Sysmon telemetry config (SwiftOnSecurity base)
│
└── tests/
    ├── test_enrichment.py
    ├── test_thehive_integration.py
    └── sample_alerts/
        └── phishing_alert.json      ← Sample Wazuh alert payload
```

---

## How It Works

1. **Detect** — Sysmon captures endpoint telemetry; Wazuh agents stream logs to the Wazuh Manager, which fires custom rules on phishing indicators (suspicious email headers, macro execution, LOLBin usage).
2. **Enrich** — Shuffle receives the webhook, calls VirusTotal (file hash / URL) and AbuseIPDB (source IP) to calculate a composite threat score.
3. **Case** — A TheHive case is auto-created with all observables, the threat score, and enrichment artifacts attached.
4. **Contain** — If the score exceeds the configured threshold, Shuffle automatically blocks the IP at the firewall, quarantines the mailbox, and notifies the SOC team via email/Slack.
5. **Review** — The analyst reviews the pre-populated TheHive case with full context — no manual log-diving required.

---

## License

```
MIT License

Copyright (c) 2024 ThreatFlow Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
Author
George Botrs Azer
Junior SOC Analyst | SIEM, Log Analysis, Threat Detection
