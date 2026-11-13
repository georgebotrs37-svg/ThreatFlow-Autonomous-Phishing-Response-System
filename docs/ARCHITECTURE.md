# ThreatFlow — Architecture Deep Dive

> This document describes the end-to-end technical architecture of the ThreatFlow Autonomous Phishing Response System, covering data flows, integration points, and security zone boundaries.

---

## 1. End-to-End Phishing Detection-to-Response Pipeline

```mermaid
flowchart TD
    A([📧 Phishing Email Arrives]) --> B[Mail Gateway / MDA\nReceives Message]
    B --> C[Sysmon + Wazuh Agent\nCaptures Endpoint Events]
    C --> D{Wazuh Manager\nRule Engine}
    D -->|No Rule Match| E([✅ Benign — Log & Continue])
    D -->|Rule Match ≥ Level 10| F[Wazuh Alert Generated\nJSON payload]
    F --> G[Shuffle Webhook Trigger\nPOST /api/v1/hooks/...]
    G --> H[Shuffle Workflow Start\nPhishing Response v2]
    H --> I[Extract IOCs\nURL · Hash · Sender IP · Domain]
    I --> J1[VirusTotal API v3\nFile Hash + URL Lookup]
    I --> J2[AbuseIPDB API v2\nIP Reputation Score]
    J1 --> K[Composite Threat Score\nCalculation]
    J2 --> K
    K --> L{Score\nThreshold?}
    L -->|Score < 50\nLow Confidence| M[TheHive Case — LOW\nManual Analyst Review]
    L -->|Score 50–79\nMedium| N[TheHive Case — MEDIUM\nAuto-enrich + Notify]
    L -->|Score ≥ 80\nHigh Confidence| O[TheHive Case — HIGH\nAuto-Contain + Notify]
    O --> P[Block IP at Firewall\niptables / pfSense API]
    O --> Q[Quarantine Mailbox\nO365 / Exchange API]
    O --> R[Notify SOC Team\nEmail + Slack]
    M --> S([📋 Case Open in TheHive])
    N --> S
    P --> S
    Q --> S
    R --> S
    S --> T[Analyst Review &\nCase Enrichment]
    T --> U{Close or\nEscalate?}
    U -->|False Positive| V[Close Case + Tune Rule]
    U -->|Confirmed| W[Incident Report\nGenerated + Closed]
```

---

## 2. Sequence Diagram — Full Incident Lifecycle

```mermaid
sequenceDiagram
    actor User as 👤 Victim User
    participant MG as Mail Gateway
    participant Sysmon as Sysmon (Endpoint)
    participant WA as Wazuh Agent
    participant WM as Wazuh Manager
    participant SH as Shuffle SOAR
    participant VT as VirusTotal API
    participant AI as AbuseIPDB API
    participant TH as TheHive
    actor Analyst as 🛡️ SOC Analyst

    User->>MG: Opens phishing email (clicks link / opens attachment)
    MG->>Sysmon: Process creation / network connection event logged
    Sysmon->>WA: Sysmon event (EventID 1, 3, 11, 22)
    WA->>WM: Encrypted log stream (port 1514)
    WM->>WM: Rule engine evaluation (custom phishing rules)
    WM-->>SH: Webhook POST — Alert JSON (rule.level ≥ 10)
    
    Note over SH: Workflow "Phishing Response v2" triggered
    
    SH->>SH: Parse alert, extract IOCs
    
    par Parallel Enrichment
        SH->>VT: GET /api/v3/files/{hash} + /urls/{url_id}
        VT-->>SH: Reputation score, detections, sandbox report
    and
        SH->>AI: GET /api/v2/check?ipAddress={ip}
        AI-->>SH: Abuse confidence score, ISP, country
    end
    
    SH->>SH: Calculate composite threat score
    
    SH->>TH: POST /api/v1/case — Create case with all observables
    TH-->>SH: Case ID, case URL
    
    alt Score ≥ 80 — AUTO-CONTAIN
        SH->>SH: Execute containment playbook
        SH-->>MG: Block sender IP + quarantine mailbox
        SH-->>Analyst: Alert email + Slack notification with TheHive URL
    else Score 50–79 — NOTIFY
        SH-->>Analyst: Alert email with enrichment summary
    else Score < 50 — LOG ONLY
        Note over TH: Case created at LOW severity
    end
    
    Analyst->>TH: Review case — examine observables, timeline, artifacts
    Analyst->>TH: Add notes, update severity, run additional Cortex analyzers
    
    alt Confirmed Phishing
        Analyst->>TH: Mark tasks complete, close case — TRUE POSITIVE
        TH-->>Analyst: Incident report generated
    else False Positive
        Analyst->>TH: Close case — FALSE POSITIVE
        Analyst->>WM: Submit rule tuning request
    end
```

---

## 3. Data Flow Description by Stage

### Stage 1 — Telemetry Collection
| Input | Processor | Output |
|-------|-----------|--------|
| Email open / attachment execution | Sysmon (EventID 1, 3, 11, 22, 23) | Windows event log entries |
| Sysmon XML events | Wazuh Agent (ossec-logcollector) | Encrypted, compressed log stream |
| Raw log stream | Wazuh Manager (ossec-analysisd) | Structured JSON alert |

**Key Sysmon Event IDs monitored:**
- `1` — Process creation (macro / script interpreter launched from email client)
- `3` — Network connection (beaconing to C2 or phishing domain)
- `11` — File creation (dropped payload)
- `22` — DNS query (suspicious domain resolution)
- `23` — File deletion (artefact cleanup attempt)

---

### Stage 2 — Detection & Alerting
Wazuh Manager's rule engine evaluates every incoming log against ~3,000 built-in rules plus ThreatFlow's custom ruleset (`local_rules.xml`). A phishing alert is generated when:

- **Rule 100001** — Email client spawns PowerShell / `cmd.exe` / `wscript.exe`
- **Rule 100002** — Outbound connection to domain in phishing feed within 60 s of email open
- **Rule 100003** — LOLBin (certutil, bitsadmin, mshta) network activity post-email-open
- **Rule 100004** — Suspicious attachment extension combination (`.doc` + macro execution)

Alerts at **level ≥ 10** trigger the Shuffle webhook.

---

### Stage 3 — Orchestration (Shuffle)
The Shuffle workflow receives the Wazuh alert JSON and executes the following steps:

1. **IOC Extraction** — Regex and JQ parsing to extract: source IP, file hash (SHA256), URL, sender domain, affected hostname.
2. **Parallel Enrichment** — Simultaneous API calls to VirusTotal (file/URL) and AbuseIPDB (IP).
3. **Score Aggregation** — Weighted formula: `(VT_malicious_engines / VT_total_engines × 60) + (AbuseIPDB_score × 0.4)` → 0–100 scale.
4. **Decision Logic** — Branching based on score thresholds (< 50 / 50–79 / ≥ 80).
5. **Case Creation** — TheHive API call with full observables package attached.
6. **Containment** (if score ≥ 80) — Firewall block + mailbox quarantine + notification.

---

### Stage 4 — Case Management (TheHive)
Every incident creates a TheHive case with:
- **Severity**: Low / Medium / High (mapped from composite score)
- **Observables**: IP address, file hash, URL, domain, email address — all auto-tagged
- **Tasks**: Pre-populated from phishing case template (Triage → Containment → Eradication → Recovery)
- **Attachments**: Raw Wazuh alert JSON, VirusTotal full report, AbuseIPDB response

Cortex analyzers (VirusTotal_GetReport, AbuseIPDB, URLScan_io) can be re-run directly from the case UI.

---

### Stage 5 — Containment & Recovery
Automated containment actions (score ≥ 80):

| Action | Mechanism | Target |
|--------|-----------|--------|
| IP Block | `block_ip.py` → iptables / pfSense REST API | Perimeter firewall |
| Mailbox Quarantine | Microsoft Graph API / Exchange PowerShell | Affected mailbox |
| Hash Block | CrowdStrike / Windows Defender API | All enrolled endpoints |
| DNS Sinkhole | Infoblox / Pi-hole API | Internal DNS resolver |
| SOC Notification | SMTP + Slack Incoming Webhook | On-call analyst |

---

## 4. Integration Points

| Integration | Direction | Protocol | Auth Method | Data Exchanged |
|-------------|-----------|----------|-------------|----------------|
| Wazuh Agent → Manager | Outbound | TCP/UDP 1514 | Pre-shared key | Compressed, encrypted log events |
| Wazuh Manager → Shuffle | Outbound | HTTPS POST | Bearer token (webhook secret) | Alert JSON payload |
| Shuffle → VirusTotal | Outbound | HTTPS REST | API Key header | File hash / URL queries + reports |
| Shuffle → AbuseIPDB | Outbound | HTTPS REST | API Key header | IP check requests + reputation data |
| Shuffle → TheHive | Outbound | HTTPS REST | API Key | Case create/update, observable attach |
| Shuffle → Firewall | Outbound | HTTPS REST | API Key / SSH | IP block rule creation |
| TheHive → Cortex | Internal | HTTPS REST | API Key | Observable analysis requests + results |
| Wazuh Dashboard → Indexer | Internal | HTTPS 9200 | Username/Password | Query & aggregation |

---

## 5. Security Zones

```mermaid
flowchart LR
    subgraph DMZ["🌐 DMZ — Monitored Endpoints"]
        direction TB
        EP1[Windows Workstation\nSysmon + Wazuh Agent]
        EP2[Linux Server\nAuditd + Wazuh Agent]
        EP3[Mail Gateway\nPostfix + Wazuh Agent]
    end

    subgraph SOC["🔒 SOC Zone — Detection & Response"]
        direction TB
        WM[Wazuh Manager\n:1514 · :55000]
        WI[Wazuh Indexer\nOpenSearch :9200]
        SH[Shuffle SOAR\n:3001]
        TH[TheHive 5\n:9000]
        CX[Cortex\n:9001]
        DB[(Cassandra\n:9042)]
        WM --> WI
        WM -->|Webhook| SH
        SH --> TH
        SH --> CX
        TH --> DB
        TH <--> CX
    end

    subgraph MGMT["⚙️ Management Zone"]
        direction TB
        WD[Wazuh Dashboard\nHTTPS :443]
        PT[Portainer\n:9443]
        WD --> WI
    end

    subgraph EXT["☁️ External Threat Intelligence"]
        direction TB
        VT[VirusTotal API v3]
        AI[AbuseIPDB API v2]
        SL[Slack Webhook]
    end

    subgraph ACTION["🛡️ Containment Targets"]
        direction TB
        FW[Perimeter Firewall]
        MBX[Exchange / O365\nMailbox Quarantine]
        DNS[DNS Sinkhole]
    end

    DMZ -->|"Encrypted Logs\n1514/TCP-UDP"| SOC
    SOC -->|"HTTPS REST API calls"| EXT
    SOC -->|"Containment Actions\nREST/SSH"| ACTION
    MGMT -.->|"Admin Access"| SOC
    MGMT -.->|"Admin Access"| DMZ
```

---

*Last updated: November 2026 — ThreatFlow v2.0*

