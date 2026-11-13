# Detection Engineering — ThreatFlow SOAR

> **Sub-module of the ThreatFlow Autonomous Phishing Response System**  
> Detection rules, Sysmon configuration, and Sigma rules for phishing TTPs.

---

## Table of Contents

1. [Detection Philosophy](#detection-philosophy)
2. [Directory Structure](#directory-structure)
3. [Files Overview](#files-overview)
4. [MITRE ATT&CK Coverage Map](#mitre-attck-coverage-map)
5. [Rule Tuning Guidance](#rule-tuning-guidance)
6. [Deployment Instructions](#deployment-instructions)
7. [Testing & Validation](#testing--validation)
8. [Contributing](#contributing)

---

## Detection Philosophy

ThreatFlow uses a **defence-in-depth, chain-aware** detection model. Rather than relying on a single high-fidelity indicator, rules are designed to:

### 1. Cover the Full Phishing Kill Chain

```
Email Delivery → Attachment Open → Execution → Persistence → C2 → Credential Theft → Lateral Movement
```

Each stage has at least two overlapping detection rules so that evasion of one rule does not create a blind spot.

### 2. Prioritise Behaviour over Signatures

Signature-based detections (file hashes, exact domain matches) are intentionally minimised in favour of **behavioural analytics**:

- *Who* spawned the process? (parent–child relationships)
- *Where* is the binary executing from? (path anomalies)
- *What* is it communicating with? (network context)
- *When* did activity cluster? (temporal correlation)

This approach catches novel phishing payloads, fileless techniques, and LOLBas abuse without requiring constant signature updates.

### 3. Tiered Confidence Levels

| Wazuh Level | Meaning | Expected Action |
|-------------|---------|-----------------|
| 1–5 | Informational / low confidence | Log only; feed threat intel baseline |
| 6–9 | Medium — worth reviewing | Auto-enrich via VirusTotal/AbuseIPDB; create TheHive alert |
| 10–12 | High confidence indicator | Auto-create TheHive case; notify SOC analyst |
| 13–15 | Critical — active attack | Immediate response: isolate endpoint; page on-call |

### 4. Minimise Alert Fatigue

The Sysmon configuration applies aggressive, targeted exclusions on high-volume, low-value events (Windows Update, AV, browsers in baseline mode) while maintaining visibility into every meaningful process executed in the phishing attack chain.

---

## Directory Structure

```
detection/
├── wazuh_rules/
│   └── phishing_detection_rules.xml   # 26 custom Wazuh rules (IDs 100100–100125)
├── sysmon/
│   └── sysmon_config.xml              # Production Sysmon 15 configuration
├── sigma_rules/
│   └── phishing_sigma_rules.yml       # 5 Sigma rules (multi-backend portable)
└── README.md                          # This file
```

---

## Files Overview

### `wazuh_rules/phishing_detection_rules.xml`

26 custom rules covering 10 detection categories:

| Rule ID Range | Category | Sysmon Event | Count |
|---------------|----------|--------------|-------|
| 100100–100104 | Email client / Office child process | EID 1 | 5 |
| 100105–100107 | Suspicious file drops | EID 11 | 3 |
| 100108–100110 | Suspicious DNS queries | EID 22 | 3 |
| 100111–100112 | Unusual outbound network | EID 3 | 2 |
| 100113–100114 | FIM – AppData modifications | FIM | 2 |
| 100115–100117 | Credential access / LSASS | EID 10, 1 | 3 |
| 100118–100119 | Defence evasion / LOLBas | EID 1 | 2 |
| 100120 | ISO/VHD mount-and-execute | EID 1 | 1 |
| 100121 | Unsigned DLL sideloading | EID 7 | 1 |
| 100122–100125 | Correlated / post-exploitation | EID 1, composite | 4 |

### `sysmon/sysmon_config.xml`

Production Sysmon 15 schema 4.90 configuration covering:
- **EID 1** – Process creation (default-include with targeted exclusions)
- **EID 3** – Network connection (default-exclude; include risky processes/ports)
- **EID 5** – Process terminated (selective)
- **EID 7** – Image/DLL loaded (Office + user-path DLLs)
- **EID 8** – CreateRemoteThread (near-all; exclude legitimate debuggers)
- **EID 10** – ProcessAccess targeting LSASS and sensitive processes
- **EID 11** – FileCreate for suspicious extensions and paths
- **EID 12/13** – Registry events on persistence keys
- **EID 15** – ADS/Zone.Identifier stream hashes
- **EID 22** – DNS queries (default-include; exclude Microsoft/update noise)
- **EID 23** – FileDelete for payload cleanup detection

### `sigma_rules/phishing_sigma_rules.yml`

| Rule Title | ID | Level |
|------------|----|-------|
| Suspicious Office Application Child Process | 7b9d1f6c-… | High |
| Email Attachment Execution via Script Host | 2c8e4f1a-… | Medium |
| Credential Access via LSASS Memory | 5a3f8b2c-… | Critical |
| Suspicious DNS Query Post-Email Activity | 8f1b4e7c-… | Medium |
| ISO/IMG Disk Image Mount and Execution | 3d6a2f9e-… | High |

Convert for your SIEM backend:

```bash
# Splunk
sigma convert -t splunk -p sysmon detection/sigma_rules/phishing_sigma_rules.yml

# Wazuh (using pySigma wazuh backend)
sigma convert -t wazuh -p sysmon detection/sigma_rules/phishing_sigma_rules.yml

# Elastic SIEM / EQL
sigma convert -t elasticsearch -p sysmon detection/sigma_rules/phishing_sigma_rules.yml

# Microsoft Sentinel KQL
sigma convert -t kusto -p sysmon detection/sigma_rules/phishing_sigma_rules.yml
```

---

## MITRE ATT&CK Coverage Map

| Tactic | Technique ID | Technique Name | Rule IDs | Sigma Rule |
|--------|-------------|----------------|----------|------------|
| Initial Access | T1566.001 | Spearphishing Attachment | 100100–104, 100107 | Rule 1, 2 |
| Initial Access | T1566.002 | Spearphishing Link | 100108, 100109 | Rule 4 |
| Execution | T1204.002 | Malicious File | 100100–107, 100120 | Rule 1, 2, 5 |
| Execution | T1059.001 | PowerShell | 100101, 100103 | Rule 1 |
| Execution | T1059.005 | Visual Basic | 100100, 100105 | Rule 2 |
| Execution | T1059.007 | JavaScript/JScript | 100100, 100105 | Rule 2 |
| Execution | T1137 | Office Application Startup | 100102, 100103 | Rule 1 |
| Defense Evasion | T1218.005 | Mshta | 100104 | Rule 2 |
| Defense Evasion | T1218.010 | Regsvr32 | 100118 | Rule 1 |
| Defense Evasion | T1218.011 | Rundll32 | 100117 | — |
| Defense Evasion | T1140 | Deobfuscate/Decode | 100119 | — |
| Defense Evasion | T1553.005 | Mark-of-the-Web Bypass | 100106, 100120 | Rule 5 |
| Defense Evasion | T1027 | Obfuscated Files | 100101 | Rule 1 |
| Persistence | T1547.001 | Registry Run Keys | 100113, 100114, 100125 | — |
| Persistence | T1053.005 | Scheduled Task | 100124 | — |
| Privilege Escalation | T1136.001 | Local Account Creation | 100123 | — |
| Credential Access | T1003.001 | LSASS Memory | 100115–100117 | Rule 3 |
| Discovery | T1082 | System Info Discovery | — | — |
| Command & Control | T1071.001 | Web Protocols | 100111, 100112 | — |
| Command & Control | T1071.004 | DNS | 100108–100110 | Rule 4 |
| Command & Control | T1102 | Web Service (staging) | 100109 | Rule 4 |
| Command & Control | T1568.002 | DGA | 100110 | Rule 4 |
| Command & Control | T1105 | Ingress Tool Transfer | 100103, 100109, 100119 | — |
| Lateral Movement | T1078 | Valid Accounts | 100115, 100123 | — |
| Collection | T1041 | Exfiltration over C2 | 100111 | — |

> **Coverage score: 24 unique ATT&CK technique IDs across 10 tactics**

---

## Rule Tuning Guidance

### Step 1 — Baseline Your Environment First

Before going live, run Sysmon and rules in **log-only mode** for 7–14 days:

```xml
<!-- Temporarily switch to log-everything mode in sysmon_config.xml -->
<ProcessCreate onmatch="include">
  <!-- remove all excludes -->
</ProcessCreate>
```

Identify your top-20 false-positive sources and add them to exclusion lists.

### Step 2 — Tune by Level, Not by Rule

Start with Level 13–15 rules only in Shuffle automation. Gradually lower the threshold as you gain confidence:

```yaml
# In Shuffle workflow trigger:
wazuh_alert_level_min: 13   # Week 1
wazuh_alert_level_min: 10   # Week 3 (after tuning)
wazuh_alert_level_min: 8    # Month 2 (steady state)
```

### Step 3 — Whitelist by Process Path, Not Name

Process names are trivially spoofed. Always pair `Image` with an absolute path check in production:

```xml
<!-- BAD — name-only match (bypassable) -->
<Image condition="is">svchost.exe</Image>

<!-- GOOD — full path match -->
<Image condition="is">C:\Windows\System32\svchost.exe</Image>
```

### Step 4 — Enrich Before Alerting

Configure the Shuffle workflow to enrich every Wazuh alert with:
1. **VirusTotal** — hash and domain reputation
2. **AbuseIPDB** — destination IP confidence score
3. **GeoIP** — destination country for C2 geo-fencing

Only create a TheHive case if enrichment confirms maliciousness **or** if the rule level is ≥ 13.

### Step 5 — Review Weekly Metrics

Track these KPIs in your SIEM dashboard:

| Metric | Target |
|--------|--------|
| True Positive Rate | > 85% |
| False Positive Rate | < 5% |
| Mean Time to Alert | < 2 minutes |
| Rules firing 0 times/week | Investigate — may need tuning or test coverage |
| Rules firing > 500 times/day | Likely noisy — add exclusion |

### Common False Positive Sources

| Scenario | Mitigation |
|----------|------------|
| IT scripts run via Outlook macros | Add parent hash to per-rule `<field name="sysmon.sha256">` exclusion |
| AV scanning LSASS | Add AV process to `filter_legit` in Sigma rule 3 / Wazuh 100115 |
| ISO mount for legitimate software deployment | Add known ISO paths to CurrentDirectory exclusion |
| PowerShell admin tasks from email reminders | Use `<same_user>` Wazuh correlation to track specific admin accounts |
| Developer tools querying paste sites | Add developer workstation hostnames to agent exclusion group |

---

## Deployment Instructions

### Deploy Sysmon Configuration

```powershell
# Install Sysmon for the first time
.\Sysmon64.exe -i detection\sysmon\sysmon_config.xml -accepteula

# Update existing Sysmon installation
.\Sysmon64.exe -c detection\sysmon\sysmon_config.xml

# Verify configuration was applied
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5

# Check Sysmon service status
Get-Service Sysmon64
```

### Deploy Wazuh Rules

```bash
# On Wazuh Manager (Linux)
cp detection/wazuh_rules/phishing_detection_rules.xml \
   /var/ossec/etc/rules/phishing_detection_rules.xml

# Validate XML syntax
/var/ossec/bin/wazuh-logtest -t

# Restart Wazuh manager to load rules
systemctl restart wazuh-manager

# Verify rules are loaded
grep "100100" /var/ossec/logs/ossec.log
```

### Convert and Deploy Sigma Rules

```bash
# Install sigma-cli
pip install sigma-cli

# Install Wazuh backend
sigma plugin install wazuh

# Convert to Wazuh format
sigma convert -t wazuh -p sysmon \
  detection/sigma_rules/phishing_sigma_rules.yml \
  -o detection/sigma_rules/wazuh_converted.xml

# Review output before deploying
cat detection/sigma_rules/wazuh_converted.xml
```

---

## Testing & Validation

### Unit Testing Rules with Atomic Red Team

```powershell
# Install Invoke-AtomicRedTeam
Install-Module -Name invoke-atomicredteam -Force

# Test Office child process rule (T1204.002)
Invoke-AtomicTest T1204.002 -TestNumbers 1

# Test LSASS access rule (T1003.001)
Invoke-AtomicTest T1003.001 -TestNumbers 2

# Test credential dumping rule
Invoke-AtomicTest T1003.001 -TestNumbers 3
```

### Validate Wazuh Rule Matching

```bash
# Use wazuh-logtest to replay sample Sysmon events
/var/ossec/bin/wazuh-logtest

# Paste a Sysmon Event ID 1 JSON log — confirm rule 100102 fires:
# {"win":{"eventdata":{"parentImage":"C:\\...\\WINWORD.EXE","image":"C:\\Windows\\System32\\cmd.exe"}}}
```

---

## Contributing

1. New rules **must** include a MITRE ATT&CK technique tag
2. Rules at level ≥ 12 **must** include at least one `falsepositives` comment
3. All Sigma rules **must** pass `sigma check` before PR merge
4. Sysmon config changes **must** be tested in lab before production push
5. Rule IDs in the 100100–100199 range are reserved for phishing detection; use 100200+ for new categories
