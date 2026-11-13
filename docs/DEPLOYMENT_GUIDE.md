# ThreatFlow — Deployment Guide

> Complete, step-by-step guide to deploying the ThreatFlow Autonomous Phishing Response System in a production or lab environment.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Docker Compose Architecture](#2-docker-compose-architecture)
3. [Step-by-Step Installation](#3-step-by-step-installation)
4. [Environment Variable Reference](#4-environment-variable-reference)
5. [Health Check Commands](#5-health-check-commands)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Prerequisites

### Hardware Requirements

| Resource | Minimum | Recommended (Production) |
|----------|---------|--------------------------|
| **CPU** | 4 vCPU | 8 vCPU |
| **RAM** | 16 GB | 32 GB |
| **Disk** | 100 GB SSD | 500 GB SSD (NVMe preferred) |
| **Network** | 1 Gbps LAN | 1 Gbps LAN + Internet egress |

> [!IMPORTANT]
> Elasticsearch and the Wazuh Indexer are memory-intensive. Running below 16 GB RAM will cause Out-of-Memory kills and cascading service failures.

### Software Requirements

| Software | Minimum Version | Installation |
|----------|----------------|-------------|
| **Operating System** | Ubuntu 22.04 LTS / Debian 12 / RHEL 9 | — |
| **Docker Engine** | 24.0.0 | `curl -fsSL https://get.docker.com \| sh` |
| **Docker Compose** | 2.20.0 (v2 plugin) | Bundled with Docker Desktop or `apt install docker-compose-plugin` |
| **Git** | 2.40+ | `apt install git` |
| **Python** | 3.11+ | `apt install python3.11` (optional, for standalone scripts) |
| **curl / jq** | Any recent | `apt install curl jq` |

### Network Requirements

| Direction | Protocol | Port(s) | Purpose |
|-----------|----------|---------|---------|
| Agents → Manager | TCP/UDP | 1514 | Wazuh agent log forwarding |
| Manager → Agents | TCP | 1515 | Agent enrolment |
| Dashboard → Server | HTTPS | 443 | Web UI |
| Shuffle (internal) | HTTP | 3001 | Workflow API |
| TheHive | HTTP | 9000 | Case management API + UI |
| Cortex | HTTP | 9001 | Analyzer API |
| OpenSearch | HTTP | 9200 | Index API |
| Egress → Internet | HTTPS | 443 | VirusTotal, AbuseIPDB APIs |

### API Keys Required

Before deployment you must obtain the following API credentials:

- **VirusTotal** — Free or premium key: https://www.virustotal.com/gui/join-us
- **AbuseIPDB** — Free key (up to 1,000 checks/day): https://www.abuseipdb.com/register
- **TheHive** — Generated during first-run setup (see Step 7)
- **Shuffle Webhook** — Auto-generated when creating a workflow trigger

---

## 2. Docker Compose Architecture

ThreatFlow's `docker-compose.yml` defines **three networks** that mirror the security zone model:

```
threatflow_dmz_net      172.20.0.0/24   Simulated monitored endpoint traffic
threatflow_soc_net      172.21.0.0/24   Internal SOC service mesh
threatflow_mgmt_net     172.22.0.0/24   Management plane (dashboards, admin)
```

**Service dependency order** (Docker `depends_on` chain):

```
cassandra
  └─→ thehive
        └─→ cortex
wazuh-indexer
  └─→ wazuh-manager
        └─→ wazuh-dashboard
shuffle-database (MongoDB)
  └─→ shuffle-backend
        └─→ shuffle-frontend
                └─→ shuffle-orborus (worker executor)
```

> [!NOTE]
> TheHive requires Cassandra to be fully healthy (not just started) before it initialises its schema. The `healthcheck` on the Cassandra service uses `cqlsh` to verify readiness, and TheHive's `depends_on.condition: service_healthy` enforces this ordering.

**Volume mounts overview:**

| Volume | Service | Purpose |
|--------|---------|---------|
| `wazuh-indexer-data` | wazuh-indexer | Persistent index storage |
| `wazuh-manager-config` | wazuh-manager | Ruleset, ossec.conf |
| `wazuh-dashboard-config` | wazuh-dashboard | Kibana config |
| `thehive-data` | thehive | Attachment file store |
| `cassandra-data` | cassandra | TheHive database |
| `shuffle-database` | shuffle-database | Workflow/app definitions |
| `shuffle-files` | shuffle-backend | Uploaded execution artefacts |
| `cortex-jobs` | cortex | Analyzer job artefacts |

---

## 3. Step-by-Step Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/your-org/threatflow-soar.git
cd "threatflow-soar"
```

### Step 2 — Configure System Parameters

Elasticsearch and OpenSearch require elevated `vm.max_map_count`. Apply permanently:

```bash
# Apply immediately
sudo sysctl -w vm.max_map_count=262144

# Persist across reboots
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Increase file descriptor limits:

```bash
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
```

### Step 3 — Configure Environment Variables

```bash
cp .env.example .env
nano .env   # or use your preferred editor
```

Fill in all required values (see [Section 4](#4-environment-variable-reference) for the full reference). At minimum, set:

```dotenv
VIRUSTOTAL_API_KEY=<your_key>
ABUSEIPDB_API_KEY=<your_key>
WAZUH_API_PASSWORD=<strong_password>
THEHIVE_SECRET=<random_64_char_string>
```

Generate a strong random secret:

```bash
openssl rand -hex 32
```

### Step 4 — Pull All Docker Images

Pre-pull images to avoid timeout issues during first `up`:

```bash
docker compose pull
```

### Step 5 — Start Infrastructure Services First

Bring up the databases before the application layer to allow proper initialisation:

```bash
# Start Cassandra, MongoDB, and Wazuh Indexer
docker compose up -d cassandra shuffle-database wazuh-indexer

# Wait for Cassandra to be healthy (usually 60–90 seconds)
docker compose ps cassandra
# STATUS should show: healthy
```

Monitor Cassandra startup:

```bash
docker compose logs -f cassandra | grep -E "Starting|listening|Startup"
# Wait for: "Startup complete"
```

### Step 6 — Start the Full Stack

```bash
docker compose up -d
```

Verify all containers started:

```bash
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
```

Expected output: all services showing `Up` or `Up (healthy)`.

### Step 7 — Initialise TheHive

On first run, TheHive needs an initial administrator account:

```bash
# Wait for TheHive to be ready
until curl -sf http://localhost:9000/api/status | jq -r '.status' | grep -q "Ok"; do
  echo "Waiting for TheHive..."; sleep 5
done

# Create the initial admin user
curl -XPOST -H "Content-Type: application/json" \
  http://localhost:9000/api/v1/user \
  -d '{
    "login": "admin@thehive.local",
    "name": "ThreatFlow Admin",
    "password": "'"${THEHIVE_ADMIN_PASSWORD}"'",
    "profile": "admin"
  }'
```

Access TheHive UI: http://localhost:9000 — log in with `admin@thehive.local`.

**Generate TheHive API Key:**

1. Log in → User menu (top right) → **API Key** → **Create**
2. Copy the key and add it to `.env` as `THEHIVE_API_KEY=<key>`

Restart the Shuffle backend to pick up the new key:

```bash
docker compose restart shuffle-backend
```

### Step 8 — Import the Shuffle Workflow

```bash
# Using Shuffle CLI or the UI
# UI method:
# 1. Navigate to http://localhost:3001
# 2. Workflows → Import Workflow
# 3. Upload: shuffle/workflows/phishing_response.json
```

After import:
1. Open the **Phishing Response v2** workflow
2. Click the **Webhook** trigger node → copy the **Webhook URL**
3. Add this URL to `.env` as `SHUFFLE_WEBHOOK_URL=<url>`
4. Activate the workflow (toggle to **Running**)

### Step 9 — Configure Wazuh Webhook Integration

```bash
# Edit the Wazuh integration config
docker compose exec wazuh-manager bash -c '
cat >> /var/ossec/etc/ossec.conf << EOF
<integration>
  <name>shuffle</name>
  <hook_url>'"${SHUFFLE_WEBHOOK_URL}"'</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
EOF
'

# Apply custom phishing rules
docker compose cp wazuh/config/local_rules.xml \
  wazuh-manager:/var/ossec/etc/rules/local_rules.xml

# Restart Wazuh manager to apply changes
docker compose restart wazuh-manager
```

### Step 10 — Enrol a Wazuh Agent (Windows Endpoint)

On the Windows endpoint (PowerShell as Administrator):

```powershell
# Download Wazuh agent MSI
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" `
  -OutFile "wazuh-agent.msi"

# Install with manager address
msiexec.exe /i wazuh-agent.msi `
  WAZUH_MANAGER="<WAZUH_MANAGER_IP>" `
  WAZUH_REGISTRATION_PASSWORD="<WAZUH_AGENT_PASSWORD>" `
  WAZUH_AGENT_GROUP="phishing-endpoints" /q

# Start the service
NET START WazuhSvc

# Verify agent is connected
Get-Service WazuhSvc
```

### Step 11 — Install and Configure Sysmon (Windows)

```powershell
# Download Sysmon and SwiftOnSecurity config
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon

# Copy ThreatFlow's Sysmon config
Copy-Item .\sysmon\sysmonconfig.xml C:\Sysmon\

# Install Sysmon with ThreatFlow config
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml

# Verify Sysmon is running
Get-Service Sysmon64
```

### Step 12 — Verify End-to-End with a Test Alert

```bash
# Simulate a phishing alert (safe test payload)
python3 scripts/simulate_phishing.py --target http://localhost:55000 \
  --user admin --password "${WAZUH_API_PASSWORD}"

# Monitor for the alert in Shuffle
# Check TheHive for auto-created case
curl -s -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
  http://localhost:9000/api/v1/case | jq '.[0] | {title, severity, status}'
```

---

## 4. Environment Variable Reference

Copy `.env.example` to `.env` and populate all values marked **Required**.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VIRUSTOTAL_API_KEY` | ✅ | — | VirusTotal API v3 key |
| `ABUSEIPDB_API_KEY` | ✅ | — | AbuseIPDB API v2 key |
| `THEHIVE_API_KEY` | ✅ | — | TheHive API key (generated post-install) |
| `THEHIVE_ADMIN_PASSWORD` | ✅ | — | TheHive administrator account password |
| `THEHIVE_SECRET` | ✅ | — | 64-char random secret for session encryption |
| `SHUFFLE_WEBHOOK_URL` | ✅ | — | Shuffle phishing workflow webhook URL |
| `WAZUH_API_PASSWORD` | ✅ | — | Wazuh REST API password (wazuh-wui user) |
| `WAZUH_AGENT_PASSWORD` | ✅ | — | Agent enrolment shared secret |
| `WAZUH_INDEXER_PASSWORD` | ✅ | — | OpenSearch admin password |
| `SLACK_WEBHOOK_URL` | ⚠️ Optional | — | Slack incoming webhook for SOC notifications |
| `SMTP_HOST` | ⚠️ Optional | — | SMTP relay host for email notifications |
| `SMTP_PORT` | ⚠️ Optional | `587` | SMTP port |
| `SMTP_USER` | ⚠️ Optional | — | SMTP authentication username |
| `SMTP_PASSWORD` | ⚠️ Optional | — | SMTP authentication password |
| `SOC_EMAIL` | ⚠️ Optional | — | Analyst notification email address |
| `FIREWALL_API_URL` | ⚠️ Optional | — | pfSense / FortiGate REST API endpoint |
| `FIREWALL_API_KEY` | ⚠️ Optional | — | Firewall API authentication key |
| `THREAT_SCORE_HIGH` | No | `80` | Score threshold for auto-contain |
| `THREAT_SCORE_MEDIUM` | No | `50` | Score threshold for medium-severity case |
| `THEHIVE_URL` | No | `http://thehive:9000` | TheHive internal URL (for Shuffle) |
| `CORTEX_URL` | No | `http://cortex:9001` | Cortex internal URL |
| `WAZUH_MANAGER_IP` | No | `wazuh-manager` | Wazuh manager hostname/IP for agents |
| `LOG_RETENTION_DAYS` | No | `90` | Wazuh index retention policy (days) |
| `TZ` | No | `UTC` | Timezone for all containers |

> [!CAUTION]
> Never commit `.env` to version control. It is listed in `.gitignore`. Rotate all API keys immediately if accidentally exposed.

---

## 5. Health Check Commands

Run these commands to verify each service after deployment:

### Overall Stack Status

```bash
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
```

### Wazuh Manager

```bash
# Check manager status and connected agents
docker compose exec wazuh-manager /var/ossec/bin/wazuh-control status
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l

# Verify rules are loaded
docker compose exec wazuh-manager /var/ossec/bin/ossec-logtest -t
```

### Wazuh Indexer (OpenSearch)

```bash
# Cluster health
curl -sk -u admin:${WAZUH_INDEXER_PASSWORD} \
  https://localhost:9200/_cluster/health | jq '.status'
# Expected: "green"

# Index list
curl -sk -u admin:${WAZUH_INDEXER_PASSWORD} \
  https://localhost:9200/_cat/indices?v | grep wazuh
```

### TheHive

```bash
# API status
curl -sf http://localhost:9000/api/status | jq '.status'
# Expected: "Ok"

# List cases
curl -s -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
  http://localhost:9000/api/v1/case/stats | jq '.'
```

### Cortex

```bash
# API health
curl -sf http://localhost:9001/api/status | jq '..'
# Should return version and analyzer count
```

### Shuffle

```bash
# Backend health
curl -sf http://localhost:3001/api/v1/health
# Expected: {"success": true}

# List workflows
curl -sf -H "Authorization: Bearer ${SHUFFLE_AUTH_TOKEN}" \
  http://localhost:3001/api/v1/workflows | jq '.[].name'
```

### Full Stack Quick Check Script

```bash
./scripts/healthcheck.sh
```

Expected output:

```
[✓] Wazuh Manager        — Running (3 agents connected)
[✓] Wazuh Indexer        — Healthy (green)
[✓] Wazuh Dashboard      — Reachable (HTTPS:443)
[✓] TheHive              — Ok (v5.2)
[✓] Cortex               — Reachable (12 analyzers loaded)
[✓] Shuffle Backend      — Healthy
[✓] Shuffle Frontend     — Reachable
[✓] Cassandra            — Healthy (1 node)
[✓] VirusTotal API       — Reachable (quota: 480/500)
[✓] AbuseIPDB API        — Reachable (quota: 992/1000)
```

---

## 6. Troubleshooting

### Issue 1 — Cassandra fails to start / TheHive stays in restart loop

**Symptom:**
```
ERROR: cassandra: exited with code 137
ERROR: thehive: Health check failed — connection refused :9042
```

**Cause:** Cassandra killed by OOM (Out of Memory), or TheHive started before Cassandra was fully ready.

**Fix:**

```bash
# Check available memory
free -h

# Reduce Cassandra heap (edit docker-compose.yml)
# Change: MAX_HEAP_SIZE=1G  HEAP_NEWSIZE=200M  (from 2G/400M)

# Force stop and clean volumes only if corrupted
docker compose down
docker volume rm threatflow_cassandra-data
docker compose up -d cassandra

# Wait for full startup before bringing up TheHive
docker compose logs -f cassandra | grep "Startup complete"
docker compose up -d thehive
```

---

### Issue 2 — Wazuh Indexer reports "red" cluster status

**Symptom:**
```json
{"status": "red", "unassigned_shards": 15}
```

**Cause:** `vm.max_map_count` is too low, or disk is full (OpenSearch blocks writes at 85% disk usage).

**Fix:**

```bash
# Check and fix vm.max_map_count
cat /proc/sys/vm/max_map_count
sudo sysctl -w vm.max_map_count=262144

# Check disk space
df -h /var/lib/docker

# If disk full — delete old indices (adjust date)
curl -XDELETE -sk -u admin:${WAZUH_INDEXER_PASSWORD} \
  "https://localhost:9200/wazuh-alerts-4.x-2024.01.*"

# Force cluster reroute to recover shards
curl -XPOST -sk -u admin:${WAZUH_INDEXER_PASSWORD} \
  "https://localhost:9200/_cluster/reroute?retry_failed=true" | jq '.acknowledged'
```

---

### Issue 3 — Shuffle workflow triggers but no TheHive case is created

**Symptom:** Wazuh alert fires, Shuffle execution log shows success, but no case appears in TheHive.

**Cause:** Incorrect TheHive API key or URL in Shuffle app configuration, or TheHive API key has insufficient permissions.

**Fix:**

```bash
# Verify TheHive is reachable from Shuffle container
docker compose exec shuffle-backend \
  curl -sf -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
  http://thehive:9000/api/status | jq '.status'
# If this fails: check network, API key, and TheHive container health

# Regenerate the API key in TheHive UI
# User Menu → API Key → Revoke → Create New
# Update THEHIVE_API_KEY in .env

# Restart Shuffle to apply new env vars
docker compose up -d --force-recreate shuffle-backend
```

Also verify the TheHive app in Shuffle:
1. Shuffle UI → Apps → TheHive → Edit
2. Confirm URL is `http://thehive:9000` (not localhost)
3. Confirm API key matches the new key

---

### Issue 4 — VirusTotal / AbuseIPDB API calls return 403 or quota errors

**Symptom:**
```
ERROR: VirusTotal returned HTTP 403
ERROR: AbuseIPDB quota exceeded (0 remaining)
```

**Cause:** Invalid API key, or daily quota exhausted (free tier: 500 VT / 1,000 AbuseIPDB per day).

**Fix:**

```bash
# Validate VirusTotal API key directly
curl -s --request GET \
  --url "https://www.virustotal.com/api/v3/users/current_user" \
  --header "x-apikey: ${VIRUSTOTAL_API_KEY}" | jq '.data.attributes.quotas'

# Validate AbuseIPDB API key
curl -s -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=8.8.8.8" \
  -H "Key: ${ABUSEIPDB_API_KEY}" -H "Accept: application/json" | jq '.data.abuseConfidenceScore'
```

If quota is exhausted, you have three options:
1. Wait for daily quota reset (midnight UTC)
2. Upgrade to a paid tier
3. Temporarily raise `THREAT_SCORE_HIGH=100` in `.env` to disable auto-containment until quota resets

---

### Issue 5 — Wazuh agents show as "Disconnected" in the Dashboard

**Symptom:** Agents enrolled but show red "Disconnected" status in Wazuh Dashboard.

**Cause:** Firewall blocking port 1514 between agent host and manager, incorrect manager IP in agent config, or time skew >60 seconds between agent and manager.

**Fix:**

```bash
# On the manager host — check if 1514 is accepting connections
sudo ss -tulpn | grep 1514
docker compose exec wazuh-manager netstat -tlpn | grep 1514

# On the agent Windows host — test connectivity
Test-NetConnection -ComputerName <WAZUH_MANAGER_IP> -Port 1514

# If blocked: open the port in the host firewall
sudo ufw allow 1514/udp
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp

# Check time synchronisation on agent
# Windows:
w32tm /query /status
# Linux agent:
timedatectl status

# Force agent reconnect
# Windows:
NET STOP WazuhSvc && NET START WazuhSvc
# Linux:
sudo systemctl restart wazuh-agent

# Verify from manager logs
docker compose logs wazuh-manager | grep -i "connected\|agent"
```

If the agent was re-enrolled with a new key, remove the old entry first:

```bash
docker compose exec wazuh-manager \
  /var/ossec/bin/agent_control -r <AGENT_ID>
```

---

> [!TIP]
> Run `docker compose logs -f <service-name>` for real-time log streaming of any specific service. All container logs are also indexed in the Wazuh Indexer and searchable from the Wazuh Dashboard.

---

*ThreatFlow Deployment Guide — v2.0 | Last updated: November 2026*

