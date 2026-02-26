# CS 5542 Lab 6 — AI Agent Integration with Antigravity IDE

**Live Dashboard:** TODO

**Demo Video:** TODO

## System Workflow

This lab extends Lab 5 (Snowflake Integration) by introducing **AI agents** to automate and enhance the data pipeline using **Google Antigravity IDE**.

It creates an operational agent-enabled system integrating data, retrieval, analytics, and interaction components.

```
CSV Data Files → Snowflake Staging → Tables → SQL Analytics → Streamlit Dashboard
```

### Architecture Overview

![Pipeline Diagram](./PIPELINE_DIAGRAM.png)

---

## Local Setup Instructions

### Prerequisites
- **Snowflake Account** (free tier eligible)
- **Python 3.9+** with pip
- **Git** for version control

### Step 1: Clone Repository and Install Dependencies

```bash
cd cs5542-lab06
pip install -r requirements.txt
```

### Step 2: Configure Snowflake Credentials

1. Copy `.env.example` to `.env`
2. Fill in your Snowflake credentials:
   ```
   SNOWFLAKE_ACCOUNT=your_account_id
   SNOWFLAKE_USER=your_username
   SNOWFLAKE_PASSWORD=your_password
   SNOWFLAKE_WAREHOUSE=CYBER_WH
   SNOWFLAKE_DATABASE=CYBER_DB
   SNOWFLAKE_SCHEMA=SECURITY
   ```

**⚠️ Important:** Never commit `.env` to version control!

### Step 2b: Configure Gemini API Key

1. Go to [aistudio.google.com](https://aistudio.google.com) and create an API key
2. Add to your `.env` file:
   ```
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

### Step 3: Generate Synthetic Data

```bash
python scripts/generate_data.py
```

**Expected Output:**
```
✓ Data generation complete!
  - assets.csv: 200 rows
  - vulnerabilities.csv: 500 rows
  - incidents.csv: 300 rows
  - security_controls.csv: 100 rows
  - threat_actors.csv: 50 rows

All files saved to: data/csv/
```

### Step 4: Ingest Data into Snowflake

```bash
python scripts/ingest.py
```

**What this does:**
1. Connects to Snowflake
2. Creates database, schema, and warehouse
3. Creates 5 data tables
4. Uploads CSV files to internal stage
5. Executes COPY INTO commands
6. Creates analytics views and materialized views
7. Logs all operations to `pipeline_logs.csv`

**Expected Output:**
```
[1/5] Connecting to Snowflake...
[2/5] Setting up Snowflake environment...
[3/5] Uploading and ingesting data...
[4/5] Creating analytics queries and views...
[5/5] Verifying data load...
✓ Pipeline complete! Check pipeline_logs.csv for details.
```

### Step 5: Launch Streamlit Dashboard

```bash
streamlit run app/dashboard.py
```

Opens at `http://localhost:8501`

**Dashboard Features:**
- **Risk Overview**: Top 10 highest-risk assets with CVSS scores
- **Incident Trends**: Monthly incident timeline and resolution rates
- **Compliance Status**: Framework-by-framework control compliance
- **Kill Chain Analysis**: Incident distribution across attack phases
- **System Status**: Pipeline performance logs and data statistics
- **AI Agent**: Gemini agentic loop with 5 Snowflake tool functions

---

## Project Structure

```
cs5542-lab06/
├── agent/
│   ├── __init__.py
│   ├── agent.py          # Gemini agentic loop
│   ├── tools.py          # 5 Snowflake tool functions
│   └── tool_schemas.py   # Gemini FunctionDeclaration objects
├── app/
│   └── dashboard.py      # Streamlit dashboard (6 analytics tabs + AI Agent tab)
├── data/csv/             # Generated CSV files (5 tables)
├── reports/              # Reports and screenshots
│   ├── task1_antigravity_report.md
│   ├── task1_antigravity_screenshot.png
│   └── task4_evaluation_report.md
├── scripts/
│   ├── generate_data.py  # Synthetic data generation
│   └── ingest.py         # Snowflake ingestion pipeline
├── sql/                  # Raw SQL setup scripts
├── pipeline_logs.csv
├── requirements.txt
└── README.md
```

---

## Data Schema

### ASSETS (200 rows)
Infrastructure inventory with asset metadata and patch status.

| Column | Type | Description |
|--------|------|-------------|
| asset_id | VARCHAR | Unique identifier |
| hostname | VARCHAR | System hostname |
| ip_address | VARCHAR | IP address |
| asset_type | VARCHAR | Server, Endpoint, Network Device, etc. |
| criticality | VARCHAR | Low, Medium, High, Critical |
| owner | VARCHAR | Team responsible for asset |
| location | VARCHAR | Physical/logical location |
| os | VARCHAR | Operating system |
| last_patched_date | DATE | Last security patch applied |

### VULNERABILITIES (500 rows)
CVE-like vulnerability data with severity scoring.

| Column | Type | Description |
|--------|------|-------------|
| vuln_id | VARCHAR | Unique identifier |
| cve_id | VARCHAR | CVE identifier |
| asset_id | VARCHAR | FK to ASSETS |
| cvss_score | DECIMAL | CVSS v3 score (1.0-10.0) |
| severity_label | VARCHAR | Critical, High, Medium, Low |
| category | VARCHAR | RCE, SQL Injection, XSS, etc. |
| status | VARCHAR | Open, In Remediation, Remediated, Accepted Risk |
| discovered_date | DATE | When vulnerability was discovered |
| remediated_date | DATE | When vulnerability was fixed (if applicable) |

### INCIDENTS (300 rows)
Security incidents with attack chain metadata.

| Column | Type | Description |
|--------|------|-------------|
| incident_id | VARCHAR | Unique identifier |
| asset_id | VARCHAR | FK to ASSETS |
| incident_type | VARCHAR | Malware, Breach, DDoS, Phishing, etc. |
| severity | VARCHAR | Low, Medium, High, Critical |
| detected_at | TIMESTAMP | Detection timestamp |
| resolved_at | TIMESTAMP | Resolution timestamp (if applicable) |
| attack_vector | VARCHAR | Network, Email, Physical, Web, etc. |
| kill_chain_phase | VARCHAR | Cyber Kill Chain phase (Lockheed Martin) |
| threat_actor_id | VARCHAR | FK to THREAT_ACTORS |

### SECURITY_CONTROLS (100 rows)
Compliance controls mapped to frameworks (NIST, SOC 2, ISO 27001, Zero Trust).

| Column | Type | Description |
|--------|------|-------------|
| control_id | VARCHAR | Unique identifier |
| framework | VARCHAR | NIST CSF, SOC 2, ISO 27001, Zero Trust |
| category | VARCHAR | Identify, Protect, Detect, Respond, Recover |
| control_name | VARCHAR | MFA, Encryption, Firewall, etc. |
| implementation_status | VARCHAR | Not Started, In Progress, Implemented, etc. |
| last_reviewed_date | DATE | Last audit/review date |
| compliance_score | DECIMAL | 0.0-100.0 compliance percentage |

### THREAT_ACTORS (50 rows)
Advanced Persistent Threat (APT) and criminal group profiles.

| Column | Type | Description |
|--------|------|-------------|
| actor_id | VARCHAR | Unique identifier |
| name | VARCHAR | Group/campaign name |
| actor_type | VARCHAR | APT, Criminal Gang, Insider Threat, Hacktivist |
| country_origin | VARCHAR | Country code |
| ttps | VARCHAR | Tactics, Techniques, Procedures |
| active_since | DATE | First observed activity |
| sophistication_level | VARCHAR | Low, Medium, High, Very High |

---

## Core Requirements

### 1. Antigravity IDE Analysis
- Screenshot of Antigravity IDE analyzing the project
- `task1_antigravity_report.md` documenting findings

### 2. Agent Tools
- `tools.py` — tool function implementations
- `tool_schemas.py` (or equivalent) — tool schema definitions/configuration

### 3. Agent Implementation
- Agent implementation code integrating with Snowflake data pipeline

### 4. Updated Streamlit Application
- Streamlit app updated with agent integration

### 5. Evaluation Report
- `task4_evaluation_report.md` documenting agent performance and results

### 6. Demo Video
- 3–5 minute demo video linked in README (see top of page)

### 7. Documentation & Supporting Artifacts
- Updated `README.md` explaining system workflow and setup
- Supporting code, diagrams, and logs

### 8. Individual Contribution Documentation
- See `BEN_CONTRIBUTIONS.md` and `TINA_CONTRIBUTIONS.md` for team member responsibilities

---

## Running Tests

### Verify Data Generation
```bash
python scripts/generate_data.py
ls -la data/csv/
# Should show 5 CSV files with rows > 0
```

### Verify Data Load
```bash
python scripts/ingest.py
# Should complete without errors and show row counts
```

### Verify Dashboard
```bash
streamlit run app/dashboard.py
# Open browser to http://localhost:8501
# All tabs should load with data and visualizations
```

### Verify Pipeline Logs
```bash
cat pipeline_logs.csv
# Should have entries for each data load operation
```

---

## Troubleshooting

### Connection Issues
**Error:** `Failed to connect to Snowflake: Database Connection Error`
- Verify `.env` credentials are correct
- Check Snowflake account ID format (without cloud/region prefix)
- Ensure warehouse is NOT suspended

### Data Load Issues
**Error:** `COPY INTO ... failed`
- Check CSV file paths are correct
- Verify CSV headers match table column names (case-sensitive)
- Check for NULL values in PRIMARY KEY columns

### Dashboard Issues
**Error:** `ModuleNotFoundError: No module named 'snowflake'`
- Run `pip install -r requirements.txt`
- Check Python version >= 3.9

---

## References

- [Snowflake Documentation](https://docs.snowflake.com/)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## License & Attribution

CS 5542 Big Data — University of Missouri-Kansas City (UMKC)
Lab 6: AI Agent Integration
February 2026

