# Ben Blake Contributions — CS 5542 Lab 6

**Role:** Backend Engineer

---

## Personal Responsibilities and Implemented Components

### 1. Snowflake Environment Setup (`sql/`)
- **`sql/01_setup.sql`** — Provisioned the Snowflake warehouse (`CYBER_WH`), database (`CYBER_DB`), schema (`SECURITY`), and role assignments.
- **`sql/02_schema.sql`** — Defined all five production tables: `ASSETS`, `VULNERABILITIES`, `INCIDENTS`, `SECURITY_CONTROLS`, `THREAT_ACTORS`, plus the `NIST_COMPLIANCE_SUMMARY` view used by the compliance tool.
- **`sql/03_staging.sql`** — Created staging tables and `COPY INTO` commands for bulk CSV ingestion from Snowflake internal stages.
- **`sql/04_queries.sql`** — Implement meaningful SQL queries for analysis.

### 2. Synthetic Data Generation (`scripts/generate_data.py`)
- Wrote the full data generation script using `pandas` and `Faker` to produce 5 realistic CSV files:
  - `data/csv/assets.csv` (500 rows — servers, endpoints, network devices)
  - `data/csv/vulnerabilities.csv` (2,000 rows — CVSS scores, severity labels, CVE IDs)
  - `data/csv/incidents.csv` (1,000 rows — kill chain phases, threat actors, resolution timestamps)
  - `data/csv/security_controls.csv` (300 rows — NIST/SOC 2/ISO 27001 controls with compliance scores)
  - `data/csv/threat_actors.csv` (50 rows — APT groups, TTPs, origin countries)
- Enforced referential integrity across tables using shared ID spaces.

### 3. Data Ingestion Pipeline (`scripts/ingest.py`)
- Built the end-to-end ingestion pipeline: loads each CSV, uploads to Snowflake internal stage via `PUT`, runs `COPY INTO` for each table, and writes a `pipeline_logs.csv` run record.
- Handles connection setup using RSA key-pair authentication from `.env`.

### 4. AI Agent Backend (`agent/`)
- **`agent/__init__.py`** — Package marker.
- **`agent/tools.py`** — Implemented all five Snowflake query functions:
  - `get_top_risk_assets(conn, limit)` — Ranks assets by max CVSS score via JOIN across ASSETS + VULNERABILITIES.
  - `get_incident_trends(conn, months)` — Aggregates monthly incident counts and resolution rates.
  - `get_compliance_summary(conn, framework)` — Queries the `NIST_COMPLIANCE_SUMMARY` view with optional framework filter.
  - `get_kill_chain_analysis(conn)` — Breaks down incidents by Kill Chain phase with actor and asset counts.
  - `get_asset_details(conn, asset_type, criticality)` — Returns operational inventory details with optional filters.
  - All functions share the dashboard's existing Snowflake connection (no second connection), return UTF-8 JSON strings, and catch all exceptions gracefully.
- **`agent/tool_schemas.py`** — Authored all five Gemini `FunctionDeclaration` objects with precise descriptions engineered to guide the LLM toward correct tool selection (including distinguishing `get_asset_details` from `get_top_risk_assets` to ensure multi-tool behavior on complex queries).
- **`agent/agent.py`** — Implemented the core agentic loop (`run_agent`):
  - Configures Gemini 3.0 Flash Preview with function-calling enabled.
  - Iterates up to 5 times: checks for `function_call` parts, dispatches to matching Python functions, sends `FunctionResponse` back via `chat.send_message()`.
  - Returns `(final_answer, tool_log)` tuple so the UI can display tool call metadata.
  - Engineered system prompt to enforce grounded, multi-tool reasoning for complex queries.

### 5. AI Agent Evaluation (`reports/task4_evaluation_report.md`)
- Designed the three evaluation scenarios (Simple / Medium / Complex tiers).
- Ran all three scenarios against live Snowflake data and documented actual tool call sequences, reasoning steps, latencies, and accuracy assessments.
- Analyzed failure modes and recorded five lessons learned around tool disambiguation, prompt engineering, and multi-step reasoning.

---

## Links to Commits / Pull Requests

| Component | Commit |
|-----------|--------|
| SQL setup & schema scripts | [`6c64ed0`](https://github.com/ben-blake/cs5542-lab06/commit/6c64ed0) |
| Data generation script | [`98e4c37`](https://github.com/ben-blake/cs5542-lab06/commit/98e4c37) |
| Ingestion pipeline | [`7eec24a`](https://github.com/ben-blake/cs5542-lab06/commit/7eec24a) |
| `agent/tools.py` | [`c8f073b`](https://github.com/ben-blake/cs5542-lab06/commit/c8f073b) |
| `agent/tool_schemas.py` | [`5b6c081`](https://github.com/ben-blake/cs5542-lab06/commit/5b6c081) |
| `agent/agent.py` | [`0ff0c7d`](https://github.com/ben-blake/cs5542-lab06/commit/0ff0c7d) |
| Evaluation report | [`3084a86`](https://github.com/ben-blake/cs5542-lab06/commit/3084a86) |

---

## Reflection: Technical Contributions and Learning Outcomes

My primary contribution to Lab 6 was architecting and implementing the backend data layer and AI agent. On the data side, I deepened my understanding of Snowflake's bulk-load pattern — staging CSVs to an internal stage and using `COPY INTO` — and learned how to enforce cross-table consistency in synthetic datasets to avoid query failures downstream.

The most technically challenging and rewarding work was building the Gemini function-calling agent. Implementing the agentic loop required understanding how the `google-generativeai` SDK structures multi-turn conversations: the model emits `function_call` parts, the application executes the tool and sends back `FunctionResponse` content, and the model continues reasoning. Getting this right involved careful attention to how Gemini batches multiple function calls within a single response turn.

The most instructive debugging experience was the Scenario 3 tool selection failure, where the agent consistently called only two of the three expected tools. The root cause was that `get_asset_details` and `get_top_risk_assets` had overlapping descriptions — the LLM treated one as a superset of the other. Fixing it required both rewriting the tool schema description to explicitly contrast the two functions *and* adding explicit multi-tool guidance to the system prompt. This taught me that LLM tool selection is highly sensitive to description precision and that system prompt engineering and schema design must be co-designed, not treated independently.

Overall, Lab 6 gave me hands-on experience with the full stack of an AI-augmented data application: cloud data warehousing, agentic reasoning, and the practical challenges of making LLMs reliably use the right tools.