# Tina Nguyen Contributions — CS 5542 Lab 6

**Role:** Frontend Engineer

---

## Personal Responsibilities and Implemented Components

### 1. Environment and Dependency Management
- **`requirements.txt`** — Added `google-generativeai>=0.8.0` for Gemini API access.
- **`.env.example`** — Documented `GEMINI_API_KEY` alongside existing Snowflake credentials.
- Diagnosed and fixed `ModuleNotFoundError: No module named 'agent'` by adding `sys.path.insert()` at the top of `app/dashboard.py` to ensure Streamlit resolves the project root correctly.

### 2. Dashboard Implementation
- **`app/dashboard.py`** — Designed and built the complete Streamlit dashboard: page configuration, dark-themed CSS, sidebar, Snowflake connection layer (`get_snowflake_connection` with RSA key-pair and password auth), and `execute_query` helper with latency tracking.
- Implemented all seven tabs: Risk Overview (KPI metrics + top-risk bar chart), All Assets (filterable inventory table + pie chart), Incident Trends (monthly line chart with resolution rate overlay), Compliance Status (framework-grouped bar charts + score table), Kill Chain Analysis (phase breakdown bar chart + actor/asset table), System Status (pipeline metadata + ingestion history), and AI Agent Chat Interface.
- Built the AI Agent chat UI integrating the backend `run_agent()` function: `st.chat_input` for queries, `st.chat_message` loop over `session_state.messages` for conversation persistence, `st.spinner` for loading state, and `st.expander` for tool call transparency.
- Implemented three example query shortcut buttons using a `session_state.agent_pending_query` + `st.rerun()` pattern to bridge button clicks into the chat flow.
- Added per-response latency and reasoning step count display via `st.caption`.

### 3. Synthetic Data (`data/`)
- **`data/csv/`** — Generated and validated the five synthetic CSV datasets (assets, vulnerabilities, incidents, security_controls, threat_actors) used to populate the Snowflake tables driving all dashboard visualizations.

### 4. Antigravity Report (`reports/`)
- **`reports/task1_antigravity_report.md`** — Documented the Antigravity IDE session: prompts used, suggestions received by category, accepted/modified/rejected decisions, and a reflection on the agentic coding experience.
- **`reports/task1_antigravity_screenshot.png`** — Captured the Antigravity IDE screenshot showing the agent interaction for Task 1.

### 5. Pipeline Diagram (`PIPELINE_DIAGRAM.png`)
- **`PIPELINE_DIAGRAM.png`** — Created the end-to-end pipeline architecture diagram illustrating the data flow from CSV generation through Snowflake ingestion to the Streamlit dashboard and AI agent layer.

---

## Links to Commits / Pull Requests

> **Note:** This repository uses manual git management. Commit hashes will be added after the final commit is made.

| Component | Commit |
|-----------|--------|
| Environment and Dependency Management | *(pending)* |
| Dashboard Implementation | *(pending)* |
| Synthetic Data | *(pending)* |
| Antigravity Report | *(pending)* |
| Pipeline Diagram | *(pending)* |

---

## Reflection: Technical Contributions and Learning Outcomes

My primary contribution to Lab 6 was designing and building the complete Streamlit dashboard, from the global connection layer through all six analytical tabs and the new AI Agent chat interface.

The most challenging aspect of the frontend work was building the AI Agent tab. Integrating an asynchronous, multi-step backend process (the Gemini function-calling loop) into Streamlit's synchronous, top-to-bottom execution model required careful use of `st.session_state` for conversation history and the `agent_pending_query` pattern to bridge button clicks to the chat loop. Streamlit reruns the entire script on every interaction, so managing state across those reruns — ensuring messages persist, preventing double-sends, and correctly ordering the spinner/display sequence — required a precise understanding of Streamlit's execution model.

Working closely with the backend engineer on the tool log format (the `(answer, tool_log)` tuple from `run_agent`) taught me how important it is to agree on API contracts between backend and frontend early — the structure of `tool_log` entries directly determined how the expander UI was laid out.

Overall, Lab 6 gave me hands-on experience building production-style data applications in Streamlit, including multi-tab layouts, dynamic filtering, interactive Plotly visualizations, and real-time AI agent integration.