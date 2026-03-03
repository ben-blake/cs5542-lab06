"""
Streamlit Dashboard for Cybersecurity Data Pipeline
Connected to Snowflake, displays analytics and real-time query results.
"""

import streamlit as st
import snowflake.connector
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import sys
import time

# Ensure project root is on sys.path so the 'agent' package is importable
# when Streamlit runs this script from the app/ subdirectory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.agent import run_agent

# ============================================================================
# Configuration and Styling
# ============================================================================
st.set_page_config(
    page_title="Cybersecurity Risk Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    [data-testid="stMetric"] {
        background-color: #1e1e2f;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #3a3a5c;
    }
    [data-testid="stMetric"] label {
        color: #a0a0b8 !important;
    }
    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #ffffff !important;
    }
    </style>
""", unsafe_allow_html=True)

load_dotenv()


def get_config(key, default=None):
    """Read config from env vars (local) or st.secrets (cloud)."""
    val = os.getenv(key)
    if val:
        return val
    try:
        return st.secrets[key]
    except (KeyError, FileNotFoundError):
        return default

# ============================================================================
# Snowflake Connection
# ============================================================================
@st.cache_resource
def get_snowflake_connection():
    """Create and cache Snowflake connection with password or API key."""
    try:
        private_key = get_config('SNOWFLAKE_PRIVATE_KEY')
        private_key_path = get_config('SNOWFLAKE_PRIVATE_KEY_PATH')

        if private_key_path and not private_key:
            with open(private_key_path, 'r') as f:
                private_key = f.read()

        password = get_config('SNOWFLAKE_PASSWORD')

        if private_key or private_key_path:
            from cryptography.hazmat.primitives import serialization

            if private_key_path and not private_key:
                with open(private_key_path, 'rb') as f:
                    private_key_data = f.read()
            else:
                private_key_data = private_key.encode() if isinstance(private_key, str) else private_key

            passphrase = get_config('SNOWFLAKE_PRIVATE_KEY_PASSPHRASE')
            p_key = serialization.load_pem_private_key(
                private_key_data,
                password=passphrase.encode() if passphrase else None
            )
            pkb = p_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            conn = snowflake.connector.connect(
                account=get_config('SNOWFLAKE_ACCOUNT'),
                user=get_config('SNOWFLAKE_USER'),
                private_key=pkb,
                warehouse=get_config('SNOWFLAKE_WAREHOUSE', 'CYBER_WH'),
                database=get_config('SNOWFLAKE_DATABASE', 'CYBER_DB'),
                schema=get_config('SNOWFLAKE_SCHEMA', 'SECURITY'),
                ocsp_fail_open=True
            )
        else:
            conn = snowflake.connector.connect(
                account=get_config('SNOWFLAKE_ACCOUNT'),
                user=get_config('SNOWFLAKE_USER'),
                password=password,
                warehouse=get_config('SNOWFLAKE_WAREHOUSE', 'CYBER_WH'),
                database=get_config('SNOWFLAKE_DATABASE', 'CYBER_DB'),
                schema=get_config('SNOWFLAKE_SCHEMA', 'SECURITY'),
                ocsp_fail_open=True
            )
        return conn
    except Exception as e:
        st.error(f"Failed to connect to Snowflake: {e}")
        st.info("If MFA is enabled, generate an API Key in Snowflake and set SNOWFLAKE_PRIVATE_KEY in .env")
        return None

# ============================================================================
# Query Functions
# ============================================================================
def execute_query(conn, query):
    """Execute a Snowflake query and return results as DataFrame."""
    try:
        start_time = time.time()
        cursor = conn.cursor()
        cursor.execute(query)
        df = cursor.fetch_pandas_all()
        cursor.close()
        latency_ms = int((time.time() - start_time) * 1000)
        return df, latency_ms
    except Exception as e:
        st.error(f"Query failed: {e}")
        return None, 0


def sql_list(values):
    """Format a Python list as a SQL IN clause string."""
    return ', '.join(f"'{v}'" for v in values)

# ============================================================================
# Page Header and Sidebar (connection only)
# ============================================================================
st.title("Cybersecurity Risk Dashboard")
st.markdown("**Real-time analysis of security vulnerabilities, incidents, and compliance**")

with st.sidebar:
    st.header("Connection")

    conn = get_snowflake_connection()
    if conn:
        st.success("Connected to Snowflake", icon="✅")
    else:
        st.error("Not connected to Snowflake", icon="❌")
        st.stop()

    st.divider()
    st.caption("Lab 6 — CS 5542 AI Agent Integration")

# Fetch asset types once for filter defaults
asset_types_df, _ = execute_query(conn, "SELECT DISTINCT asset_type FROM ASSETS ORDER BY asset_type;")
all_asset_types = asset_types_df['ASSET_TYPE'].tolist() if asset_types_df is not None else []
all_severities = ['Critical', 'High', 'Medium', 'Low']

# ============================================================================
# Main Content - Tabs
# ============================================================================
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📊 Risk Overview",
    "🖥️ All Assets",
    "📈 Incident Trends",
    "✅ Compliance Status",
    "🎯 Kill Chain Analysis",
    "📋 System Status",
    "🤖 AI Agent"
])

# ============================================================================
# TAB 1: Risk Overview
# ============================================================================
with tab1:
    st.header("Asset Risk Overview")

    col1, col2, col3, col4 = st.columns(4)

    total_assets_df, _ = execute_query(conn, "SELECT COUNT(*) as cnt FROM ASSETS;")
    total_vulns_df, _ = execute_query(conn, "SELECT COUNT(*) as cnt FROM VULNERABILITIES;")
    critical_vulns_df, _ = execute_query(conn, "SELECT COUNT(*) as cnt FROM VULNERABILITIES WHERE severity_label = 'Critical';")
    total_incidents_df, _ = execute_query(conn, "SELECT COUNT(*) as cnt FROM INCIDENTS;")

    with col1:
        st.metric("Total Assets", int(total_assets_df['CNT'].iloc[0]) if total_assets_df is not None else 0)
    with col2:
        st.metric("Vulnerabilities", int(total_vulns_df['CNT'].iloc[0]) if total_vulns_df is not None else 0)
    with col3:
        st.metric("Critical Vulns", int(critical_vulns_df['CNT'].iloc[0]) if critical_vulns_df is not None else 0)
    with col4:
        st.metric("Total Incidents", int(total_incidents_df['CNT'].iloc[0]) if total_incidents_df is not None else 0)

    st.divider()

    st.subheader("Top 10 Highest-Risk Assets")
    risk_query = """
        SELECT
            a.asset_id, a.hostname, a.asset_type, a.criticality,
            COUNT(DISTINCT v.vuln_id) AS total_vulnerabilities,
            ROUND(AVG(v.cvss_score), 2) AS avg_cvss_score,
            MAX(v.cvss_score) AS max_cvss_score,
            SUM(CASE WHEN v.severity_label = 'Critical' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN v.severity_label = 'High' THEN 1 ELSE 0 END) AS high_count
        FROM ASSETS a
        LEFT JOIN VULNERABILITIES v ON a.asset_id = v.asset_id
        GROUP BY a.asset_id, a.hostname, a.asset_type, a.criticality
        ORDER BY max_cvss_score DESC NULLS LAST, total_vulnerabilities DESC
        LIMIT 10;
    """
    risk_df, latency = execute_query(conn, risk_query)

    if risk_df is not None and not risk_df.empty:
        fig = px.bar(
            risk_df,
            x='HOSTNAME',
            y='MAX_CVSS_SCORE',
            color='MAX_CVSS_SCORE',
            color_continuous_scale='YlOrRd',
            range_color=[0, 10],
            title="Maximum CVSS Score by Asset",
            labels={'MAX_CVSS_SCORE': 'CVSS Score', 'HOSTNAME': 'Hostname'}
        )
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(risk_df, use_container_width=True)
        st.caption(f"Query executed in {latency}ms")
    else:
        st.info("No data matches the current filters.")

# ============================================================================
# TAB 2: All Assets
# ============================================================================
with tab2:
    st.header("Asset Inventory")

    # -- Filters --
    t2_asset_types = st.multiselect("Asset Type:", all_asset_types, default=all_asset_types, key="t2_asset")

    t2_at = f"a.asset_type IN ({sql_list(t2_asset_types)})" if t2_asset_types else "1=1"

    st.divider()

    assets_query = f"""
        SELECT
            a.asset_id, a.hostname, a.ip_address, a.asset_type,
            a.criticality, a.owner, a.location, a.os, a.last_patched_date
        FROM ASSETS a
        WHERE {t2_at}
        ORDER BY a.criticality DESC, a.hostname;
    """
    assets_df, latency = execute_query(conn, assets_query)

    if assets_df is not None and not assets_df.empty:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Assets Shown", len(assets_df))
        with col2:
            critical_count = len(assets_df[assets_df['CRITICALITY'] == 'Critical']) if 'CRITICALITY' in assets_df.columns else 0
            st.metric("Critical Assets", critical_count)
        with col3:
            unique_types = assets_df['ASSET_TYPE'].nunique() if 'ASSET_TYPE' in assets_df.columns else 0
            st.metric("Asset Types", unique_types)

        st.divider()

        if 'ASSET_TYPE' in assets_df.columns:
            type_counts = assets_df['ASSET_TYPE'].value_counts().reset_index()
            type_counts.columns = ['Asset Type', 'Count']
            fig = px.pie(
                type_counts,
                names='Asset Type',
                values='Count',
                title='Asset Distribution by Type'
            )
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Asset Details")
        st.dataframe(assets_df, use_container_width=True)
        st.caption(f"Query executed in {latency}ms")
    else:
        st.info("No assets match the current filters.")

# ============================================================================
# TAB 3: Incident Trends
# ============================================================================
with tab3:
    st.header("Incident Trends")

    # -- Filters --
    fc1, fc2, fc3 = st.columns(3)
    with fc1:
        t3_date = st.date_input(
            "Date range:",
            value=(datetime.now() - timedelta(days=365), datetime.now()),
            max_value=datetime.now(),
            key="t3_date"
        )
        if isinstance(t3_date, tuple) and len(t3_date) == 2:
            t3_start, t3_end = t3_date
        else:
            t3_start, t3_end = datetime.now() - timedelta(days=365), datetime.now()
    with fc2:
        t3_asset_types = st.multiselect("Asset Type:", all_asset_types, default=all_asset_types, key="t3_asset")
    with fc3:
        t3_severity = st.multiselect("Severity:", all_severities, default=all_severities, key="t3_sev")

    t3_at = f"a.asset_type IN ({sql_list(t3_asset_types)})" if t3_asset_types else "1=1"
    t3_sv = f"i.severity IN ({sql_list(t3_severity)})" if t3_severity else "1=1"
    t3_dc = f"i.detected_at BETWEEN '{t3_start}'::TIMESTAMP AND '{t3_end}'::TIMESTAMP + INTERVAL '1 day'"

    st.divider()

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Monthly Incident Timeline")
        trends_query = f"""
            SELECT
                DATE_TRUNC('MONTH', i.detected_at) AS incident_month,
                COUNT(*) AS total_incidents,
                SUM(CASE WHEN i.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_incidents,
                SUM(CASE WHEN i.severity = 'High' THEN 1 ELSE 0 END) AS high_incidents,
                ROUND(100.0 * SUM(CASE WHEN i.resolved_at IS NOT NULL THEN 1 ELSE 0 END) / COUNT(*), 2) AS resolution_rate
            FROM INCIDENTS i
            JOIN ASSETS a ON i.asset_id = a.asset_id
            WHERE {t3_dc} AND {t3_at} AND {t3_sv}
            GROUP BY DATE_TRUNC('MONTH', i.detected_at)
            ORDER BY incident_month DESC;
        """
        trends_df, latency = execute_query(conn, trends_query)

        if trends_df is not None and not trends_df.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=trends_df['INCIDENT_MONTH'],
                y=trends_df['TOTAL_INCIDENTS'],
                mode='lines+markers',
                name='Total Incidents',
                line=dict(color='#1f77b4', width=3),
                marker=dict(size=8)
            ))
            fig.add_trace(go.Scatter(
                x=trends_df['INCIDENT_MONTH'],
                y=trends_df['CRITICAL_INCIDENTS'],
                mode='lines+markers',
                name='Critical Incidents',
                line=dict(color='#d62728', width=2),
                marker=dict(size=6)
            ))
            fig.update_layout(
                title="Incident Count Over Time",
                xaxis_title="Month",
                yaxis_title="Count",
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No incidents match the current filters.")

    with col2:
        st.subheader("Key Metrics")
        if trends_df is not None and not trends_df.empty:
            avg_resolution = trends_df['RESOLUTION_RATE'].mean()
            st.metric("Avg Resolution Rate", f"{avg_resolution:.1f}%")
            st.metric("Latest Month Incidents", int(trends_df['TOTAL_INCIDENTS'].iloc[0]))

    st.divider()

    st.subheader("Recent Incidents")
    recent_query = f"""
        SELECT i.incident_id, i.asset_id, i.incident_type, i.severity,
               i.detected_at, i.attack_vector, i.kill_chain_phase
        FROM INCIDENTS i
        JOIN ASSETS a ON i.asset_id = a.asset_id
        WHERE {t3_dc} AND {t3_at} AND {t3_sv}
        ORDER BY i.detected_at DESC
        LIMIT 20;
    """
    incidents_df, _ = execute_query(conn, recent_query)

    if incidents_df is not None and not incidents_df.empty:
        st.dataframe(incidents_df, use_container_width=True)
    else:
        st.info("No incidents match the current filters.")

# ============================================================================
# TAB 4: Compliance Status
# ============================================================================
with tab4:
    st.header("Security Control Compliance")

    compliance_df, latency = execute_query(conn, """
        SELECT framework, category, total_controls, compliant_controls,
               compliance_percentage, avg_compliance_score
        FROM NIST_COMPLIANCE_SUMMARY
        ORDER BY framework, compliance_percentage DESC;
    """)

    if compliance_df is not None and not compliance_df.empty:
        col1, col2 = st.columns(2)

        with col1:
            framework_summary = compliance_df.groupby('FRAMEWORK').agg({
                'COMPLIANCE_PERCENTAGE': 'mean',
                'TOTAL_CONTROLS': 'sum'
            }).reset_index()

            fig = px.bar(
                framework_summary,
                x='FRAMEWORK',
                y='COMPLIANCE_PERCENTAGE',
                title="Framework Compliance Rate",
                labels={'COMPLIANCE_PERCENTAGE': 'Compliance %', 'FRAMEWORK': 'Framework'},
                color='COMPLIANCE_PERCENTAGE',
                color_continuous_scale='RdYlGn'
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            fig = go.Figure(data=[
                go.Pie(
                    labels=['Compliant', 'Non-Compliant'],
                    values=[
                        compliance_df['COMPLIANT_CONTROLS'].sum(),
                        compliance_df['TOTAL_CONTROLS'].sum() - compliance_df['COMPLIANT_CONTROLS'].sum()
                    ],
                    marker=dict(colors=['#2ecc71', '#e74c3c'])
                )
            ])
            fig.update_layout(title="Overall Control Status")
            st.plotly_chart(fig, use_container_width=True)

        st.divider()
        st.subheader("Control Details by Category")
        st.dataframe(compliance_df, use_container_width=True)
    else:
        st.info("No compliance data available.")

# ============================================================================
# TAB 5: Kill Chain Analysis
# ============================================================================
with tab5:
    st.header("Attack Kill Chain Analysis")

    # -- Filters --
    t5_date = st.date_input(
        "Date range:",
        value=(datetime.now() - timedelta(days=365), datetime.now()),
        max_value=datetime.now(),
        key="t5_date"
    )
    if isinstance(t5_date, tuple) and len(t5_date) == 2:
        t5_start, t5_end = t5_date
    else:
        t5_start, t5_end = datetime.now() - timedelta(days=365), datetime.now()

    t5_dc = f"i.detected_at BETWEEN '{t5_start}'::TIMESTAMP AND '{t5_end}'::TIMESTAMP + INTERVAL '1 day'"

    st.divider()

    killchain_query = f"""
        SELECT
            i.kill_chain_phase,
            COUNT(*) AS total_incidents,
            COUNT(DISTINCT i.threat_actor_id) AS unique_actors,
            COUNT(DISTINCT i.asset_id) AS affected_assets,
            SUM(CASE WHEN i.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_incidents,
            SUM(CASE WHEN i.resolved_at IS NOT NULL THEN 1 ELSE 0 END) AS resolved_incidents
        FROM INCIDENTS i
        WHERE {t5_dc}
        GROUP BY i.kill_chain_phase
        ORDER BY total_incidents DESC;
    """
    killchain_df, latency = execute_query(conn, killchain_query)

    if killchain_df is not None and not killchain_df.empty:
        col1, col2 = st.columns(2)

        with col1:
            fig = px.bar(
                killchain_df,
                x='KILL_CHAIN_PHASE',
                y='TOTAL_INCIDENTS',
                title="Incidents by Kill Chain Phase",
                labels={'TOTAL_INCIDENTS': 'Count', 'KILL_CHAIN_PHASE': 'Phase'},
                color='CRITICAL_INCIDENTS',
                color_continuous_scale='Reds'
            )
            fig.update_xaxes(tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            fig = go.Figure(data=[
                go.Bar(name='Unique Actors', x=killchain_df['KILL_CHAIN_PHASE'], y=killchain_df['UNIQUE_ACTORS']),
                go.Bar(name='Affected Assets', x=killchain_df['KILL_CHAIN_PHASE'], y=killchain_df['AFFECTED_ASSETS'])
            ])
            fig.update_layout(
                title="Adversary Footprint by Phase",
                barmode='group',
                xaxis_tickangle=-45
            )
            st.plotly_chart(fig, use_container_width=True)

        st.divider()
        st.subheader("Kill Chain Phase Breakdown")
        st.dataframe(killchain_df, use_container_width=True)
    else:
        st.info("No kill chain data matches the current filters.")

# ============================================================================
# TAB 6: System Status
# ============================================================================
with tab6:
    st.header("Pipeline Status & Performance")

    col1, col2, col3 = st.columns(3)

    logs_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'pipeline_logs.csv')
    if os.path.exists(logs_path):
        logs_df = pd.read_csv(logs_path)

        with col1:
            st.metric("Total Log Entries", len(logs_df))
        with col2:
            successful = len(logs_df[logs_df['status'] == 'SUCCESS'])
            st.metric("Successful Operations", successful)
        with col3:
            avg_latency = logs_df['latency_ms'].mean()
            st.metric("Avg Query Latency", f"{int(avg_latency)}ms")

        st.divider()
        st.subheader("Pipeline Execution Log")
        st.dataframe(logs_df, use_container_width=True)
    else:
        st.warning("Pipeline logs not found. Run ingest.py to generate logs.")

    st.divider()
    st.subheader("Data Statistics")

    stats_cols = st.columns(5)
    tables = ['ASSETS', 'VULNERABILITIES', 'INCIDENTS', 'SECURITY_CONTROLS', 'THREAT_ACTORS']
    for col, table in zip(stats_cols, tables):
        count_df, _ = execute_query(conn, f"SELECT COUNT(*) as cnt FROM {table};")
        if count_df is not None:
            with col:
                st.metric(table, int(count_df['CNT'].iloc[0]))

    st.divider()
    st.caption("Last updated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ============================================================================
# TAB 7: AI Agent
# ============================================================================
with tab7:
    st.header("AI Security Analyst Agent")
    st.markdown(
        "Ask natural-language questions about your security data. "
        "The agent queries Snowflake in real time to answer you."
    )
    st.divider()

    # Initialise chat history and pending query in session state
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "agent_pending_query" not in st.session_state:
        st.session_state.agent_pending_query = None

    # Example queries
    if not st.session_state.messages:
        st.markdown("**Example queries:**")
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("What are the top 5 highest-risk assets?", use_container_width=True):
                st.session_state.agent_pending_query = "What are the top 5 highest-risk assets?"
                st.rerun()
        with col2:
            if st.button("Compare incident trends over the last 6 months with our compliance posture.", use_container_width=True):
                st.session_state.agent_pending_query = "Compare incident trends over the last 6 months with our compliance posture."
                st.rerun()
        with col3:
            if st.button("Which kill chain phases are most active, which assets are most exposed, and what should we prioritize?", use_container_width=True):
                st.session_state.agent_pending_query = "Which kill chain phases are most active, which assets are most exposed, and what should we prioritize?"
                st.rerun()
        st.divider()

    # Render existing conversation
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("tool_log"):
                with st.expander("Tool calls", expanded=False):
                    for entry in msg["tool_log"]:
                        st.markdown(f"**`{entry['tool']}`** — args: `{entry['args']}`")
                        st.code(entry["result_preview"], language="json")

    # Chat input (or example query button click)
    _pending = st.session_state.agent_pending_query
    if _pending:
        st.session_state.agent_pending_query = None
    if prompt := (st.chat_input("Ask about your security data...") or _pending):
        # Show user message immediately
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Run agent and display response
        with st.chat_message("assistant"):
            with st.spinner("Agent thinking..."):
                _t0 = time.time()
                answer, tool_log = run_agent(prompt, conn)
                _latency_ms = int((time.time() - _t0) * 1000)
            st.markdown(answer)
            st.caption(f"Latency: {_latency_ms} ms | Reasoning steps: {len(tool_log)}")
            if tool_log:
                with st.expander("Tool calls", expanded=False):
                    for entry in tool_log:
                        st.markdown(f"**`{entry['tool']}`** — args: `{entry['args']}`")
                        st.code(entry["result_preview"], language="json")

        st.session_state.messages.append({
            "role": "assistant",
            "content": answer,
            "tool_log": tool_log,
        })
