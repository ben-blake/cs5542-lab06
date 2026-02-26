"""
Agent tool functions for Lab 6.
Each function wraps a Snowflake query and returns a JSON string.
"""

import json


def get_top_risk_assets(conn, limit: int = 10) -> str:
    """
    Return the top N highest-risk assets ranked by maximum CVSS score.

    Args:
        conn: Active Snowflake connection.
        limit: Number of assets to return (default 10).

    Returns:
        JSON string with list of assets and their vulnerability stats.
    """
    try:
        query = f"""
            SELECT
                a.asset_id, a.hostname, a.asset_type, a.criticality,
                COUNT(DISTINCT v.vuln_id) AS total_vulnerabilities,
                ROUND(AVG(v.cvss_score), 2) AS avg_cvss_score,
                MAX(v.cvss_score) AS max_cvss_score,
                SUM(CASE WHEN v.severity_label = 'Critical' THEN 1 ELSE 0 END) AS critical_count
            FROM ASSETS a
            LEFT JOIN VULNERABILITIES v ON a.asset_id = v.asset_id
            GROUP BY a.asset_id, a.hostname, a.asset_type, a.criticality
            ORDER BY max_cvss_score DESC NULLS LAST, total_vulnerabilities DESC
            LIMIT {int(limit)};
        """
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cols = [d[0].lower() for d in cursor.description]
        cursor.close()
        result = [dict(zip(cols, row)) for row in rows]
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


def get_incident_trends(conn, months: int = 6) -> str:
    """
    Return monthly incident counts and resolution rates for the past N months.

    Args:
        conn: Active Snowflake connection.
        months: How many months of history to return (default 6).

    Returns:
        JSON string with monthly trend data.
    """
    try:
        query = f"""
            SELECT
                DATE_TRUNC('MONTH', detected_at) AS incident_month,
                COUNT(*) AS total_incidents,
                SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_incidents,
                SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high_incidents,
                ROUND(100.0 * SUM(CASE WHEN resolved_at IS NOT NULL THEN 1 ELSE 0 END) / COUNT(*), 2) AS resolution_rate
            FROM INCIDENTS
            WHERE detected_at >= DATEADD('MONTH', -{int(months)}, CURRENT_DATE())
            GROUP BY DATE_TRUNC('MONTH', detected_at)
            ORDER BY incident_month DESC;
        """
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cols = [d[0].lower() for d in cursor.description]
        cursor.close()
        result = [dict(zip(cols, row)) for row in rows]
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


def get_compliance_summary(conn, framework: str = None) -> str:
    """
    Return compliance percentages grouped by framework and category.

    Args:
        conn: Active Snowflake connection.
        framework: Optional framework filter (e.g. 'NIST CSF', 'SOC 2', 'ISO 27001', 'Zero Trust').
                   Pass None to get all frameworks.

    Returns:
        JSON string with compliance summary data.
    """
    try:
        where = f"WHERE framework = '{framework}'" if framework else ""
        query = f"""
            SELECT framework, category, total_controls, compliant_controls,
                   compliance_percentage, avg_compliance_score
            FROM NIST_COMPLIANCE_SUMMARY
            {where}
            ORDER BY framework, compliance_percentage DESC;
        """
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cols = [d[0].lower() for d in cursor.description]
        cursor.close()
        result = [dict(zip(cols, row)) for row in rows]
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


def get_kill_chain_analysis(conn) -> str:
    """
    Return incident counts and actor footprint broken down by Cyber Kill Chain phase.

    Args:
        conn: Active Snowflake connection.

    Returns:
        JSON string with kill chain phase breakdown.
    """
    try:
        query = """
            SELECT
                kill_chain_phase,
                COUNT(*) AS total_incidents,
                COUNT(DISTINCT threat_actor_id) AS unique_actors,
                COUNT(DISTINCT asset_id) AS affected_assets,
                SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_incidents,
                ROUND(100.0 * SUM(CASE WHEN resolved_at IS NOT NULL THEN 1 ELSE 0 END) / COUNT(*), 2) AS resolution_rate
            FROM INCIDENTS
            GROUP BY kill_chain_phase
            ORDER BY total_incidents DESC;
        """
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cols = [d[0].lower() for d in cursor.description]
        cursor.close()
        result = [dict(zip(cols, row)) for row in rows]
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


def get_asset_details(conn, asset_type: str = None, criticality: str = None) -> str:
    """
    Return asset inventory, optionally filtered by type and/or criticality.

    Args:
        conn: Active Snowflake connection.
        asset_type: Optional filter (e.g. 'Server', 'Endpoint', 'Network Device').
        criticality: Optional filter (e.g. 'Critical', 'High', 'Medium', 'Low').

    Returns:
        JSON string with matching asset records.
    """
    try:
        conditions = []
        if asset_type:
            conditions.append(f"asset_type = '{asset_type}'")
        if criticality:
            conditions.append(f"criticality = '{criticality}'")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        query = f"""
            SELECT asset_id, hostname, ip_address, asset_type,
                   criticality, owner, location, os, last_patched_date
            FROM ASSETS
            {where}
            ORDER BY criticality DESC, hostname
            LIMIT 50;
        """
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cols = [d[0].lower() for d in cursor.description]
        cursor.close()
        result = [dict(zip(cols, row)) for row in rows]
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})
