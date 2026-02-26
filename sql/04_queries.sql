-- CS 5542 Lab 6: Analytics Queries, Views, and Extensions
-- Implement ≥3 meaningful SQL queries for analysis

USE DATABASE CYBER_DB;
USE SCHEMA SECURITY;

-- ============================================================================
-- QUERY 1: Top 10 Highest-Risk Assets
-- Joins ASSETS + VULNERABILITIES, aggregates risk scores
-- ============================================================================
CREATE OR REPLACE VIEW TOP_RISK_ASSETS AS
SELECT
    a.asset_id,
    a.hostname,
    a.asset_type,
    a.criticality,
    COUNT(DISTINCT v.vuln_id) AS total_vulnerabilities,
    ROUND(AVG(v.cvss_score), 2) AS avg_cvss_score,
    MAX(v.cvss_score) AS max_cvss_score,
    SUM(CASE WHEN v.severity_label = 'Critical' THEN 1 ELSE 0 END) AS critical_count,
    SUM(CASE WHEN v.severity_label = 'High' THEN 1 ELSE 0 END) AS high_count
FROM ASSETS a
LEFT JOIN VULNERABILITIES v ON a.asset_id = v.asset_id
GROUP BY a.asset_id, a.hostname, a.asset_type, a.criticality
ORDER BY max_cvss_score DESC, total_vulnerabilities DESC
LIMIT 10;

SELECT * FROM TOP_RISK_ASSETS;

-- ============================================================================
-- QUERY 2: Monthly Incident Trends
-- Time-based analysis of incidents by month
-- ============================================================================
CREATE OR REPLACE VIEW MONTHLY_INCIDENT_TRENDS AS
SELECT
    TRUNC(detected_at, 'MONTH') AS incident_month,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_incidents,
    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high_incidents,
    COUNT(DISTINCT incident_type) AS incident_types,
    COUNT(DISTINCT threat_actor_id) AS unique_actors,
    ROUND(100.0 * SUM(CASE WHEN resolved_at IS NOT NULL THEN 1 ELSE 0 END) / COUNT(*), 2) AS resolution_rate
FROM INCIDENTS
GROUP BY TRUNC(detected_at, 'MONTH')
ORDER BY incident_month DESC;

SELECT * FROM MONTHLY_INCIDENT_TRENDS;

-- ============================================================================
-- QUERY 3: NIST Compliance Status by Control Category
-- Grouped analysis of security control implementation
-- ============================================================================
CREATE OR REPLACE VIEW NIST_COMPLIANCE_SUMMARY AS
SELECT
    framework,
    category,
    COUNT(*) AS total_controls,
    SUM(CASE WHEN implementation_status = 'Compliant' THEN 1 ELSE 0 END) AS compliant_controls,
    SUM(CASE WHEN implementation_status = 'Non-Compliant' THEN 1 ELSE 0 END) AS non_compliant_controls,
    ROUND(100.0 * SUM(CASE WHEN implementation_status = 'Compliant' THEN 1 ELSE 0 END) / COUNT(*), 2) AS compliance_percentage,
    ROUND(AVG(compliance_score), 2) AS avg_compliance_score
FROM SECURITY_CONTROLS
GROUP BY framework, category
ORDER BY framework, compliance_percentage DESC;

SELECT * FROM NIST_COMPLIANCE_SUMMARY;

-- ============================================================================
-- QUERY 4: Kill Chain Phase Analysis
-- Threat actor technique mapping across attack phases
-- ============================================================================
CREATE OR REPLACE VIEW KILL_CHAIN_ANALYSIS AS
SELECT
    kill_chain_phase,
    COUNT(*) AS total_incidents,
    COUNT(DISTINCT threat_actor_id) AS unique_actors,
    COUNT(DISTINCT asset_id) AS affected_assets,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_incidents,
    SUM(CASE WHEN resolved_at IS NOT NULL THEN 1 ELSE 0 END) AS resolved_incidents,
    LISTAGG(DISTINCT incident_type, ', ') WITHIN GROUP (ORDER BY incident_type) AS incident_types
FROM INCIDENTS
GROUP BY kill_chain_phase
ORDER BY total_incidents DESC;

SELECT * FROM KILL_CHAIN_ANALYSIS;

-- ============================================================================
-- EXTENSION 1: Materialized View for Risk Scoring
-- Pre-computed risk scores for query performance optimization
-- ============================================================================
CREATE OR REPLACE VIEW ASSET_RISK_SCORES AS
SELECT
    a.asset_id,
    a.hostname,
    a.asset_type,
    a.criticality,
    a.owner,
    COUNT(DISTINCT v.vuln_id) AS vulnerability_count,
    ROUND(COALESCE(AVG(v.cvss_score), 0), 2) AS avg_cvss_score,
    COALESCE(MAX(v.cvss_score), 0) AS max_cvss_score,
    COUNT(DISTINCT i.incident_id) AS incident_count,
    ROUND(
        (COALESCE(MAX(v.cvss_score), 0) / 10.0) * 0.5 +
        (COUNT(DISTINCT i.incident_id) / 100.0) * 0.3 +
        CASE WHEN a.criticality = 'Critical' THEN 20
             WHEN a.criticality = 'High' THEN 15
             WHEN a.criticality = 'Medium' THEN 10
             ELSE 5
        END * 0.2,
        2
    ) AS composite_risk_score
FROM ASSETS a
LEFT JOIN VULNERABILITIES v ON a.asset_id = v.asset_id
LEFT JOIN INCIDENTS i ON a.asset_id = i.asset_id
GROUP BY a.asset_id, a.hostname, a.asset_type, a.criticality, a.owner
ORDER BY composite_risk_score DESC;

-- ============================================================================
-- EXTENSION 2: Advanced Analytics - Asset Vulnerability Exposure Index
-- Create a queryable view for dashboard parameterization
-- ============================================================================
CREATE OR REPLACE VIEW ASSET_EXPOSURE_INDEX AS
SELECT
    a.asset_id,
    a.hostname,
    a.asset_type,
    a.criticality,
    a.location,
    a.owner,
    COUNT(DISTINCT v.vuln_id) AS open_vulnerabilities,
    SUM(v.cvss_score) AS total_cvss_exposure,
    MAX(v.cvss_score) AS highest_cvss,
    COUNT(DISTINCT CASE WHEN v.status = 'Open' THEN v.vuln_id END) AS unpatched_count,
    COUNT(DISTINCT i.incident_id) AS historical_incidents,
    DATEDIFF(day, a.last_patched_date, CURRENT_DATE()) AS days_since_patch,
    CASE
        WHEN MAX(v.cvss_score) >= 9.0 THEN 'CRITICAL'
        WHEN MAX(v.cvss_score) >= 7.0 THEN 'HIGH'
        WHEN MAX(v.cvss_score) >= 4.0 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS risk_level
FROM ASSETS a
LEFT JOIN VULNERABILITIES v ON a.asset_id = v.asset_id AND v.status = 'Open'
LEFT JOIN INCIDENTS i ON a.asset_id = i.asset_id AND DATEDIFF(day, i.detected_at, CURRENT_DATE()) <= 365
GROUP BY a.asset_id, a.hostname, a.asset_type, a.criticality, a.location, a.owner, a.last_patched_date
ORDER BY total_cvss_exposure DESC;

SELECT * FROM ASSET_EXPOSURE_INDEX;

-- ============================================================================
-- Show all created views
-- ============================================================================
SHOW VIEWS IN SCHEMA CYBER_DB.SECURITY;
