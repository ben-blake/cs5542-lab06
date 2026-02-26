-- CS 5542 Lab 6: Schema Design
-- Create 5 tables for cybersecurity data

USE DATABASE CYBER_DB;
USE SCHEMA SECURITY;

-- ============================================================================
-- 1. THREAT_ACTORS Table
-- ============================================================================
CREATE OR REPLACE TABLE THREAT_ACTORS (
    actor_id VARCHAR(10) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    actor_type VARCHAR(50),
    country_origin VARCHAR(2),
    ttps VARCHAR(500),
    active_since DATE,
    sophistication_level VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

-- ============================================================================
-- 2. ASSETS Table
-- ============================================================================
CREATE OR REPLACE TABLE ASSETS (
    asset_id VARCHAR(10) PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip_address VARCHAR(15),
    asset_type VARCHAR(50),
    criticality VARCHAR(50),
    owner VARCHAR(100),
    location VARCHAR(100),
    os VARCHAR(50),
    last_patched_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

-- ============================================================================
-- 3. VULNERABILITIES Table
-- ============================================================================
CREATE OR REPLACE TABLE VULNERABILITIES (
    vuln_id VARCHAR(10) PRIMARY KEY,
    cve_id VARCHAR(20),
    asset_id VARCHAR(10) NOT NULL,
    cvss_score DECIMAL(3, 1),
    severity_label VARCHAR(20),
    category VARCHAR(50),
    description VARCHAR(500),
    discovered_date DATE,
    remediated_date DATE,
    status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
    FOREIGN KEY (asset_id) REFERENCES ASSETS(asset_id)
);

-- ============================================================================
-- 4. INCIDENTS Table
-- ============================================================================
CREATE OR REPLACE TABLE INCIDENTS (
    incident_id VARCHAR(10) PRIMARY KEY,
    asset_id VARCHAR(10) NOT NULL,
    incident_type VARCHAR(100),
    severity VARCHAR(20),
    detected_at TIMESTAMP NOT NULL,
    resolved_at TIMESTAMP,
    attack_vector VARCHAR(50),
    kill_chain_phase VARCHAR(50),
    threat_actor_id VARCHAR(10),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
    FOREIGN KEY (asset_id) REFERENCES ASSETS(asset_id),
    FOREIGN KEY (threat_actor_id) REFERENCES THREAT_ACTORS(actor_id)
);

-- ============================================================================
-- 5. SECURITY_CONTROLS Table
-- ============================================================================
CREATE OR REPLACE TABLE SECURITY_CONTROLS (
    control_id VARCHAR(10) PRIMARY KEY,
    framework VARCHAR(50),
    category VARCHAR(50),
    control_name VARCHAR(150),
    implementation_status VARCHAR(50),
    last_reviewed_date DATE,
    compliance_score DECIMAL(5, 1),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

-- Show table definitions
SHOW TABLES IN SCHEMA CYBER_DB.SECURITY;
