-- CS 5542 Lab 6: Staging and Data Loading
-- Set up CSV file format and internal stage, then COPY data into tables

USE DATABASE CYBER_DB;
USE SCHEMA SECURITY;

-- ============================================================================
-- Create File Format for CSV
-- ============================================================================
CREATE OR REPLACE FILE FORMAT CSV_FORMAT
  TYPE = CSV
  FIELD_DELIMITER = ','
  SKIP_HEADER = 1
  NULL_IF = ('NULL', 'null', '');

-- ============================================================================
-- Create Internal Stage for CSV uploads
-- ============================================================================
CREATE OR REPLACE STAGE CSV_STAGE
  FILE_FORMAT = CSV_FORMAT;

-- ============================================================================
-- COPY Commands (execute these after uploading files via ingest.py)
-- ============================================================================

-- Copy threat_actors
COPY INTO THREAT_ACTORS
  FROM @CSV_STAGE/threat_actors.csv
  FILE_FORMAT = CSV_FORMAT
  ON_ERROR = 'CONTINUE';

-- Copy assets
COPY INTO ASSETS
  FROM @CSV_STAGE/assets.csv
  FILE_FORMAT = CSV_FORMAT
  ON_ERROR = 'CONTINUE';

-- Copy vulnerabilities
COPY INTO VULNERABILITIES
  FROM @CSV_STAGE/vulnerabilities.csv
  FILE_FORMAT = CSV_FORMAT
  ON_ERROR = 'CONTINUE';

-- Copy incidents
COPY INTO INCIDENTS
  FROM @CSV_STAGE/incidents.csv
  FILE_FORMAT = CSV_FORMAT
  ON_ERROR = 'CONTINUE';

-- Copy security_controls
COPY INTO SECURITY_CONTROLS
  FROM @CSV_STAGE/security_controls.csv
  FILE_FORMAT = CSV_FORMAT
  ON_ERROR = 'CONTINUE';

-- ============================================================================
-- Verify data loaded
-- ============================================================================
SELECT COUNT(*) AS THREAT_ACTORS_COUNT FROM THREAT_ACTORS;
SELECT COUNT(*) AS ASSETS_COUNT FROM ASSETS;
SELECT COUNT(*) AS VULNERABILITIES_COUNT FROM VULNERABILITIES;
SELECT COUNT(*) AS INCIDENTS_COUNT FROM INCIDENTS;
SELECT COUNT(*) AS SECURITY_CONTROLS_COUNT FROM SECURITY_CONTROLS;
