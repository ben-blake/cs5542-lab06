"""
Ingest cybersecurity data into Snowflake.
Handles:
1. Database/schema setup
2. Table creation
3. CSV upload to internal stage
4. COPY INTO commands
5. Pipeline logging
"""

import os
import csv
import time
from datetime import datetime
import snowflake.connector
from pathlib import Path
from dotenv import load_dotenv

# Load credentials from .env
load_dotenv()

# ============================================================================
# Snowflake Connection Parameters
# ============================================================================
SNOWFLAKE_ACCOUNT = os.getenv('SNOWFLAKE_ACCOUNT')
SNOWFLAKE_USER = os.getenv('SNOWFLAKE_USER')
SNOWFLAKE_PASSWORD = os.getenv('SNOWFLAKE_PASSWORD')

# Support both inline key and file-based key
SNOWFLAKE_PRIVATE_KEY = os.getenv('SNOWFLAKE_PRIVATE_KEY')
SNOWFLAKE_PRIVATE_KEY_PATH = os.getenv('SNOWFLAKE_PRIVATE_KEY_PATH')
if SNOWFLAKE_PRIVATE_KEY_PATH and not SNOWFLAKE_PRIVATE_KEY:
    with open(SNOWFLAKE_PRIVATE_KEY_PATH, 'r') as f:
        SNOWFLAKE_PRIVATE_KEY = f.read()

SNOWFLAKE_PRIVATE_KEY_PASSPHRASE = os.getenv('SNOWFLAKE_PRIVATE_KEY_PASSPHRASE')
SNOWFLAKE_WAREHOUSE = os.getenv('SNOWFLAKE_WAREHOUSE', 'CYBER_WH')
SNOWFLAKE_DATABASE = os.getenv('SNOWFLAKE_DATABASE', 'CYBER_DB')
SNOWFLAKE_SCHEMA = os.getenv('SNOWFLAKE_SCHEMA', 'SECURITY')

PIPELINE_LOG = 'pipeline_logs.csv'
CSV_FILES = [
    'data/csv/threat_actors.csv',
    'data/csv/assets.csv',
    'data/csv/vulnerabilities.csv',
    'data/csv/incidents.csv',
    'data/csv/security_controls.csv'
]

# ============================================================================
# Initialize Pipeline Log
# ============================================================================
def init_pipeline_log():
    """Create pipeline_logs.csv with headers if it doesn't exist."""
    if not os.path.exists(PIPELINE_LOG):
        with open(PIPELINE_LOG, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp', 'feature', 'operation', 'latency_ms', 'record_count', 'status'
            ])
            writer.writeheader()

def log_pipeline(feature, operation, latency_ms, record_count, status='SUCCESS'):
    """Log a pipeline operation."""
    timestamp = datetime.now().isoformat()
    with open(PIPELINE_LOG, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'timestamp', 'feature', 'operation', 'latency_ms', 'record_count', 'status'
        ])
        writer.writerow({
            'timestamp': timestamp,
            'feature': feature,
            'operation': operation,
            'latency_ms': latency_ms,
            'record_count': record_count,
            'status': status
        })
    print(f"  ✓ Logged: {feature} - {operation} ({latency_ms}ms, {record_count} rows)")

# ============================================================================
# Connect to Snowflake
# ============================================================================
def connect_snowflake():
    """Establish Snowflake connection with password or API key."""
    print("\n[1/5] Connecting to Snowflake...")
    try:
        # Determine authentication method
        if SNOWFLAKE_PRIVATE_KEY or SNOWFLAKE_PRIVATE_KEY_PATH:
            # Use private key (API key) authentication
            print("  Using API Key authentication...")
            from cryptography.hazmat.primitives import serialization

            # Read key from file or use inline key
            if SNOWFLAKE_PRIVATE_KEY_PATH and not SNOWFLAKE_PRIVATE_KEY:
                with open(SNOWFLAKE_PRIVATE_KEY_PATH, 'rb') as f:
                    private_key_data = f.read()
            else:
                private_key_data = SNOWFLAKE_PRIVATE_KEY.encode() if isinstance(SNOWFLAKE_PRIVATE_KEY, str) else SNOWFLAKE_PRIVATE_KEY

            # Load the private key
            p_key = serialization.load_pem_private_key(
                private_key_data,
                password=SNOWFLAKE_PRIVATE_KEY_PASSPHRASE.encode() if SNOWFLAKE_PRIVATE_KEY_PASSPHRASE else None
            )

            # Get DER-encoded bytes
            pkb = p_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            conn = snowflake.connector.connect(
                account=SNOWFLAKE_ACCOUNT,
                user=SNOWFLAKE_USER,
                private_key=pkb,
                warehouse=SNOWFLAKE_WAREHOUSE,
                database=SNOWFLAKE_DATABASE,
                schema=SNOWFLAKE_SCHEMA,
                ocsp_fail_open=True
            )
        else:
            # Use password authentication (may fail if MFA is enabled)
            print("  Using password authentication...")
            conn = snowflake.connector.connect(
                account=SNOWFLAKE_ACCOUNT,
                user=SNOWFLAKE_USER,
                password=SNOWFLAKE_PASSWORD,
                warehouse=SNOWFLAKE_WAREHOUSE,
                database=SNOWFLAKE_DATABASE,
                schema=SNOWFLAKE_SCHEMA,
                ocsp_fail_open=True
            )

        print("  ✓ Connected to Snowflake")
        return conn
    except Exception as e:
        print(f"  ✗ Failed to connect: {e}")
        print("\n  ✗ Connection failed!")
        print("\n  Troubleshooting:")
        print("  1. Verify SNOWFLAKE_ACCOUNT is correct (format: xy12345)")
        print("  2. Verify SNOWFLAKE_USER is correct")
        print("  3. If using private key, check format:")
        print("     - Should start with: -----BEGIN PRIVATE KEY-----")
        print("     - Or: -----BEGIN RSA PRIVATE KEY-----")
        print("  4. Verify key file has correct content (no extra spaces/lines)")
        raise

# ============================================================================
# Setup Database and Tables
# ============================================================================
def setup_database(conn):
    """Create database, schema, warehouse, and tables."""
    print("\n[2/5] Setting up Snowflake environment...")
    cursor = conn.cursor()

    try:
        # Read and execute setup SQL
        with open('sql/01_setup.sql', 'r') as f:
            setup_sql = f.read()

        for statement in setup_sql.split(';'):
            if statement.strip():
                cursor.execute(statement)

        print("  ✓ Database and warehouse configured")

        # Read and execute schema creation
        with open('sql/02_schema.sql', 'r') as f:
            schema_sql = f.read()

        for statement in schema_sql.split(';'):
            if statement.strip():
                cursor.execute(statement)

        print("  ✓ Tables created")

    except Exception as e:
        print(f"  ✗ Setup failed: {e}")
        raise
    finally:
        cursor.close()

# ============================================================================
# Upload CSV Files and Execute COPY INTO
# ============================================================================
def ingest_data(conn):
    """Load CSV data into Snowflake tables using INSERT statements."""
    print("\n[3/5] Uploading and ingesting data...")
    import pandas as pd

    # Table mapping: CSV file -> (table name, columns to exclude from INSERT)
    table_mapping = {
        'data/csv/threat_actors.csv': 'THREAT_ACTORS',
        'data/csv/assets.csv': 'ASSETS',
        'data/csv/vulnerabilities.csv': 'VULNERABILITIES',
        'data/csv/incidents.csv': 'INCIDENTS',
        'data/csv/security_controls.csv': 'SECURITY_CONTROLS'
    }

    try:
        for csv_file, table_name in table_mapping.items():
            if not os.path.exists(csv_file):
                print(f"  ⚠ File not found: {csv_file}")
                continue

            start_time = time.time()

            # Read CSV into DataFrame
            df = pd.read_csv(csv_file)
            row_count = len(df)

            # Build INSERT statements in batches
            cursor = conn.cursor()
            columns = df.columns.tolist()
            col_names = ', '.join(columns)
            placeholders = ', '.join(['%s'] * len(columns))

            # Truncate table first (in case of re-run)
            cursor.execute(f"DELETE FROM {table_name}")

            # Insert data in batches
            batch_size = 100
            for i in range(0, len(df), batch_size):
                batch = df.iloc[i:i+batch_size]
                values = [tuple(None if pd.isna(v) else v for v in row) for row in batch.values]
                cursor.executemany(
                    f"INSERT INTO {table_name} ({col_names}) VALUES ({placeholders})",
                    values
                )

            cursor.close()

            latency_ms = int((time.time() - start_time) * 1000)
            log_pipeline(table_name, 'DATA_LOAD', latency_ms, row_count)
            print(f"  ✓ Loaded {table_name} ({row_count} rows, {latency_ms}ms)")

    except Exception as e:
        print(f"  ✗ Ingestion failed: {e}")
        raise

# ============================================================================
# Create Views and Queries
# ============================================================================
def create_analytics(conn):
    """Create analytics queries, views, and extensions."""
    print("\n[4/5] Creating analytics queries and views...")
    cursor = conn.cursor()

    try:
        with open('sql/04_queries.sql', 'r') as f:
            queries_sql = f.read()

        # Execute each query/view creation
        for statement in queries_sql.split(';'):
            # Strip comment-only lines to get actual SQL
            lines = statement.strip().splitlines()
            sql_lines = [l for l in lines if not l.strip().startswith('--')]
            clean_sql = '\n'.join(sql_lines).strip()

            if not clean_sql:
                continue

            try:
                start_time = time.time()
                cursor.execute(statement.strip())
                latency_ms = int((time.time() - start_time) * 1000)

                # Extract view/query name if available
                if 'CREATE OR REPLACE' in statement:
                    parts = clean_sql.split()
                    if 'VIEW' in parts:
                        idx = parts.index('VIEW') + 1
                    elif 'TABLE' in parts:
                        idx = parts.index('TABLE') + 1
                    else:
                        idx = -1
                    name = parts[idx] if 0 <= idx < len(parts) else 'QUERY'
                    log_pipeline('ANALYTICS', f'CREATE_{name}', latency_ms, 0)
                    print(f"  ✓ Created {name}")
            except Exception as e:
                print(f"  ⚠ Query execution skipped: {str(e)[:100]}")

        print("  ✓ Analytics views and extensions created")

    except Exception as e:
        print(f"  ✗ Analytics creation failed: {e}")
        raise
    finally:
        cursor.close()

# ============================================================================
# Verify Data Load
# ============================================================================
def verify_data(conn):
    """Verify data was loaded successfully."""
    print("\n[5/5] Verifying data load...")
    cursor = conn.cursor()

    try:
        tables = [
            'THREAT_ACTORS', 'ASSETS', 'VULNERABILITIES', 'INCIDENTS', 'SECURITY_CONTROLS'
        ]

        total_rows = 0
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table};")
            count = cursor.fetchone()[0]
            total_rows += count
            status = "✓" if count > 0 else "⚠"
            print(f"  {status} {table}: {count} rows")

        print(f"\n  Total rows loaded: {total_rows}")
        log_pipeline('PIPELINE', 'VERIFICATION', 0, total_rows)

    except Exception as e:
        print(f"  ✗ Verification failed: {e}")
    finally:
        cursor.close()

# ============================================================================
# Main Execution
# ============================================================================
def main():
    print("=" * 70)
    print("CS 5542 6 — Snowflake Data Ingestion Pipeline")
    print("=" * 70)

    init_pipeline_log()

    conn = None
    try:
        conn = connect_snowflake()
        setup_database(conn)
        ingest_data(conn)
        create_analytics(conn)
        verify_data(conn)

        print("\n" + "=" * 70)
        print("✓ Pipeline complete! Check pipeline_logs.csv for details.")
        print("=" * 70)

    except Exception as e:
        print(f"\n✗ Pipeline failed: {e}")
        exit(1)
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    main()
