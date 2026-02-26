"""
Generate synthetic cybersecurity datasets for Snowflake pipeline.
Creates 5 CSV files in data/csv/:
- assets.csv
- vulnerabilities.csv
- incidents.csv
- security_controls.csv
- threat_actors.csv
"""

import pandas as pd
import random
from faker import Faker
from datetime import datetime, timedelta
import os

fake = Faker()

# Create data/csv directory if it doesn't exist
os.makedirs('data/csv', exist_ok=True)

# ============================================================================
# 1. THREAT_ACTORS (50 rows)
# ============================================================================
print("Generating threat_actors.csv...")
threat_actors = []
actor_types = ['APT', 'Criminal Gang', 'Insider Threat', 'Hacktivist']
ttps = [
    'Spear Phishing', 'SQL Injection', 'Privilege Escalation', 'Data Exfiltration',
    'DDoS', 'Malware Deployment', 'Social Engineering', 'Supply Chain Attack'
]

for i in range(1, 51):
    threat_actors.append({
        'actor_id': f'TA{i:03d}',
        'name': fake.word().capitalize() + ' ' + fake.word().capitalize(),
        'actor_type': random.choice(actor_types),
        'country_origin': fake.country_code(),
        'ttps': ', '.join(random.sample(ttps, k=random.randint(1, 3))),
        'active_since': (datetime.now() - timedelta(days=random.randint(365, 3650))).strftime('%Y-%m-%d'),
        'sophistication_level': random.choice(['Low', 'Medium', 'High', 'Very High'])
    })

df_actors = pd.DataFrame(threat_actors)
df_actors.to_csv('data/csv/threat_actors.csv', index=False)

# ============================================================================
# 2. ASSETS (200 rows)
# ============================================================================
print("Generating assets.csv...")
assets = []
asset_types = ['Server', 'Endpoint', 'Network Device', 'Database', 'Application', 'IoT Device']
os_types = ['Linux', 'Windows', 'macOS', 'Android', 'iOS']
criticality_levels = ['Low', 'Medium', 'High', 'Critical']

for i in range(1, 201):
    assets.append({
        'asset_id': f'AST{i:04d}',
        'hostname': f'{fake.word()}-{fake.word()}-{i:03d}'.lower(),
        'ip_address': fake.ipv4(),
        'asset_type': random.choice(asset_types),
        'criticality': random.choice(criticality_levels),
        'owner': fake.name(),
        'location': fake.city(),
        'os': random.choice(os_types),
        'last_patched_date': (datetime.now() - timedelta(days=random.randint(0, 180))).strftime('%Y-%m-%d')
    })

df_assets = pd.DataFrame(assets)
df_assets.to_csv('data/csv/assets.csv', index=False)

# ============================================================================
# 3. VULNERABILITIES (500 rows)
# ============================================================================
print("Generating vulnerabilities.csv...")
vulnerabilities = []
vuln_categories = ['RCE', 'SQL Injection', 'XSS', 'Authentication', 'Encryption', 'Authorization', 'Information Disclosure']
vuln_statuses = ['Open', 'In Remediation', 'Remediated', 'Accepted Risk']

for i in range(1, 501):
    asset_id = random.choice(df_assets['asset_id'].tolist())
    cvss_score = round(random.uniform(1.0, 10.0), 1)

    if cvss_score >= 9.0:
        severity = 'Critical'
    elif cvss_score >= 7.0:
        severity = 'High'
    elif cvss_score >= 4.0:
        severity = 'Medium'
    else:
        severity = 'Low'

    discovered_date = (datetime.now() - timedelta(days=random.randint(0, 365))).strftime('%Y-%m-%d')

    vulnerabilities.append({
        'vuln_id': f'VUL{i:05d}',
        'cve_id': f'CVE-{random.randint(2019, 2024)}-{random.randint(10000, 99999)}',
        'asset_id': asset_id,
        'cvss_score': cvss_score,
        'severity_label': severity,
        'category': random.choice(vuln_categories),
        'description': fake.sentence(nb_words=8),
        'discovered_date': discovered_date,
        'remediated_date': (datetime.strptime(discovered_date, '%Y-%m-%d') + timedelta(days=random.randint(1, 120))).strftime('%Y-%m-%d') if random.random() > 0.4 else None,
        'status': random.choice(vuln_statuses)
    })

df_vulns = pd.DataFrame(vulnerabilities)
df_vulns.to_csv('data/csv/vulnerabilities.csv', index=False)

# ============================================================================
# 4. INCIDENTS (300 rows)
# ============================================================================
print("Generating incidents.csv...")
incidents = []
incident_types = ['Malware Detection', 'Unauthorized Access', 'Data Breach', 'DDoS Attack', 'Phishing', 'Insider Threat']
attack_vectors = ['Network', 'Email', 'Physical', 'Supply Chain', 'Web Application', 'Social Engineering']
kill_chain_phases = ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'Command & Control', 'Actions on Objectives']

for i in range(1, 301):
    asset_id = random.choice(df_assets['asset_id'].tolist())
    actor_id = random.choice(df_actors['actor_id'].tolist())
    detected_at = (datetime.now() - timedelta(days=random.randint(0, 365))).strftime('%Y-%m-%d %H:%M:%S')

    incidents.append({
        'incident_id': f'INC{i:05d}',
        'asset_id': asset_id,
        'incident_type': random.choice(incident_types),
        'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
        'detected_at': detected_at,
        'resolved_at': (datetime.strptime(detected_at, '%Y-%m-%d %H:%M:%S') + timedelta(hours=random.randint(1, 720))).strftime('%Y-%m-%d %H:%M:%S') if random.random() > 0.3 else None,
        'attack_vector': random.choice(attack_vectors),
        'kill_chain_phase': random.choice(kill_chain_phases),
        'threat_actor_id': actor_id
    })

df_incidents = pd.DataFrame(incidents)
df_incidents.to_csv('data/csv/incidents.csv', index=False)

# ============================================================================
# 5. SECURITY_CONTROLS (100 rows)
# ============================================================================
print("Generating security_controls.csv...")
controls = []
frameworks = ['NIST CSF', 'SOC 2', 'ISO 27001', 'Zero Trust']
nist_categories = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']
control_names = [
    'MFA Implementation', 'Data Encryption', 'Access Control Review', 'Network Segmentation',
    'Vulnerability Assessment', 'Incident Response Plan', 'Security Training', 'Log Monitoring',
    'Firewall Configuration', 'Backup & Recovery', 'Patch Management', 'SIEM Deployment'
]
implementation_statuses = ['Not Started', 'In Progress', 'Implemented', 'Compliant', 'Non-Compliant']

for i in range(1, 101):
    controls.append({
        'control_id': f'CTL{i:04d}',
        'framework': random.choice(frameworks),
        'category': random.choice(nist_categories),
        'control_name': random.choice(control_names),
        'implementation_status': random.choice(implementation_statuses),
        'last_reviewed_date': (datetime.now() - timedelta(days=random.randint(0, 365))).strftime('%Y-%m-%d'),
        'compliance_score': round(random.uniform(0.0, 100.0), 1)
    })

df_controls = pd.DataFrame(controls)
df_controls.to_csv('data/csv/security_controls.csv', index=False)

# ============================================================================
# Summary
# ============================================================================
print("\n✓ Data generation complete!")
print(f"  - assets.csv: {len(df_assets)} rows")
print(f"  - vulnerabilities.csv: {len(df_vulns)} rows")
print(f"  - incidents.csv: {len(df_incidents)} rows")
print(f"  - security_controls.csv: {len(df_controls)} rows")
print(f"  - threat_actors.csv: {len(df_actors)} rows")
print(f"\nAll files saved to: data/csv/")
