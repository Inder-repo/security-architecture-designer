import sqlite3
import pandas as pd

DB_FILE = "security_architecture.db"

# --- Initial Data for Flow Mappings ---
INITIAL_FLOW_MAPPINGS = [
    {"FlowType": "HTTPS", "OWASPID": "A01:2021", "Requirement": "Ensure TLS 1.2+ with strong ciphers and perfect forward secrecy. Implement HSTS.", "GRCMapping": "NIST 800-53 SC-8 (Transmission Integrity)"},
    {"FlowType": "Database", "OWASPID": "A04:2021", "Requirement": "Use parameterized queries to prevent SQL injection. Encrypt sensitive data at rest.", "GRCMapping": "NIST 800-53 SC-3 (Security Functionality)"},
    {"FlowType": "API Call", "OWASPID": "A03:2021", "Requirement": "Implement robust authentication and authorization. Apply rate limiting to prevent brute-force attacks.", "GRCMapping": "ISO 27002 A.9.2.1 (Access Control Policy)"},
    {"FlowType": "File Transfer", "OWASPID": "A05:2021", "Requirement": "Ensure integrity checks (e.g., checksums) for transferred files. Scan for malware.", "GRCMapping": "NIST 800-53 SI-3 (Malware Protection)"},
    {"FlowType": "User Login", "OWASPID": "A07:2021", "Requirement": "Implement multi-factor authentication (MFA). Enforce strong password policies.", "GRCMapping": "ISO 27002 A.9.2.4 (User Access Provisioning)"},
    {"FlowType": "Internal RPC", "OWASPID": "A01:2021", "Requirement": "Authenticate and authorize all internal service-to-service communication.", "GRCMapping": "NIST 800-53 AC-3 (Access Enforcement)"},
    {"FlowType": "Payment Gateway", "OWASPID": "A04:2021", "Requirement": "PCI DSS compliance for all payment processing and storage.", "GRCMapping": "PCI DSS Requirement 3 (Protect Stored Data)"},
    {"FlowType": "Message Queue", "OWASPID": "A05:2021", "Requirement": "Encrypt messages in transit and at rest within the queue.", "GRCMapping": "NIST 800-53 SC-8 (Transmission Integrity)"},
    {"FlowType": "Email", "OWASPID": "A06:2021", "Requirement": "Implement SPF, DKIM, DMARC for email authenticity. Use TLS for email transport.", "GRCMapping": "GDPR Article 32 (Security of Processing)"},
    {"FlowType": "Logging", "OWASPID": "A09:2021", "Requirement": "Ensure comprehensive logging of security-relevant events. Protect log integrity.", "GRCMapping": "NIST 800-53 AU-2 (Audit Events)"},
    {"FlowType": "Admin Access", "OWASPID": "A07:2021", "Requirement": "Implement JIT (Just-in-Time) access and strict least privilege for administrative functions.", "GRCMapping": "ISO 27002 A.9.2.5 (Privileged Access Control)"},
]

# --- Initial Data for Threat Mappings ---
INITIAL_STRIDE_MAPPINGS = [
    {"SourceDomain": "People", "TargetDomain": "Application", "STRIDE_Threat": "Spoofing", "MITRE_Technique": "T1078 - Valid Accounts", "Recommended_Control": "Implement Multi-Factor Authentication (MFA)", "NIST_Control": "AC-2", "ISO_Control": "A.9.2.2"},
    {"SourceDomain": "Application", "TargetDomain": "Data", "STRIDE_Threat": "Tampering", "MITRE_Technique": "T1486 - Data Encrypted for Impact", "Recommended_Control": "Encrypt data at rest and in transit", "NIST_Control": "SC-12", "ISO_Control": "A.13.1.1"},
    {"SourceDomain": "Platform", "TargetDomain": "Network", "STRIDE_Threat": "Denial of Service", "MITRE_Technique": "T1499 - Network Denial of Service", "Recommended_Control": "Implement Network Ingress/Egress Filtering and DDoS protection", "NIST_Control": "SC-7", "ISO_Control": "A.13.1.2"},
    {"SourceDomain": "Network", "TargetDomain": "Application", "STRIDE_Threat": "Information Disclosure", "MITRE_Technique": "T1059.001 - Command and Scripting Interpreter", "Recommended_Control": "Enforce strict network segmentation and firewall rules", "NIST_Control": "SC-7", "ISO_Control": "A.13.1.2"},
    {"SourceDomain": "Application", "TargetDomain": "Application", "STRIDE_Threat": "Elevation of Privilege", "MITRE_Technique": "T1134 - Access Token Manipulation", "Recommended_Control": "Implement Least Privilege Access Control and RBAC", "NIST_Control": "AC-6", "ISO_Control": "A.9.2.1"},
    {"SourceDomain": "Data", "TargetDomain": "People", "STRIDE_Threat": "Information Disclosure", "MITRE_Technique": "T1020 - Automated Exfiltration", "Recommended_Control": "Data Loss Prevention (DLP) solutions", "NIST_Control": "AC-4", "ISO_Control": "A.13.2.1"},
    {"SourceDomain": "Application", "TargetDomain": "Platform", "STRIDE_Threat": "Repudiation", "MITRE_Technique": "T1562.001 - Disable or Modify System Recovery", "Recommended_Control": "Ensure comprehensive logging and audit trails", "NIST_Control": "AU-2", "ISO_Control": "A.12.4.1"},
    {"SourceDomain": "People", "TargetDomain": "Network", "STRIDE_Threat": "Spoofing", "MITRE_Technique": "T1078.003 - Local Accounts", "Recommended_Control": "Implement Network Access Control (NAC)", "NIST_Control": "AC-8", "ISO_Control": "A.9.1.2"},
    {"SourceDomain": "Network", "TargetDomain": "Data", "STRIDE_Threat": "Tampering", "MITRE_Technique": "T1485 - Data Destruction", "Recommended_Control": "Implement Intrusion Detection/Prevention Systems (IDPS)", "NIST_Control": "SI-4", "ISO_Control": "A.14.2.1"},
    {"SourceDomain": "Application", "TargetDomain": "Data", "STRIDE_Threat": "Elevation of Privilege", "MITRE_Technique": "T1003 - OS Credential Dumping", "Recommended_Control": "Secure API keys and credentials, use vaulting solutions", "NIST_Control": "SC-28", "ISO_Control": "A.12.7.1"},
    {"SourceDomain": "Platform", "TargetDomain": "Application", "STRIDE_Threat": "Information Disclosure", "MITRE_Technique": "T1560 - Archive Collected Data", "Recommended_Control": "Secure configuration management and vulnerability scanning", "NIST_Control": "CM-6", "ISO_Control": "A.12.6.1"},
    {"SourceDomain": "People", "TargetDomain": "Data", "STRIDE_Threat": "Tampering", "MITRE_Technique": "T1056.001 - Keylogging", "Recommended_Control": "Implement endpoint detection and response (EDR)", "NIST_Control": "SI-3", "ISO_Control": "A.16.1.7"},
    {"SourceDomain": "Network", "TargetDomain": "Platform", "STRIDE_Threat": "Denial of Service", "MITRE_Technique": "T1498 - Defacement", "Recommended_Control": "Robust patching and vulnerability management", "NIST_Control": "RA-5", "ISO_Control": "A.12.6.1"},
    {"SourceDomain": "Application", "TargetDomain": "Network", "STRIDE_Threat": "Repudiation", "MITRE_Technique": "T1070.004 - File Deletion", "Recommended_Control": "Enforce strong change management for network configurations", "NIST_Control": "CM-3", "ISO_Control": "A.12.1.2"},
    {"SourceDomain": "Data", "TargetDomain": "Platform", "STRIDE_Threat": "Spoofing", "MITRE_Technique": "T1550.002 - Steal or Forge Kerberos Tickets", "Recommended_Control": "Data encryption in transit and at rest", "NIST_Control": "SC-13", "ISO_Control": "A.13.1.1"},
    {"SourceDomain": "People", "TargetDomain": "People", "STRIDE_Threat": "Spoofing", "MITRE_Technique": "T1078.001 - Domain Accounts", "Recommended_Control": "Security Awareness Training and phishing drills", "NIST_Control": "AT-2", "ISO_Control": "A.8.2.2"},
]

# --- Example Initial Architecture Elements and Interactions ---
# Note: These are for the *app.py*'s internal state (usually stored in Excel),
# but if you wanted to directly inject them into the .db file for testing
# a hypothetical 'architecture_elements' and 'architecture_interactions' table,
# this is how that data would look.
# For the current code, app.py uses architecture_data.xlsx for these.
INITIAL_ARCHITECTURE_ELEMENTS = [
    {"Domain": "People", "Element": "End User"},
    {"Domain": "Application", "Element": "Web App"},
    {"Domain": "Application", "Element": "Microservice A"},
    {"Domain": "Platform", "Element": "K8s Cluster"},
    {"Domain": "Network", "Element": "Load Balancer"},
    {"Domain": "Data", "Element": "User Database"},
    {"Domain": "Data", "Element": "Logs Storage"},
]

INITIAL_ARCHITECTURE_INTERACTIONS = [
    {"Source": "End User", "Target": "Load Balancer", "FlowType": "HTTPS"},
    {"Source": "Load Balancer", "Target": "Web App", "FlowType": "HTTPS"},
    {"Source": "Web App", "Target": "Microservice A", "FlowType": "Internal RPC"},
    {"Source": "Microservice A", "Target": "User Database", "FlowType": "Database"},
    {"Source": "Web App", "Target": "Logs Storage", "FlowType": "Logging"},
]


def create_and_populate_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create flow_mappings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flow_mappings (
            FlowType TEXT PRIMARY KEY,
            OWASPID TEXT,
            Requirement TEXT,
            GRCMapping TEXT
        )
    """)

    # Create threat_mappings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_mappings (
            SourceDomain TEXT,
            TargetDomain TEXT,
            STRIDE_Threat TEXT,
            MITRE_Technique TEXT,
            Recommended_Control TEXT,
            NIST_Control TEXT,
            ISO_Control TEXT,
            PRIMARY KEY (SourceDomain, TargetDomain, STRIDE_Threat, MITRE_Technique)
        )
    """)
    conn.commit()

    # Populate flow_mappings if empty
    cursor.execute("SELECT COUNT(*) FROM flow_mappings")
    if cursor.fetchone()[0] == 0:
        flow_df = pd.DataFrame(INITIAL_FLOW_MAPPINGS)
        flow_df.to_sql('flow_mappings', conn, if_exists='append', index=False)
        print("Initial Flow Mappings populated.")

    # Populate threat_mappings if empty
    cursor.execute("SELECT COUNT(*) FROM threat_mappings")
    if cursor.fetchone()[0] == 0:
        stride_df = pd.DataFrame(INITIAL_STRIDE_MAPPINGS)
        stride_df.to_sql('threat_mappings', conn, if_exists='append', index=False)
        print("Initial STRIDE/MITRE Mappings populated.")
    
    conn.commit()
    conn.close()
    print(f"Database '{DB_FILE}' created/updated successfully.")

if __name__ == "__main__":
    create_and_populate_db()

    # Optional: You can add code here to also generate architecture_data.xlsx
    # if you want a complete initial setup file for the main app.
    # For now, the main app creates it on first save.
    print(f"\nRemember that '{DB_FILE}' contains Flow Mappings and Threat Mappings.")
    print("Your main 'app.py' will still create 'architecture_data.xlsx' for elements and interactions on first save.")