import streamlit as st
import pandas as pd
import sqlite3
import os
from pyvis.network import Network
import streamlit.components.v1 as components
import requests

# --- Configuration Constants ---
DB_FILE = "security_architecture.db" # Database file for security controls

# Define the domains for the architecture elements
DOMAINS = ["People", "Application", "Platform", "Network", "Data"]

# Define ASVS Levels
ASVS_LEVELS = ["L1", "L2", "L3"]

# --- Initial Data (Now embedded directly in app.py for self-population) ---

# This will be replaced by ASVS controls in the DB
# INITIAL_FLOW_MAPPINGS will now link FlowType to ASVS_IDs
INITIAL_ASVS_CONTROLS = [
    # ASVS V1: Architecture, Design and Threat Modeling
    {"ASVS_ID": "V1.1.1", "ASVS_Level": "L1", "Requirement": "Verify the application uses an actively managed, secure software development lifecycle (SDLC).", "GRCMapping": "NIST 800-53 SA-3"},
    {"ASVS_ID": "V1.2.1", "ASVS_Level": "L2", "Requirement": "Verify that authentication is performed by a trusted component.", "GRCMapping": "ISO 27002 A.9.2.1"},
    {"ASVS_ID": "V1.2.2", "ASVS_Level": "L3", "Requirement": "Verify that all components that interact with unauthenticated clients (e.g., login pages) are hardened to prevent enumeration attacks and DoS.", "GRCMapping": "NIST 800-53 SC-5"},

    # ASVS V2: Authentication Verification Requirements
    {"ASVS_ID": "V2.1.1", "ASVS_Level": "L1", "Requirement": "Verify that all passwords are at least 12 characters long and can contain spaces and special characters.", "GRCMapping": "NIST 800-63B 5.1.1"},
    {"ASVS_ID": "V2.2.1", "ASVS_Level": "L2", "Requirement": "Verify that all authenticators use multi-factor authentication (MFA) for high-value accounts.", "GRCMapping": "NIST 800-63B 5.1.2"},
    {"ASVS_ID": "V2.3.1", "ASVS_Level": "L1", "Requirement": "Verify that authenticated sessions are regenerated upon any change in authentication context (e.e.g., privilege escalation).", "GRCMapping": "OWASP Top 10 A07"},
    {"ASVS_ID": "V2.4.1", "ASVS_Level": "L2", "Requirement": "Verify that credential storage uses a strong, salted, adaptive hashing function (e.g., Argon2, bcrypt).", "GRCMapping": "NIST 800-63B 5.1.1"},

    # ASVS V3: Session Management Verification Requirements
    {"ASVS_ID": "V3.1.1", "ASVS_Level": "L1", "Requirement": "Verify that session tokens are cryptographically random and unpredictable.", "GRCMapping": "OWASP Top 10 A07"},
    {"ASVS_ID": "V3.2.1", "ASVS_Level": "L2", "Requirement": "Verify that sessions are bound to the client's IP address or other suitable attributes.", "GRCMapping": "ISO 27002 A.9.4.1"},
    {"ASVS_ID": "V3.3.1", "ASVS_Level": "L1", "Requirement": "Verify that sessions have appropriate idle and absolute timeouts.", "GRCMapping": "OWASP Top 10 A07"},

    # ASVS V4: Access Control Verification Requirements
    {"ASVS_ID": "V4.1.1", "ASVS_Level": "L1", "Requirement": "Verify that access control policies are defined and enforced at the server-side and are not bypassable.", "GRCMapping": "OWASP Top 10 A01"},
    {"ASVS_ID": "V4.2.1", "ASVS_Level": "L2", "Requirement": "Verify that all functions, resources, and services enforce authorization checks.", "GRCMapping": "NIST 800-53 AC-3"},

    # ASVS V5: Validation, Sanitization and Encoding Verification Requirements
    {"ASVS_ID": "V5.1.1", "ASVS_Level": "L1", "Requirement": "Verify that all untrusted input is validated, sanitized, or encoded based on context.", "GRCMapping": "OWASP Top 10 A03"},
    {"ASVS_ID": "V5.2.1", "ASVS_Level": "L2", "Requirement": "Verify that dynamic SQL queries use parameterized statements or object-relational mapping (ORM).", "GRCMapping": "OWASP Top 10 A03"},

    # ASVS V6: Stored Cryptography Verification Requirements
    {"ASVS_ID": "V6.1.1", "ASVS_Level": "L1", "Requirement": "Verify that sensitive data at rest is encrypted using strong, modern, industry-accepted algorithms and protocols.", "GRCMapping": "NIST 800-53 SC-28"},

    # ASVS V9: Communications Verification Requirements (HTTPS related)
    {"ASVS_ID": "V9.1.1", "ASVS_Level": "L1", "Requirement": "Verify that all communication with external services uses TLS 1.2+ with strong ciphers and perfect forward secrecy.", "GRCMapping": "NIST 800-53 SC-8"},
    {"ASVS_ID": "V9.1.2", "ASVS_Level": "L2", "Requirement": "Verify that the application uses HSTS with a long max-age and preloading.", "GRCMapping": "NIST 800-53 SC-8"},
    {"ASVS_ID": "V9.2.1", "ASVS_Level": "L1", "Requirement": "Verify that server certificates are valid, not expired, and issued by a trusted Certificate Authority.", "GRCMapping": "NIST 800-53 SC-8"},

    # ASVS V13: API and Web Service Verification Requirements
    {"ASVS_ID": "V13.1.1", "ASVS_Level": "L1", "Requirement": "Verify that API endpoints are protected by appropriate authentication and authorization.", "GRCMapping": "OWASP Top 10 A01"},
    {"ASVS_ID": "V13.2.1", "ASVS_Level": "L2", "Requirement": "Verify that RESTful APIs correctly use HTTP methods (GET, POST, PUT, DELETE) and enforce statelessness.", "GRCMapping": "OWASP Top 10 A01"},
]

# Update INITIAL_FLOW_MAPPINGS to use ASVS IDs
# A single FlowType can now map to multiple ASVS_IDs
INITIAL_FLOW_MAPPINGS = [
    {"FlowType": "HTTPS", "ASVS_IDs": ["V9.1.1", "V9.1.2", "V9.2.1", "V1.1.1"]}, # Example: HTTPS triggers multiple ASVS controls
    {"FlowType": "Database", "ASVS_IDs": ["V5.2.1", "V6.1.1", "V1.1.1"]},
    {"FlowType": "API Call", "ASVS_IDs": ["V13.1.1", "V4.1.1", "V13.2.1", "V1.2.1"]},
    {"FlowType": "File Transfer", "ASVS_IDs": ["V5.1.1", "V1.1.1"]}, # Placeholder, actual ASVS for file transfer would be V12
    {"FlowType": "User Login", "ASVS_IDs": ["V2.1.1", "V2.2.1", "V2.3.1", "V2.4.1", "V3.1.1", "V3.3.1", "V1.2.1", "V1.2.2"]},
    {"FlowType": "Internal RPC", "ASVS_IDs": ["V4.2.1", "V9.1.1"]},
    {"FlowType": "Payment Gateway", "ASVS_IDs": ["V4.1.1", "V6.1.1", "V9.1.1"]}, # PCI DSS would often require L3 ASVS
    {"FlowType": "Message Queue", "ASVS_IDs": ["V9.1.1", "V6.1.1"]},
    {"FlowType": "Email", "ASVS_IDs": ["V9.1.1"]}, # SPF/DKIM/DMARC are more communication protocol level, but TLS is ASVS
    {"FlowType": "Admin Access", "ASVS_IDs": ["V2.2.1", "V4.2.1", "V1.2.2"]},
]

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


class SecurityArchitectureManager:
    """
    Manages the security architecture data, interactions, and related analyses.
    Reads security control mappings from the SQLite database.
    """

    def __init__(self):
        # Initialize database tables and populate if empty
        self._initialize_database_and_populate_if_empty()
        
        # Load security control data from SQLite
        self._load_data_from_db()

        # Initialize session state variables for architecture elements and interactions IF THEY DON'T EXIST
        if "architecture" not in st.session_state:
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
        if "interactions" not in st.session_state:
            st.session_state.interactions = []
        
        # Load the dynamic architecture (elements and interactions) from Excel or initialize
