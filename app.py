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
        self._load_architecture_from_excel()

    def _get_db_connection(self):
        """Establishes and returns a SQLite database connection."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn

    def _initialize_database_and_populate_if_empty(self):
        """
        Creates tables for general security controls if they don't exist,
        and populates them with initial data if they are empty.
        """
        conn = self._get_db_connection()
        cursor = conn.cursor()

        # Create flow_mappings table (updated to reference ASVS_IDs)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flow_mappings (
                FlowType TEXT PRIMARY KEY,
                ASVS_IDs TEXT -- Stored as comma-separated string, or JSON, for simplicity
            )
        """)

        # Create asvs_controls table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS asvs_controls (
                ASVS_ID TEXT PRIMARY KEY,
                ASVS_Level TEXT NOT NULL,
                Requirement TEXT NOT NULL,
                GRCMapping TEXT
            )
        """)

        # Create threat_mappings table (STRIDE/MITRE)
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

        # --- Populate tables if they are empty ---
        # Populate asvs_controls if empty
        cursor.execute("SELECT COUNT(*) FROM asvs_controls")
        if cursor.fetchone()[0] == 0:
            asvs_df = pd.DataFrame(INITIAL_ASVS_CONTROLS)
            asvs_df.to_sql('asvs_controls', conn, if_exists='append', index=False)
            st.toast("Initial ASVS Controls populated in DB.", icon="✅")

        # Populate flow_mappings if empty (updated for ASVS_IDs)
        cursor.execute("SELECT COUNT(*) FROM flow_mappings")
        if cursor.fetchone()[0] == 0:
            # Convert ASVS_IDs list to a comma-separated string for storage
            flow_df = pd.DataFrame(INITIAL_FLOW_MAPPINGS)
            flow_df['ASVS_IDs'] = flow_df['ASVS_IDs'].apply(lambda x: ','.join(x))
            flow_df.to_sql('flow_mappings', conn, if_exists='append', index=False)
            st.toast("Initial Flow Mappings (with ASVS) populated in DB.", icon="✅")

        # Populate threat_mappings if empty
        cursor.execute("SELECT COUNT(*) FROM threat_mappings")
        if cursor.fetchone()[0] == 0:
            stride_df = pd.DataFrame(INITIAL_STRIDE_MAPPINGS)
            stride_df.to_sql('threat_mappings', conn, if_exists='append', index=False)
            st.toast("Initial STRIDE/MITRE Mappings populated in DB.", icon="✅")
        
        conn.commit()
        conn.close()

    def _load_data_from_db(self):
        """Loads security control data from SQLite into Pandas DataFrames."""
        conn = self._get_db_connection()
        try:
            self.flow_mappings = pd.read_sql_query("SELECT * FROM flow_mappings", conn)
            # Convert ASVS_IDs back to a list of strings
            self.flow_mappings['ASVS_IDs'] = self.flow_mappings['ASVS_IDs'].apply(lambda x: x.split(',') if x else [])
            
            self.asvs_controls = pd.read_sql_query("SELECT * FROM asvs_controls", conn)
            self.threat_mappings = pd.read_sql_query("SELECT * FROM threat_mappings", conn)
        except Exception as e:
            st.error(f"Error loading data from database: {e}. Ensure the database file '{DB_FILE}' is accessible.")
            self.flow_mappings = pd.DataFrame(columns=["FlowType", "ASVS_IDs"])
            self.asvs_controls = pd.DataFrame(columns=["ASVS_ID", "ASVS_Level", "Requirement", "GRCMapping"])
            self.threat_mappings = pd.DataFrame(columns=["SourceDomain", "TargetDomain", "STRIDE_Threat", "MITRE_Technique", "Recommended_Control", "NIST_Control", "ISO_Control"])
        finally:
            conn.close()

    # --- ARCHITECTURE PERSISTENCE (Existing Excel methods for the active design) ---
    def _save_architecture_to_excel(self):
        """Saves current architecture elements and interactions to Excel."""
        elements_data = []
        for domain, elements in st.session_state.architecture.items():
            for elem in elements:
                elements_data.append({"Domain": domain, "Element": elem})
        df_elements = pd.DataFrame(elements_data)
        
        df_interactions = pd.DataFrame(st.session_state.interactions, columns=["Source", "Target", "FlowType"])
        
        try:
            with pd.ExcelWriter("architecture_data.xlsx") as writer:
                df_elements.to_excel(writer, sheet_name="Elements", index=False)
                df_interactions.to_excel(writer, sheet_name="Interactions", index=False)
            st.success("Architecture saved to architecture_data.xlsx!")
        except Exception as e:
            st.error(f"Failed to save architecture to architecture_data.xlsx: {e}")


    def _load_architecture_from_excel(self):
        """
        Loads architecture elements and interactions from Excel.
        Crucially, it only loads and overwrites session state if the file exists and is valid.
        Otherwise, it leaves the current session state as is.
        """
        excel_file_path = "architecture_data.xlsx"
        try:
            if os.path.exists(excel_file_path) and os.path.getsize(excel_file_path) > 0:
                data = pd.read_excel(excel_file_path, sheet_name=None)
                df_elements = data.get("Elements", pd.DataFrame())
                df_interactions = data.get("Interactions", pd.DataFrame())
                
                # ONLY CLEAR AND OVERWRITE session state if the file was successfully read
                st.session_state.architecture = {domain: [] for domain in DOMAINS}
                st.session_state.interactions = []

                for index, row in df_elements.iterrows():
                    domain = row["Domain"]
                    element = row["Element"]
                    if domain in DOMAINS and element not in st.session_state.architecture[domain]:
                        st.session_state.architecture[domain].append(element)
                
                for index, row in df_interactions.iterrows():
                    interaction = [row["Source"], row["Target"], row["FlowType"]]
                    if interaction not in st.session_state.interactions:
                        st.session_state.interactions.append(interaction)
                
                st.success("Architecture loaded successfully from architecture_data.xlsx!")
            else:
                st.info("No existing 'architecture_data.xlsx' found or file is empty. Starting a new architecture.")
        except Exception as e:
            st.error(f"Failed to load architecture from architecture_data.xlsx: {e}")
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
            st.session_state.interactions = []

    # --- CORE APPLICATION LOGIC ---

    def add_element(self, domain, name):
        """Adds a security architecture element."""
        name = name.strip() # Clean whitespace
        if name and name not in st.session_state.architecture[domain]:
            st.session_state.architecture[domain].append(name)
            st.success(f"Added '{name}' to {domain}.")
            self._save_architecture_to_excel() # Save immediately after modification
        else:
            st.warning(f"Element '{name}' already exists in {domain} or is empty.")

    def add_interaction(self, source, target, flow_type):
        """Adds an interaction between two elements."""
        new_interaction = [source.strip(), target.strip(), flow_type.strip()] # Clean whitespace
        if new_interaction not in st.session_state.interactions:
            st.session_state.interactions.append(new_interaction)
            st.success(f"Added interaction: {source} --({flow_type})--> {target}")
            self._save_architecture_to_excel() # Save immediately after modification
        else:
            st.warning("This interaction already exists.")

    def delete_element(self, domain, name):
        """Deletes a security architecture element and its related interactions."""
        if name in st.session_state.architecture[domain]:
            st.session_state.architecture[domain].remove(name)
            # Remove interactions involving the deleted element
            st.session_state.interactions = [
                i for i in st.session_state.interactions
                if i[0] != name and i[1] != name
            ]
            st.success(f"Deleted '{name}' from {domain} and associated interactions.")
            self._save_architecture_to_excel() # Save immediately after modification
        else:
            st.warning(f"Element '{name}' not found in {domain}.")

    def delete_interaction(self, interaction_list):
        """Deletes a specific interaction (expecting a list [source, target, flow_type])."""
        if interaction_list in st.session_state.interactions:
            st.session_state.interactions.remove(interaction_list)
            st.success(f"Deleted interaction: {interaction_list[0]} --({interaction_list[2]})--> {interaction_list[1]}")
            self._save_architecture_to_excel() # Save immediately after modification
        else:
            st.warning("Interaction not found.")

    def generate_requirements(self, asvs_level_filter: str = None):
        """
        Generates security requirements based on defined interactions and flow types,
        using ASVS controls and filtering by selected ASVS level.
        """
        # FIX: Corrected syntax error here: .empty for asvs_controls
        if self.flow_mappings.empty or self.asvs_controls.empty:
            st.warning("Flow mappings or ASVS controls data is not loaded or is empty. Cannot generate requirements. Please run the Data Manager app or ensure initial data is loaded.")
            return pd.DataFrame(columns=["Interaction No.", "Interaction", "Flow Type", "ASVS ID", "ASVS Level", "Requirement", "GRC Mapping"])
        
        requirements = []
        for i, (source, target, flow_type) in enumerate(st.session_state.interactions):
            # Find relevant flow mapping
            flow_map_entry = self.flow_mappings[self.flow_mappings["FlowType"] == flow_type]
            
            if not flow_map_entry.empty:
                asvs_ids_for_flow = flow_map_entry.iloc[0]["ASVS_IDs"] # This is now a list of ASVS_IDs
                
                # Filter ASVS controls by the IDs linked to this flow type
                relevant_asvs_controls = self.asvs_controls[
                    self.asvs_controls["ASVS_ID"].isin(asvs_ids_for_flow)
                ].copy() # Use .copy() to avoid SettingWithCopyWarning
                
                # Apply ASVS level filter
                if asvs_level_filter and asvs_level_filter != "None":
                    # For a requirement to be included, its ASVS_Level must be less than or equal to the selected level.
                    # L1 requirements apply to L1, L2, L3. L2 requirements apply to L2, L3. L3 requirements apply to L3.
                    if asvs_level_filter == "L1":
                        level_filter_condition = relevant_asvs_controls["ASVS_Level"].isin(["L1"])
                    elif asvs_level_filter == "L2":
                        level_filter_condition = relevant_asvs_controls["ASVS_Level"].isin(["L1", "L2"])
                    elif asvs_level_filter == "L3":
                        level_filter_condition = relevant_asvs_controls["ASVS_Level"].isin(["L1", "L2", "L3"])
                    
                    relevant_asvs_controls = relevant_asvs_controls[level_filter_condition]

                # Add each relevant ASVS control as a requirement
                for index, row in relevant_asvs_controls.iterrows():
                    requirements.append({
                        "Interaction No.": i + 1,
                        "Interaction": f"{source} --({flow_type})--> {target}",
                        "Flow Type": flow_type,
                        "ASVS ID": row["ASVS_ID"],
                        "ASVS Level": row["ASVS_Level"],
                        "Requirement": row["Requirement"],
                        "GRC Mapping": row["GRCMapping"]
                    })
        
        # Remove duplicates, keeping the first occurrence (important if multiple flows link to same ASVS ID)
        if requirements:
            df = pd.DataFrame(requirements)
            # Define a unique key for requirements (excluding interaction number if it's the same requirement for different interactions)
            # Here, we keep interaction number to show which interaction triggered it.
            # If a requirement applies to multiple interactions, it will appear multiple times.
            return df.drop_duplicates(subset=["Interaction No.", "ASVS ID"], keep="first").sort_values(by=["Interaction No.", "ASVS ID"])
        return pd.DataFrame(columns=["Interaction No.", "Interaction", "Flow Type", "ASVS ID", "ASVS Level", "Requirement", "GRC Mapping"])


    def generate_threat_analysis(self):
        """Generates a STRIDE-based threat analysis with MITRE ATT&CK and controls, with numbering."""
        if self.threat_mappings.empty:
            st.warning("Threat mappings data is not loaded or is empty. Cannot generate threat analysis. Please run the Data Manager app or ensure initial data is loaded.")
            return pd.DataFrame(columns=["Interaction No.", "Interaction", "Source Domain", "Target Domain", "STRIDE Threat", "MITRE Technique", "Recommended Control", "NIST Control", "ISO Control"])

        threats = []
        element_domain_map = {
            elem: domain for domain, elements in st.session_state.architecture.items() for elem in elements
        }
        
        for i, (source, target, flow_type) in enumerate(st.session_state.interactions):
            src_domain = element_domain_map.get(source)
            tgt_domain = element_domain_map.get(target)

            if not src_domain or not tgt_domain:
                st.warning(f"Domain not found for '{source}' or '{target}'. Skipping threat analysis for interaction: {source} -> {target}.")
                continue

            relevant_threats = self.threat_mappings[
                (self.threat_mappings["SourceDomain"] == src_domain) &
                (self.threat_mappings["TargetDomain"] == tgt_domain)
            ]
            
            for index, row in relevant_threats.iterrows():
                threats.append({
                    "Interaction No.": i + 1, # Add the interaction number
                    "Interaction": f"{source} --({flow_type})--> {target}",
                    "Source Domain": row["SourceDomain"],
                    "Target Domain": row["TargetDomain"],
                    "STRIDE Threat": row["STRIDE_Threat"],
                    "MITRE Technique": row["MITRE_Technique"],
                    "Recommended Control": row["Recommended_Control"],
                    "NIST Control": row["NIST_Control"],
                    "ISO Control": row["ISO_Control"]
                })
        return pd.DataFrame(threats)


    def render_graph(self):
        """Renders the architecture graph using Pyvis."""
        color_map = {
            "People": "lightcoral",
            "Application": "lightblue",
            "Platform": "lightgreen",
            "Network": "orange",
            "Data": "lightgoldenrodyellow"
        }
        net = Network(height="600px", width="100%", directed=True, notebook=True)
        
        # Add nodes
        for domain, elements in st.session_state.architecture.items():
            for el in elements:
                net.add_node(el, label=el, title=domain, color=color_map.get(domain, "gray"), size=25, font={'size': 14})
        
        # Add edges
        for src, tgt, flow_type in st.session_state.interactions:
            if src in net.get_nodes() and tgt in net.get_nodes():
                net.add_edge(src, tgt, title=flow_type, label=flow_type, color='darkgray', width=2)
            else:
                st.warning(f"Skipping graph edge for '{src} -> {tgt}' as one or both elements not found in graph nodes (check if elements were added).")
        
        try:
            html_file = "graph.html"
            net.save_graph(html_file)
            with open(html_file, "r", encoding="utf-8") as f:
                html = f.read()
            components.html(html, height=600, scrolling=True)
        except Exception as e:
            st.error(f"Failed to render graph: {e}")

    def create_github_issue(self, title: str, body: str) -> bool:
        """Creates a GitHub issue."""
        GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        REPO_OWNER = os.getenv("GITHUB_REPO_OWNER")
        REPO_NAME = os.getenv("GITHUB_REPO_NAME")
        
        if not GITHUB_TOKEN or not REPO_OWNER or not REPO_NAME:
            st.error("GitHub credentials (GITHUB_TOKEN, GITHUB_REPO_OWNER, GITHUB_REPO_NAME) not configured.")
            st.info("Please set these as environment variables or using Streamlit secrets.")
            return False

        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues"
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        data = {"title": title, "body": body}
        
        try:
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 201:
                st.success(f"GitHub issue created: {response.json().get('html_url', 'URL not available')}")
                return True
            else:
                st.error(f"Failed to create GitHub issue: {response.status_code} - {response.json().get('message', 'No error message')}")
                return False
        except requests.exceptions.RequestException as e:
            st.error(f"Network error or API issue when creating GitHub issue: {e}")
            return False

# --- Streamlit UI for Main Application ---
st.set_page_config(layout="wide", page_title="Security Architecture Designer")

st.title("🛡️ Security Architecture Designer & Threat Modeling")
st.markdown("Use this tool to design your architecture and analyze security requirements and threats.")
st.markdown("---")

# Initialize the manager
manager = SecurityArchitectureManager()

# Sidebar for common actions and help
st.sidebar.header("Architecture Actions")
if st.sidebar.button("💾 Save Current Architecture"):
    manager._save_architecture_to_excel()
if st.sidebar.button("📂 Load Architecture"):
    manager._load_architecture_from_excel()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.header("Manage Security Controls")
st.sidebar.markdown("""
To add, edit, or delete the underlying security requirements and threat mappings (like Flow Types, ASVS Controls, STRIDE, MITRE controls):

**Run the separate Data Manager application (if available):**
`streamlit run data_manager_app.py`

*(Note: Initial data for controls is automatically populated by this app on first run if database is empty.)*
""")

# Main content area
st.subheader("📝 Define Architecture Elements")
cols = st.columns(len(DOMAINS))
for i, domain in enumerate(DOMAINS):
    with cols[i]:
        st.markdown(f"**{domain}**")
        with st.container(border=True):
            # Display current elements for the domain
            if st.session_state.architecture[domain]:
                for elem in list(st.session_state.architecture[domain]): 
                    col_elem, col_btn = st.columns([0.7, 0.3])
                    with col_elem:
                        st.markdown(f"- {elem}")
                    with col_btn:
                        if st.button("Remove", key=f"del-{domain}-{elem}"):
                            manager.delete_element(domain, elem)
                            st.rerun()
            else:
                st.write(f"No {domain} elements defined yet.")

            # Form to add new elements
            with st.form(key=f"add_form_{domain}", clear_on_submit=True):
                new_elem_input = st.text_input(f"Add new {domain} element:", key=f"add_elem_input_form_{domain}")
                add_button_clicked = st.form_submit_button(f"Add {domain} Element")
                
                if add_button_clicked:
                    if new_elem_input:
                        manager.add_element(domain, new_elem_input)
                        st.rerun() # Re-run the app to display the updated state
                    else:
                        st.warning("Element name cannot be empty.")


st.subheader("🔗 Define Interactions Between Elements")
all_elements_flat = [item for sublist in st.session_state.architecture.values() for item in sublist]

if not all_elements_flat:
    st.warning("Please add some elements before defining interactions.")
else:
    with st.form(key="add_interaction_form", clear_on_submit=True):
        col_src, col_tgt, col_flow = st.columns(3)
        with col_src:
            source_elem = st.selectbox("Source Element", [""] + sorted(all_elements_flat), key="source_select")
        with col_tgt:
            target_elem = st.selectbox("Target Element", [""] + sorted(all_elements_flat), key="target_select")
        
        flow_type_options = manager.flow_mappings["FlowType"].tolist() if not manager.flow_mappings.empty else []
        if not flow_type_options:
            st.warning("No Flow Types loaded from database. Please run the Data Manager app or ensure initial data is loaded.")
        with col_flow:
            flow_type_selected = st.selectbox("Flow Type", [""] + sorted(flow_type_options), key="flowtype_select")

        add_interaction_button_clicked = st.form_submit_button("Add Interaction", use_container_width=True)

        if add_interaction_button_clicked:
            if source_elem and target_elem and flow_type_selected:
                if source_elem == target_elem:
                    st.error("Source and Target elements cannot be the same.")
                else:
                    manager.add_interaction(source_elem, target_elem, flow_type_selected)
                    st.rerun()
            else:
                st.error("Please select all fields for the interaction.")

    st.markdown("---")
    st.markdown("#### Current Interactions")
    if st.session_state.interactions:
        for i, interaction in enumerate(list(st.session_state.interactions)):
            col_display, col_remove = st.columns([0.8, 0.2])
            with col_display:
                st.write(f"{i+1}. {interaction[0]} ➡️ {interaction[1]} ({interaction[2]})")
            with col_remove:
                if st.button("Remove", key=f"remove_interaction_{i}"):
                    manager.delete_interaction(interaction)
                    st.rerun()
    else:
        st.info("No interactions defined yet.")

st.subheader("📈 Architecture Graph Visualization")
if st.session_state.architecture or st.session_state.interactions:
    manager.render_graph()
else:
    st.info("Add elements and interactions to see the architecture graph.")

st.subheader("🔒 Security Requirements Analysis (OWASP ASVS)")
st.markdown("Select the target ASVS level. Higher levels include requirements from lower levels.")
selected_asvs_level = st.selectbox(
    "Select ASVS Verification Level",
    options=["None"] + ASVS_LEVELS, # "None" means show all applicable by default, no filtering by level
    index=0 # Default to "None"
)

requirements_df = manager.generate_requirements(selected_asvs_level)
if not requirements_df.empty:
    st.dataframe(requirements_df, use_container_width=True)
else:
    st.info("No security requirements generated. Ensure interactions are defined and ASVS control mappings are loaded for the selected level.")

st.subheader("🚨 Threat Modelling Recommendations (STRIDE/MITRE)")
threat_analysis_df = manager.generate_threat_analysis()
if not threat_analysis_df.empty:
    st.dataframe(threat_analysis_df, use_container_width=True)
else:
    st.info("No threat analysis generated. Ensure interactions are defined and control mappings are loaded.")

st.sidebar.markdown("---")
st.sidebar.markdown("### GitHub Integration Setup")
st.sidebar.markdown("""
To enable GitHub issue creation:
1.  Go to your GitHub repository settings.
2.  Navigate to `Secrets and variables` -> `Actions`.
3.  Add repository secrets:
    * `GITHUB_TOKEN`: Your GitHub Personal Access Token (PAT) with `repo` scope.
    * `GITHUB_REPO_OWNER`: Your GitHub username or organization name.
    * `GITHUB_REPO_NAME`: The name of your repository (e.g., `my-security-architecture`).
4.  Alternatively, set these as environment variables where you run the Streamlit app.
""")
st.sidebar.warning("Never hardcode your GitHub Token in the script for production!")
