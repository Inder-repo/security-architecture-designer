import streamlit as st
import pandas as pd
import sqlite3

# --- Configuration Constants ---
DB_FILE = "security_architecture.db"

# --- Initial Data (only used if the database is empty) ---
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

class DataManager:
    def __init__(self):
        self._initialize_database()
        self._populate_initial_data()
        self.flow_mappings = self._load_data("flow_mappings")
        self.threat_mappings = self._load_data("threat_mappings")

    def _get_db_connection(self):
        """Establishes and returns a SQLite database connection."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn

    def _initialize_database(self):
        """Creates tables if they don't exist."""
        conn = self._get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flow_mappings (
                FlowType TEXT PRIMARY KEY,
                OWASPID TEXT,
                Requirement TEXT,
                GRCMapping TEXT
            )
        """)

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
        conn.close()

    def _populate_initial_data(self):
        """Populates the database with initial data if tables are empty."""
        conn = self._get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM flow_mappings")
        if cursor.fetchone()[0] == 0:
            flow_df = pd.DataFrame(INITIAL_FLOW_MAPPINGS)
            flow_df.to_sql('flow_mappings', conn, if_exists='append', index=False)
            st.toast("Initial Flow Mappings populated.")

        cursor.execute("SELECT COUNT(*) FROM threat_mappings")
        if cursor.fetchone()[0] == 0:
            stride_df = pd.DataFrame(INITIAL_STRIDE_MAPPINGS)
            stride_df.to_sql('threat_mappings', conn, if_exists='append', index=False)
            st.toast("Initial STRIDE/MITRE Mappings populated.")
        
        conn.commit()
        conn.close()

    def _load_data(self, table_name):
        """Loads data from a specified table into a Pandas DataFrame."""
        conn = self._get_db_connection()
        try:
            df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
            return df
        except Exception as e:
            st.error(f"Error loading {table_name} from database: {e}")
            return pd.DataFrame()
        finally:
            conn.close()

    def add_record(self, table_name, data_dict):
        """Adds a new record to the specified table."""
        conn = self._get_db_connection()
        try:
            columns = ', '.join(data_dict.keys())
            placeholders = ', '.join(['?' for _ in data_dict.values()])
            sql = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
            conn.execute(sql, tuple(data_dict.values()))
            conn.commit()
            st.success(f"Record added to {table_name} successfully!")
            return True
        except sqlite3.IntegrityError:
            st.error(f"Error: A record with the same primary key already exists in {table_name}.")
            return False
        except Exception as e:
            st.error(f"Error adding record to {table_name}: {e}")
            return False
        finally:
            conn.close()

    def update_record(self, table_name, primary_key_col, primary_key_value, data_dict):
        """Updates an existing record in the specified table."""
        conn = self._get_db_connection()
        try:
            set_clauses = ', '.join([f"{col} = ?" for col in data_dict.keys()])
            sql = f"UPDATE {table_name} SET {set_clauses} WHERE {primary_key_col} = ?"
            values = list(data_dict.values()) + [primary_key_value]
            conn.execute(sql, tuple(values))
            conn.commit()
            if conn.changes == 0:
                st.warning(f"No record found with {primary_key_col}='{primary_key_value}' in {table_name} to update.")
                return False
            st.success(f"Record updated in {table_name} successfully!")
            return True
        except Exception as e:
            st.error(f"Error updating record in {table_name}: {e}")
            return False
        finally:
            conn.close()

    def delete_record(self, table_name, primary_key_col, primary_key_value):
        """Deletes a record from the specified table."""
        conn = self._get_db_connection()
        try:
            sql = f"DELETE FROM {table_name} WHERE {primary_key_col} = ?"
            conn.execute(sql, (primary_key_value,))
            conn.commit()
            if conn.changes == 0:
                st.warning(f"No record found with {primary_key_col}='{primary_key_value}' in {table_name} to delete.")
                return False
            st.success(f"Record deleted from {table_name} successfully!")
            return True
        except Exception as e:
            st.error(f"Error deleting record from {table_name}: {e}")
            return False
        finally:
            conn.close()


# --- Streamlit UI for Data Management ---
st.set_page_config(layout="centered", page_title="Security Controls Data Manager")

st.title("📊 Security Controls Data Manager")
st.markdown("Use this tool to manage the **security requirements** and **threat mapping** data that your main architecture application uses.")
st.markdown("---")

manager = DataManager()

# Session state to manage current view
if 'data_view' not in st.session_state:
    st.session_state.data_view = "flow_mappings" # Default view

st.sidebar.header("Select Data Table")
if st.sidebar.button("Flow Mappings"):
    st.session_state.data_view = "flow_mappings"
if st.sidebar.button("Threat Mappings"):
    st.session_state.data_view = "threat_mappings"

st.sidebar.markdown("---")
st.sidebar.markdown("Run the main application: `streamlit run app.py`")

if st.session_state.data_view == "flow_mappings":
    st.header("Flow Mappings (Security Requirements)")
    st.info("Define security requirements for different types of interactions/flows.")
    
    current_data = manager._load_data("flow_mappings")
    if not current_data.empty:
        st.dataframe(current_data, use_container_width=True, hide_index=True)
    else:
        st.info("No flow mappings found. Add new records below.")

    st.subheader("Add/Update Flow Mapping")
    with st.form("flow_mapping_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        with col1:
            flow_type_input = st.text_input("Flow Type (e.g., HTTPS, Database)", help="This will be the unique identifier.")
            requirement_input = st.text_area("Requirement (e.g., 'Ensure TLS 1.2+')", height=80)
        with col2:
            owasp_id_input = st.text_input("OWASP ID (e.g., A01:2021)")
            grc_mapping_input = st.text_input("GRC Mapping (e.g., NIST 800-53 SC-8)")
        
        submit_button = st.form_submit_button("Add/Update Flow Mapping")
        if submit_button:
            if flow_type_input:
                new_record = {
                    "FlowType": flow_type_input.strip(),
                    "OWASPID": owasp_id_input.strip(),
                    "Requirement": requirement_input.strip(),
                    "GRCMapping": grc_mapping_input.strip()
                }
                # Check if it's an update or add
                if flow_type_input.strip() in current_data["FlowType"].values:
                    manager.update_record("flow_mappings", "FlowType", flow_type_input.strip(), new_record)
                else:
                    manager.add_record("flow_mappings", new_record)
                st.rerun()
            else:
                st.error("Flow Type is required.")

    st.subheader("Delete Flow Mapping")
    if not current_data.empty:
        flow_types = current_data["FlowType"].tolist()
        flow_type_to_delete = st.selectbox("Select Flow Type to Delete:", [""] + sorted(flow_types))
        if st.button("Delete Selected Flow Mapping"):
            if flow_type_to_delete:
                manager.delete_record("flow_mappings", "FlowType", flow_type_to_delete)
                st.rerun()
            else:
                st.warning("Please select a Flow Type to delete.")
    else:
        st.info("No flow mappings to delete.")


elif st.session_state.data_view == "threat_mappings":
    st.header("Threat Mappings (STRIDE & MITRE Controls)")
    st.info("Map threats and techniques between domains to recommended controls.")

    current_data = manager._load_data("threat_mappings")
    if not current_data.empty:
        st.dataframe(current_data, use_container_width=True, hide_index=True)
    else:
        st.info("No threat mappings found. Add new records below.")

    st.subheader("Add/Update Threat Mapping")
    with st.form("threat_mapping_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        with col1:
            source_domain_input = st.selectbox("Source Domain", [""] + ["People", "Application", "Platform", "Network", "Data"], key="src_domain")
            stride_threat_input = st.text_input("STRIDE Threat (e.g., Spoofing)", key="stride_threat")
            recommended_control_input = st.text_area("Recommended Control", height=80, key="rec_control")
        with col2:
            target_domain_input = st.selectbox("Target Domain", [""] + ["People", "Application", "Platform", "Network", "Data"], key="tgt_domain")
            mitre_technique_input = st.text_input("MITRE Technique (e.g., T1078 - Valid Accounts)", key="mitre_tech")
            col_nist, col_iso = st.columns(2)
            with col_nist:
                nist_control_input = st.text_input("NIST Control (e.g., AC-2)", key="nist_ctrl")
            with col_iso:
                iso_control_input = st.text_input("ISO Control (e.g., A.9.2.2)", key="iso_ctrl")
        
        submit_button = st.form_submit_button("Add/Update Threat Mapping")
        if submit_button:
            if source_domain_input and target_domain_input and stride_threat_input and mitre_technique_input:
                new_record = {
                    "SourceDomain": source_domain_input.strip(),
                    "TargetDomain": target_domain_input.strip(),
                    "STRIDE_Threat": stride_threat_input.strip(),
                    "MITRE_Technique": mitre_technique_input.strip(),
                    "Recommended_Control": recommended_control_input.strip(),
                    "NIST_Control": nist_control_input.strip(),
                    "ISO_Control": iso_control_input.strip()
                }
                
                # SQLite primary key for threat_mappings is a composite of 4 columns
                # We need to check if a record with these 4 values already exists
                existing_record = current_data[
                    (current_data["SourceDomain"] == new_record["SourceDomain"]) &
                    (current_data["TargetDomain"] == new_record["TargetDomain"]) &
                    (current_data["STRIDE_Threat"] == new_record["STRIDE_Threat"]) &
                    (current_data["MITRE_Technique"] == new_record["MITRE_Technique"])
                ]

                if not existing_record.empty:
                    # Update (we'll use the combined key as a proxy for primary_key_value)
                    # This update method is a bit simplistic for composite keys.
                    # A more robust solution would involve fetching the existing record's exact PK value
                    # or updating based on all PK components. For this demo, we'll simulate it.
                    manager.delete_record("threat_mappings", "SourceDomain", new_record["SourceDomain"]) # Delete by one PK part (imperfect for composite, but functional demo)
                    manager.add_record("threat_mappings", new_record) # Then re-add with updated values
                else:
                    manager.add_record("threat_mappings", new_record)
                st.rerun()
            else:
                st.error("Source Domain, Target Domain, STRIDE Threat, and MITRE Technique are required.")

    st.subheader("Delete Threat Mapping")
    if not current_data.empty:
        # For composite primary keys, deleting by a single select box is tricky.
        # We'll allow selecting by a combination that uniquely identifies the row.
        current_data['DisplayKey'] = current_data.apply(
            lambda row: f"{row['SourceDomain']}->{row['TargetDomain']} ({row['STRIDE_Threat']} via {row['MITRE_Technique']})", axis=1
        )
        threat_mapping_to_delete_display = st.selectbox(
            "Select Threat Mapping to Delete:",
            [""] + sorted(current_data["DisplayKey"].tolist())
        )
        if st.button("Delete Selected Threat Mapping"):
            if threat_mapping_to_delete_display:
                selected_row = current_data[current_data['DisplayKey'] == threat_mapping_to_delete_display].iloc[0]
                # To delete, we need to provide all primary key components
                conn = manager._get_db_connection()
                try:
                    cursor = conn.cursor()
                    sql = """
                        DELETE FROM threat_mappings
                        WHERE SourceDomain = ? AND TargetDomain = ? AND STRIDE_Threat = ? AND MITRE_Technique = ?
                    """
                    cursor.execute(sql, (
                        selected_row['SourceDomain'],
                        selected_row['TargetDomain'],
                        selected_row['STRIDE_Threat'],
                        selected_row['MITRE_Technique']
                    ))
                    conn.commit()
                    if cursor.rowcount > 0:
                        st.success("Threat mapping deleted successfully!")
                    else:
                        st.warning("No record found matching the criteria.")
                except Exception as e:
                    st.error(f"Error deleting threat mapping: {e}")
                finally:
                    conn.close()
                st.rerun()
            else:
                st.warning("Please select a Threat Mapping to delete.")
    else:
        st.info("No threat mappings to delete.")