import streamlit as st
import pandas as pd
import sqlite3
import os
import re
import logging
import requests
from github import Github, InputGitAuthor
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

# --- Configuration Constants ---
DB_FILE = "security_architecture.db"

# Set file permissions for DB (OWASP: Secure configuration)
if os.path.exists(DB_FILE):
    os.chmod(DB_FILE, 0o600)  # Owner read/write only

# Set up logging for security events (OWASP: Logging and monitoring)
logging.basicConfig(filename='security_app.log', level=logging.WARNING,
                    format='%(asctime)s - %(levelname)s - %(message)s')
def log_security_event(event):
    logging.warning(event)
    # You might also want to display a warning in the UI for critical events
    # st.warning(f"Security Alert: {event}") # Consider if this is appropriate for users

# --- Input Validation Utility (OWASP: Input validation & sanitization) ---
def validate_input(user_input, pattern=r'^[\w\s\-.@:/]+$'):
    """
    Validates user input against a regex pattern.
    Default pattern allows letters, numbers, spaces, hyphens, periods, "@", "/", and ":".
    Returns True if valid, False otherwise. Logs rejected input.
    """
    if not isinstance(user_input, str):
        user_input = str(user_input) # Ensure it's a string for regex matching

    if not re.match(pattern, user_input):
        log_security_event(f"Rejected input due to invalid characters: '{user_input}'")
        return False
    return True

# --- Secure File Upload (OWASP: File upload restrictions) ---
def secure_file_uploader(label, type_list):
    """
    Provides a Streamlit file uploader with security checks:
    - File size limit (2MB)
    - Type restriction (controlled by type_list)
    Logs rejected files.
    """
    uploaded_file = st.file_uploader(label, type=type_list)
    if uploaded_file:
        if uploaded_file.size > 2 * 1024 * 1024:  # 2MB limit
            st.error("File too large. Maximum size is 2MB.")
            log_security_event(f"Rejected file upload: {uploaded_file.name}, size: {uploaded_file.size/1024/1024:.2f}MB")
            return None
        # Further checks like magic bytes for file type verification could be added here
        return uploaded_file
    return None

# --- Secure HTTPS Requests (OWASP: Communications Security) ---
def safe_get(url, **kwargs):
    """
    Performs a GET request, enforcing HTTPS and handling common network errors.
    Includes a timeout to prevent hanging requests.
    Logs blocked non-HTTPS requests and network errors.
    """
    if not url.lower().startswith("https://"):
        st.error("Only HTTPS connections are allowed for security reasons.")
        log_security_event(f"Blocked non-HTTPS request: {url}")
        return None
    try:
        response = requests.get(url, timeout=10, **kwargs) # Added kwargs to allow more flexibility
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.Timeout:
        st.error(f"Network request timed out after 10 seconds for {url}.")
        log_security_event(f"Network timeout for {url}")
        return None
    except requests.RequestException as e:
        st.error(f"Network error occurred for {url}: {e}")
        log_security_event(f"Network error for {url}: {e}")
        return None

# --- Error Handling (OWASP: Do not leak sensitive info) ---
def safe_execute(func, *args, **kwargs):
    """
    Wraps a function call in a try-except block to catch and log exceptions,
    preventing sensitive information leakage to the UI.
    Displays a generic error message to the user.
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        st.error("An internal error occurred. Please contact support.")
        log_security_event(f"Internal error executing {func.__name__}: {e}", exc_info=True) # exc_info to log traceback
        return None

# --- Domains, Levels, Initial Data ---
DOMAINS = ["People", "Application", "Platform", "Network", "Data"]
ASVS_LEVELS = ["L1", "L2", "L3"]
FLOW_TYPES = ["HTTPS", "API-to-API", "User Login", "Database Query", "File Transfer", "Other"]
STRIDE_THREATS = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"]

# Initial ASVS Controls with 'DetailedRecommendation' for direct OWASP content
# THIS SECTION MUST BE DEFINED BEFORE IT IS MODIFIED
INITIAL_ASVS_CONTROLS = [
    # ASVS V1: Architecture, Design and Threat Modeling
    {"ASVS_ID": "V1.1.1", "ASVS_Level": "L1", "Requirement": "Verify the application uses an actively managed, secure software development lifecycle (SDLC).", "GRCMapping": "NIST 800-53 SA-3", "DetailedRecommendation": "Ensure your SDLC integrates security practices at every phase, from requirements to deployment. This includes threat modeling, secure design reviews, static and dynamic analysis, and security testing."},
    {"ASVS_ID": "V1.2.1", "ASVS_Level": "L2", "Requirement": "Verify that authentication is performed by a trusted component.", "GRCMapping": "ISO 27002 A.9.2.1", "DetailedRecommendation": "Authentication should be handled by a dedicated, trusted component (e.g., an identity provider, secure microservice) rather than being scattered within business logic. This centralizes and hardens the process."},
    {"ASVS_ID": "V1.2.2", "ASVS_Level": "L3", "Requirement": "Verify that all components that interact with unauthenticated clients (e.g., login pages) are hardened to prevent enumeration attacks and DoS.", "GRCMapping": "NIST 800-53 SC-5", "DetailedRecommendation": "Implement rate limiting, CAPTCHAs, and generic error messages (e.g., 'Invalid credentials' instead of 'User not found') to prevent attackers from enumerating valid usernames or brute-forcing accounts."},

    # ASVS V2: Authentication Verification Requirements
    {"ASVS_ID": "V2.1.1", "ASVS_Level": "L1", "Requirement": "Verify that all passwords are at least 12 characters long and can contain spaces and special characters.", "GRCMapping": "NIST 800-63B 5.1.1", "DetailedRecommendation": "Prioritize password length and the use of passphrases over complex character requirements. Allow all printable ASCII characters, including spaces, to enable users to create longer, more memorable, and secure passwords."},
    {"ASVS_ID": "V2.2.1", "ASVS_Level": "L2", "Requirement": "Verify that all authenticators use multi-factor authentication (MFA) for high-value accounts.", "GRCMapping": "NIST 800-63B 5.1.2", "DetailedRecommendation": "Mandate strong MFA (e.g., TOTP, FIDO2/WebAuthn, hardware tokens) for all administrative accounts, privileged users, and accounts with access to sensitive data or critical functions. SMS-based MFA is generally discouraged due to SIM-swapping risks."},
    {"ASVS_ID": "V2.3.1", "ASVS_Level": "L1", "Requirement": "Verify that authenticated sessions are regenerated upon any change in authentication context (e.g., privilege escalation).", "GRCMapping": "OWASP Top 10 A07", "DetailedRecommendation": "When a user logs in, changes their password, or escalates privileges, their existing session ID must be immediately invalidated and a new, random one issued. This prevents session fixation attacks."},
    {"ASVS_ID": "V2.4.1", "ASVS_Level": "L2", "Requirement": "Verify that credential storage uses a strong, salted, adaptive hashing function (e.g., Argon2, bcrypt).", "GRCMapping": "NIST 800-63B 5.1.1", "DetailedRecommendation": "Never store passwords in plain text. Use modern, slow, memory-hard hashing algorithms like Argon2 (recommended), bcrypt, or scrypt. Ensure a unique, cryptographically secure random salt is generated for each password and stored alongside the hash."},

    # ASVS V3: Session Management
    {"ASVS_ID": "V3.1.1", "ASVS_Level": "L1", "Requirement": "Verify that session tokens are generated by a cryptographically secure random number generator.", "GRCMapping": "NIST 800-63B 7", "DetailedRecommendation": "Session tokens must be unpredictable. Use `os.urandom` or a similar cryptographically strong PRNG to generate session IDs. Do not use predictable sequences or simple timestamps."},
    {"ASVS_ID": "V3.2.1", "ASVS_Level": "L1", "Requirement": "Verify that session tokens are transmitted over TLS and cookies have the Secure flag.", "GRCMapping": "NIST 800-53 SC-8", "DetailedRecommendation": "All session traffic, including the initial session token issuance, must occur over HTTPS. Ensure the 'Secure' flag is set on session cookies to prevent them from being sent over unencrypted connections."},

    # ASVS V4: Access Control
    {"ASVS_ID": "V4.1.1", "ASVS_Level": "L1", "Requirement": "Verify that access control decisions are enforced by a trusted server-side component.", "GRCMapping": "OWASP Top 10 A01", "DetailedRecommendation": "Never rely solely on client-side controls for authorization. All authorization checks must be performed on the server-side, verifying that the authenticated user is authorized to perform the requested action on the specific resource."},

    # ASVS V5: Validation & Sanitization
    {"ASVS_ID": "V5.1.1", "ASVS_Level": "L1", "Requirement": "Verify that all input from untrusted sources is validated using a positive (whitelist) validation approach.", "GRCMapping": "OWASP Top 10 A03", "DetailedRecommendation": "Implement strict whitelist validation for all user input. Define what is allowed (e.g., 'only digits', 'only specific string values') rather than what is disallowed (blacklisting)."},

    # ASVS V6: Error Handling and Logging
    {"ASVS_ID": "V6.1.1", "ASVS_Level": "L1", "Requirement": "Verify that error messages do not leak sensitive information.", "GRCMapping": "OWASP Top 10 A07", "DetailedRecommendation": "Generic error messages should be presented to the user (e.g., 'An error occurred'). Detailed technical error information (stack traces, database errors) should only be logged securely on the server and never displayed to the end-user."},
]

# Initial FLOW_MAPPINGS must be defined before it's updated
INITIAL_FLOW_MAPPINGS = [
    {"FlowType": "HTTPS", "ASVS_IDs": ["V3.1.1", "V3.2.1", "V6.1.1", "V1.2.2"]},
    {"FlowType": "API-to-API", "ASVS_IDs": ["V1.2.1", "V2.2.1", "V4.1.1", "V5.1.1"]},
    {"FlowType": "User Login", "ASVS_IDs": ["V2.1.1", "V2.2.1", "V2.3.1", "V2.4.1", "V5.1.1", "V6.1.1", "V1.2.2"]},
    {"FlowType": "Database Query", "ASVS_IDs": ["V4.1.1", "V5.1.1", "V6.1.1"]},
    {"FlowType": "File Transfer", "ASVS_IDs": ["V3.2.1", "V5.1.1"]},
    {"FlowType": "Other", "ASVS_IDs": ["V1.1.1", "V6.1.1"]},
]


# ADDED CUSTOM SECURITY REQUIREMENTS from your input
CUSTOM_SECURITY_REQUIREMENTS_DATA = {
    "User -> Application": [
        "Enforce strong user authentication (multi-factor if possible).",
        "Implement role-based access control (RBAC) and least privilege.",
        "Validate and sanitize all user input to prevent injection attacks.",
        "Encrypt sensitive data in transit (TLS) and at rest.",
        "Log all authentication attempts and access events.",
        "Apply session management best practices (timeout, secure cookies).",
        "Deny access by default; explicitly grant minimal required permissions.",
        "Display generic error messages to avoid information leakage.",
    ],
    "Application -> Application": [
        "Require mutual authentication (e.g., OAuth, mTLS, API keys).",
        "Authorize each API call based on the calling application's identity and role.",
        "Enforce least privilege for inter-application communication.",
        "Validate and sanitize all data exchanged between applications.",
        "Encrypt all inter-application traffic using TLS.",
        "Log all API access and errors for audit purposes.",
        "Rate-limit and monitor API usage to detect abuse.",
    ],
    "Application -> Data": [
        "Restrict application data access to only what is necessary (least privilege).",
        "Enforce access control at the data layer (row/column-level security if possible).",
        "Encrypt sensitive data at rest and in transit.",
        "Validate all data inputs and outputs.",
        "Log all data access and modification events.",
        "Use parameterized queries or ORM to prevent SQL injection.",
    ],
    "Database Admin -> Database": [
        "Require strong authentication for database administrators.",
        "Grant admin privileges only as needed and use separate accounts for admin tasks.",
        "Log all administrative actions and access to sensitive data.",
        "Enforce encryption for connections to the database.",
        "Regularly review and audit admin privileges and activity.",
        "Apply the principle of least privilege and segregate duties.",
        "Ensure secure backup and recovery procedures.",
    ],
    "Administrator -> Application": [
        "Require strong, multi-factor authentication for administrators.",
        "Enforce least privilege and role separation for admin functions.",
        "Log all administrative actions in the application.",
        "Restrict admin interface access to trusted networks or VPN.",
        "Audit and review admin activities regularly.",
        "Apply secure session management for admin sessions.",
    ],
    "Administrator -> Platform": [
        "Require multi-factor authentication for platform administrators.",
        "Apply the principle of least privilege and use role-based access.",
        "Log and monitor all platform-level administrative actions.",
        "Restrict platform management interfaces to secure networks.",
        "Regularly audit and review platform admin accounts and privileges.",
        "Enforce secure configuration and patch management.",
    ],
}

# Convert custom requirements into ASVS-like entries
def _generate_custom_asvs_entries(custom_reqs_data):
    custom_asvs = []
    for scenario, req_list in custom_reqs_data.items():
        prefix = scenario.replace(" -> ", "_").replace(" ", "").replace("-", "").upper() # Convert to uppercase
        for i, req in enumerate(req_list):
            asvs_id = f"CUSTOM-{prefix}-{i+1}"
            # Assign a reasonable ASVS level and GRC mapping. L1 for general, L2/L3 for more advanced.
            level = "L1"
            grc_mapping = "Custom"
            
            # You could add logic here to infer higher levels or specific GRC
            if "multi-factor" in req.lower() or "mTLS" in req.lower() or "strong authentication" in req.lower():
                level = "L2"
            elif "row/column-level security" in req.lower() or "segregate duties" in req.lower():
                level = "L3" # More advanced data access control or organizational controls
            
            # Simple GRC mapping suggestions
            if "authentication" in req.lower() or "mfa" in req.lower():
                grc_mapping = "NIST 800-63B IA-2"
            elif "access control" in req.lower() or "least privilege" in req.lower() or "rbac" in req.lower() or "role separation" in req.lower():
                grc_mapping = "NIST 800-53 AC-3/AC-6"
            elif "validate" in req.lower() or "sanitize" in req.lower() or "injection" in req.lower() or "parameterized queries" in req.lower():
                grc_mapping = "OWASP Top 10 A03"
            elif "encrypt" in req.lower() or "tls" in req.lower():
                grc_mapping = "NIST 800-53 SC-8/SC-13"
            elif "log" in req.lower() or "audit" in req.lower() or "monitor" in req.lower():
                grc_mapping = "NIST 800-53 AU-2/AU-6"
            elif "session management" in req.lower():
                grc_mapping = "OWASP Top 10 A07"
            elif "secure configuration" in req.lower() or "patch management" in req.lower():
                grc_mapping = "NIST 800-53 CM-2"
            elif "backup and recovery" in req.lower():
                grc_mapping = "NIST 800-53 CP-9"


            custom_asvs.append({
                "ASVS_ID": asvs_id,
                "ASVS_Level": level,
                "Requirement": req,
                "GRCMapping": grc_mapping,
                "DetailedRecommendation": req # Using the requirement itself as a detailed recommendation
            })
    return custom_asvs

# Generate custom ASVS entries and extend INITIAL_ASVS_CONTROLS
GENERATED_CUSTOM_ASVS = _generate_custom_asvs_entries(CUSTOM_SECURITY_REQUIREMENTS_DATA)
INITIAL_ASVS_CONTROLS.extend(GENERATED_CUSTOM_ASVS)

# Update INITIAL_FLOW_MAPPINGS with new custom ASVS IDs
def _update_flow_mappings_with_custom_asvs(initial_flow_mappings, generated_custom_asvs):
    # Create a mutable dictionary version of initial mappings for easier update
    updated_mappings = {mapping['FlowType']: set(mapping['ASVS_IDs']) for mapping in initial_flow_mappings}

    for custom_entry in generated_custom_asvs:
        asvs_id = custom_entry['ASVS_ID']
        # Extract the scenario part from the ASVS_ID (e.g., 'USER_APPLICATION')
        scenario_key_parts = asvs_id.split('-')[1:]
        scenario_key = "-".join(scenario_key_parts[:-1]).lower() # Reconstruct e.g., 'user-application'

        # Map to relevant FlowTypes based on the original scenario
        if 'user_application' in scenario_key:
            updated_mappings.setdefault('User Login', set()).add(asvs_id)
            updated_mappings.setdefault('HTTPS', set()).add(asvs_id)
        elif 'application_application' in scenario_key:
            updated_mappings.setdefault('API-to-API', set()).add(asvs_id)
            updated_mappings.setdefault('HTTPS', set()).add(asvs_id) # API is often over HTTPS
        elif 'application_data' in scenario_key:
            updated_mappings.setdefault('Database Query', set()).add(asvs_id)
            updated_mappings.setdefault('File Transfer', set()).add(asvs_id) # For data movement scenarios
        elif 'databaseadmin_database' in scenario_key:
            updated_mappings.setdefault('Database Query', set()).add(asvs_id)
            updated_mappings.setdefault('Other', set()).add(asvs_id) # For general admin tasks
        elif 'administrator_application' in scenario_key or 'administrator_platform' in scenario_key:
            updated_mappings.setdefault('User Login', set()).add(asvs_id)
            updated_mappings.setdefault('Other', set()).add(asvs_id) # General admin activities
            updated_mappings.setdefault('HTTPS', set()).add(asvs_id)

    # Convert sets back to lists for the final structure
    final_mappings = [{"FlowType": ft, "ASVS_IDs": list(ids)} for ft, ids in updated_mappings.items()]
    return final_mappings

INITIAL_FLOW_MAPPINGS = _update_flow_mappings_with_custom_asvs(INITIAL_FLOW_MAPPINGS, GENERATED_CUSTOM_ASVS)

# Initial STRIDE_MAPPINGS remain as is, your new requirements are more control-focused.
INITIAL_STRIDE_MAPPINGS = [
    {"SourceDomain": "Application", "TargetDomain": "Data", "STRIDE_Threat": "Information Disclosure", "MITRE_Technique": "T1040", "Recommended_Control": "Encrypt data at rest", "NIST_Control": "SC-13", "ISO_Control": "10.1.1"},
    {"SourceDomain": "Network", "TargetDomain": "Application", "STRIDE_Threat": "Spoofing", "MITRE_Technique": "T1110", "Recommended_Control": "Mutual TLS", "NIST_Control": "SC-8", "ISO_Control": "13.1.1"},
    {"SourceDomain": "People", "TargetDomain": "Application", "STRIDE_Threat": "Spoofing", "MITRE_Technique": "T1078", "Recommended_Control": "Strong Authentication, MFA", "NIST_Control": "IA-2", "ISO_Control": "9.2.1"},
    {"SourceDomain": "Application", "TargetDomain": "Application", "STRIDE_Threat": "Tampering", "MITRE_Technique": "T1484", "Recommended_Control": "Input Validation & Output Encoding", "NIST_Control": "SI-10", "ISO_Control": "14.2.1"},
    {"SourceDomain": "Application", "TargetDomain": "Platform", "STRIDE_Threat": "Elevation of Privilege", "MITRE_Technique": "T1055", "Recommended_Control": "Principle of Least Privilege", "NIST_Control": "AC-6", "ISO_Control": "9.4.1"},
    {"SourceDomain": "Platform", "TargetDomain": "Network", "STRIDE_Threat": "Denial of Service", "MITRE_Technique": "T1499", "Recommended_Control": "Rate Limiting, DDoS Protection", "NIST_Control": "SC-5", "ISO_Control": "12.7.1"},
]


# --- SecurityArchitectureManager Class ---
class SecurityArchitectureManager:
    def __init__(self):
        self._initialize_database_and_populate_if_empty()
        self._load_data_from_db()
        if "architecture" not in st.session_state:
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
        if "interactions" not in st.session_state:
            st.session_state.interactions = []

    def _get_db_connection(self):
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_database_and_populate_if_empty(self):
        conn = self._get_db_connection()
        cursor = conn.cursor()

        # Create flow_mappings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flow_mappings (
                FlowType TEXT PRIMARY KEY,
                ASVS_IDs TEXT
            )
        """)
        # Create asvs_controls table (ADDED DetailedRecommendation column)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS asvs_controls (
                ASVS_ID TEXT PRIMARY KEY,
                ASVS_Level TEXT NOT NULL,
                Requirement TEXT NOT NULL,
                GRCMapping TEXT,
                DetailedRecommendation TEXT
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

        # Populate asvs_controls if empty (ensure DataFrame includes new column)
        cursor.execute("SELECT COUNT(*) FROM asvs_controls")
        if cursor.fetchone()[0] == 0:
            asvs_df = pd.DataFrame(INITIAL_ASVS_CONTROLS)
            if 'DetailedRecommendation' not in asvs_df.columns:
                asvs_df['DetailedRecommendation'] = ''
            asvs_df.to_sql('asvs_controls', conn, if_exists='append', index=False)
            st.toast("Initial ASVS Controls populated in DB.", icon="✅")

        # Populate flow_mappings if empty
        cursor.execute("SELECT COUNT(*) FROM flow_mappings")
        if cursor.fetchone()[0] == 0:
            flow_df = pd.DataFrame(INITIAL_FLOW_MAPPINGS)
            # Ensure ASVS_IDs are comma-separated strings for DB storage
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
            # Ensure ASVS_IDs are lists when loaded from DB
            self.flow_mappings['ASVS_IDs'] = self.flow_mappings['ASVS_IDs'].apply(lambda x: x.split(',') if x else [])

            self.asvs_controls = pd.read_sql_query("SELECT * FROM asvs_controls", conn)
            self.threat_mappings = pd.read_sql_query("SELECT * FROM threat_mappings", conn)
        except Exception as e:
            st.error(f"Error loading data from database: {e}. Ensure the database file '{DB_FILE}' is accessible.")
            log_security_event(f"Database loading error: {e}", exc_info=True)
            self.flow_mappings = pd.DataFrame(columns=["FlowType", "ASVS_IDs"])
            self.asvs_controls = pd.DataFrame(columns=["ASVS_ID", "ASVS_Level", "Requirement", "GRCMapping", "DetailedRecommendation"])
            self.threat_mappings = pd.DataFrame(columns=["SourceDomain", "TargetDomain", "STRIDE_Threat", "MITRE_Technique", "Recommended_Control", "NIST_Control", "ISO_Control"])
        finally:
            conn.close()

    def add_element(self, domain, name):
        """Adds a new element to the architecture."""
        if not validate_input(name):
            st.error(f"Invalid characters in element name: '{name}'. Please use only letters, numbers, spaces, hyphens, periods, '/', '@', or ':'.")
            return
        if name not in st.session_state.architecture[domain]:
            st.session_state.architecture[domain].append(name)
            st.toast(f"'{name}' added to {domain} domain.", icon="➕")
        else:
            st.warning(f"'{name}' already exists in {domain} domain.")

    def delete_element(self, domain, name):
        """Deletes an element from the architecture."""
        if name in st.session_state.architecture[domain]:
            st.session_state.architecture[domain].remove(name)
            # Also remove any interactions involving this element
            st.session_state.interactions = [
                i for i in st.session_state.interactions
                if i['source'] != name and i['target'] != name
            ]
            st.toast(f"'{name}' deleted from {domain} domain and related interactions removed.", icon="🗑️")
        else:
            st.warning(f"'{name}' not found in {domain} domain.")

    def add_interaction(self, source, target, flow_type):
        """Adds a new interaction between elements."""
        # Validate inputs for source, target, flow_type if they are user-entered
        if not (validate_input(source) and validate_input(target) and validate_input(flow_type)):
            st.error("Invalid characters detected in source, target, or flow type. Please use allowed characters.")
            return

        interaction = {"source": source, "target": target, "flow_type": flow_type}
        if interaction not in st.session_state.interactions:
            st.session_state.interactions.append(interaction)
            st.toast(f"Interaction from {source} to {target} ({flow_type}) added.", icon="➡️")
        else:
            st.warning("This interaction already exists.")

    def delete_interaction(self, index):
        """Deltes an interaction by its index."""
        if 0 <= index < len(st.session_state.interactions):
            del st.session_state.interactions[index]
            st.toast("Interaction deleted.", icon="🗑️")

    def generate_requirements(self, asvs_level_filter: str = None):
        """
        Generates a DataFrame of security requirements based on defined interactions,
        filtered by ASVS level.
        Includes the 'Detailed Recommendation' from ASVS controls.
        """
        requirements = []
        for i, interaction in enumerate(st.session_state.interactions):
            source = interaction['source']
            target = interaction['target']
            flow_type = interaction['flow_type']

            # Find ASVS IDs for the flow type
            relevant_flow_asvs_ids = self.flow_mappings[self.flow_mappings['FlowType'] == flow_type]['ASVS_IDs']
            if relevant_flow_asvs_ids.empty:
                continue

            asvs_ids_for_flow = relevant_flow_asvs_ids.iloc[0]

            # Filter ASVS controls by relevant IDs and ASVS Level
            relevant_asvs_controls = self.asvs_controls[
                self.asvs_controls['ASVS_ID'].isin(asvs_ids_for_flow)
            ].copy() # Use .copy() to avoid SettingWithCopyWarning

            if asvs_level_filter and asvs_level_filter != "None":
                # Filter logic: L3 includes L1, L2. L2 includes L1.
                if asvs_level_filter == "L1":
                    relevant_asvs_controls = relevant_asvs_controls[
                        relevant_asvs_controls['ASVS_Level'] == 'L1'
                    ]
                elif asvs_level_filter == "L2":
                    relevant_asvs_controls = relevant_asvs_controls[
                        (relevant_asvs_controls['ASVS_Level'] == 'L1') |
                        (relevant_asvs_controls['ASVS_Level'] == 'L2')
                    ]
                elif asvs_level_filter == "L3":
                    relevant_asvs_controls = relevant_asvs_controls # All levels

            # Prepare for display, including the new 'Detailed Recommendation'
            for _, row in relevant_asvs_controls.iterrows():
                requirements.append({
                    "Interaction No.": i + 1,
                    "Interaction": f"{source} --({flow_type})--> {target}",
                    "Flow Type": flow_type,
                    "ASVS ID": row["ASVS_ID"],
                    "ASVS Level": row["ASVS_Level"],
                    "Requirement": row["Requirement"],
                    "Detailed Recommendation": row.get("DetailedRecommendation", ""), # Safely get the new column
                    "GRC Mapping": row["GRCMapping"],
                })

        if requirements:
            df = pd.DataFrame(requirements)
            return df.drop_duplicates(subset=["Interaction No.", "ASVS ID"], keep="first").sort_values(by=["Interaction No.", "ASVS ID"]).reindex(columns=[
                "Interaction No.", "Interaction", "Flow Type", "ASVS ID", "ASVS Level", "Requirement", "Detailed Recommendation", "GRC Mapping"
            ])
        return pd.DataFrame(columns=["Interaction No.", "Interaction", "Flow Type", "ASVS ID", "ASVS Level", "Requirement", "Detailed Recommendation", "GRC Mapping"])

    def generate_threat_model(self):
        """Generates a DataFrame of potential threats based on interactions using STRIDE/MITRE."""
        threats = []
        for i, interaction in enumerate(st.session_state.interactions):
            source_domain = next((d for d, elements in st.session_state.architecture.items() if interaction['source'] in elements), None)
            target_domain = next((d for d, elements in st.session_state.architecture.items() if interaction['target'] in elements), None)

            if source_domain and target_domain:
                # Find matching threat mappings
                matching_threats = self.threat_mappings[
                    (self.threat_mappings['SourceDomain'] == source_domain) &
                    (self.threat_mappings['TargetDomain'] == target_domain)
                ]

                for _, threat_row in matching_threats.iterrows():
                    threats.append({
                        "Interaction No.": i + 1,
                        "Interaction": f"{interaction['source']} --({interaction['flow_type']})--> {interaction['target']}",
                        "Source Domain": source_domain,
                        "Target Domain": target_domain,
                        "STRIDE Threat": threat_row["STRIDE_Threat"],
                        "MITRE Technique": threat_row["MITRE_Technique"],
                        "Recommended Control": threat_row["Recommended_Control"],
                        "NIST Control": threat_row["NIST_Control"],
                        "ISO Control": threat_row["ISO_Control"],
                    })
        if threats:
            df = pd.DataFrame(threats)
            return df.drop_duplicates().sort_values(by=["Interaction No.", "STRIDE Threat"])
        return pd.DataFrame(columns=[
            "Interaction No.", "Interaction", "Source Domain", "Target Domain",
            "STRIDE Threat", "MITRE Technique", "Recommended Control", "NIST Control", "ISO Control"
        ])

    def create_github_issue(self, title, body):
        """
        Creates a GitHub issue using PyGithub.
        Requires GITHUB_TOKEN and GITHUB_REPO environment variables.
        """
        github_token = os.getenv("GITHUB_TOKEN")
        repo_name = os.getenv("GITHUB_REPO")

        if not github_token:
            st.error("GitHub personal access token (GITHUB_TOKEN) not set in environment variables.")
            log_security_event("GitHub issue creation failed: GITHUB_TOKEN not set.")
            return

        if not repo_name:
            st.error("GitHub repository name (GITHUB_REPO) not set in environment variables (e.g., 'owner/repo_name').")
            log_security_event("GitHub issue creation failed: GITHUB_REPO not set.")
            return

        # Use safe_execute for the actual GitHub API call
        def _create_issue_api():
            g = Github(github_token)
            repo = g.get_repo(repo_name)
            issue = repo.create_issue(title=title, body=body)
            st.success(f"GitHub issue created: [{issue.title}]({issue.html_url})")
            log_security_event(f"GitHub issue created: {issue.html_url}")

        safe_execute(_create_issue_api) # Call via safe_execute


# --- Pyvis Diagramming Function ---
def render_pyvis_graph(architecture_elements, interactions):
    """
    Generates an interactive network graph using pyvis and embeds it in Streamlit.
    """
    # Create a NetworkX graph first to easily manage nodes and edges
    G = nx.DiGraph()

    # Define colors for domains
    color_map = {
        "People": "#FFDDC1",  # Light Peach
        "Application": "#B3E0FF", # Light Blue
        "Platform": "#D4EDDA", # Light Green
        "Network": "#FFF0B3", # Light Yellow
        "Data": "#F8C4B4"    # Light Salmon
    }

    # Add nodes to the NetworkX graph with domain as an attribute
    for domain, elements in architecture_elements.items():
        for element_name in elements:
            G.add_node(element_name, domain=domain, label=element_name,
                       color=color_map.get(domain, '#CCCCCC'), # Default grey
                       title=f"{element_name} ({domain} Domain)")

    # Add edges to the NetworkX graph
    for interaction in interactions:
        source = interaction['source']
        target = interaction['target']
        flow_type = interaction['flow_type']
        if source in G.nodes and target in G.nodes: # Only add if both nodes exist
            G.add_edge(source, target, title=flow_type, label=flow_type)
        else:
            log_security_event(f"Skipping interaction due to missing element: {source} -> {target}")


    # Create a Pyvis network
    net = Network(height="600px", width="100%", directed=True, notebook=True,
                  cdn_resources='remote') # Use remote CDN for stability in deployment

    # Add nodes and edges from NetworkX graph to Pyvis network
    net.from_nx(G)

    # Add physics, layout, etc. for better visualization (optional)
    net.toggle_physics(True)
    net.show_buttons(filter_=['physics', 'nodes', 'edges', 'layout']) # Show controls to user

    # Save the network to an HTML file
    try:
        html_file_path = "pyvis_graph.html"
        net.save_graph(html_file_path)

        # Read the HTML and embed it in Streamlit
        with open(html_file_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        components.html(html_content, height=600, scrolling=True)

        # Clean up the temporary HTML file
        if os.path.exists(html_file_path):
            os.remove(html_file_path)

    except Exception as e:
        st.error(f"Error rendering interactive graph: {e}. Check browser console for details.")
        log_security_event(f"Pyvis rendering error: {e}", exc_info=True)


# --- Main Streamlit App Logic ---
def main():
    st.set_page_config(layout="wide", page_title="OWASP-Hardened Security Architecture Designer")

    # Initialize manager
    manager = SecurityArchitectureManager()

    st.sidebar.title("App Navigation")
    page = st.sidebar.radio("Go to", ["Architecture Definition", "Security Requirements", "Threat Modeling", "OWASP Cheat Sheet Explorer"])

    if page == "Architecture Definition":
        st.title("🛡️ Security Architecture Designer")
        st.markdown("""
            Define your system's architecture by adding elements to different domains
            (People, Application, Platform, Network, Data) and then define interactions between them.
            This forms the basis for generating security requirements and threat models.
        """)

        st.header("1. Define Architecture Elements")
        new_element_name = st.text_input("New Element Name (e.g., 'Web App', 'Database', 'User', 'Firewall')", key="new_element_name_input")
        selected_domain = st.selectbox("Select Domain for New Element", options=DOMAINS, key="new_element_domain_select")

        col1, col2 = st.columns(2)
        with col1:
            if st.button(f"Add '{new_element_name}' to {selected_domain} Domain", disabled=not new_element_name):
                manager.add_element(selected_domain, new_element_name)
                # No rerun needed here, pyvis will update on interaction add
        with col2:
            # Dropdown for deleting elements
            all_elements = [element for domain_list in st.session_state.architecture.values() for element in domain_list]
            if all_elements:
                element_to_delete = st.selectbox("Select element to delete", options=[""] + all_elements, key="element_to_delete_select")
                if element_to_delete and st.button(f"Delete '{element_to_delete}'"):
                    for domain, elements in st.session_state.architecture.items():
                        if element_to_delete in elements:
                            manager.delete_element(domain, element_to_delete)
                            # No rerun needed here, pyvis will update on interaction add
                            break
            else:
                st.info("No elements to delete yet.")

        st.subheader("Current Architecture Elements:")
        for domain in DOMAINS:
            if st.session_state.architecture[domain]:
                st.markdown(f"**{domain} Domain:**")
                st.write(", ".join(st.session_state.architecture[domain]))
            else:
                st.markdown(f"**{domain} Domain:** *None defined*")

        st.header("2. Define Interactions Between Elements")
        all_defined_elements = [item for sublist in st.session_state.architecture.values() for item in sublist]

        if len(all_defined_elements) >= 2:
            source_element = st.selectbox("Source Element", options=[""] + all_defined_elements, key="source_element_select")
            target_element = st.selectbox("Target Element", options=[""] + all_defined_elements, key="target_element_select")
            flow_type = st.selectbox("Flow Type", options=[""] + FLOW_TYPES, key="flow_type_select")

            if source_element and target_element and flow_type and source_element != target_element:
                if st.button("Add Interaction"):
                    manager.add_interaction(source_element, target_element, flow_type)
                    # No rerun needed here, pyvis will update on interaction add
            else:
                st.info("Select valid source, target, and flow type to add an interaction.")
        else:
            st.info("Define at least two elements before adding interactions.")

        st.subheader("Current Interactions:")
        if st.session_state.interactions:
            interactions_df = pd.DataFrame(st.session_state.interactions)
            st.dataframe(interactions_df, use_container_width=True, hide_index=True)

            col_int1, col_int2 = st.columns(2)
            with col_int1:
                if st.button("Delete All Interactions", key="delete_all_interactions"):
                    st.session_state.interactions = []
                    st.toast("All interactions deleted.", icon="🗑️")
            with col_int2:
                # Option to delete individual interactions
                interaction_options = [f"{i+1}. {interaction['source']} --({interaction['flow_type']})--> {interaction['target']}"
                                    for i, interaction in enumerate(st.session_state.interactions)]
                if interaction_options:
                    selected_interaction_index = st.selectbox("Select interaction to delete", options=[""] + interaction_options, key="delete_interaction_select")
                    if selected_interaction_index:
                        index_to_delete = int(selected_interaction_index.split(".")[0]) - 1
                        if st.button(f"Delete Selected Interaction ({selected_interaction_index})", key="delete_selected_interaction_button"):
                            manager.delete_interaction(index_to_delete)
                else:
                    st.info("No interactions to delete.")
        else:
            st.info("No interactions defined yet.")

        # --- Architecture Diagram (using pyvis) ---
        st.header("3. Visualized Architecture Diagram (Interactive)")
        if st.session_state.architecture and any(st.session_state.architecture.values()):
            render_pyvis_graph(st.session_state.architecture, st.session_state.interactions)
        else:
            st.info("Add elements and interactions to visualize your architecture.")


    elif page == "Security Requirements":
        st.title("📋 Generated Security Requirements")
        st.markdown("""
            Based on your defined interactions and their flow types,
            this section generates relevant ASVS (Application Security Verification Standard) requirements.
            You can filter these requirements by ASVS Level.
            **This now includes custom general security recommendations tailored to common access scenarios.**
        """)

        st.subheader("Filter ASVS Requirements")
        asvs_level_selection = st.selectbox(
            "Select ASVS Level (Higher levels include lower level requirements):",
            options=["None"] + ASVS_LEVELS,
            index=0
        )
        requirements_df = manager.generate_requirements(asvs_level_selection)

        if not requirements_df.empty:
            st.dataframe(requirements_df, use_container_width=True, hide_index=True)
            csv_requirements = requirements_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Requirements as CSV",
                data=csv_requirements,
                file_name="security_requirements.csv",
                mime="text/csv",
            )

            st.markdown("---")
            st.subheader("🚀 Create GitHub Issues from Requirements")
            st.write("Automatically create GitHub issues for selected security requirements. Ensure `GITHUB_TOKEN` and `GITHUB_REPO` are set as environment variables.")

            # Multi-select for requirements
            req_options = [f"{row['ASVS ID']} - {row['Requirement']}" for index, row in requirements_df.iterrows()]
            selected_reqs_for_issue = st.multiselect(
                "Select Requirements to Create GitHub Issues For:",
                options=req_options,
                key="selected_reqs_for_github"
            )

            if st.button("Create GitHub Issues", key="create_github_issues_button"):
                if selected_reqs_for_issue:
                    for req_text in selected_reqs_for_issue:
                        matching_req = requirements_df[
                            requirements_df.apply(lambda row: f"{row['ASVS ID']} - {row['Requirement']}" == req_text, axis=1)
                        ].iloc[0]

                        issue_title = f"Security Requirement: {matching_req['ASVS ID']} - {matching_req['Requirement']}"
                        issue_body = (
                            f"**Generated from Security Architecture Designer**\n\n"
                            f"**Interaction:** {matching_req['Interaction']}\n"
                            f"**Flow Type:** {matching_req['Flow Type']}\n"
                            f"**ASVS ID:** {matching_req['ASVS ID']}\n"
                            f"**ASVS Level:** {matching_req['ASVS Level']}\n"
                            f"**Requirement:** {matching_req['Requirement']}\n"
                            f"**Detailed Recommendation:** {matching_req.get('Detailed Recommendation', 'N/A')}\n\n"
                            f"**GRC Mapping:** {matching_req['GRC Mapping']}\n\n"
                            f"---"
                            f"\n*This issue was automatically generated. Please update with more details as needed.*"
                        )
                        manager.create_github_issue(issue_title, issue_body)
                else:
                    st.warning("Please select at least one requirement to create a GitHub issue.")
        else:
            st.info("No security requirements generated yet. Define elements and interactions in the 'Architecture Definition' page.")

    elif page == "Threat Modeling":
        st.title("😈 Automated Threat Modeling (STRIDE/MITRE)")
        st.markdown("""
            This section performs a basic threat model based on your defined interactions,
            mapping them to potential STRIDE threats and MITRE ATT&CK techniques,
            along with recommended controls.
        """)
        threat_model_df = manager.generate_threat_model()

        if not threat_model_df.empty:
            st.dataframe(threat_model_df, use_container_width=True, hide_index=True)
            csv_threats = threat_model_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Threat Model as CSV",
                data=csv_threats,
                file_name="threat_model.csv",
                mime="text/csv",
            )
        else:
            st.info("No threats identified yet. Define elements and interactions in the 'Architecture Definition' page.")

    elif page == "OWASP Cheat Sheet Explorer":
        st.title("📖 OWASP Cheat Sheet Explorer")
        st.markdown("""
            This section allows you to explore the pre-integrated OWASP ASVS controls and their detailed recommendations.
            This content is directly incorporated into the app's database, including custom general security recommendations.
        """)

        # Display all ASVS controls, allowing search/filter
        st.subheader("Search ASVS Controls and Recommendations")
        search_query = st.text_input("Search by ASVS ID, Requirement, or Recommendation content:", "")

        filtered_controls = manager.asvs_controls.copy()
        if search_query:
            filtered_controls = filtered_controls[
                filtered_controls['ASVS_ID'].str.contains(search_query, case=False, na=False) |
                filtered_controls['Requirement'].str.contains(search_query, case=False, na=False) |
                filtered_controls['DetailedRecommendation'].str.contains(search_query, case=False, na=False)
            ]

        if not filtered_controls.empty:
            # Display using expanders for detailed recommendations
            for idx, row in filtered_controls.iterrows():
                with st.expander(f"**{row['ASVS_ID']} ({row['ASVS_Level']}):** {row['Requirement']}"):
                    st.write(f"**GRC Mapping:** {row['GRCMapping']}")
                    if row['DetailedRecommendation']:
                        st.markdown(f"**OWASP Recommendation:**\n{row['DetailedRecommendation']}")
                    else:
                        st.info("No detailed recommendation available for this control in the current data.")
        else:
            st.info("No ASVS controls found matching your search query or no controls defined.")

        st.markdown("---")
        st.subheader("OWASP Hardening Feature Examples (from your provided code):")

        st.markdown("### Secure Input Validation Demo")
        input_demo_name = st.text_input("Enter a test string for validation (try special chars like `!@#`)", key="input_demo_name")
        if st.button("Validate Input"):
            if validate_input(input_demo_name):
                st.success(f"Input '{input_demo_name}' is valid!")
            else:
                st.error(f"Input '{input_demo_name}' is invalid according to the defined pattern.")
                st.info("Check logs for security event warning.")


        st.markdown("### Secure File Upload Demo")
        uploaded_file_demo = secure_file_uploader("Upload a dummy file (max 2MB, CSV/XLSX only)", ['csv', 'xlsx'], key="file_upload_demo")
        if uploaded_file_demo:
            st.success(f"File '{uploaded_file_demo.name}' uploaded securely.")
        else:
            st.info("No file uploaded or file rejected due to security checks.")

        st.markdown("### Secure HTTPS Request Demo")
        url_demo = st.text_input("Enter an HTTPS URL to fetch (e.g., `https://www.google.com`)", key="url_demo")
        if st.button("Fetch URL"):
            if url_demo:
                response = safe_get(url_demo)
                if response:
                    st.write(f"Successfully fetched content from {url_demo}. Content length: {len(response.content)} bytes.")
                else:
                    st.warning("Failed to fetch URL securely. Check errors above.")
            else:
                st.warning("Please enter a URL.")

# Run the main app
if __name__ == "__main__":
    main()
