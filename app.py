import streamlit as st
import pandas as pd
import sqlite3
import os
from pyvis.network import Network
import streamlit.components.v1 as components
import requests

# --- Configuration Constants ---
DB_FILE = "security_architecture.db" # Database file for security controls
# EXCEL_FILE = "architecture_data.xlsx" # No longer needed for control mappings
# REQUIREMENTS_FILE = "security_requirements_full.xlsx" # No longer needed
# THREAT_MODEL_FILE = "stride_mitre_control_mapping.xlsx" # No longer needed

# Define the domains for the architecture elements
DOMAINS = ["People", "Application", "Platform", "Network", "Data"]

class SecurityArchitectureManager:
    """
    Manages the security architecture data, interactions, and related analyses.
    Reads security control mappings from the SQLite database.
    """

    def __init__(self):
        # Initialize database tables if they don't exist
        self._initialize_database_for_app_data()
        
        # Load security control data from SQLite
        self._load_data_from_db()

        # Initialize session state variables for architecture elements and interactions
        # These are specific to the current user's active architecture design,
        # not the global security control mappings.
        if "architecture" not in st.session_state:
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
        if "interactions" not in st.session_state:
            st.session_state.interactions = []
        
        # You might still want to save/load the *current architecture* to Excel,
        # or switch this to SQLite as well for persistence between sessions.
        # For now, let's keep the existing architecture save/load methods.
        self._load_architecture_from_excel() # Keep this if you want to persist the dynamic architecture

    def _get_db_connection(self):
        """Establishes and returns a SQLite database connection."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn

    def _initialize_database_for_app_data(self):
        """
        Creates tables for general security controls if they don't exist.
        This ensures the database structure is present even if the data manager
        hasn't been run yet.
        """
        conn = self._get_db_connection()
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
        conn.close()

    def _load_data_from_db(self):
        """Loads security control data from SQLite into Pandas DataFrames."""
        conn = self._get_db_connection()
        try:
            self.flow_mappings = pd.read_sql_query("SELECT * FROM flow_mappings", conn)
            self.threat_mappings = pd.read_sql_query("SELECT * FROM threat_mappings", conn)
        except Exception as e:
            st.error(f"Error loading data from database: {e}. Please ensure the Data Manager has been run to populate the database.")
            self.flow_mappings = pd.DataFrame(columns=["FlowType", "OWASPID", "Requirement", "GRCMapping"])
            self.threat_mappings = pd.DataFrame(columns=["SourceDomain", "TargetDomain", "STRIDE_Threat", "MITRE_Technique", "Recommended_Control", "NIST_Control", "ISO_Control"])
        finally:
            conn.close()

    # --- ARCHITECTURE PERSISTENCE (Existing Excel methods for the active design) ---
    # You could convert these to SQLite as well for unified storage
    # but for typical Streamlit session-based apps, this might be fine,
    # or you might want to save to a specific project file.

    def _save_architecture_to_excel(self):
        """Saves current architecture elements and interactions to Excel."""
        elements = [(d, e) for d, el in st.session_state.architecture.items() for e in el]
        df_elements = pd.DataFrame(elements, columns=["Domain", "Element"])
        df_interactions = pd.DataFrame(st.session_state.interactions, columns=["Source", "Target", "FlowType"])
        with pd.ExcelWriter("architecture_data.xlsx") as writer:
            df_elements.to_excel(writer, sheet_name="Elements", index=False)
            df_interactions.to_excel(writer, sheet_name="Interactions", index=False)

    def _load_architecture_from_excel(self):
        """Loads architecture elements and interactions from Excel."""
        try:
            data = pd.read_excel("architecture_data.xlsx", sheet_name=None)
            df_elements = data.get("Elements", pd.DataFrame())
            df_interactions = data.get("Interactions", pd.DataFrame())
            
            # Clear current state before loading
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
            st.session_state.interactions = []

            for domain in DOMAINS:
                domain_elements = df_elements[df_elements["Domain"] == domain]["Element"].dropna().tolist()
                st.session_state.architecture[domain] = domain_elements
            st.session_state.interactions = df_interactions.dropna().values.tolist()
            st.success("Architecture loaded successfully from architecture_data.xlsx!")
        except FileNotFoundError:
            st.info("No existing 'architecture_data.xlsx' found. Starting a new architecture.")
            # Reset session state if file not found
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
            st.session_state.interactions = []
        except Exception as e:
            st.error(f"Failed to load architecture from architecture_data.xlsx: {e}")

    # --- CORE APPLICATION LOGIC (Mostly unchanged, but now using self.flow_mappings/threat_mappings) ---

    def add_element(self, domain, name):
        """Adds a security architecture element."""
        if name and name not in st.session_state.architecture[domain]:
            st.session_state.architecture[domain].append(name)
            st.success(f"Added '{name}' to {domain}.")
        else:
            st.warning(f"Element '{name}' already exists in {domain} or is empty.")

    def add_interaction(self, source, target, flow_type):
        """Adds an interaction between two elements."""
        new_interaction = [source, target, flow_type]
        if new_interaction not in st.session_state.interactions:
            st.session_state.interactions.append(new_interaction)
            st.success(f"Added interaction: {source} --({flow_type})--> {target}")
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
        else:
            st.warning(f"Element '{name}' not found in {domain}.")

    def delete_interaction(self, interaction_list):
        """Deletes a specific interaction (expecting a list [source, target, flow_type])."""
        if interaction_list in st.session_state.interactions:
            st.session_state.interactions.remove(interaction_list)
            st.success(f"Deleted interaction: {interaction_list[0]} --({interaction_list[2]})--> {interaction_list[1]}")
        else:
            st.warning("Interaction not found.")

    def generate_requirements(self):
        """Generates security requirements based on defined interactions and flow types."""
        reqs = {}
        if self.flow_mappings.empty:
            st.warning("Flow mappings data is not loaded or is empty. Cannot generate requirements. Please run the Data Manager app.")
            return {}

        for source, target, flow_type in st.session_state.interactions:
            filtered = self.flow_mappings[self.flow_mappings["FlowType"] == flow_type]
            key = f"{source} -> {target} ({flow_type})"
            reqs[key] = [
                f"{row['Requirement']} (OWASP {row['OWASPID']}) - GRC: {row['GRCMapping']}"
                for _, row in filtered.iterrows()
            ]
        return reqs

    def generate_threat_analysis(self):
        """Generates a STRIDE-based threat analysis with MITRE ATT&CK and controls."""
        threats = {}
        if self.threat_mappings.empty:
            st.warning("Threat mappings data is not loaded or is empty. Cannot generate threat analysis. Please run the Data Manager app.")
            return {}

        element_domain_map = {
            elem: domain for domain, elements in st.session_state.architecture.items() for elem in elements
        }
        for source, target, _ in st.session_state.interactions:
            src_domain = element_domain_map.get(source)
            tgt_domain = element_domain_map.get(target)

            if not src_domain or not tgt_domain:
                # This could happen if elements were added, but their domains aren't defined in the mapping
                st.warning(f"Domain not found for '{source}' or '{target}'. Skipping threat analysis for this interaction.")
                continue

            filtered = self.threat_mappings[
                (self.threat_mappings["SourceDomain"] == src_domain) &
                (self.threat_mappings["TargetDomain"] == tgt_domain)
            ]
            
            key = f"{source} -> {target}"
            threats[key] = [
                f"{row['STRIDE_Threat']} via {row['MITRE_Technique']} ➤ {row['Recommended_Control']}\n • NIST: {row['NIST_Control']}\n • ISO: {row['ISO_Control']}"
                for _, row in filtered.iterrows()
            ]
        return threats

    def render_graph(self):
        """Renders the architecture graph using Pyvis."""
        # Your Pyvis rendering logic here (unchanged from previous version)
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
            net.add_edge(src, tgt, title=flow_type, label=flow_type, color='darkgray', width=2)
        
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
        # IMPORTANT: DO NOT HARDCODE YOUR GITHUB TOKEN
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
    st.sidebar.success("Architecture saved!")
if st.sidebar.button("📂 Load Architecture"):
    manager._load_architecture_from_excel()
    st.sidebar.success("Architecture loaded!")

st.sidebar.markdown("---")
st.sidebar.header("Manage Security Controls")
st.sidebar.markdown("""
To add, edit, or delete the underlying security requirements and threat mappings (like Flow Types, OWASP IDs, STRIDE, MITRE controls):

**Run the separate Data Manager application:**
`streamlit run data_manager_app.py`
""")

# Main content area
st.subheader("📝 Define Architecture Elements")
cols = st.columns(len(DOMAINS))
for i, domain in enumerate(DOMAINS):
    with cols[i]:
        st.markdown(f"**{domain}**")
        with st.container(border=True):
            if st.session_state.architecture[domain]:
                for elem in list(st.session_state.architecture[domain]): # Use list() to allow modification during iteration
                    col_elem, col_btn = st.columns([0.7, 0.3])
                    with col_elem:
                        st.markdown(f"- {elem}")
                    with col_btn:
                        if st.button("Remove", key=f"del-{domain}-{elem}"):
                            manager.delete_element(domain, elem)
                            st.rerun()
            else:
                st.write(f"No {domain} elements defined yet.")

            new_elem = st.text_input(f"Add new {domain} element:", key=f"add_elem_input_{domain}")
            if st.button(f"Add {domain} Element", key=f"add_elem_btn_{domain}"):
                if new_elem:
                    manager.add_element(domain, new_elem.strip())
                    st.rerun()

st.subheader("🔗 Define Interactions Between Elements")
all_elements_flat = [item for sublist in st.session_state.architecture.values() for item in sublist]
if not all_elements_flat:
    st.warning("Please add some elements before defining interactions.")
else:
    col_src, col_tgt, col_flow = st.columns(3)
    with col_src:
        source_elem = st.selectbox("Source Element", [""] + sorted(all_elements_flat), key="source_select")
    with col_tgt:
        target_elem = st.selectbox("Target Element", [""] + sorted(all_elements_flat), key="target_select")
    
    flow_type_options = manager.flow_mappings["FlowType"].tolist() if not manager.flow_mappings.empty else []
    if not flow_type_options:
        st.warning("No Flow Types loaded from database. Please run the Data Manager app.")
    with col_flow:
        flow_type_selected = st.selectbox("Flow Type", [""] + sorted(flow_type_options), key="flowtype_select")

    if st.button("Add Interaction", use_container_width=True):
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

st.subheader("🔒 Security Requirements Analysis")
requirements = manager.generate_requirements()
if isinstance(requirements, pd.DataFrame) and not requirements.empty:
    st.dataframe(requirements, use_container_width=True)
else:
    st.info("No security requirements generated. Ensure interactions are defined and control mappings are loaded.")

st.subheader("🚨 Threat Modelling Recommendations")
threats = manager.generate_threat_analysis()
if isinstance(threats, pd.DataFrame) and not threats.empty:
    st.dataframe(threats, use_container_width=True)
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