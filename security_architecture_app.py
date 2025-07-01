import streamlit as st
import pandas as pd
from io import BytesIO
from xhtml2pdf import pisa # Keep if needed for PDF generation elsewhere, not directly used in the provided logic
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import requests
import os # For environment variables

# --- Configuration Constants ---
DOMAINS = ["People", "Application", "Platform", "Network", "Data"]
EXCEL_FILE = "architecture_data.xlsx"
REQUIREMENTS_FILE = "security_requirements_full.xlsx"
THREAT_MODEL_FILE = "stride_mitre_control_mapping.xlsx"

# --- SecurityArchitectureManager Class (Encapsulating Logic) ---
class SecurityArchitectureManager:
    """
    Manages the security architecture data, interactions, and related analyses.
    Implements principles of encapsulation and acts as a facade for data persistence
    and external integrations.
    """

    def __init__(self):
        # Initialize data structures if they don't exist in session_state
        if "architecture" not in st.session_state:
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
        if "interactions" not in st.session_state:
            st.session_state.interactions = []
        if "flow_mappings" not in st.session_state:
            self._load_flow_mappings()
        if "threat_mappings" not in st.session_state:
            self._load_threat_mappings()

    def _authorize_action(self, action_type: str, details: dict = None) -> bool:
        """
        Placeholder for authorization logic.
        In a real application, this would check user roles/permissions.
        Returns True if authorized, False otherwise.
        """
        # Example: Log the attempted action for auditing
        st.info(f"Attempting action: {action_type} with details: {details}")
        # For this demo, always authorize. In production, integrate with an AuthN/AuthZ system.
        # e.g., if not current_user.can_perform(action_type): return False
        return True

    def _load_flow_mappings(self):
        """Loads security flow mappings from Excel."""
        try:
            st.session_state.flow_mappings = pd.read_excel(REQUIREMENTS_FILE)
            if st.session_state.flow_mappings.empty:
                st.session_state.flow_mappings = pd.DataFrame(columns=["FlowType", "OWASPID", "Requirement", "GRCMapping"])
        except FileNotFoundError:
            st.error(f"Error: {REQUIREMENTS_FILE} not found. Please ensure it's in the same directory.")
            st.session_state.flow_mappings = pd.DataFrame(columns=["FlowType", "OWASPID", "Requirement", "GRCMapping"])
        except Exception as e:
            st.error(f"Failed to load flow mappings from {REQUIREMENTS_FILE}: {e}")
            st.session_state.flow_mappings = pd.DataFrame(columns=["FlowType", "OWASPID", "Requirement", "GRCMapping"])

    def _load_threat_mappings(self):
        """Loads threat model mappings from Excel."""
        try:
            st.session_state.threat_mappings = pd.read_excel(THREAT_MODEL_FILE)
            if st.session_state.threat_mappings.empty:
                st.session_state.threat_mappings = pd.DataFrame(columns=["SourceDomain", "TargetDomain", "STRIDE_Threat", "MITRE_Technique", "Recommended_Control", "NIST_Control", "ISO_Control"])
        except FileNotFoundError:
            st.error(f"Error: {THREAT_MODEL_FILE} not found. Please ensure it's in the same directory.")
            st.session_state.threat_mappings = pd.DataFrame(columns=["SourceDomain", "TargetDomain", "STRIDE_Threat", "MITRE_Technique", "Recommended_Control", "NIST_Control", "ISO_Control"])
        except Exception as e:
            st.error(f"Failed to load threat mappings from {THREAT_MODEL_FILE}: {e}")
            st.session_state.threat_mappings = pd.DataFrame(columns=["SourceDomain", "TargetDomain", "STRIDE_Threat", "MITRE_Technique", "Recommended_Control", "NIST_Control", "ISO_Control"])

    def save_architecture(self):
        """Saves current architecture elements and interactions to Excel."""
        if not self._authorize_action("save_architecture"):
            st.warning("Authorization failed to save architecture.")
            return False
        
        try:
            elements = [(d, e) for d, el in st.session_state.architecture.items() for e in el]
            df_elements = pd.DataFrame(elements, columns=["Domain", "Element"])
            df_interactions = pd.DataFrame(st.session_state.interactions, columns=["Source", "Target", "FlowType"])
            
            with pd.ExcelWriter(EXCEL_FILE) as writer:
                df_elements.to_excel(writer, sheet_name="Elements", index=False)
                df_interactions.to_excel(writer, sheet_name="Interactions", index=False)
            st.success("Architecture saved successfully!")
            return True
        except Exception as e:
            st.error(f"Failed to save architecture: {e}")
            return False

    def load_architecture(self):
        """Loads architecture elements and interactions from Excel."""
        if not self._authorize_action("load_architecture"):
            st.warning("Authorization failed to load architecture.")
            return False
        
        try:
            data = pd.read_excel(EXCEL_FILE, sheet_name=None)
            df_elements = data.get("Elements", pd.DataFrame())
            df_interactions = data.get("Interactions", pd.DataFrame())
            
            # Clear current state before loading
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
            st.session_state.interactions = []

            for domain in DOMAINS:
                domain_elements = df_elements[df_elements["Domain"] == domain]["Element"].dropna().tolist()
                st.session_state.architecture[domain] = domain_elements
            st.session_state.interactions = df_interactions.dropna().values.tolist()
            st.success("Architecture loaded successfully!")
            return True
        except FileNotFoundError:
            st.warning(f"No existing architecture file '{EXCEL_FILE}' found. Starting fresh.")
            # Reset session state if file not found
            st.session_state.architecture = {domain: [] for domain in DOMAINS}
            st.session_state.interactions = []
            return False
        except Exception as e:
            st.error(f"Failed to load architecture: {e}")
            return False

    def add_element(self, domain: str, element_name: str) -> bool:
        """Adds a new element to a specified domain."""
        if not self._authorize_action("add_element", {"domain": domain, "element": element_name}):
            st.warning(f"Authorization failed to add element '{element_name}'.")
            return False
        
        if not element_name or not domain:
            st.error("Element name and domain cannot be empty.")
            return False
        if element_name in sum(st.session_state.architecture.values(), []):
            st.warning(f"Element '{element_name}' already exists.")
            return False

        if domain in st.session_state.architecture:
            st.session_state.architecture[domain].append(element_name)
            st.success(f"Added '{element_name}' to {domain} domain.")
            return True
        else:
            st.error(f"Invalid domain: {domain}")
            return False

    def remove_element(self, domain: str, element_name: str) -> bool:
        """Removes an element from a specified domain and cleans up associated interactions."""
        if not self._authorize_action("remove_element", {"domain": domain, "element": element_name}):
            st.warning(f"Authorization failed to remove element '{element_name}'.")
            return False
        
        if domain in st.session_state.architecture and element_name in st.session_state.architecture[domain]:
            st.session_state.architecture[domain].remove(element_name)
            # Remove any interactions involving this element
            st.session_state.interactions = [
                interaction for interaction in st.session_state.interactions
                if interaction[0] != element_name and interaction[1] != element_name
            ]
            st.success(f"Removed '{element_name}' from {domain} and its associated interactions.")
            return True
        else:
            st.warning(f"Element '{element_name}' not found in {domain}.")
            return False

    def add_interaction(self, source: str, target: str, flow_type: str) -> bool:
        """Adds a new interaction between two elements."""
        if not self._authorize_action("add_interaction", {"source": source, "target": target, "flow_type": flow_type}):
            st.warning("Authorization failed to add interaction.")
            return False
        
        if not source or not target or not flow_type:
            st.error("Source, target, and flow type cannot be empty.")
            return False
        
        # Check if source and target elements actually exist
        all_elements = sum(st.session_state.architecture.values(), [])
        if source not in all_elements:
            st.error(f"Source element '{source}' does not exist.")
            return False
        if target not in all_elements:
            st.error(f"Target element '{target}' does not exist.")
            return False
        
        new_interaction = [source, target, flow_type]
        if new_interaction in st.session_state.interactions:
            st.warning("This interaction already exists.")
            return False
            
        st.session_state.interactions.append(new_interaction)
        st.success(f"Added interaction: {source} -> {target} ({flow_type}).")
        return True

    def remove_interaction(self, interaction_to_remove: list) -> bool:
        """Removes a specific interaction."""
        if not self._authorize_action("remove_interaction", {"interaction": interaction_to_remove}):
            st.warning("Authorization failed to remove interaction.")
            return False
        
        if interaction_to_remove in st.session_state.interactions:
            st.session_state.interactions.remove(interaction_to_remove)
            st.success(f"Removed interaction: {interaction_to_remove[0]} -> {interaction_to_remove[1]} ({interaction_to_remove[2]}).")
            return True
        else:
            st.warning(f"Interaction {interaction_to_remove} not found.")
            return False

    def generate_requirements(self) -> dict:
        """Generates security requirements based on defined interactions."""
        reqs = {}
        if st.session_state.flow_mappings.empty:
            st.warning("Flow mappings data is not loaded or is empty. Cannot generate requirements.")
            return {}

        for source, target, flow_type in st.session_state.interactions:
            # Basic validation for flow_type
            if flow_type not in st.session_state.flow_mappings["FlowType"].unique():
                st.warning(f"Unknown FlowType '{flow_type}' in interaction {source} -> {target}. Skipping requirements for this interaction.")
                continue

            filtered = st.session_state.flow_mappings[st.session_state.flow_mappings["FlowType"] == flow_type]
            key = f"{source} -> {target} ({flow_type})"
            reqs[key] = [
                f"{row['Requirement']} (OWASP {row['OWASPID']}) - GRC: {row['GRCMapping']}"
                for _, row in filtered.iterrows()
            ]
        return reqs

    def generate_threat_analysis(self) -> dict:
        """Generates threat analysis recommendations."""
        threats = {}
        if st.session_state.threat_mappings.empty:
            st.warning("Threat mappings data is not loaded or is empty. Cannot generate threat analysis.")
            return {}

        element_domain_map = {
            elem: domain for domain, elements in st.session_state.architecture.items() for elem in elements
        }
        for source, target, _ in st.session_state.interactions:
            src_domain = element_domain_map.get(source)
            tgt_domain = element_domain_map.get(target)

            if not src_domain:
                st.warning(f"Source element '{source}' has no mapped domain. Skipping threat analysis for this interaction.")
                continue
            if not tgt_domain:
                st.warning(f"Target element '{target}' has no mapped domain. Skipping threat analysis for this interaction.")
                continue

            # Filtering based on source and target domains
            filtered = st.session_state.threat_mappings[
                (st.session_state.threat_mappings["SourceDomain"] == src_domain) &
                (st.session_state.threat_mappings["TargetDomain"] == tgt_domain)
            ]
            
            key = f"{source} -> {target}"
            threats[key] = [
                f"{row['STRIDE_Threat']} via {row['MITRE_Technique']} ➤ {row['Recommended_Control']}\n • NIST: {row['NIST_Control']}\n • ISO: {row['ISO_Control']}"
                for _, row in filtered.iterrows()
            ]
        return threats

    def render_graph(self):
        """Renders the architecture graph using Pyvis."""
        color_map = {
            "People": "lightcoral",
            "Application": "lightblue",
            "Platform": "lightgreen",
            "Network": "orange",
            "Data": "lightgoldenrodyellow"
        }
        net = Network(height="600px", width="100%", directed=True, notebook=True) # notebook=True for Streamlit compatibility
        
        # Add nodes
        for domain, elements in st.session_state.architecture.items():
            for el in elements:
                net.add_node(el, label=el, title=domain, color=color_map.get(domain, "gray"), size=25, font={'size': 14})
        
        # Add edges
        for src, tgt, flow_type in st.session_state.interactions:
            net.add_edge(src, tgt, title=flow_type, label=flow_type, color='darkgray', width=2)
        
        try:
            # Save the graph to an HTML file
            html_file = "graph.html"
            net.save_graph(html_file)

            # Read the HTML file and display it in Streamlit
            with open(html_file, "r", encoding="utf-8") as f:
                html = f.read()
            components.html(html, height=600, scrolling=True)
        except Exception as e:
            st.error(f"Failed to render graph: {e}")

    def create_github_issue(self, title: str, body: str) -> bool:
        """Creates a GitHub issue."""
        if not self._authorize_action("create_github_issue", {"title": title}):
            st.warning("Authorization failed to create GitHub issue.")
            return False

        # IMPORTANT: DO NOT HARDCODE YOUR GITHUB TOKEN
        # Use Streamlit Secrets (recommended) or environment variables
        # https://docs.streamlit.io/deploy/streamlit-cloud/connect-to-data-sources/secrets
        # Example using st.secrets:
        # GITHUB_TOKEN = st.secrets["GITHUB_TOKEN"]
        # REPO_OWNER = st.secrets["GITHUB_REPO_OWNER"]
        # REPO_NAME = st.secrets["GITHUB_REPO_NAME"]

        # For demonstration, using environment variable as a fallback
        GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        REPO_OWNER = os.getenv("GITHUB_REPO_OWNER")
        REPO_NAME = os.getenv("GITHUB_REPO_NAME")
        
        # Fallback to hardcoded for local testing IF you understand the risk
        if not GITHUB_TOKEN or not REPO_OWNER or not REPO_NAME:
            st.error("GitHub credentials (GITHUB_TOKEN, GITHUB_REPO_OWNER, GITHUB_REPO_NAME) not configured.")
            st.info("Please set these as environment variables or using Streamlit secrets.")
            # Placeholder values - replace with your actual repo
            # GITHUB_TOKEN = "ghp_YOUR_REAL_GITHUB_TOKEN_HERE" # REMOVE THIS LINE IN PRODUCTION
            # REPO_OWNER = "your-github-username" # REMOVE THIS LINE IN PRODUCTION
            # REPO_NAME = "your-repo-name" # REMOVE THIS LINE IN PRODUCTION
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

# --- Streamlit UI ---
st.set_page_config(layout="wide", page_title="Security Architecture Designer")

# Initialize the manager
manager = SecurityArchitectureManager()

st.title("🛡️ Security Architecture Designer (Threat Modelling + GitHub Integration)")

# Sidebar for common actions
st.sidebar.header("Architecture Actions")
if st.sidebar.button("💾 Save Architecture"):
    manager.save_architecture()
if st.sidebar.button("📂 Load Existing Architecture"):
    manager.load_architecture()
st.sidebar.info("Remember to save frequently!")

# Main content area
st.subheader("📝 Define Architecture Elements")
cols = st.columns(len(DOMAINS))
for i, domain in enumerate(DOMAINS):
    with cols[i]:
        st.markdown(f"**{domain}**")
        with st.container(border=True):
            # Display existing elements and their remove buttons
            if st.session_state.architecture[domain]:
                for elem in list(st.session_state.architecture[domain]): # Use list() to allow modification during iteration
                    col_elem, col_btn = st.columns([0.7, 0.3])
                    with col_elem:
                        st.markdown(f"- {elem}")
                    with col_btn:
                        if st.button("Remove", key=f"del-{domain}-{elem}"):
                            manager.remove_element(domain, elem)
                            st.rerun() # Rerun to update the UI immediately after removal
            else:
                st.write(f"No {domain} elements defined yet.")

            # Input for adding new elements
            new_elem = st.text_input(f"Add new {domain} element:", key=f"add_elem_input_{domain}")
            if st.button(f"Add {domain} Element", key=f"add_elem_btn_{domain}"):
                if new_elem:
                    manager.add_element(domain, new_elem.strip())
                    st.rerun() # Rerun to update the UI with new element

st.subheader("🔗 Define Interactions Between Elements")
all_elements_flat = sum(st.session_state.architecture.values(), [])
if not all_elements_flat:
    st.warning("Please add some elements before defining interactions.")
else:
    col_src, col_tgt, col_flow = st.columns(3)
    with col_src:
        source_elem = st.selectbox("Source Element", all_elements_flat, key="source_select")
    with col_tgt:
        target_elem = st.selectbox("Target Element", all_elements_flat, key="target_select")
    
    flow_types_available = st.session_state.flow_mappings["FlowType"].unique()
    if len(flow_types_available) == 0:
        st.error(f"No FlowTypes found in '{REQUIREMENTS_FILE}'. Please check the file.")
        flow_type_selected = ""
    else:
        with col_flow:
            flow_type_selected = st.selectbox("Flow Type", flow_types_available, key="flowtype_select")

    if st.button("Add Interaction", use_container_width=True):
        if source_elem and target_elem and flow_type_selected:
            manager.add_interaction(source_elem, target_elem, flow_type_selected)
            st.rerun() # Rerun to update the UI

    st.markdown("---")
    st.markdown("#### Current Interactions")
    if st.session_state.interactions:
        for i, interaction in enumerate(list(st.session_state.interactions)): # Use list() for safe iteration
            col_display, col_remove = st.columns([0.8, 0.2])
            with col_display:
                st.write(f"{i+1}. {interaction[0]} ➡️ {interaction[1]} ({interaction[2]})")
            with col_remove:
                if st.button("Remove", key=f"remove_interaction_{i}"):
                    manager.remove_interaction(interaction)
                    st.rerun() # Rerun to update the UI
    else:
        st.info("No interactions defined yet.")

st.subheader("📈 Architecture Graph Visualization")
if st.session_state.architecture or st.session_state.interactions:
    manager.render_graph()
else:
    st.info("Add elements and interactions to see the architecture graph.")

st.subheader("🔒 Security Requirements Analysis")
requirements = manager.generate_requirements()
if requirements:
    for title, req_list in requirements.items():
        st.markdown(f"**{title}**")
        with st.container(border=True):
            if req_list:
                for j, r in enumerate(req_list):
                    col_req, col_github = st.columns([0.7, 0.3])
                    with col_req:
                        st.markdown(f"- {r}")
                    with col_github:
                        if st.button("Create GitHub Task", key=f"github_task_{title}_{j}"):
                            manager.create_github_issue(f"Security Requirement: {title}", r)
            else:
                st.info("No specific security requirements found for this interaction based on mappings.")
else:
    st.info("No interactions or flow mappings defined to generate security requirements.")

st.subheader("🚨 Threat Modelling Recommendations")
threats = manager.generate_threat_analysis()
if threats:
    for title, threat_list in threats.items():
        st.markdown(f"**{title}**")
        with st.container(border=True):
            if threat_list:
                for t in threat_list:
                    st.markdown(f"- {t}")
            else:
                st.info("No specific threats found for this interaction based on domain mappings.")
else:
    st.info("No interactions or threat mappings defined to generate threat analysis.")

# --- Instructions for GitHub Integration ---
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
