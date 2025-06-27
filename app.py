
import streamlit as st
import pandas as pd
from io import BytesIO
from xhtml2pdf import pisa
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import requests

DOMAINS = ["People", "Application", "Platform", "Network", "Data"]
EXCEL_FILE = "architecture_data.xlsx"
REQUIREMENTS_FILE = "security_requirements.xlsx"

if "architecture" not in st.session_state:
    st.session_state.architecture = {domain: [] for domain in DOMAINS}
    st.session_state.interactions = []

if "flow_mappings" not in st.session_state:
    try:
        st.session_state.flow_mappings = pd.read_excel(REQUIREMENTS_FILE)
    except:
        st.session_state.flow_mappings = pd.DataFrame(columns=["FlowType", "OWASPID", "Requirement", "GRCMapping"])

def save_to_excel():
    elements = [(d, e) for d, el in st.session_state.architecture.items() for e in el]
    df_elements = pd.DataFrame(elements, columns=["Domain", "Element"])
    df_interactions = pd.DataFrame(st.session_state.interactions, columns=["Source", "Target", "FlowType"])
    with pd.ExcelWriter(EXCEL_FILE) as writer:
        df_elements.to_excel(writer, sheet_name="Elements", index=False)
        df_interactions.to_excel(writer, sheet_name="Interactions", index=False)

def load_from_excel():
    try:
        data = pd.read_excel(EXCEL_FILE, sheet_name=None)
        df_elements = data.get("Elements", pd.DataFrame())
        df_interactions = data.get("Interactions", pd.DataFrame())
        for domain in DOMAINS:
            st.session_state.architecture[domain] = df_elements[df_elements["Domain"] == domain]["Element"].dropna().tolist()
        st.session_state.interactions = df_interactions.dropna().values.tolist()
    except Exception as e:
        st.error(f"Failed to load: {e}")

def generate_requirements():
    reqs = {}
    for domain, elements in st.session_state.architecture.items():
        for element in elements:
            reqs[element] = []
    for source, target, flow_type in st.session_state.interactions:
        filtered = st.session_state.flow_mappings[st.session_state.flow_mappings["FlowType"] == flow_type]
        key = f"{source} -> {target} ({flow_type})"
        reqs[key] = [
            f"{row['Requirement']} (OWASP {row['OWASPID']}) - GRC: {row['GRCMapping']}"
            for _, row in filtered.iterrows()
        ]
    return reqs

def render_graph():
    color_map = {
        "People": "lightcoral",
        "Application": "lightblue",
        "Platform": "lightgreen",
        "Network": "orange",
        "Data": "lightgoldenrodyellow"
    }
    net = Network(height="600px", width="100%", directed=True)
    for domain, elements in st.session_state.architecture.items():
        for el in elements:
            net.add_node(el, label=el, title=domain, color=color_map.get(domain, "gray"))
    for src, tgt, _ in st.session_state.interactions:
        net.add_edge(src, tgt)
    net.save_graph("graph.html")
    with open("graph.html", "r", encoding="utf-8") as f:
        html = f.read()
    components.html(html, height=600, scrolling=True)

def create_github_issue(title, body):
    repo = "your-username/your-repo"
    token = "ghp_yourgithubtokenhere"  # Secure this in real app
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {"Authorization": f"token {token}"}
    data = {"title": title, "body": body}
    response = requests.post(url, headers=headers, json=data)
    return response.status_code == 201

st.title("Security Architecture Designer (Custom Mappings + GitHub)")

if st.button("Load Existing Architecture"):
    load_from_excel()

st.subheader("Define Architecture")
cols = st.columns(len(DOMAINS))
for i, domain in enumerate(DOMAINS):
    with cols[i]:
        st.text(domain)
        for elem in st.session_state.architecture[domain]:
            if st.button(f"❌ {elem}", key=f"del-{domain}-{elem}"):
                st.session_state.architecture[domain].remove(elem)
        new_elem = st.text_input(f"Add to {domain}", key=f"add-{domain}")
        if st.button(f"Add {domain}", key=f"btn-{domain}"):
            if new_elem:
                st.session_state.architecture[domain].append(new_elem)

st.subheader("Define Interactions")
source = st.selectbox("Source Element", sum(st.session_state.architecture.values(), []), key="source")
target = st.selectbox("Target Element", sum(st.session_state.architecture.values(), []), key="target")
flow_type = st.selectbox("Flow Type", st.session_state.flow_mappings["FlowType"].unique(), key="flowtype")
if st.button("Add Interaction"):
    st.session_state.interactions.append([source, target, flow_type])

st.write("### Interactions")
st.write(st.session_state.interactions)

if st.button("Save to Excel"):
    save_to_excel()
    st.success("Saved!")

st.write("### Security Requirements")
requirements = generate_requirements()
for title, req_list in requirements.items():
    st.markdown(f"**{title}**")
    for r in req_list:
        st.markdown(f"- {r}")
        if st.button(f"Create GitHub Task for: {r}", key=f"task-{title}-{r}"):
            if create_github_issue(title, r):
                st.success("GitHub issue created")
            else:
                st.error("Failed to create issue")

st.subheader("📈 Architecture Graph")
render_graph()
