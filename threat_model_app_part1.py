import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import json
from datetime import datetime
import uuid

# Configure Streamlit page
st.set_page_config(
    page_title="Threat Modeling Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'components' not in st.session_state:
    st.session_state.components = []
if 'data_flows' not in st.session_state:
    st.session_state.data_flows = []
if 'threats' not in st.session_state:
    st.session_state.threats = []
if 'current_diagram' not in st.session_state:
    st.session_state.current_diagram = None

# Component types and their properties
COMPONENT_TYPES = {
    'External Entity': {'color': '#FF6B6B', 'shape': 'square'},
    'Process': {'color': '#4ECDC4', 'shape': 'circle'},
    'Data Store': {'color': '#45B7D1', 'shape': 'diamond'},
    'Trust Boundary': {'color': '#96CEB4', 'shape': 'square-dot'}
}

# STRIDE threat categories
STRIDE_CATEGORIES = {
    'Spoofing': 'Identity verification threats',
    'Tampering': 'Data integrity threats',
    'Repudiation': 'Non-repudiation threats',
    'Information Disclosure': 'Confidentiality threats',
    'Denial of Service': 'Availability threats',
    'Elevation of Privilege': 'Authorization threats'
}

class ThreatModelingApp:
    def __init__(self):
        self.setup_sidebar()
        
    def setup_sidebar(self):
        """Setup the sidebar navigation"""
        st.sidebar.title("🔒 Threat Modeling Tool")
        
        # Navigation menu
        menu_options = [
            "📊 Dashboard",
            "🏗️ System Architecture",
            "🔄 Data Flow Diagram",
            "⚠️ Threat Analysis",
            "📈 Risk Assessment",
            "📋 Reports"
        ]
        
        selected = st.sidebar.selectbox("Navigate to:", menu_options)
        
        # Export/Import functionality
        st.sidebar.markdown("---")
        st.sidebar.subheader("Data Management")
        
        if st.sidebar.button("Export Model"):
            self.export_model()
        
        uploaded_file = st.sidebar.file_uploader("Import Model", type=['json'])
        if uploaded_file:
            self.import_model(uploaded_file)
        
        return selected
    
    def export_model(self):
        """Export the current threat model"""
        model_data = {
            'components': st.session_state.components,
            'data_flows': st.session_state.data_flows,
            'threats': st.session_state.threats,
            'export_date': datetime.now().isoformat()
        }
        
        st.sidebar.download_button(
            label="Download Model",
            data=json.dumps(model_data, indent=2),
            file_name=f"threat_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    def import_model(self, uploaded_file):
        """Import a threat model"""
        try:
            model_data = json.load(uploaded_file)
            st.session_state.components = model_data.get('components', [])
            st.session_state.data_flows = model_data.get('data_flows', [])
            st.session_state.threats = model_data.get('threats', [])
            st.sidebar.success("Model imported successfully!")
        except Exception as e:
            st.sidebar.error(f"Error importing model: {str(e)}")
    
    def dashboard(self):
        """Main dashboard view"""
        st.title("🔒 Threat Modeling Dashboard")
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("System Components", len(st.session_state.components))
        
        with col2:
            st.metric("Data Flows", len(st.session_state.data_flows))
        
        with col3:
            st.metric("Identified Threats", len(st.session_state.threats))
        
        with col4:
            high_risk_threats = len([t for t in st.session_state.threats if t.get('risk_level') == 'High'])
            st.metric("High Risk Threats", high_risk_threats)
        
        # Recent activity
        st.subheader("Recent Activity")
        if st.session_state.components or st.session_state.data_flows or st.session_state.threats:
            activities = []
            
            for comp in st.session_state.components[-5:]:
                activities.append({
                    'Type': 'Component Added',
                    'Name': comp['name'],
                    'Category': comp['type'],
                    'Time': 'Recently'
                })
            
            for flow in st.session_state.data_flows[-5:]:
                activities.append({
                    'Type': 'Data Flow Added',
                    'Name': flow['name'],
                    'Category': f"{flow['source']} → {flow['destination']}",
                    'Time': 'Recently'
                })
            
            if activities:
                df = pd.DataFrame(activities)
                st.dataframe(df, use_container_width=True)
        else:
            st.info("No activity yet. Start by creating system components or data flows.")
    
    def system_architecture(self):
        """System architecture management"""
        st.title("🏗️ System Architecture")
        
        # Component management
        st.subheader("System Components")
        
        # Add new component
        with st.expander("Add New Component"):
            col1, col2 = st.columns(2)
            
            with col1:
                comp_name = st.text_input("Component Name")
                comp_type = st.selectbox("Component Type", list(COMPONENT_TYPES.keys()))
            
            with col2:
                comp_description = st.text_area("Description")
                comp_trust_level = st.selectbox("Trust Level", ["Low", "Medium", "High"])
            
            if st.button("Add Component"):
                if comp_name:
                    new_component = {
                        'id': str(uuid.uuid4()),
                        'name': comp_name,
                        'type': comp_type,
                        'description': comp_description,
                        'trust_level': comp_trust_level,
                        'created_at': datetime.now().isoformat()
                    }
                    st.session_state.components.append(new_component)
                    st.success(f"Component '{comp_name}' added successfully!")
                    st.rerun()
        
        # Display existing components
        if st.session_state.components:
            st.subheader("Current Components")
            
            for i, comp in enumerate(st.session_state.components):
                with st.expander(f"{comp['name']} ({comp['type']})"):
                    col1, col2, col3 = st.columns([2, 1, 1])
                    
                    with col1:
                        st.write(f"**Description:** {comp['description']}")
                        st.write(f"**Trust Level:** {comp['trust_level']}")
                    
                    with col2:
                        if st.button(f"Edit", key=f"edit_{i}"):
                            st.session_state.edit_component = i
                    
                    with col3:
                        if st.button(f"Delete", key=f"delete_{i}"):
                            st.session_state.components.pop(i)
                            st.rerun()
        else:
            st.info("No components defined yet. Add your first component above.")
    
    def data_flow_diagram(self):
        """Data flow diagram creation and management"""
        st.title("🔄 Data Flow Diagram")
        
        # Create data flow
        st.subheader("Create Data Flow")
        
        if len(st.session_state.components) >= 2:
            with st.expander("Add New Data Flow"):
                col1, col2 = st.columns(2)
                
                with col1:
                    flow_name = st.text_input("Flow Name")
                    source_comp = st.selectbox("Source Component", 
                                             [comp['name'] for comp in st.session_state.components])
                    destination_comp = st.selectbox("Destination Component", 
                                                  [comp['name'] for comp in st.session_state.components])
                
                with col2:
                    data_type = st.selectbox("Data Type", 
                                           ["Personal Data", "Financial Data", "Authentication Data", 
                                            "System Data", "Public Data", "Other"])
                    flow_description = st.text_area("Flow Description")
                    encryption = st.checkbox("Encrypted in Transit")
                
                if st.button("Add Data Flow"):
                    if flow_name and source_comp != destination_comp:
                        new_flow = {
                            'id': str(uuid.uuid4()),
                            'name': flow_name,
                            'source': source_comp,
                            'destination': destination_comp,
                            'data_type': data_type,
                            'description': flow_description,
                            'encrypted': encryption,
                            'created_at': datetime.now().isoformat()
                        }
                        st.session_state.data_flows.append(new_flow)
                        st.success(f"Data flow '{flow_name}' added successfully!")
                        st.rerun()
        else:
            st.warning("You need at least 2 components to create data flows.")
        
        # Display data flow diagram
        if st.session_state.components and st.session_state.data_flows:
            st.subheader("Data Flow Diagram")
            
            # Create network diagram
            fig = self.create_data_flow_diagram()
            st.plotly_chart(fig, use_container_width=True)
            
            # Display flows table
            st.subheader("Data Flows Summary")
            flows_df = pd.DataFrame([{
                'Flow Name': flow['name'],
                'Source': flow['source'],
                'Destination': flow['destination'],
                'Data Type': flow['data_type'],
                'Encrypted': '✅' if flow['encrypted'] else '❌'
            } for flow in st.session_state.data_flows])
            
            st.dataframe(flows_df, use_container_width=True)
        
        elif st.session_state.components:
            st.info("Add data flows to visualize the system architecture.")
        else:
            st.info("Add system components first to create data flows.")
    
    def create_data_flow_diagram(self):
        """Create a network diagram for data flows"""
        fig = go.Figure()
        
        # Component positions (simple layout)
        import math
        n_components = len(st.session_state.components)
        
        # Position components in a circle
        positions = {}
        for i, comp in enumerate(st.session_state.components):
            angle = 2 * math.pi * i / n_components
            x = math.cos(angle) * 3
            y = math.sin(angle) * 3
            positions[comp['name']] = (x, y)
        
        # Draw data flows (edges)
        for flow in st.session_state.data_flows:
            if flow['source'] in positions and flow['destination'] in positions:
                x0, y0 = positions[flow['source']]
                x1, y1 = positions[flow['destination']]
                
                # Draw arrow
                fig.add_trace(go.Scatter(
                    x=[x0, x1],
                    y=[y0, y1],
                    mode='lines',
                    line=dict(
                        color='red' if not flow['encrypted'] else 'green',
                        width=2,
                        dash='dash' if not flow['encrypted'] else 'solid'
                    ),
                    name=flow['name'],
                    hovertemplate=f"<b>{flow['name']}</b><br>" +
                                f"Data Type: {flow['data_type']}<br>" +
                                f"Encrypted: {'Yes' if flow['encrypted'] else 'No'}<br>" +
                                f"{flow['source']} → {flow['destination']}<extra></extra>"
                ))
        
        # Draw components (nodes)
        for comp in st.session_state.components:
            x, y = positions[comp['name']]
            color = COMPONENT_TYPES[comp['type']]['color']
            
            fig.add_trace(go.Scatter(
                x=[x],
                y=[y],
                mode='markers+text',
                marker=dict(
                    size=30,
                    color=color,
                    line=dict(width=2, color='black')
                ),
                text=comp['name'],
                textposition="middle center",
                name=comp['name'],
                hovertemplate=f"<b>{comp['name']}</b><br>" +
                            f"Type: {comp['type']}<br>" +
                            f"Trust Level: {comp['trust_level']}<br>" +
                            f"Description: {comp['description']}<extra></extra>"
            ))
        
        fig.update_layout(
            title="System Data Flow Diagram",
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=40),
            annotations=[
                dict(
                    text="Red dashed lines = Unencrypted data flows<br>Green solid lines = Encrypted data flows",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002,
                    xanchor='left', yanchor='bottom',
                    font=dict(size=12)
                )
            ],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='rgba(0,0,0,0)',
            height=600
        )
        
        return fig
    
    def threat_analysis(self):
        """Threat analysis using STRIDE methodology"""
        st.title("⚠️ Threat Analysis")
        
        # STRIDE methodology explanation
        with st.expander("About STRIDE Methodology"):
            st.markdown("""
            **STRIDE** is a threat modeling methodology that helps identify security threats:
            
            - **S**poofing: Threats to authentication
            - **T**ampering: Threats to integrity
            - **R**epudiation: Threats to non-repudiation
            - **I**nformation Disclosure: Threats to confidentiality
            - **D**enial of Service: Threats to availability
            - **E**levation of Privilege: Threats to authorization
            """)
        
        if not st.session_state.components or not st.session_state.data_flows:
            st.warning("Create system components and data flows first to perform threat analysis.")
            return
        
        # Threat identification
        st.subheader("Identify Threats")
        
        with st.expander("Add New Threat"):
            col1, col2 = st.columns(2)
            
            with col1:
                threat_title = st.text_input("Threat Title")
                threat_category = st.selectbox("STRIDE Category", list(STRIDE_CATEGORIES.keys()))
                affected_component = st.selectbox("Affected Component", 
                                                [comp['name'] for comp in st.session_state.components])
                affected_flow = st.selectbox("Affected Data Flow (Optional)", 
                                           ["None"] + [flow['name'] for flow in st.session_state.data_flows])
            
            with col2:
                threat_description = st.text_area("Threat Description")
                attack_vector = st.text_area("Attack Vector")
                potential_impact = st.text_area("Potential Impact")
            
            if st.button("Add Threat"):
                if threat_title and threat_description:
                    new_threat = {
                        'id': str(uuid.uuid4()),
                        'title': threat_title,
                        'category': threat_category,
                        'description': threat_description,
                        'attack_vector': attack_vector,
                        'potential_impact': potential_impact,
                        'affected_component': affected_component,
                        'affected_flow': affected_flow if affected_flow != "None" else None,
                        'likelihood': 'Medium',
                        'impact': 'Medium',
                        'risk_level': 'Medium',
                        'mitigation_status': 'Open',
                        'mitigations': [],
                        'created_at': datetime.now().isoformat()
                    }
                    st.session_state.threats.append(new_threat)
                    st.success(f"Threat '{threat_title}' added successfully!")
                    st.rerun()
        
        # Automated threat suggestions
        st.subheader("Suggested Threats")
        
        if st.button("Generate Threat Suggestions"):
            suggestions = self.generate_threat_suggestions()
            
            if suggestions:
                st.write("Based on your system architecture, consider these potential threats:")
                
                for suggestion in suggestions:
                    with st.expander(f"⚠️ {suggestion['title']} ({suggestion['category']})"):
                        st.write(f"**Component:** {suggestion['component']}")
                        st.write(f"**Description:** {suggestion['description']}")
                        st.write(f"**Rationale:** {suggestion['rationale']}")
                        
                        if st.button(f"Add This Threat", key=f"add_{suggestion['id']}"):
                            new_threat = {
                                'id': str(uuid.uuid4()),
                                'title': suggestion['title'],
                                'category': suggestion['category'],
                                'description': suggestion['description'],
                                'attack_vector': suggestion.get('attack_vector', ''),
                                'potential_impact': suggestion.get('potential_impact', ''),
                                'affected_component': suggestion['component'],
                                'affected_flow': None,
                                'likelihood': 'Medium',
                                'impact': 'Medium',
                                'risk_level': 'Medium',
                                'mitigation_status': 'Open',
                                'mitigations': [],
                                'created_at': datetime.now().isoformat()
                            }
                            st.session_state.threats.append(new_threat)
                            st.success(f"Threat '{suggestion['title']}' added!")
                            st.rerun()
        
        # Display existing threats
        if st.session_state.threats:
            st.subheader("Identified Threats")
            
            # Filter threats
            col1, col2 = st.columns(2)
            with col1:
                filter_category = st.selectbox("Filter by Category", 
                                             ["All"] + list(STRIDE_CATEGORIES.keys()))
            with col2:
                filter_status = st.selectbox("Filter by Status", 
                                           ["All", "Open", "In Progress", "Resolved"])
            
            filtered_threats = st.session_state.threats
            if filter_category != "All":
                filtered_threats = [t for t in filtered_threats if t['category'] == filter_category]
            if filter_status != "All":
                filtered_threats = [t for t in filtered_threats if t['mitigation_status'] == filter_status]
            
            for i, threat in enumerate(filtered_threats):
                with st.expander(f"{threat['title']} - {threat['category']} ({threat['risk_level']} Risk)"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Component:** {threat['affected_component']}")
                        if threat['affected_flow']:
                            st.write(f"**Data Flow:** {threat['affected_flow']}")
                        st.write(f"**Description:** {threat['description']}")
                        st.write(f"**Attack Vector:** {threat['attack_vector']}")
                        st.write(f"**Potential Impact:** {threat['potential_impact']}")
                    
                    with col2:
                        st.write(f"**Status:** {threat['mitigation_status']}")
                        st.write(f"**Risk Level:** {threat['risk_level']}")
                        st.write(f"**Likelihood:** {threat['likelihood']}")
                        st.write(f"**Impact:** {threat['impact']}")
                        
                        # Update threat status
                        new_status = st.selectbox("Update Status", 
                                                ["Open", "In Progress", "Resolved"], 
                                                key=f"status_{threat['id']}",
                                                index=["Open", "In Progress", "Resolved"].index(threat['mitigation_status']))
                        
                        if st.button(f"Update Status", key=f"update_{threat['id']}"):
                            threat['mitigation_status'] = new_status
                            st.success("Status updated!")
                            st.rerun()
        
        # Threat statistics
        if st.session_state.threats:
            st.subheader("Threat Statistics")
            
            # STRIDE category distribution
            col1, col2 = st.columns(2)
            
            with col1:
                category_counts = {}
                for threat in st.session_state.threats:
                    category = threat['category']
                    category_counts[category] = category_counts.get(category, 0) + 1
                
                fig_pie = px.pie(
                    values=list(category_counts.values()),
                    names=list(category_counts.keys()),
                    title="Threats by STRIDE Category"
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            
            with col2:
                status_counts = {}
                for threat in st.session_state.threats:
                    status = threat['mitigation_status']
                    status_counts[status] = status_counts.get(status, 0) + 1
                
                fig_bar = px.bar(
                    x=list(status_counts.keys()),
                    y=list(status_counts.values()),
                    title="Threats by Status"
                )
                st.plotly_chart(fig_bar, use_container_width=True)
    
    def generate_threat_suggestions(self):
        """Generate automated threat suggestions based on system architecture"""
        suggestions = []
        
        # Common threat patterns based on component types
        threat_patterns = {
            'External Entity': [
                {
                    'title': 'Identity Spoofing',
                    'category': 'Spoofing',
                    'description': 'Attacker impersonates legitimate external entity',
                    'rationale': 'External entities are common targets for spoofing attacks'
                },
                {
                    'title': 'Unauthorized Access',
                    'category': 'Elevation of Privilege',
                    'description': 'External entity gains unauthorized access to system resources',
                    'rationale': 'External entities should have limited access privileges'
                }
            ],
            'Process': [
                {
                    'title': 'Process Tampering',
                    'category': 'Tampering',
                    'description': 'Malicious modification of process logic or data',
                    'rationale': 'Processes are vulnerable to tampering attacks'
                },
                {
                    'title': 'Denial of Service',
                    'category': 'Denial of Service',
                    'description': 'Process becomes unavailable due to resource exhaustion',
                    'rationale': 'Processes can be overwhelmed with excessive requests'
                }
            ],
            'Data Store': [
                {
                    'title': 'Data Breach',
                    'category': 'Information Disclosure',
                    'description': 'Unauthorized access to sensitive data in storage',
                    'rationale': 'Data stores contain valuable information for attackers'
                },
                {
                    'title': 'Data Tampering',
                    'category': 'Tampering',
                    'description': 'Malicious modification of stored data',
                    'rationale': 'Data integrity is crucial for system operations'
                }
            ]
        }
        
        # Generate suggestions for each component
        for comp in st.session_state.components:
            if comp['type'] in threat_patterns:
                for pattern in threat_patterns[comp['type']]:
                    suggestion = pattern.copy()
                    suggestion['id'] = str(uuid.uuid4())
                    suggestion['component'] = comp['name']
                    suggestions.append(suggestion)
        
        # Additional suggestions based on data flows
        for flow in st.session_state.data_flows:
            if not flow['encrypted']:
                suggestions.append({
                    'id': str(uuid.uuid4()),
                    'title': 'Data Interception',
                    'category': 'Information Disclosure',
                    'description': f'Unencrypted data flow from {flow["source"]} to {flow["destination"]} can be intercepted',
                    'rationale': 'Unencrypted data flows are vulnerable to eavesdropping',
                    'component': flow['destination']
                })
        
        return suggestions[:10]  # Return top 10 suggestions
    
    def risk_assessment(self):
        """Risk assessment and prioritization"""
        st.title("📈 Risk Assessment")
        
        if not st.session_state.threats:
            st.warning("Identify threats first to perform risk assessment.")
            return
        
        # Risk matrix explanation
        with st.expander("Risk Assessment Matrix"):
            st.markdown("""
            **Risk Level = Likelihood × Impact**
            
            - **Likelihood**: How likely is the threat to occur?
            - **Impact**: What would be the consequence if it occurs?
            - **Risk Level**: Overall risk prioritization
            
            **Levels**: Low, Medium, High, Critical
            """)
        
        # Risk assessment for each threat
        st.subheader("Assess Threat Risks")
        
        for i, threat in enumerate(st.session_state.threats):
            with st.expander(f"Risk Assessment: {threat['title']}"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    likelihood = st.selectbox("Likelihood", 
                                            ["Low", "Medium", "High", "Critical"],
                                            key=f"likelihood_{threat['id']}",
                                            index=["Low", "Medium", "High", "Critical"].index(threat['likelihood']))
                
                with col2:
                    impact = st.selectbox("Impact", 
                                        ["Low", "Medium", "High", "Critical"],
                                        key=f"impact_{threat['id']}",
                                        index=["Low", "Medium", "High", "Critical"].index(threat['impact']))
                
                with col3:
                    # Calculate risk level
                    risk_level = self.calculate_risk_level(likelihood, impact)
                    st.write(f"**Risk Level:** {risk_level}")
                
                # Add mitigation
                st.subheader("Mitigation Strategies")
                
                mitigation_text = st.text_area("Add Mitigation Strategy", 
                                             key=f"mitigation_{threat['id']}")
                
                if st.button(f"Add Mitigation", key=f"add_mit_{threat['id']}"):
                    if mitigation_text:
                        threat['mitigations'].append({
                            'id': str(uuid.uuid4()),
                            'description': mitigation_text,
                            'status': 'Planned',
                            'created_at': datetime.now().isoformat()
                        })
                        st.success("Mitigation added!")
                        st.rerun()
                
                # Display existing mitigations
                if threat['mitigations']:
                    st.write("**Current Mitigations:**")
                    for mit in threat['mitigations']:
                        st.write(f"• {mit['description']} (Status: {mit['status']})")
                
                # Update risk assessment
                if st.button(f"Update Risk Assessment", key=f"update_risk_{threat['id']}"):
                    threat['likelihood'] = likelihood
                    threat['impact'] = impact
                    threat['risk_level'] = risk_level
                    st.success("Risk assessment updated!")
                    st.rerun()
        
        # Risk dashboard
        st.subheader("Risk Dashboard")
        
        # Risk distribution
        col1, col2 = st.columns(2)
        
        with col1:
            risk_counts = {}
            for threat in st.session_state.threats:
                risk = threat['risk_level']
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            fig_risk = px.bar(
                x=list(risk_counts.keys()),
                y=list(risk_counts.values()),
                title="Risk Level Distribution",
                color=list(risk_counts.keys()),
                color_discrete_map={
                    'Low': '#90EE90',
                    'Medium': '#FFD700',
                    'High': '#FFA500',
                    'Critical': '#FF6B6B'
                }
            )
            st.plotly_chart(fig_risk, use_container_width=True)
        
        with col2:
            # Risk matrix
            risk_matrix_data = []
            for threat in st.session_state.threats:
                risk_matrix_data.append({
                    'Threat': threat['title'],
                    'Likelihood': threat['likelihood'],
                    'Impact': threat['impact'],
                    'Risk Level': threat['risk_level']
                })
            
            df_risk = pd.DataFrame(risk_matrix_data)
            st.dataframe(df_risk, use_container_width=True)
        
        # High-priority threats
        high_risk_threats = [t for t in st.session_state.threats if t['risk_level'] in ['High', 'Critical']]
        
        if high_risk_threats:
            st.subheader("High Priority Threats")
            st.error(f"⚠️ {len(high_risk_threats)} high-priority threats require immediate attention!")
            
            for threat in high_risk_threats:
                st.write(f"**{threat['title']}** - {threat['risk_level']} Risk")
                st.write(f"Component: {threat['affected_component']}")
                st.write(f"Mitigations: {len(threat['mitigations'])}")
                st.write("---")
    
    def calculate_risk_level(self, likelihood, impact):
        """Calculate risk level based on likelihood and impact"""
        risk_matrix = {
            ('Low', 'Low'): 'Low',
            ('Low', 'Medium'): 'Low',
            ('Low', 'High'): 'Medium',
            ('Low', 'Critical'): 'High',
            ('Medium', 'Low'): 'Low',
            ('Medium', 'Medium'): 'Medium',
            ('Medium', 'High'): 'High',
            ('Medium', 'Critical'): 'High',
            ('High', 'Low'): 'Medium',
            ('High', 'Medium'): 'High',
            ('High', 'High'): 'High',
            ('High', 'Critical'): 'Critical',
            ('Critical', 'Low'): 'High',
            ('Critical', 'Medium'): 'High',
            ('Critical', 'High'): 'Critical',
            ('Critical', 'Critical'): 'Critical'
        }
        
        return risk_matrix.get((likelihood, impact), 'Medium')
    
    def generate_reports(self):
        """Generate comprehensive threat modeling reports"""
        st.title("📋 Threat Modeling Report")
        
        if not st.session_state.components:
            st.warning("Create system components first to generate reports.")
            return
        
        # Report header
        st.markdown("---")
        st.subheader("Executive Summary")
        
        # System overview
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Components", len(st.session_state.components))
        with col2:
            st.metric("Data Flows", len(st.session_state.data_flows))
        with col3:
            st.metric("Threats", len(st.session_state.threats))
        with col4:
            critical_threats = len([t for t in st.session_state.threats if t['risk_level'] == 'Critical'])
            st.metric("Critical Threats", critical_threats)
        
        # System architecture summary
        st.subheader("System Architecture")
        
        if st.session_state.components:
            arch_df = pd.DataFrame([{
                'Component': comp['name'],
                'Type': comp['type'],
                'Trust Level': comp['trust_level'],
                'Description': comp['description']
            } for comp in st.session_state.components])
            st.dataframe(arch_df, use_container_width=True)
        
        # Data flows summary
        if st.session_state.data_flows:
            st.subheader("Data Flows")
            
            flows_df = pd.DataFrame([{
                'Flow': flow['name'],
                'Source': flow['source'],
                'Destination': flow['destination'],
                'Data Type': flow['data_type'],
                'Encrypted': '✅' if flow['encrypted'] else '❌'
            } for flow in st.session_state.data_flows])
            st.dataframe(flows_df, use_container_width=True)
        
        # Threat analysis summary
        if st.session_state.threats:
            st.subheader("Threat Analysis")
            
            threat_df = pd.DataFrame([{
                'Threat': threat['title'],
                'Category': threat['category'],
                'Component': threat['affected_component'],
                'Risk Level': threat['risk_level'],
                'Status': threat['mitigation_status'],
                'Mitigations': len(threat['mitigations'])
            } for threat in st.session_state.threats])
            st.dataframe(threat_df, use_container_width=True)
        
        # Risk assessment
        if st.session_state.threats:
            st.subheader("Risk Assessment")
            
            risk_summary = {}
            for threat in st.session_state.threats:
                risk = threat['risk_level']
                risk_summary[risk] = risk_summary.get(risk, 0) + 1
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Risk Distribution:**")
                for risk, count in risk_summary.items():
                    st.write(f"• {risk}: {count} threats")
            
            with col2:
                completion_rate = len([t for t in st.session_state.threats if t['mitigation_status'] == 'Resolved']) / len(st.session_state.threats) * 100
                st.metric("Mitigation Completion", f"{completion_rate:.1f}%")
        
        # Recommendations
        st.subheader("Recommendations")
        
        recommendations = self.generate_recommendations()
        for i, rec in enumerate(recommendations, 1):
            st.write(f"{i}. {rec}")
        
        # Generate downloadable report
        st.subheader("Download Report")
        
        if st.button("Generate PDF Report"):
            report_content = self.generate_report_content()
            st.download_button(
                label="Download Report",
                data=report_content,
                file_name=f"threat_model_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    
    def generate_recommendations(self):
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Check for unencrypted flows
        unencrypted_flows = [f for f in st.session_state.data_flows if not f['encrypted']]
        if unencrypted_flows:
            recommendations.append(f"Implement encryption for {len(unencrypted_flows)} unencrypted data flows")
        
        # Check for high-risk threats
        high_risk_threats = [t for t in st.session_state.threats if t['risk_level'] in ['High', 'Critical']]
        if high_risk_threats:
            recommendations.append(f"Prioritize mitigation of {len(high_risk_threats)} high-risk threats")
        
        # Check for external entities
        external_entities = [c for c in st.session_state.components if c['type'] == 'External Entity']
        if external_entities:
            recommendations.append("Implement strong authentication for all external entity interactions")
        
        # Check for low trust components
        low_trust_components = [c for c in st.session_state.components if c['trust_level'] == 'Low']
        if low_trust_components:
            recommendations.append("Apply additional security controls to low-trust components")
        
        # General recommendations
        recommendations.extend([
            "Implement comprehensive logging and monitoring",
            "Establish incident response procedures",
            "Conduct regular security assessments",
            "Provide security awareness training",
            "Implement defense-in-depth strategies"
        ])
        
        return recommendations[:10]  # Return top 10
    
    def generate_report_content(self):
        """Generate text report content"""
        report = f"""
THREAT MODELING REPORT
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SYSTEM OVERVIEW
===============
Components: {len(st.session_state.components)}
Data Flows: {len(st.session_state.data_flows)}
Identified Threats: {len(st.session_state.threats)}

SYSTEM COMPONENTS
=================
"""
        
        for comp in st.session_state.components:
            report += f"""
Component: {comp['name']}
Type: {comp['type']}
Trust Level: {comp['trust_level']}
Description: {comp['description']}
"""
        
        report += "\nTHREATS IDENTIFIED\n=================="
        
        for threat in st.session_state.threats:
            report += f"""
Threat: {threat['title']}
Category: {threat['category']}
Component: {threat['affected_component']}
Risk Level: {threat['risk_level']}
Status: {threat['mitigation_status']}
Description: {threat['description']}
Mitigations: {len(threat['mitigations'])}
"""
        
        report += "\nRECOMMENDATIONS\n==============="
        
        for i, rec in enumerate(self.generate_recommendations(), 1):
            report += f"\n{i}. {rec}"
        
        return report

# Main application
def main():
    app = ThreatModelingApp()
    
    # Get selected menu option
    selected = app.setup_sidebar()
    
    # Route to appropriate page
    if "Dashboard" in selected:
        app.dashboard()
    elif "System Architecture" in selected:
        app.system_architecture()
    elif "Data Flow Diagram" in selected:
        app.data_flow_diagram()
    elif "Threat Analysis" in selected:
        app.threat_analysis()
    elif "Risk Assessment" in selected:
        app.risk_assessment()
    elif "Reports" in selected:
        app.generate_reports()

if __name__ == "__main__":
    main()