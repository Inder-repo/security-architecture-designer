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
    {"ASVS_ID": "V2.4.1", "ASVS_Level": "L2", "Requirement": "Verify that credential storage uses a strong, salted, adaptive hashing function (e.g., Argon2, bcrypt).", "
