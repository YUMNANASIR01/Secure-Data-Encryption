# admin1234
import streamlit as st
import hashlib
import json
import os
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

load_dotenv()

# Configuration
DATA_FILE = Path("datastore.json")
ENV_FILE = Path(".env")

# Session state setup
session_defaults = {
    'stored_data': {},
    'failed_attempts': 0,
    'redirect_to': None,
    'fernet_key': None
}

for key, val in session_defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

# Key generation with validation
def generate_valid_fernet_key():
    """Generate a guaranteed valid Fernet key using PBKDF2"""
    password = base64.urlsafe_b64encode(os.urandom(32)).decode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def init_fernet_key():
    """Initialize or repair Fernet key"""
    if not st.session_state.fernet_key:
        env_key = os.getenv("FERNET_KEY")
        
        if env_key:
            try:
                # Validate key structure
                Fernet(env_key.encode())
                st.session_state.fernet_key = env_key.encode()
                return
            except (ValueError, TypeError):
                st.warning("Invalid Fernet key found, generating new one...")
        
        # Generate new secure key
        new_key = generate_valid_fernet_key()
        with open(ENV_FILE, "w") as f:
            f.write(f"FERNET_KEY={new_key.decode()}\n")
            f.write("ADMIN_PASSWORD=your_secure_password_here\n")
        
        st.session_state.fernet_key = new_key
        st.rerun()

init_fernet_key()
cipher = Fernet(st.session_state.fernet_key)

# Data handling functions
def load_data():
    try:
        return json.loads(DATA_FILE.read_text()) if DATA_FILE.exists() else {}
    except Exception as e:
        st.error(f"Data load error: {str(e)}")
        return {}

def save_data(data):
    try:
        DATA_FILE.write_text(json.dumps(data))
    except Exception as e:
        st.error(f"Data save error: {str(e)}")

if not st.session_state.stored_data:
    st.session_state.stored_data = load_data()

# Security functions
def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), st.session_state.fernet_key, 100000).hex()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# UI Components
def main():
    st.title("🔒 Secure Data Vault")
    
    # Handle redirects
    if st.session_state.redirect_to:
        st.session_state.nav_choice = st.session_state.redirect_to
        st.session_state.redirect_to = None
        st.rerun()
    
    # Navigation
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Menu", menu, key="nav_choice")
    
    # Pages
    if choice == "Home":
        st.subheader("🏠 Welcome")
        col1, col2 = st.columns(2)
        col1.button("📥 Store Data", on_click=lambda: set_redirect("Store Data"))
        col2.button("📤 Retrieve Data", on_click=lambda: set_redirect("Retrieve Data"))
        
    elif choice == "Store Data":
        handle_store_data()
    
    elif choice == "Retrieve Data":
        handle_retrieve_data()
    
    elif choice == "Login":
        handle_login()

def set_redirect(target):
    st.session_state.redirect_to = target
    st.rerun()

def handle_store_data():
    st.subheader("📂 Store Data")
    with st.form("store_form"):
        data_id = st.text_input("Unique ID:")
        data = st.text_area("Secret Data:")
        passkey = st.text_input("Passkey:", type="password")
        
        if st.form_submit_button("Encrypt"):
            if all([data_id, data, passkey]):
                if data_id in st.session_state.stored_data:
                    st.error("ID exists!")
                else:
                    st.session_state.stored_data[data_id] = {
                        "encrypted": encrypt_data(data),
                        "passkey": hash_passkey(passkey)
                    }
                    save_data(st.session_state.stored_data)
                    st.success("Data secured!")
            else:
                st.error("All fields required!")

def handle_retrieve_data():
    st.subheader("🔍 Retrieve Data")
    with st.form("retrieve_form"):
        data_id = st.text_input("Data ID:")
        passkey = st.text_input("Passkey:", type="password")
        
        if st.form_submit_button("Decrypt"):
            entry = st.session_state.stored_data.get(data_id)
            if entry and entry["passkey"] == hash_passkey(passkey):
                st.success("Decrypted:")
                st.text_area("", value=decrypt_data(entry["encrypted"]), height=200)
                st.session_state.failed_attempts = 0
            else:
                handle_failed_attempt()

def handle_failed_attempt():
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= 3:
        st.error("🔒 Locked! Contact admin.")
        set_redirect("Login")
    else:
        st.error(f"Invalid credentials! {3 - st.session_state.failed_attempts} attempts left")

def handle_login():
    st.subheader("🔑 Admin Login")
    with st.form("login_form"):
        password = st.text_input("Admin Password:", type="password")
        if st.form_submit_button("Unlock"):
            if password == os.getenv("ADMIN_PASSWORD", "admin123"):
                st.session_state.failed_attempts = 0
                set_redirect("Retrieve Data")
            else:
                st.error("Invalid admin password!")

if __name__ == "__main__":
    main()







# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet

# # Initialize session state variables
# if 'stored_data' not in st.session_state:
#     st.session_state.stored_data = {}

# if 'failed_attempts' not in st.session_state:
#     st.session_state.failed_attempts = 0

# if 'fernet_key' not in st.session_state:
#     st.session_state.fernet_key = Fernet.generate_key()

# if 'redirect_to' not in st.session_state:
#     st.session_state.redirect_to = None

# cipher = Fernet(st.session_state.fernet_key)

# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# def encrypt_data(text):
#     return cipher.encrypt(text.encode()).decode()

# def decrypt_data(encrypted_text):
#     return cipher.decrypt(encrypted_text.encode()).decode()

# # Streamlit UI
# st.title("🔒 Secure Data Encryption System")

# # Handle redirection
# if st.session_state.redirect_to:
#     st.session_state.nav_choice = st.session_state.redirect_to
#     st.session_state.redirect_to = None
#     st.rerun()

# # Navigation control
# menu = ["Home", "Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.selectbox("Navigation", menu, key="nav_choice")

# if choice == "Home":
#     st.subheader("🏠 Welcome to the Secure Data System")
#     st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
#     st.write("### Features:")
#     st.write("- 🔐 Military-grade encryption using Fernet")
#     st.write("- 🚫 Automatic lockout after 3 failed attempts")
#     st.write("- 💾 In-memory data storage")

# elif choice == "Store Data":
#     st.subheader("📂 Store Data Securely")
#     data_id = st.text_input("Enter unique data identifier:")
#     user_data = st.text_area("Enter sensitive data:")
#     passkey = st.text_input("Create passkey:", type="password")

#     if st.button("Encrypt & Save"):
#         if data_id and user_data and passkey:
#             if data_id in st.session_state.stored_data:
#                 st.error("Identifier already exists! Please choose a unique name.")
#             else:
#                 hashed_passkey = hash_passkey(passkey)
#                 encrypted_text = encrypt_data(user_data)
#                 st.session_state.stored_data[data_id] = {
#                     "encrypted_text": encrypted_text,
#                     "passkey": hashed_passkey
#                 }
#                 st.success("Data encrypted and stored successfully!")
#                 st.code(f"Identifier: {data_id}\nPasskey: {'*' * len(passkey)}")
#         else:
#             st.error("All fields are required!")

# elif choice == "Retrieve Data":
#     st.subheader("🔍 Retrieve Your Data")
#     data_id = st.text_input("Enter data identifier:")
#     passkey = st.text_input("Enter passkey:", type="password")

#     if st.button("Decrypt"):
#         if data_id and passkey:
#             if data_id in st.session_state.stored_data:
#                 entry = st.session_state.stored_data[data_id]
#                 hashed_input = hash_passkey(passkey)
                
#                 if entry["passkey"] == hashed_input:
#                     decrypted_text = decrypt_data(entry["encrypted_text"])
#                     st.session_state.failed_attempts = 0
#                     st.success("Decryption successful!")
#                     st.text_area("Decrypted Data:", value=decrypted_text, height=200)
#                 else:
#                     st.session_state.failed_attempts += 1
#                     remaining = 3 - st.session_state.failed_attempts
#                     st.error(f"Invalid passkey! {remaining} attempts remaining")
                    
#                     if st.session_state.failed_attempts >= 3:
#                         st.error("🔒 Maximum attempts reached! Redirecting to Login...")
#                         st.session_state.redirect_to = "Login"
#                         st.rerun()
#             else:
#                 st.error("Identifier not found in database!")
#         else:
#             st.error("Both fields are required!")

# elif choice == "Login":
#     st.subheader("🔑 Reauthentication Required")
#     st.warning("You must verify your identity to continue")
#     admin_pass = st.text_input("Enter admin password:", type="password")
    
#     if st.button("Authenticate"):
#         if admin_pass == "admin123":
#             st.session_state.failed_attempts = 0
#             st.success("Authentication successful!")
#             st.session_state.redirect_to = "Retrieve Data"
#             st.rerun()
#         else:
#             st.error("Incorrect admin password!")

# # Security disclaimer
# st.sidebar.markdown("---")
# st.sidebar.warning("""
# **Security Note:**  
# This is a demo application. For production use:
# - Use proper user authentication
# - Store encryption keys securely
# - Implement additional security layers
# - Change default admin password
# """)
