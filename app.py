import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# ------------------------ SETUP ------------------------
DATA_FILE = "data.json"
LOCKOUT_TIME = 60  # in seconds

# Load or generate encryption key
if "fernet_key" not in st.session_state:
    if not os.path.exists("key.key"):
        with open("key.key", "wb") as key_file:
            key_file.write(Fernet.generate_key())
    with open("key.key", "rb") as key_file:
        key = key_file.read()
    st.session_state.fernet_key = key

cipher = Fernet(st.session_state.fernet_key)

# Session State for login
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "locked_until" not in st.session_state:
    st.session_state.locked_until = None

# ------------------------ DATA MANAGEMENT ------------------------

# Load stored data from file
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# ------------------------ SECURITY FUNCTIONS ------------------------

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ------------------------ STREAMLIT UI ------------------------

st.set_page_config(page_title="🔐 Secure Data App", layout="centered")
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📁 Navigate", menu)

# ------------------------ PAGES ------------------------

# 🏠 HOME
if choice == "Home":
    st.header("🏠 Welcome")
    st.write("""
    - 🔐 Store and retrieve sensitive data securely  
    - 💬 Data is encrypted and protected with a passkey  
    - 🚫 Multiple wrong attempts will lock you out temporarily
    """)

# 🗃️ STORE DATA
elif choice == "Store Data":
    st.subheader("📂 Store Your Data Securely")

    label = st.text_input("Enter a label / title for your data:")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("🔒 Encrypt & Save"):
        if label and user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            stored_data[label] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            save_data()
            st.success("✅ Data encrypted and saved successfully!")
        else:
            st.error("⚠️ All fields are required!")

# 🔓 RETRIEVE DATA
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")

    if st.session_state.locked_until:
        if datetime.now() < st.session_state.locked_until:
            st.error(f"⏳ Locked out due to failed attempts. Try again at {st.session_state.locked_until.strftime('%H:%M:%S')}")
            st.stop()
        else:
            st.session_state.failed_attempts = 0
            st.session_state.locked_until = None

    label = st.selectbox("Select stored data:", list(stored_data.keys()) if stored_data else ["No data found"])
    passkey = st.text_input("Enter passkey to decrypt:", type="password")

    if st.button("🔓 Decrypt"):
        if label == "No data found":
            st.warning("📭 No stored data found.")
        elif passkey:
            hashed = hash_passkey(passkey)
            entry = stored_data.get(label)

            if entry and entry["passkey"] == hashed:
                decrypted = decrypt_data(entry["encrypted_text"])
                st.success(f"✅ Your data:\n\n{decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Attempts left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.locked_until = datetime.now() + timedelta(seconds=LOCKOUT_TIME)
                    st.warning("🔐 Too many failed attempts. Temporary lock applied.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please enter the passkey.")

# 🔑 LOGIN / UNLOCK
elif choice == "Login":
    st.subheader("🔑 Admin Re-Authorization")

    password = st.text_input("Enter master password:", type="password")
    if st.button("🔓 Login"):
        if password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.locked_until = None
            st.success("✅ Reauthorized successfully! You can try retrieving data again.")
        else:
            st.error("❌ Incorrect master password!")
