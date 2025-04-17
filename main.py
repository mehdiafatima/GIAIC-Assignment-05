
import json
import os
import streamlit as st
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
import base64
import time

# Constants
DATA_FILE = "data_store.json"
LOCKOUT_TIME = 60  # seconds
MAX_ATTEMPTS = 3

# Helper functions for file I/O
def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Generate or load key
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as f:
        f.write(Fernet.generate_key())
with open("secret.key", "rb") as f:
    KEY = f.read()
cipher = Fernet(KEY)

# In-memory tracking
session = {
    "failed_attempts": {},
    "lockout_until": {}
}

# Secure hash function using PBKDF2
def hash_passkey(username, passkey):
    salt = username.encode()
    key = pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return base64.b64encode(key).decode()

# Encrypt and Decrypt
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Streamlit App Starts Here
st.set_page_config(page_title="Secure Vault", page_icon="🔐")
st.title("🔐 Secure Multi-User Encryption Vault")

menu = ["Home", "Register", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

data_store = load_data()

# Home
if choice == "Home":
    st.subheader("🏡 Welcome!")
    st.markdown("""
        - 🔐 Encrypt and store your data securely
        - 🔍 Retrieve it anytime with your passkey
        - 🧠 Now with JSON persistence, PBKDF2 hashing, lockouts, and multi-user support!
    """)

# Register
elif choice == "Register":
    st.subheader("🆕 Register User")
    new_user = st.text_input("👤 Username")
    new_pass = st.text_input("🔑 Password", type="password")

    if st.button("Register"):
        if new_user in data_store:
            st.error("🚫 User already exists.")
        else:
            data_store[new_user] = {
                "password": hash_passkey(new_user, new_pass),
                "vault": {}
            }
            save_data(data_store)
            st.success("✅ Registered successfully!")

# Login
elif choice == "Login":
    st.subheader("🔐 Login")
    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    if st.button("Login"):
        if username in session["lockout_until"] and time.time() < session["lockout_until"][username]:
            remaining = int(session["lockout_until"][username] - time.time())
            st.warning(f"🚫 Locked out! Try again in {remaining} seconds.")
        elif username in data_store and data_store[username]["password"] == hash_passkey(username, password):
            st.session_state["user"] = username
            session["failed_attempts"][username] = 0
            st.success("✅ Logged in!")
        else:
            session["failed_attempts"][username] = session["failed_attempts"].get(username, 0) + 1
            st.error("❌ Invalid credentials.")
            if session["failed_attempts"][username] >= MAX_ATTEMPTS:
                session["lockout_until"][username] = time.time() + LOCKOUT_TIME
                st.warning(f"🚫 Too many attempts. Locked out for {LOCKOUT_TIME} seconds.")

# Store Data
elif choice == "Store Data":
    if "user" not in st.session_state:
        st.warning("🔑 Please login first.")
    else:
        st.subheader("📥 Store Data")
        text = st.text_area("📝 Enter your secret text")
        if st.button("Encrypt & Save"):
            encrypted = encrypt_data(text)
            data_store[st.session_state["user"]]["vault"][encrypted] = True
            save_data(data_store)
            st.success("✅ Stored successfully!")
            st.code(encrypted)

# Retrieve Data
elif choice == "Retrieve Data":
    if "user" not in st.session_state:
        st.warning("🔑 Please login first.")
    else:
        st.subheader("📤 Retrieve Data")
        encrypted = st.text_area("🔒 Paste Encrypted Text")
        if st.button("Decrypt"):
            if encrypted in data_store[st.session_state["user"]]["vault"]:
                try:
                    decrypted = decrypt_data(encrypted)
                    st.success("✅ Decrypted:")
                    st.code(decrypted)
                except Exception:
                    st.error("❌ Invalid encrypted text.")
            else:
                st.error("🚫 Not found in your vault.")


