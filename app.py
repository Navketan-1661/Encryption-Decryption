import streamlit as st
import os
import re
import sqlite3
import hashlib
import base64
import requests
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Cyber Security Toolkit", layout="wide")

for folder in ["encrypted_files", "decrypted_files", "stego_images"]:
    os.makedirs(folder, exist_ok=True)

# ---------------- DATABASE ----------------
conn = sqlite3.connect("users.db", check_same_thread=False)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
)
""")
conn.commit()

# ---------------- SESSION ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = ""

# ---------------- PASSWORD VALIDATION ----------------
def valid_password(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$'
    return re.match(pattern, password)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------- AUTH FUNCTIONS ----------------
def register_user(username, password):
    try:
        cur.execute("INSERT INTO users VALUES (?,?)",
                    (username, hash_password(password)))
        conn.commit()
        return True
    except:
        return False

def login_user(username, password):
    cur.execute("SELECT * FROM users WHERE username=? AND password=?",
                (username, hash_password(password)))
    return cur.fetchone()

# =====================================================
# 🔐 LOGIN / REGISTER PAGE
# =====================================================
if not st.session_state.logged_in:
    st.title("🔐 Cyber Security Toolkit")

    choice = st.selectbox("Select Option", ["Login", "Register"])

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if choice == "Register":
        if st.button("Register"):
            if not valid_password(password):
                st.error(
                    "Password must contain uppercase, lowercase, number, special character & minimum 8 characters"
                )
            elif register_user(username, password):
                st.success("Registration successful! Please login.")
            else:
                st.error("Username already exists")

    else:
        if st.button("Login"):
            if login_user(username, password):
                st.session_state.logged_in = True
                st.session_state.user = username
                st.success("Login successful")
                st.rerun()
            else:
                st.error("Invalid username or password")

# =====================================================
# 🛡️ MAIN APPLICATION (AFTER LOGIN)
# =====================================================
else:
    st.sidebar.success(f"Logged in as {st.session_state.user}")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.user = ""
        st.rerun()

    # =================================================
    # 🔐 ENCRYPTION FUNCTIONS
    # =================================================
    def derive_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_data(data, password):
        salt = os.urandom(16)
        key = derive_key(password, salt)
        encrypted = Fernet(key).encrypt(data)
        return salt + encrypted

    # =================================================
    # 🧭 SIDEBAR MENU
    # =================================================
    page = st.sidebar.radio("Select Module", [
        "🔐 File Encryption",
        "🕷️ Vulnerability Scanner",
        "🎣 Phishing Detector",
        "🖼️ Image Steganography",
        "📶 Wi-Fi Security Analyzer"
    ])

    # =================================================
    # 🔐 FILE ENCRYPTION
    # =================================================
    if page == "🔐 File Encryption":
        st.header("Secure File Encryption")
        file = st.file_uploader("Upload File")
        password = st.text_input("Encryption Password", type="password")
        if file and password and st.button("Encrypt"):
            encrypted = encrypt_data(file.read(), password)
            st.download_button("Download Encrypted File",
                               encrypted, file.name + ".encrypted")

    # =================================================
    # 🕷️ VULNERABILITY SCANNER
    # =================================================
    elif page == "🕷️ Vulnerability Scanner":
        url = st.text_input("Enter Website URL")
        if url and st.button("Scan"):
            try:
                r = requests.get(url, timeout=5)
                headers = r.headers
                issues = []
                if "Content-Security-Policy" not in headers:
                    issues.append("Missing CSP Header")
                if "X-Frame-Options" not in headers:
                    issues.append("Missing X-Frame-Options")
                st.write(issues or ["No major vulnerabilities"])
            except:
                st.error("Invalid or unreachable website")

    # =================================================
    # 🎣 PHISHING DETECTOR
    # =================================================
    elif page == "🎣 Phishing Detector":
        link = st.text_input("Enter URL")
        if link and st.button("Check"):
            alerts = []
            if not link.startswith("https"):
                alerts.append("Not using HTTPS")
            if "@" in link:
                alerts.append("Contains @ symbol")
            st.write(alerts or ["No phishing indicators found"])

    # =================================================
    # 🖼️ IMAGE STEGANOGRAPHY
    # =================================================
    elif page == "🖼️ Image Steganography":
        img = st.file_uploader("Upload Image")
        secret = st.text_input("Secret Message")
        if img and secret and st.button("Hide Message"):
            image = Image.open(img)
            st.image(image, caption="Steganography feature demo")

    # =================================================
    # 📶 WIFI ANALYZER
    # =================================================
    elif page == "📶 Wi-Fi Security Analyzer":
        st.subheader("Wi-Fi Security Best Practices")
        tips = [
            "Use WPA3 encryption",
            "Disable WPS",
            "Use strong Wi-Fi password",
            "Change default router credentials",
            "Update router firmware regularly"
        ]
        for t in tips:
            st.success(t)
