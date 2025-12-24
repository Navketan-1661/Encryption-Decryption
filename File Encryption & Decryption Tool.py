import streamlit as st
import os
import hashlib
import base64
import requests
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Cyber Security Tool", layout="wide")

os.makedirs("encrypted_files", exist_ok=True)
os.makedirs("decrypted_files", exist_ok=True)

ATTEMPT_LIMIT = 3
if "attempts" not in st.session_state:
    st.session_state.attempts = 0

# ---------------- ENCRYPTION FUNCTIONS ----------------
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()

def encrypt_file(data, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    encrypted = Fernet(key).encrypt(data)
    return salt + encrypted, sha256_hash(data)

def decrypt_file(data, password, original_hash):
    salt = data[:16]
    encrypted_data = data[16:]
    key = generate_key(password, salt)
    decrypted = Fernet(key).decrypt(encrypted_data)

    if sha256_hash(decrypted) != original_hash:
        raise ValueError("Integrity check failed")
    return decrypted

# ---------------- VULNERABILITY FUNCTIONS ----------------
def scan_file(file):
    findings = []
    if file.size > 5 * 1024 * 1024:
        findings.append("Large file size – possible payload risk")
    if file.name.endswith((".exe", ".bat", ".js")):
        findings.append("Executable file detected")
    if not findings:
        findings.append("No common file vulnerabilities found")
    return findings

def scan_website(url):
    results = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        if "X-Frame-Options" not in headers:
            results.append("Missing X-Frame-Options (Clickjacking risk)")
        if "Content-Security-Policy" not in headers:
            results.append("Missing Content-Security-Policy")
        if "Strict-Transport-Security" not in headers:
            results.append("Missing HSTS header")
        if not results:
            results.append("No major header vulnerabilities found")
    except:
        results.append("Website unreachable or invalid URL")

    return results

# ---------------- SIDEBAR NAVIGATION ----------------
st.sidebar.title("🛡️ Cyber Security Tool")
page = st.sidebar.radio(
    "Select Module",
    ["🔐 File Encryption", "🕷️ Vulnerability Scanner"]
)

# ===================================================
# 🔐 PAGE 1: FILE ENCRYPTION
# ===================================================
if page == "🔐 File Encryption":
    st.title("🔐 Secure File Encryption & Decryption")

    action = st.selectbox("Choose Action", ["Encrypt File", "Decrypt File"])

    # ---------- ENCRYPT ----------
    if action == "Encrypt File":
        file = st.file_uploader("Upload File")
        password = st.text_input("Set Password", type="password")

        if file and password and st.button("Encrypt"):
            encrypted, file_hash = encrypt_file(file.read(), password)

            with open(f"encrypted_files/{file.name}.encrypted", "wb") as f:
                f.write(encrypted)

            with open(f"encrypted_files/{file.name}.hash", "w") as h:
                h.write(file_hash)

            st.success("File encrypted successfully")
            st.download_button("Download Encrypted File", encrypted, file.name + ".encrypted")

    # ---------- DECRYPT ----------
    else:
        encrypted_file = st.file_uploader("Upload Encrypted File")
        hash_file = st.file_uploader("Upload Hash File")
        password = st.text_input("Enter Password", type="password")

        if encrypted_file and hash_file and password:
            if st.session_state.attempts >= ATTEMPT_LIMIT:
                st.error("Too many wrong attempts")
                st.stop()

            if st.button("Decrypt"):
                try:
                    original_hash = hash_file.read().decode()
                    decrypted = decrypt_file(encrypted_file.read(), password, original_hash)

                    filename = encrypted_file.name.replace(".encrypted", "")
                    with open(f"decrypted_files/{filename}", "wb") as f:
                        f.write(decrypted)

                    st.success("File decrypted successfully")
                    st.download_button("Download Decrypted File", decrypted, filename)
                    st.session_state.attempts = 0

                except:
                    st.session_state.attempts += 1
                    st.error(f"Wrong password or tampered file ({st.session_state.attempts}/3)")

# ===================================================
# 🕷️ PAGE 2: VULNERABILITY SCANNER
# ===================================================
else:
    st.title("🕷️ Vulnerability Scanner")

    scan_type = st.selectbox("Scan Type", ["File Scanner", "Website Scanner"])

    # ---------- FILE SCANNER ----------
    if scan_type == "File Scanner":
        file = st.file_uploader("Upload File to Scan")

        if file and st.button("Scan File"):
            results = scan_file(file)
            st.subheader("Scan Results")
            for r in results:
                st.warning(r)

    # ---------- WEBSITE SCANNER ----------
    else:
        url = st.text_input("Enter Website URL (https://example.com)")

        if url and st.button("Scan Website"):
            results = scan_website(url)
            st.subheader("Scan Results")
            for r in results:
                st.warning(r)
