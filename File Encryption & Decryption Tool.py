import streamlit as st
import os

# ---------- SAFE IMPORT ----------
try:
    from cryptography.fernet import Fernet
except ImportError:
    st.error("❌ cryptography library not installed.")
    st.info("Add 'cryptography' to requirements.txt and restart the app.")
    st.stop()

# ---------- CONFIG ----------
st.set_page_config(page_title="File Encryption Tool", layout="centered")

KEY_FILE = "secret.key"
ENC_DIR = "encrypted_files"
DEC_DIR = "decrypted_files"

os.makedirs(ENC_DIR, exist_ok=True)
os.makedirs(DEC_DIR, exist_ok=True)

# ---------- FUNCTIONS ----------
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return None
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_data(data, key):
    return Fernet(key).encrypt(data)

def decrypt_data(data, key):
    return Fernet(key).decrypt(data)

# ---------- UI ----------
st.title("🔐 File Encryption & Decryption Tool")

menu = st.radio("Choose Action", ["Generate Key", "Encrypt File", "Decrypt File"])

# ---------- GENERATE KEY ----------
if menu == "Generate Key":
    if st.button("Generate Secret Key"):
        key = generate_key()
        st.success("✅ Key Generated Successfully")
        st.code(key.decode())

# ---------- ENCRYPT ----------
elif menu == "Encrypt File":
    uploaded_file = st.file_uploader("Upload File to Encrypt")

    if uploaded_file:
        key = load_key()
        if key is None:
            st.warning("⚠️ Generate key first!")
        elif st.button("Encrypt"):
            encrypted = encrypt_data(uploaded_file.read(), key)
            filename = uploaded_file.name + ".encrypted"

            with open(f"{ENC_DIR}/{filename}", "wb") as f:
                f.write(encrypted)

            st.success("✅ File Encrypted")
            st.download_button("Download Encrypted File", encrypted, filename)

# ---------- DECRYPT ----------
elif menu == "Decrypt File":
    encrypted_file = st.file_uploader("Upload Encrypted File")

    if encrypted_file:
        key = load_key()
        if key is None:
            st.warning("⚠️ Key file not found!")
        elif st.button("Decrypt"):
            try:
                decrypted = decrypt_data(encrypted_file.read(), key)
                original_name = encrypted_file.name.replace(".encrypted", "")

                with open(f"{DEC_DIR}/{original_name}", "wb") as f:
                    f.write(decrypted)

                st.success("✅ File Decrypted")
                st.download_button("Download Decrypted File", decrypted, original_name)

            except Exception:
                st.error("❌ Invalid key or corrupted file")
