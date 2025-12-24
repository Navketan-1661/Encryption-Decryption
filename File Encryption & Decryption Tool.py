import streamlit as st
import os
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Secure File Encryption Tool", layout="centered")

os.makedirs("encrypted_files", exist_ok=True)
os.makedirs("decrypted_files", exist_ok=True)

ATTEMPT_LIMIT = 3
if "attempts" not in st.session_state:
    st.session_state.attempts = 0

# ---------------- FUNCTIONS ----------------
def generate_key_from_password(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def calculate_hash(data: bytes):
    return hashlib.sha256(data).hexdigest()

def encrypt_file(data, password):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    encrypted = Fernet(key).encrypt(data)
    file_hash = calculate_hash(data)
    return salt + encrypted, file_hash

def decrypt_file(data, password, original_hash):
    salt = data[:16]
    encrypted_data = data[16:]
    key = generate_key_from_password(password, salt)
    decrypted = Fernet(key).decrypt(encrypted_data)

    if calculate_hash(decrypted) != original_hash:
        raise ValueError("File integrity check failed")

    return decrypted

# ---------------- UI ----------------
st.title("🔐 Secure File Encryption & Decryption Tool")

menu = st.selectbox("Choose Action", ["Encrypt File", "Decrypt File"])

# ---------------- ENCRYPT ----------------
if menu == "Encrypt File":
    uploaded_file = st.file_uploader("Upload file to encrypt")
    password = st.text_input("Set Encryption Password", type="password")

    if uploaded_file and password:
        if st.button("Encrypt"):
            encrypted_data, file_hash = encrypt_file(uploaded_file.read(), password)

            filename = uploaded_file.name + ".encrypted"
            hashfile = filename + ".hash"

            with open(f"encrypted_files/{filename}", "wb") as f:
                f.write(encrypted_data)

            with open(f"encrypted_files/{hashfile}", "w") as h:
                h.write(file_hash)

            st.success("✅ File encrypted successfully")
            st.download_button("Download Encrypted File", encrypted_data, filename)

# ---------------- DECRYPT ----------------
elif menu == "Decrypt File":
    encrypted_file = st.file_uploader("Upload encrypted file")
    hash_file = st.file_uploader("Upload hash file")
    password = st.text_input("Enter Password", type="password")

    if encrypted_file and hash_file and password:
        if st.session_state.attempts >= ATTEMPT_LIMIT:
            st.error("❌ Too many wrong attempts. Access locked.")
            st.stop()

        if st.button("Decrypt"):
            try:
                original_hash = hash_file.read().decode()
                decrypted_data = decrypt_file(encrypted_file.read(), password, original_hash)

                filename = encrypted_file.name.replace(".encrypted", "")
                with open(f"decrypted_files/{filename}", "wb") as f:
                    f.write(decrypted_data)

                st.success("✅ File decrypted & integrity verified")
                st.download_button("Download Decrypted File", decrypted_data, filename)
                st.session_state.attempts = 0

            except:
                st.session_state.attempts += 1
                st.error(f"❌ Wrong password or tampered file (Attempt {st.session_state.attempts}/3)")
