import streamlit as st
from cryptography.fernet import Fernet
import os

# ------------------ CONFIG ------------------
st.set_page_config(page_title="File Encryption Tool", layout="centered")

if not os.path.exists("encrypted_files"):
    os.mkdir("encrypted_files")

if not os.path.exists("decrypted_files"):
    os.mkdir("decrypted_files")

# ------------------ FUNCTIONS ------------------
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    return open("secret.key", "rb").read()

def encrypt_file(file, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(file.read())
    return encrypted

def decrypt_file(file, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(file.read())
    return decrypted

# ------------------ UI ------------------
st.title("🔐 File Encryption & Decryption Tool")

menu = ["Generate Key", "Encrypt File", "Decrypt File"]
choice = st.selectbox("Select Action", menu)

# ------------------ GENERATE KEY ------------------
if choice == "Generate Key":
    if st.button("Generate Secret Key"):
        key = generate_key()
        st.success("Secret Key Generated Successfully!")
        st.code(key.decode())

# ------------------ ENCRYPT FILE ------------------
elif choice == "Encrypt File":
    uploaded_file = st.file_uploader("Upload File to Encrypt")
    
    if uploaded_file:
        if st.button("Encrypt"):
            key = load_key()
            encrypted_data = encrypt_file(uploaded_file, key)

            file_path = f"encrypted_files/{uploaded_file.name}.encrypted"
            with open(file_path, "wb") as f:
                f.write(encrypted_data)

            st.success("File Encrypted Successfully!")
            st.download_button("Download Encrypted File", encrypted_data, file_name=uploaded_file.name + ".encrypted")

# ------------------ DECRYPT FILE ------------------
elif choice == "Decrypt File":
    encrypted_file = st.file_uploader("Upload Encrypted File")

    if encrypted_file:
        if st.button("Decrypt"):
            try:
                key = load_key()
                decrypted_data = decrypt_file(encrypted_file, key)

                file_name = encrypted_file.name.replace(".encrypted", "")
                file_path = f"decrypted_files/{file_name}"

                with open(file_path, "wb") as f:
                    f.write(decrypted_data)

                st.success("File Decrypted Successfully!")
                st.download_button("Download Decrypted File", decrypted_data, file_name=file_name)

            except:
                st.error("Invalid Key or Corrupted File!")
