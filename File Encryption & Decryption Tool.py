import streamlit as st
import os
import hashlib
import base64
import requests
import validators
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from scapy.all import rdpcap

# ---------------- BASIC CONFIG ----------------
st.set_page_config(page_title="Cyber Security Toolkit", layout="wide")

for d in ["encrypted_files", "decrypted_files", "stego_images"]:
    os.makedirs(d, exist_ok=True)

# ======================================================
# 🔐 ENCRYPTION FUNCTIONS
# ======================================================
def gen_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = gen_key(password, salt)
    encrypted = Fernet(key).encrypt(data)
    return salt + encrypted, hashlib.sha256(data).hexdigest()

def decrypt_data(data, password, original_hash):
    salt = data[:16]
    enc = data[16:]
    key = gen_key(password, salt)
    dec = Fernet(key).decrypt(enc)
    if hashlib.sha256(dec).hexdigest() != original_hash:
        raise ValueError("Integrity failed")
    return dec

# ======================================================
# 🕷️ VULNERABILITY SCANNERS
# ======================================================
def scan_file(file):
    issues = []
    if file.size > 5 * 1024 * 1024:
        issues.append("Large file size")
    if file.name.endswith((".exe", ".bat", ".js")):
        issues.append("Executable file detected")
    return issues or ["No major file risks found"]

def scan_website(url):
    findings = []
    try:
        r = requests.get(url, timeout=5)
        h = r.headers
        if "Content-Security-Policy" not in h:
            findings.append("Missing CSP header")
        if "X-Frame-Options" not in h:
            findings.append("Missing X-Frame-Options")
        if "Strict-Transport-Security" not in h:
            findings.append("Missing HSTS")
    except:
        findings.append("Invalid or unreachable URL")
    return findings or ["No major web vulnerabilities"]

# ======================================================
# 🎣 PHISHING LINK DETECTOR
# ======================================================
def phishing_check(url):
    flags = []
    if not validators.url(url):
        flags.append("Invalid URL format")
    if "@" in url:
        flags.append("URL contains @ symbol")
    if url.count("-") > 3:
        flags.append("Suspicious hyphen usage")
    if url.startswith("http://"):
        flags.append("Not using HTTPS")
    return flags or ["No obvious phishing indicators"]

# ======================================================
# 🖼️ IMAGE STEGANOGRAPHY
# ======================================================
def hide_text(image, text):
    img = image.convert("RGB")
    data = img.load()
    text += "#####"
    bits = ''.join(format(ord(c), '08b') for c in text)
    idx = 0

    for y in range(img.height):
        for x in range(img.width):
            if idx < len(bits):
                r, g, b = data[x, y]
                r = (r & ~1) | int(bits[idx])
                data[x, y] = (r, g, b)
                idx += 1
    return img

def reveal_text(image):
    img = image.convert("RGB")
    data = img.load()
    bits = ""

    for y in range(img.height):
        for x in range(img.width):
            bits += str(data[x, y][0] & 1)

    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    text = ""
    for c in chars:
        text += chr(int(c, 2))
        if text.endswith("#####"):
            return text.replace("#####", "")
    return "No hidden message"

# ======================================================
# 📡 PACKET ANALYZER (PCAP)
# ======================================================
def analyze_pcap(file):
    packets = rdpcap(file)
    summary = {}
    for pkt in packets:
        proto = pkt.summary().split()[0]
        summary[proto] = summary.get(proto, 0) + 1
    return summary

# ======================================================
# 📶 WIFI SECURITY ANALYZER (AUDIT)
# ======================================================
def wifi_audit():
    return [
        "Check WPA2/WPA3 encryption enabled",
        "Disable WPS",
        "Use strong Wi-Fi password",
        "Change default router credentials",
        "Update router firmware"
    ]

# ======================================================
# 🧭 SIDEBAR NAVIGATION
# ======================================================
st.sidebar.title("🛡️ Cyber Security Toolkit")
page = st.sidebar.radio("Select Module", [
    "🔐 File Encryption",
    "🕷️ Vulnerability Scanner",
    "🎣 Phishing Detector",
    "🖼️ Image Steganography",
    "📡 Packet Analyzer",
    "📶 Wi-Fi Security Analyzer"
])

# ======================================================
# 🔐 PAGE 1
# ======================================================
if page == "🔐 File Encryption":
    st.header("Secure File Encryption")
    f = st.file_uploader("Upload File")
    pwd = st.text_input("Password", type="password")
    if f and pwd and st.button("Encrypt"):
        enc, h = encrypt_data(f.read(), pwd)
        st.download_button("Download Encrypted", enc, f.name + ".encrypted")

# ======================================================
# 🕷️ PAGE 2
# ======================================================
elif page == "🕷️ Vulnerability Scanner":
    choice = st.selectbox("Scan Type", ["File", "Website"])
    if choice == "File":
        f = st.file_uploader("Upload File")
        if f and st.button("Scan"):
            st.write(scan_file(f))
    else:
        url = st.text_input("Website URL")
        if url and st.button("Scan"):
            st.write(scan_website(url))

# ======================================================
# 🎣 PAGE 3
# ======================================================
elif page == "🎣 Phishing Detector":
    url = st.text_input("Enter URL")
    if url and st.button("Check"):
        st.write(phishing_check(url))

# ======================================================
# 🖼️ PAGE 4
# ======================================================
elif page == "🖼️ Image Steganography":
    img = st.file_uploader("Upload Image")
    msg = st.text_input("Secret Message")
    if img and msg and st.button("Hide Message"):
        result = hide_text(Image.open(img), msg)
        st.image(result)
    if img and st.button("Reveal Message"):
        st.write(reveal_text(Image.open(img)))

# ======================================================
# 📡 PAGE 5
# ======================================================
elif page == "📡 Packet Analyzer":
    pcap = st.file_uploader("Upload PCAP file")
    if pcap and st.button("Analyze"):
        st.write(analyze_pcap(pcap))

# ======================================================
# 📶 PAGE 6
# ======================================================
elif page == "📶 Wi-Fi Security Analyzer":
    st.subheader("Wi-Fi Security Best Practices")
    for tip in wifi_audit():
        st.success(tip)
