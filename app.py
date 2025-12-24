import streamlit as st
import os
import hashlib
import base64
import requests
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ---------------- SAFE OPTIONAL IMPORT ----------------
try:
    from scapy.all import rdpcap
    SCAPY_OK = True
except:
    SCAPY_OK = False

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Cyber Security Toolkit", layout="wide")

for folder in ["encrypted_files", "decrypted_files", "stego_images"]:
    os.makedirs(folder, exist_ok=True)

# =====================================================
# 🔐 ENCRYPTION FUNCTIONS
# =====================================================
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
    return salt + encrypted, hashlib.sha256(data).hexdigest()

def decrypt_data(data, password, original_hash):
    salt = data[:16]
    enc = data[16:]
    key = derive_key(password, salt)
    dec = Fernet(key).decrypt(enc)
    if hashlib.sha256(dec).hexdigest() != original_hash:
        raise ValueError("Integrity failed")
    return dec

# =====================================================
# 🕷️ VULNERABILITY SCANNERS
# =====================================================
def scan_file(file):
    issues = []
    if file.size > 5 * 1024 * 1024:
        issues.append("Large file size detected")
    if file.name.endswith((".exe", ".bat", ".js")):
        issues.append("Executable file – potential risk")
    return issues or ["No major file vulnerabilities found"]

def scan_website(url):
    findings = []
    if not url.startswith("http"):
        return ["Invalid URL format"]
    try:
        r = requests.get(url, timeout=5)
        h = r.headers
        if "Content-Security-Policy" not in h:
            findings.append("Missing Content-Security-Policy")
        if "X-Frame-Options" not in h:
            findings.append("Missing X-Frame-Options")
        if "Strict-Transport-Security" not in h:
            findings.append("Missing HSTS header")
    except:
        findings.append("Website unreachable")
    return findings or ["No major web vulnerabilities found"]

# =====================================================
# 🎣 PHISHING LINK DETECTOR
# =====================================================
def phishing_check(url):
    flags = []
    if not url.startswith("http"):
        flags.append("URL does not start with http/https")
    if "@" in url:
        flags.append("Contains '@' symbol")
    if url.startswith("http://"):
        flags.append("Not using HTTPS")
    if url.count("-") > 3:
        flags.append("Too many hyphens in URL")
    return flags or ["No obvious phishing indicators"]

# =====================================================
# 🖼️ IMAGE STEGANOGRAPHY
# =====================================================
def hide_text(image, text):
    img = image.convert("RGB")
    pixels = img.load()
    text += "#####"
    bits = ''.join(format(ord(c), '08b') for c in text)
    i = 0
    for y in range(img.height):
        for x in range(img.width):
            if i < len(bits):
                r, g, b = pixels[x, y]
                pixels[x, y] = ((r & ~1) | int(bits[i]), g, b)
                i += 1
    return img

def reveal_text(image):
    img = image.convert("RGB")
    pixels = img.load()
    bits = ""
    for y in range(img.height):
        for x in range(img.width):
            bits += str(pixels[x, y][0] & 1)
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    msg = ""
    for c in chars:
        msg += chr(int(c, 2))
        if msg.endswith("#####"):
            return msg.replace("#####", "")
    return "No hidden message found"

# =====================================================
# 📡 PACKET ANALYZER
# =====================================================
def analyze_pcap(file):
    if not SCAPY_OK:
        return ["Scapy not available in this environment"]
    packets = rdpcap(file)
    summary = {}
    for pkt in packets:
        proto = pkt.summary().split()[0]
        summary[proto] = summary.get(proto, 0) + 1
    return summary

# =====================================================
# 📶 WIFI SECURITY ANALYZER
# =====================================================
def wifi_audit():
    return [
        "Use WPA2/WPA3 encryption",
        "Disable WPS",
        "Change default router credentials",
        "Use strong Wi-Fi password",
        "Update router firmware regularly"
    ]

# =====================================================
# 🧭 SIDEBAR NAVIGATION
# =====================================================
st.sidebar.title("🛡️ Cyber Security Toolkit")
page = st.sidebar.radio("Select Module", [
    "🔐 File Encryption",
    "🕷️ Vulnerability Scanner",
    "🎣 Phishing Detector",
    "🖼️ Image Steganography",
    "📡 Packet Analyzer",
    "📶 Wi-Fi Security Analyzer"
])

# =====================================================
# 🔐 FILE ENCRYPTION PAGE
# =====================================================
if page == "🔐 File Encryption":
    st.header("Secure File Encryption")
    f = st.file_uploader("Upload File")
    pwd = st.text_input("Password", type="password")
    if f and pwd and st.button("Encrypt"):
        enc, h = encrypt_data(f.read(), pwd)
        st.download_button("Download Encrypted File", enc, f.name + ".encrypted")

# =====================================================
# 🕷️ VULNERABILITY PAGE
# =====================================================
elif page == "🕷️ Vulnerability Scanner":
    opt = st.selectbox("Scan Type", ["File", "Website"])
    if opt == "File":
        f = st.file_uploader("Upload File")
        if f and st.button("Scan File"):
            st.write(scan_file(f))
    else:
        url = st.text_input("Enter Website URL")
        if url and st.button("Scan Website"):
            st.write(scan_website(url))

# =====================================================
# 🎣 PHISHING PAGE
# =====================================================
elif page == "🎣 Phishing Detector":
    url = st.text_input("Enter URL")
    if url and st.button("Check URL"):
        st.write(phishing_check(url))

# =====================================================
# 🖼️ STEGANOGRAPHY PAGE
# =====================================================
elif page == "🖼️ Image Steganography":
    img = st.file_uploader("Upload Image")
    msg = st.text_input("Secret Message")
    if img and msg and st.button("Hide Message"):
        st.image(hide_text(Image.open(img), msg))
    if img and st.button("Reveal Message"):
        st.write(reveal_text(Image.open(img)))

# =====================================================
# 📡 PACKET ANALYZER PAGE
# =====================================================
elif page == "📡 Packet Analyzer":
    pcap = st.file_uploader("Upload PCAP file")
    if pcap and st.button("Analyze"):
        st.write(analyze_pcap(pcap))

# =====================================================
# 📶 WIFI ANALYZER PAGE
# =====================================================
elif page == "📶 Wi-Fi Security Analyzer":
    st.subheader("Wi-Fi Security Best Practices")
    for tip in wifi_audit():
        st.success(tip)
