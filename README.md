# 🕵️‍♂️ Covert Database Detection & Hiding Tool

An advanced desktop GUI application built using Python and Tkinter for detecting, hiding, and recovering covert databases using multiple cybersecurity and steganographic techniques.

---

## 🧠 Features

### 🔍 Detection Capabilities
- **Local Disk Scan**: Identify database files on local drives.
- **Network Scan**: Discover accessible databases (MySQL, PostgreSQL, MSSQL) on the local network.
- **Hidden DB Detection**: Detect concealed databases using:
  - Rename Extension
  - LSB Steganography
  - Cryptography
  - File Chunk Split
  - Alternate Data Streams (ADS)
  - Machine Learning-based Obfuscation
  - Hybrid Method (combined techniques)

### 🛡️ Hiding Techniques
- Rename database files with misleading extensions.
- Embed databases into images using LSB steganography.
- Encrypt files using Fernet encryption.
- Split databases into small chunks.
- Store databases in NTFS alternate data streams (Windows only).
- Obfuscate using lightweight ML signatures.
- Combine encryption and obfuscation for hybrid hiding.

### 📊 Performance Analytics
- Analyze detection methods on:
  - Time taken
  - Detection count
  - Success rate
  - Processing speed
  - Precision and efficiency score
- Visual graphs using `matplotlib` in a notebook-style view.

### 🧰 Additional Features
- Built-in **documentation and quick start guide**
- Persistent encryption keys
- Responsive multi-threaded scanning
- Modern UI with light/dark themes

---

## 🔧 Requirements

- Python 3.8+
- Dependencies:
  ```bash
  pip install numpy matplotlib scikit-learn pillow cryptography stegano nmap
