# 🛡️ YARA Malware Scanner with PDF Report

A lightweight and customizable malware scanning tool built with Python and the [YARA framework](https://virustotal.github.io/yara/).  
It scans files and directories for malicious patterns based on YARA rules, displays results in a **color-coded terminal view**, and generates a **PDF report**.

---

## 📌 Features
- 🔍 **File & Directory Scanning** – Supports scanning single files or entire directories recursively.
- 📂 **Custom YARA Rules** – Easily add or modify detection rules in `.yar` format.
- 🎨 **Color-coded Output** – Clear visual distinction between CLEAN and INFECTED files.
- 📄 **PDF Report Generation** – Professional PDF scan report for documentation and presentations.
- 🧾 **JSON Report Output** – Machine-readable format for automation.
- ⚡ **Progress Bar** – Visual feedback during large scans.
- 🛠 **Cross-Platform** – Works on Windows, Linux, and macOS.

---

## 📁 Project Structure
yara_scanner/
│── rules/ # YARA rule files (.yar)
│ ├── trojan_rule.yar
│ ├── phishing_rule.yar
│ ├── ransomware_rule.yar
│
│── samples/ # Sample files to scan
│ ├── harmless.txt
│ ├── trojan_test.txt
│ ├── phishing_test.txt
│
│── scanner.py # Main Python script
│── requirements.txt # Python dependencies


---

##  Installation

1. **Clone the repo**
   ```bash
   git clone https://github.com/mounika19004/YARA-Scanner.git
   cd YARA-Scanner
2. **Install Dependencies**
pip install -r requirements.txt

## Usage
python scanner.py -d /pathtoyourfile -r rules -o scan_report.pdf

