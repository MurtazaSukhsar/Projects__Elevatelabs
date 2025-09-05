# 🔎 URL Scanner – Malicious Link Detector

A simple Python tool that scans URLs and flags potential phishing or malicious patterns using **rule-based detection**.  
This project was developed with the assistance of **AI.**

---

## 🚀 Features
- Detects **suspicious domains** (bit.ly, tinyurl, free hosting, etc.)
- Flags **IP-based URLs** instead of domains
- Identifies **phishing keywords** in links (login, verify, account, bank, etc.)
- Detects **unusually long or obfuscated links**
- Warns about **Punycode (IDN) domains** that may hide homograph attacks
- Scans a **single URL** or a **list of URLs from a file**
- ✅ **Automatically saves reports** in a `reports/` folder with a unique **timestamped filename**

---

  ## 📂 Project Structure
  ```
  URL-Scanner/
│── README.md
│── url_scanner.py
│── samples/
│ ├── urls.txt # Example list of test URLs
│ └── safe_urls.txt # Example list of safe URLs
└── reports/
├── report_2025-09-05_18-42-31.txt
├── report_2025-09-05_18-50-12.txt

```
---

## ⚙️ Installation
1. Clone the repository:
```bash
git clone https://github.com/MurtazaSukhsar/URL-Scanner.git
cd URL-Scanner


2. (Recommended) Create a *virtual environment* to keep dependencies isolated:

python3 -m venv venv

source venv/bin/activate      # On Linux/Mac


3. Install dependencies (currently none required, script uses only Python built-ins):
bash
pip install --upgrade pip

```

---

## 🛠 Usage

### 1️⃣ Scan a Single URL
```bash
python url_scanner.py http://bit.ly/fakebank-login
```

### 2️⃣ Scan URLs from File
```bash
python url_scanner.py samples/urls.txt
```

---
## 📊 Example Output

### 🚨 Suspicious URL
```
============================================================
               🔎  URL SCANNER - MALICIOUS LINK DETECTOR
============================================================
   👨‍💻 Author: Murtaza Sukhsarwala
   🔗 GitHub: github.com/MurtazaSukhsar

🔍 Scanning URL: http://bit.ly/fakebank-login
⚠ Issues Found:
   → Suspicious domain/shortener detected: bit.ly
   → Keyword 'login' found in URL
🚨 RESULT: SUSPICIOUS URL 🚨

📄 Report saved to reports/report_2025-09-05_18-42-31.txt

```
### ✅ Safe URL
```
============================================================
               🔎  URL SCANNER - MALICIOUS LINK DETECTOR
============================================================
   👨‍💻 Author: Murtaza Sukhsarwala
   🔗 GitHub: github.com/MurtazaSukhsar

🔍 Scanning URL: https://Youtube.com
✅ No issues detected

✔ RESULT: URL LOOKS SAFE ✔

📄 Report saved to reports/report_2025-09-05_18-43-22.txt

```
---

## 📂 Reports
All reports are saved automatically in the **reports/**
```
folder with timestamped filenames, e.g.:

reports/report_2025-09-05_18-45-22.txt
```
---

## ✅ Future Improvements
- Integrate with VirusTotal / URLHaus APIs for real-time threat lookup

- Add GUI version (Tkinter) for a desktop app

- Export results to JSON/CSV for easier reporting

---

##  👨‍💻Author
**Murtaza Sukhsarwala**
📧 Email: murtazasukhsarwala58@gmail.com  
🔗 GitHub: [MurtazaSukhsar](https://github.com/MurtazaSukhsar)
