# 🔎 URL Scanner – Malicious Link Detector

A simple Python tool that scans URLs and flags potential phishing or malicious patterns using **rule-based detection**.  
This project was developed with the assistance of **AI (ChatGPT)** to design detection logic, structure the code, and prepare professional documentation.

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

## 📂 Reports
All reports are saved automatically in the **reports/** folder with timestamped filenames, e.g.:
```
reports/report_2025-09-05_18-45-22.txt
```

---

👨💻 Author: Murtaza Sukhsarwala  
🔗 GitHub: [MurtazaSukhsar](https://github.com/MurtazaSukhsar)
