# 📧 Phishing Email Detector 🚨  

A Python-based tool to analyze email text files and detect potential phishing attempts.  
This project was developed with the assistance of **AI (ChatGPT)** to improve detection logic.

---

## 🚀 Features
- Detects suspicious **keywords** (urgent, verify, account, etc.)
- Identifies **URLs** and flags shortened links (bit.ly, tinyurl, etc.)
- Saves results into a `report.txt`
- **Beautiful CLI output** with colors and banners
- Example phishing and safe emails included

---

## 📂 Project Structure
```
Phishing-Email-Detector/
│── README.md
│── requirements.txt
│── phishing_detector.py
│── report.txt
└── samples/
    ├── phishing_email.txt
    └── safe_email.txt
```

---

## ⚙️ Installation
```bash
git clone https://github.com/MurtazaSukhsar/project-1-Phishing-Email-Detector.git
cd Phishing-Email-Detector
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
```

---

## ▶️ Usage
```bash
python phishing_detector.py samples/phishing_email.txt
```

---

## 📊 Example Output

### 🚨 Phishing Detected
```
==================================================
   📧  PHISHING EMAIL DETECTOR  🚨
==================================================
   👨‍💻 Author: Murtaza Sukhsarwala
   🔗 GitHub: github.com/MurtazaSukhsar

🔍 Analyzing email...

⚠️  Suspicious Keywords Found:
   → urgent
   → verify
   → account

⚠️  Suspicious URLs Found:
   → http://fake-login.com

==================================================
🚨 RESULT: PHISHING DETECTED 🚨
==================================================
```

### ✅ Safe Email
```
==================================================
   📧  PHISHING EMAIL DETECTOR  🚨
==================================================
   👨‍💻 Author: Murtaza Sukhsarwala
   🔗 GitHub: github.com/MurtazaSukhsar

🔍 Analyzing email...

✅ No suspicious keywords detected.
✅ No suspicious URLs detected.

==================================================
✅ RESULT: EMAIL LOOKS SAFE ✅
==================================================
```

---

## ✅ Future Improvements
- GUI version using Tkinter
- Machine Learning model for smarter phishing detection
- Integration with email clients for real-time scanning

---

## 👨‍💻 Author
**Murtaza Sukhsarwala**  
📧 Email: murtazasukhsarwala58@gmail.com  
🔗 GitHub: [MurtazaSukhsar](https://github.com/MurtazaSukhsar)  


Using AI boosted productivity and allowed me to focus more on **cybersecurity concepts** rather than just syntax.
