import os
import sys
import tldextract
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# List of suspicious keywords
KEYWORDS = ["urgent", "verify","click here", "limited time",
            "password reset", "confirm", "lottery"]# Suspicious keyword phrases instead of single words
SUSPICIOUS_PHRASES = [
    "verify your account",
    "reset your password",
    "click here to login",
    "urgent action required",
    "update billing information",
    "confirm your identity",
    "login immediately",
    "unusual activity detected"
]

def check_suspicious_keywords(email_text):
    found_phrases = []
    lowered = email_text.lower()
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in lowered:
            found_phrases.append(phrase)
    return found_phrases

def banner():
    print(Fore.CYAN + "="*50)
    print(Fore.MAGENTA + "   📧  PHISHING EMAIL DETECTOR  🚨")
    print(Fore.CYAN + "="*50)
    print(Fore.YELLOW + "   👨‍💻 Author: Murtaza Sukhsarwala")
    print(Fore.YELLOW + "   🔗 GitHub: github.com/MurtazaSukhsar\n")


def analyze_email(file_path):
    if not os.path.exists(file_path):
        print(Fore.RED + f"[!] File '{file_path}' not found. Please check the path.")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().lower()

    suspicious_keywords = [word for word in KEYWORDS if word in content]
    suspicious_urls = []

    words = content.split()
    for word in words:
        if word.startswith("http://") or word.startswith("https://"):
            extracted = tldextract.extract(word)
            domain = f"{extracted.domain}.{extracted.suffix}"
            suspicious_urls.append(word)

            if "bit.ly" in word or "tinyurl" in word:
                suspicious_urls.append(f"Shortened URL detected: {word}")

    # Result
    print(Fore.YELLOW + "🔍 Analyzing email...\n")

    if suspicious_keywords:
        print(Fore.RED + "⚠️  Suspicious Keywords Found:")
        for k in suspicious_keywords:
            print(Fore.LIGHTRED_EX + f"   → {k}")
    else:
        print(Fore.GREEN + "✅ No suspicious keywords detected.")

    print()

    if suspicious_urls:
        print(Fore.RED + "⚠️  Suspicious URLs Found:")
        for url in suspicious_urls:
            print(Fore.LIGHTRED_EX + f"   → {url}")
    else:
        print(Fore.GREEN + "✅ No suspicious URLs detected.")

    print("\n" + Fore.CYAN + "="*50)

    if suspicious_keywords or suspicious_urls:
        result = Fore.RED + Style.BRIGHT + "🚨 RESULT: PHISHING DETECTED 🚨"
    else:
        result = Fore.GREEN + Style.BRIGHT + "✅ RESULT: EMAIL LOOKS SAFE ✅"

    print(result)
    print(Fore.CYAN + "="*50)

    # Save to report.txt
    with open("report.txt", "w") as report:
        report.write("Email Analysis Report\n")
        report.write("=====================\n\n")
        report.write("Suspicious keywords: " + ", ".join(suspicious_keywords) + "\n")
        report.write("Suspicious URLs: " + ", ".join(suspicious_urls) + "\n")
        report.write("Result: " + ("PHISHING DETECTED" if suspicious_keywords or suspicious_urls else "EMAIL SAFE") + "\n")


if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        print(Fore.YELLOW + "Usage: python phishing_detector.py <email_file>")
    else:
        analyze_email(sys.argv[1])

def banner():
    print(Fore.CYAN + "="*50)
    print(Fore.MAGENTA + "   📧  PHISHING EMAIL DETECTOR  🚨")
    print(Fore.CYAN + "="*50)
    print(Fore.YELLOW + "   👨‍💻 Author: Murtaza Sukhsarwala")
    print(Fore.YELLOW + "   🔗 GitHub: github.com/MurtazaSukhsar\n")
