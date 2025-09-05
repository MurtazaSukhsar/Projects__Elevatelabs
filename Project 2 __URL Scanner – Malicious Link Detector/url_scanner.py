import re
import sys
from urllib.parse import urlparse
import os
import datetime

# Suspicious keywords often found in phishing URLs
SUSPICIOUS_KEYWORDS = ["login", "verify", "update", "secure", "account", "bank", "confirm"]

# Suspicious domains (shorteners, free hosting, etc.)
SUSPICIOUS_DOMAINS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "weebly", "000webhost", "freehosting"]

def banner():
    print("="*60)
    print("               🔎  URL SCANNER - MALICIOUS LINK DETECTOR")
    print("="*60)
    print("    👨‍💻Author: Murtaza Sukhsarwala")
    print("   🔗 GitHub: github.com/MurtazaSukhsar\n")

def is_ip_address(url):
    """Check if URL uses an IP instead of a domain."""
    return bool(re.match(r"^(http|https)://(\d{1,3}\.){3}\d{1,3}", url))

def ensure_scheme(u: str) -> str:
    """Add http:// if user pasted URL without scheme."""
    if not re.match(r"^https?://", u, re.IGNORECASE):
        return "http://" + u
    return u

def analyze_url(raw_url):
    url = ensure_scheme(raw_url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

    issues = []

    # Suspicious domain checks
    for bad in SUSPICIOUS_DOMAINS:
        if bad in domain:
            issues.append(f"Suspicious domain/shortener detected: {domain}")

    # IP-based URL
    if is_ip_address(url):
        issues.append("URL uses an IP address instead of domain (Suspicious)")

    # Suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            issues.append(f"Keyword '{keyword}' found in URL")

    # Length / complexity
    if len(url) > 100:
        issues.append("URL is unusually long (may be obfuscated)")

    # Too many special characters in path/query
    special_count = len(re.findall(r"[^\w./:?=&%-]", path_query))
    if special_count >= 5:
        issues.append("URL contains many special characters (potential obfuscation)")

    # Punycode (IDN) domains
    if "xn--" in domain:
        issues.append("Punycode (IDN) domain detected (watch for homograph attacks)")

    return url, issues

def save_report(results, report_dir="reports"):
    # Ensure reports folder exists
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    # Create filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = os.path.join(report_dir, f"report_{timestamp}.txt")

    with open(report_file, "w") as f:
        f.write("URL Scan Report\n")
        f.write("="*40 + "\n\n")
        for url, issues in results:
            f.write(f"URL: {url}\n")
            if issues:
                for issue in issues:
                    f.write(f"  - {issue}\n")
                f.write("  RESULT: SUSPICIOUS\n\n")
            else:
                f.write("  RESULT: SAFE\n\n")

    print(f"\n📄 Report saved to {report_file}")

if __name__ == "__main__":
    banner()

    if len(sys.argv) < 2:
        print("Usage: python url_scanner.py <URL | file.txt>")
        print("Example: python url_scanner.py bit.ly/fake-login")
        sys.exit(1)

    input_arg = sys.argv[1]
    results = []

    if os.path.isfile(input_arg):
        with open(input_arg, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"📂 Scanning {len(urls)} URLs from file...\n")
        for url in urls:
            results.append(analyze_url(url))
    else:
        results.append(analyze_url(input_arg))

    # Show results in CLI
    for url, issues in results:
        print(f"\n🔍 Scanning URL: {url}")
        if issues:
            print("⚠ Issues Found:")
            for issue in issues:
                print(f"   → {issue}")
            print("🚨 RESULT: SUSPICIOUS URL 🚨")
        else:
            print("✅ No issues detected")
            print("✔ RESULT: URL LOOKS SAFE ✔")

    # Save report automatically in reports/
    save_report(results)
