# Api-vulnerability-scanner
A Python-based CLI tool that scans HTTP requests (Burp Suite format) for API vulnerabilities like SQLi, XSS, LFI, SSRF, and Command Injection. It also detects missing security headers and CORS misconfigurations-ideal for automating API security assessments.
## 🚀 Features

- SQL Injection detection
- XSS (Cross-Site Scripting) detection
- Local File Inclusion (LFI)
- Server Side Request Forgery (SSRF)
- Command Injection
- Missing Security Headers
- CORS misconfiguration

## 🛠️ Installation

```bash
git clone https://github.com/vraj002/Api-vulnerability-scanner.git
cd Api-vulnerability-scanner
pip install -r requirements.txt
```

Usage

Run the script using the command line:

- ****
  ** help menu**
  ```bash
  python3 vulnsec.py -h
  ```

- **Scan a HTTP request file:**
  ```bash
  python3 vulnsec.py -f file.txt -a
  ```

- **URL Based Scan :**
  ```bash
  python3 vulnsec.py -u http://example.com
  ```
