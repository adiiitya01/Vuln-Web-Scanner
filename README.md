# Vuln-Web-Scanner

Automated web vulnerability scanner that detects OWASP Top 10 vulnerabilities and generates structured security reports.

Built as a practical security tool — not a coursework project. Tested against DVWA and WebGoat in isolated lab environments.

---

## What it detects

- SQL Injection (error-based and time-based)
- Cross-Site Scripting (XSS) — reflected and stored
- Cross-Site Request Forgery (CSRF)
- Missing/misconfigured HTTP security headers
- Insecure cookie attributes (Secure, HttpOnly, SameSite flags)

---

## How it works

1. Takes a target URL as input (permission-based testing only)
2. Sends crafted HTTP payloads using Python `requests`
3. Analyses responses for injection vectors and misconfigurations
4. Generates a severity-rated HTML report with remediation steps

---

## Tech stack

| Component | Technology |
|---|---|
| Backend | Python 3, Flask |
| HTTP engine | Python `requests` |
| Payload delivery | Custom HTTP payload builder |
| Reporting | HTML report generator |
| Test targets | DVWA, WebGoat |

---

## Setup

```bash
git clone https://github.com/adiiitya01/Vuln-Web-Scanner.git
cd Vuln-Web-Scanner
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` and enter a target URL to begin scanning.

---

## Sample output

```
[*] Starting scan on: http://testphp.vulnweb.com
[+] SQL Injection found — parameter: id (error-based)
[+] XSS found — parameter: search
[-] CSRF: No token detected on POST forms
[!] Missing headers: X-Frame-Options, Content-Security-Policy
[*] Report saved: report_20260201_143022.html
```

---

## Legal disclaimer

This tool is intended for authorized security testing only.
Never run against systems without explicit written permission.
The author is not responsible for misuse.

---

## Skills demonstrated

`Penetration Testing` `Web Application Security` `OWASP Top 10` `Python` `Flask` `Security Automation` `Vulnerability Assessment`

---

## Author

Aditya Udugade — CEH Certified | Mumbai

[LinkedIn](https://linkedin.com/in/aditya-udugade-28147b345) · 

[GitHub](https://github.com/adiiitya01)
