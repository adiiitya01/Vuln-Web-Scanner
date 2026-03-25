# 🛡️ Web Vulnerability Scanner

A Python-based command-line tool for detecting common web application vulnerabilities — including **SQL Injection**, **Cross-Site Scripting (XSS)**, and open ports — built for educational purposes and authorized penetration testing.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Security](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red?style=flat-square)

---

## 📸 Preview

```
╔══════════════════════════════════════════════════════════════╗
║          Web Vulnerability Scanner v1.0                      ║
║          SQL Injection | XSS | Port Scanner                  ║
╚══════════════════════════════════════════════════════════════╝
  [!] For educational and authorized testing purposes only.

[*] Target URL : https://testphp.vulnweb.com
[*] Max Pages  : 50
[*] Threads    : 10

[*] Testing connectivity...
[+] Connected! HTTP 200

 VULNERABILITY FOUND 
  Type   : SQL Injection
  URL    : https://testphp.vulnweb.com/listproducts.php?cat='
  Payload: ' OR '1'='1
  Detail : SQL error detected: 'warning: mysql'
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 🕷️ **Web Crawler** | Automatically crawls the target site and extracts all links and forms |
| 💉 **SQL Injection** | Tests URL parameters and form fields with 10 common SQLi payloads |
| ⚡ **XSS Detection** | Checks for reflected XSS across GET/POST parameters with 8 payloads |
| 🔍 **Port Scanner** | TCP connect scan across 17 common ports (like Nmap basics) |
| 🧵 **Multithreading** | Parallel scanning with configurable thread pool for speed |
| 🎨 **Colored Output** | Clean, color-coded terminal output using `colorama` |
| 📄 **Report Export** | Save results to JSON or plain-text reports |
| 🛡️ **Error Handling** | Handles invalid URLs, timeouts, DNS failures, and redirects gracefully |

---

## 🗂️ Project Structure

```
web-vuln-scanner/
│
├── web_vuln_scanner.py     # Main scanner script
├── README.md               # Project documentation
└── requirements.txt        # Python dependencies
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/web-vuln-scanner.git
cd web-vuln-scanner
```

### 2. Install dependencies

```bash
pip install requests beautifulsoup4 colorama
```

Or using the requirements file:

```bash
pip install -r requirements.txt
```

> **Python 3.8+** is required.

---

## 🚀 Usage

### Basic scan

```bash
python web_vuln_scanner.py --url https://testphp.vulnweb.com
```

### Save report to JSON

```bash
python web_vuln_scanner.py --url https://testphp.vulnweb.com --output report.json
```

### Save report to text file

```bash
python web_vuln_scanner.py --url https://testphp.vulnweb.com --output-txt report.txt
```

### Fast scan (more threads, fewer pages)

```bash
python web_vuln_scanner.py --url https://testphp.vulnweb.com --threads 15 --max-pages 20
```

### Skip port scan (vulnerability testing only)

```bash
python web_vuln_scanner.py --url https://testphp.vulnweb.com --no-ports
```

### Only test SQL injection (skip XSS and ports)

```bash
python web_vuln_scanner.py --url https://testphp.vulnweb.com --no-xss --no-ports
```

---

## 🔧 CLI Options

| Flag | Default | Description |
|---|---|---|
| `--url` | *(required)* | Target URL to scan |
| `--max-pages` | `50` | Maximum pages to crawl |
| `--threads` | `10` | Number of concurrent threads |
| `--no-ports` | `False` | Skip port scanning |
| `--no-sqli` | `False` | Skip SQL injection testing |
| `--no-xss` | `False` | Skip XSS testing |
| `--output` | `None` | Export results as JSON file |
| `--output-txt` | `None` | Export results as text file |
| `--user-agent` | Chrome UA | Custom User-Agent string |

---

## 🧪 Detection Details

### SQL Injection
- **Payloads:** `' OR '1'='1`, `UNION SELECT NULL--`, `DROP TABLE`, and 7 more
- **Detection:** Matches 15+ database error signatures from MySQL, MSSQL, Oracle, PostgreSQL, SQLite, and MS Access
- **Coverage:** URL query parameters + HTML form fields (GET & POST)

### Cross-Site Scripting (XSS)
- **Payloads:** `<script>alert('XSS')</script>`, `<img src=x onerror=...>`, SVG/iframe/body event handlers
- **Detection:** Confirms payload reflection in HTTP response body
- **Coverage:** URL query parameters + HTML form fields (GET & POST)

### Port Scanner
Scans the following ports by default:

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 445 | SMB |
| 23 | Telnet | 3306 | MySQL |
| 25 | SMTP | 3389 | RDP |
| 53 | DNS | 5432 | PostgreSQL |
| 80 | HTTP | 6379 | Redis |
| 110 | POP3 | 8080 | HTTP-Alt |
| 143 | IMAP | 27017 | MongoDB |

---

## 📦 Requirements

```
requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
```

---

## 🧑‍💻 Tech Stack

- **Python 3.8+**
- [`requests`](https://pypi.org/project/requests/) — HTTP requests
- [`BeautifulSoup4`](https://pypi.org/project/beautifulsoup4/) — HTML parsing & form extraction
- [`colorama`](https://pypi.org/project/colorama/) — Cross-platform colored terminal output
- `threading` / `concurrent.futures` — Parallel scanning (stdlib)
- `socket` — Raw TCP port scanning (stdlib)
- `argparse` — CLI interface (stdlib)

---

## 🌐 Safe Test Targets

> Always test only on sites you own or have explicit permission to test.

These publicly available vulnerable sites are designed for scanner testing:

| Site | Description |
|------|-------------|
| `http://testphp.vulnweb.com` | Acunetix vulnerable PHP app |
| `http://books.toscrape.com` | Scraping practice site (safe, no vulns) |
| `http://localhost` | Your own local web app |

---

## 📊 Sample JSON Report

```json
{
  "scanner": "Web Vulnerability Scanner v1.0",
  "target": "https://testphp.vulnweb.com",
  "scan_date": "2026-03-25T10:30:00",
  "scan_duration_seconds": 42.5,
  "summary": {
    "total_vulnerabilities": 3,
    "open_ports": 2,
    "by_type": {
      "SQL Injection": 2,
      "Cross-Site Scripting (XSS)": 1
    }
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "url": "https://testphp.vulnweb.com/listproducts.php?cat='",
      "payload": "' OR '1'='1",
      "detail": "SQL error detected: 'warning: mysql'",
      "method": "GET",
      "parameter": "cat"
    }
  ],
  "open_ports": [
    { "port": 80, "service": "HTTP", "state": "open" },
    { "port": 443, "service": "HTTPS", "state": "open" }
  ]
}
```

---

## ⚠️ Disclaimer

> **This tool is intended for educational purposes and authorized security testing only.**
>
> Unauthorized scanning of websites or networks is **illegal** and unethical. Always obtain explicit written permission from the system owner before running any security tests. The author is not responsible for any misuse or damage caused by this tool.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙋‍♂️ Author

**Aditya**
- GitHub: [@your-username](https://github.com/your-username)

---

> ⭐ If you found this useful, consider giving it a star on GitHub!

👨‍💻 Author

Aditya Udugade
