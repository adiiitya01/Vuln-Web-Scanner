
"""
Web Vulnerability Scanner
=========================
A Python-based tool for detecting common web vulnerabilities including:
- SQL Injection
- Cross-Site Scripting (XSS)
- Basic Port Scanning

Usage:
    python web_vuln_scanner.py --url https://example.com [options]

Requirements:
    pip install requests beautifulsoup4 colorama
"""

import argparse
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

try:
    import requests
    import bs4
    from colorama import Fore, Back, Style, init as colorama_init
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Install with: pip install requests beautifulsoup4 colorama")
    sys.exit(1)

colorama_init(autoreset=True)


SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' AND 1=2--",
    "admin'--",
    "' OR 1=1#",
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error",
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "ora-01756",
    "sqlite_master",
    "pg_query",
    "invalid query",
    "microsoft ole db provider for odbc drivers",
    "odbc microsoft access driver",
    "jet database engine",
    "access database engine",
    "microsoft jet database",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
]

COMMON_PORTS = [
    21,   
    22,  
    23,   
    25,  
    53,  
    80,  
    110,  
    143,  
    443,  
    445,  
    3306, 
    3389, 
    5432,
    6379, 
    8080, 
    8443, 
    27017,
]

TIMEOUT = 10
MAX_CRAWL_PAGES = 50
MAX_THREADS = 10

def print_banner():
    """Print the tool banner."""
    banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║          Web Vulnerability Scanner v1.0                      ║
║          SQL Injection | XSS | Port Scanner                  ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.YELLOW}  [!] For educational and authorized testing purposes only.{Style.RESET_ALL}
"""
    print(banner)


def print_info(msg):
    """Print an informational message."""
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")


def print_success(msg):
    """Print a success/finding message."""
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def print_warning(msg):
    """Print a warning message."""
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def print_error(msg):
    """Print an error message."""
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def print_vuln(vuln_type, url, payload, detail=""):
    """Print a formatted vulnerability finding."""
    print(f"\n{Back.RED}{Fore.WHITE} VULNERABILITY FOUND {Style.RESET_ALL}")
    print(f"  {Fore.RED}Type   :{Style.RESET_ALL} {vuln_type}")
    print(f"  {Fore.RED}URL    :{Style.RESET_ALL} {url}")
    print(f"  {Fore.RED}Payload:{Style.RESET_ALL} {payload}")
    if detail:
        print(f"  {Fore.RED}Detail :{Style.RESET_ALL} {detail}")


def print_section(title):
    """Print a section header."""
    print(f"\n{Fore.BLUE}{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}{Style.RESET_ALL}")

def validate_url(url):
    """
    Validate that the provided URL is well-formed and reachable.
    Returns the normalized URL or raises an exception.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: '{url}' — could not extract hostname.")

    return url


def get_base_domain(url):
    """Extract the base domain from a URL to restrict crawling scope."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def get_session(user_agent=None):
    """Create and return a requests Session with common headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    return session


def fetch_page(session, url):
    """
    Fetch a web page and return the response.
    Returns None on failure.
    """
    try:
        response = session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        return response
    except requests.exceptions.ConnectionError:
        print_error(f"Connection refused or DNS failure: {url}")
    except requests.exceptions.Timeout:
        print_error(f"Request timed out: {url}")
    except requests.exceptions.TooManyRedirects:
        print_error(f"Too many redirects: {url}")
    except requests.exceptions.RequestException as e:
        print_error(f"Request error for {url}: {e}")
    return None


def extract_links(soup, base_url, base_domain):
    """
    Parse all anchor tags from BeautifulSoup object.
    Returns a set of absolute URLs belonging to the same domain.
    """
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        
        if href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        full_url = urljoin(base_url, href)
       
        full_url = full_url.split("#")[0]
       
        if full_url.startswith(base_domain):
            links.add(full_url)
    return links


def extract_forms(soup, page_url):
    """
    Extract all HTML forms from the page.
    Returns a list of dicts with form action, method, and inputs.
    """
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(page_url, action) if action else page_url

        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            input_type = tag.get("type", "text").lower()
            input_name = tag.get("name", "")
            input_value = tag.get("value", "test")

            
            if input_type in ("submit", "button", "image", "file", "reset"):
                continue
            if input_name:
                inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_value,
                })

        forms.append({
            "action": action_url,
            "method": method,
            "inputs": inputs,
        })
    return forms


def crawl(start_url, session, max_pages=MAX_CRAWL_PAGES):
    """
    Crawl a website starting from start_url.
    Returns a dict mapping URLs to their discovered forms.
    """
    print_section("CRAWLING")
    print_info(f"Starting crawl from: {start_url}")

    base_domain = get_base_domain(start_url)
    visited = set()
    to_visit = {start_url}
    crawled_data = {}  

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue

        print_info(f"Crawling: {url}")
        response = fetch_page(session, url)
        if response is None:
            continue

        visited.add(url)

        try:
            soup = bs4.BeautifulSoup(response.text, "html.parser")
        except Exception:
            continue

      
        new_links = extract_links(soup, url, base_domain)
        to_visit.update(new_links - visited)

        forms = extract_forms(soup, url)
        crawled_data[url] = forms

    print_success(f"Crawled {len(visited)} pages, found {sum(len(f) for f in crawled_data.values())} forms.")
    return crawled_data

def detect_sql_error(response_text):
    """
    Check response text for common SQL error signatures.
    Returns the matched error string or None.
    """
    lower_text = response_text.lower()
    for error in SQL_ERRORS:
        if error in lower_text:
            return error
    return None


def test_sqli_url(session, url):
    """
    Test a URL's query parameters for SQL injection by injecting payloads.
    Returns a list of vulnerability dicts.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param_name in params:
        for payload in SQL_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload

            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))

            response = fetch_page(session, test_url)
            if response is None:
                continue

            error = detect_sql_error(response.text)
            if error:
                findings.append({
                    "type": "SQL Injection",
                    "url": test_url,
                    "payload": payload,
                    "detail": f"SQL error detected: '{error}'",
                    "method": "GET",
                    "parameter": param_name,
                })
                print_vuln("SQL Injection (GET)", test_url, payload, f"Error: {error}")
                break  
    return findings


def test_sqli_form(session, form):
    """
    Test an HTML form for SQL injection by submitting payloads.
    Returns a list of vulnerability dicts.
    """
    findings = []
    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    if not inputs:
        return findings

    for target_input in inputs:
        for payload in SQL_PAYLOADS:
           
            data = {i["name"]: i["value"] for i in inputs}
            data[target_input["name"]] = payload

            try:
                if method == "post":
                    response = session.post(action, data=data, timeout=TIMEOUT, verify=False)
                else:
                    response = session.get(action, params=data, timeout=TIMEOUT, verify=False)
            except requests.exceptions.RequestException:
                continue

            error = detect_sql_error(response.text)
            if error:
                findings.append({
                    "type": "SQL Injection",
                    "url": action,
                    "payload": payload,
                    "detail": f"SQL error in form field '{target_input['name']}': '{error}'",
                    "method": method.upper(),
                    "parameter": target_input["name"],
                })
                print_vuln(
                    f"SQL Injection ({method.upper()} Form)",
                    action,
                    payload,
                    f"Field: {target_input['name']} | Error: {error}",
                )
                break 

    return findings
def test_xss_url(session, url):
    """
    Test URL query parameters for reflected XSS vulnerabilities.
    Returns a list of vulnerability dicts.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param_name in params:
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload

            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))

            response = fetch_page(session, test_url)
            if response is None:
                continue
            if payload in response.text:
                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "url": test_url,
                    "payload": payload,
                    "detail": f"Payload reflected in response for parameter '{param_name}'",
                    "method": "GET",
                    "parameter": param_name,
                })
                print_vuln("XSS (GET)", test_url, payload, f"Reflected in parameter: {param_name}")
                break

    return findings


def test_xss_form(session, form):
    """
    Test an HTML form for reflected XSS by submitting payloads.
    Returns a list of vulnerability dicts.
    """
    findings = []
    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    if not inputs:
        return findings

    for target_input in inputs:
        for payload in XSS_PAYLOADS:
            data = {i["name"]: i["value"] for i in inputs}
            data[target_input["name"]] = payload

            try:
                if method == "post":
                    response = session.post(action, data=data, timeout=TIMEOUT, verify=False)
                else:
                    response = session.get(action, params=data, timeout=TIMEOUT, verify=False)
            except requests.exceptions.RequestException:
                continue

            if payload in response.text:
                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "url": action,
                    "payload": payload,
                    "detail": f"Payload reflected via form field '{target_input['name']}'",
                    "method": method.upper(),
                    "parameter": target_input["name"],
                })
                print_vuln(
                    f"XSS ({method.upper()} Form)",
                    action,
                    payload,
                    f"Field: {target_input['name']}",
                )
                break

    return findings

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def scan_port(host, port, timeout=1.5):
    """
    Attempt a TCP connection to host:port.
    Returns (port, True) if open, (port, False) otherwise.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False


def port_scan(target_url, ports=None, max_threads=MAX_THREADS):
    """
    Scan common (or specified) ports on the target host using threading.
    Returns a list of open port dicts.
    """
    print_section("PORT SCAN")
    parsed = urlparse(target_url)
    host = parsed.hostname

    if not host:
        print_error("Could not extract hostname for port scan.")
        return []

    ports = ports or COMMON_PORTS
    print_info(f"Scanning {len(ports)} ports on {host} ...")

    open_ports = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = PORT_SERVICES.get(port, "Unknown")
                with lock:
                    open_ports.append({"port": port, "service": service, "state": "open"})
                    print_success(f"Port {port:>5}/tcp  OPEN  ({service})")

    if not open_ports:
        print_warning("No open ports found in the scanned range.")

    return sorted(open_ports, key=lambda x: x["port"])

def run_vulnerability_scan(crawled_data, session, max_threads=MAX_THREADS):
    """
    Run SQL injection and XSS tests against all crawled URLs and forms.
    Uses a thread pool for parallel scanning.
    Returns a list of all findings.
    """
    print_section("VULNERABILITY SCANNING")
    all_findings = []
    lock = threading.Lock()

    def scan_url(url, forms):
        local_findings = []
        local_findings += test_sqli_url(session, url)
        local_findings += test_xss_url(session, url)
        for form in forms:
            local_findings += test_sqli_form(session, form)
            local_findings += test_xss_form(session, form)
        return local_findings

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_url, url, forms): url
            for url, forms in crawled_data.items()
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                results = future.result()
                with lock:
                    all_findings.extend(results)
            except Exception as e:
                print_error(f"Error scanning {url}: {e}")

    return all_findings

def print_summary(findings, open_ports, target_url, scan_duration):
    """Print a formatted summary of all scan results."""
    print_section("SCAN SUMMARY")
    print_info(f"Target       : {target_url}")
    print_info(f"Scan Time    : {scan_duration:.2f} seconds")
    print_info(f"Open Ports   : {len(open_ports)}")
    print_info(f"Vulnerabilities Found: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}{'─'*60}")
        print(f"  VULNERABILITIES")
        print(f"{'─'*60}{Style.RESET_ALL}")
        by_type = {}
        for f in findings:
            by_type.setdefault(f["type"], []).append(f)

        for vuln_type, items in by_type.items():
            print(f"\n  {Fore.RED}{vuln_type}{Style.RESET_ALL} ({len(items)} found)")
            for item in items:
                print(f"    • {item['url']}")
                print(f"      Payload   : {item['payload']}")
                print(f"      Detail    : {item.get('detail', '')}")
    else:
        print_success("No vulnerabilities detected in the scanned scope.")

    if open_ports:
        print(f"\n{Fore.CYAN}{'─'*60}")
        print(f"  OPEN PORTS")
        print(f"{'─'*60}{Style.RESET_ALL}")
        for p in open_ports:
            print(f"  {p['port']:>5}/tcp  {Fore.GREEN}OPEN{Style.RESET_ALL}  {p['service']}")


def export_report(findings, open_ports, target_url, scan_duration, output_path):
    """
    Export scan results to a JSON file.
    """
    report = {
        "scanner": "Web Vulnerability Scanner v1.0",
        "target": target_url,
        "scan_date": datetime.now().isoformat(),
        "scan_duration_seconds": round(scan_duration, 2),
        "summary": {
            "total_vulnerabilities": len(findings),
            "open_ports": len(open_ports),
            "by_type": {},
        },
        "vulnerabilities": findings,
        "open_ports": open_ports,
    }
    for f in findings:
        t = f["type"]
        report["summary"]["by_type"][t] = report["summary"]["by_type"].get(t, 0) + 1

    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2)

    print_success(f"Report saved to: {output_path}")


def export_text_report(findings, open_ports, target_url, scan_duration, output_path):
    """
    Export scan results to a plain-text file.
    """
    lines = [
        "=" * 60,
        "WEB VULNERABILITY SCANNER REPORT",
        "=" * 60,
        f"Target       : {target_url}",
        f"Date         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Duration     : {scan_duration:.2f}s",
        f"Vulns Found  : {len(findings)}",
        f"Open Ports   : {len(open_ports)}",
        "",
    ]

    if findings:
        lines.append("VULNERABILITIES")
        lines.append("-" * 40)
        for f in findings:
            lines.append(f"Type    : {f['type']}")
            lines.append(f"URL     : {f['url']}")
            lines.append(f"Payload : {f['payload']}")
            lines.append(f"Detail  : {f.get('detail', '')}")
            lines.append("")

    if open_ports:
        lines.append("OPEN PORTS")
        lines.append("-" * 40)
        for p in open_ports:
            lines.append(f"  {p['port']}/tcp  OPEN  ({p['service']})")

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))

    print_success(f"Text report saved to: {output_path}")
def parse_args():
    parser = argparse.ArgumentParser(
        prog="web_vuln_scanner",
        description="Web Vulnerability Scanner — SQLi, XSS & Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_vuln_scanner.py --url https://testphp.vulnweb.com
  python web_vuln_scanner.py --url https://example.com --no-ports --output report.json
  python web_vuln_scanner.py --url https://example.com --max-pages 20 --threads 5
        """,
    )
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument(
        "--max-pages", type=int, default=MAX_CRAWL_PAGES,
        help=f"Maximum pages to crawl (default: {MAX_CRAWL_PAGES})"
    )
    parser.add_argument(
        "--threads", type=int, default=MAX_THREADS,
        help=f"Number of concurrent threads (default: {MAX_THREADS})"
    )
    parser.add_argument(
        "--no-ports", action="store_true",
        help="Skip port scanning"
    )
    parser.add_argument(
        "--no-sqli", action="store_true",
        help="Skip SQL injection testing"
    )
    parser.add_argument(
        "--no-xss", action="store_true",
        help="Skip XSS testing"
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Export results to JSON file (e.g. report.json)"
    )
    parser.add_argument(
        "--output-txt", metavar="FILE",
        help="Export results to text file (e.g. report.txt)"
    )
    parser.add_argument(
        "--user-agent", metavar="UA",
        help="Custom User-Agent string"
    )
    return parser.parse_args()

def main():
   
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print_banner()
    args = parse_args()
    try:
        target_url = validate_url(args.url)
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)

    print_info(f"Target URL : {target_url}")
    print_info(f"Max Pages  : {args.max_pages}")
    print_info(f"Threads    : {args.threads}")
    print()

    session = get_session(args.user_agent)
    start_time = time.time()

    print_info("Testing connectivity...")
    initial_response = fetch_page(session, target_url)
    if initial_response is None:
        print_error("Cannot reach target URL. Please verify the URL and your network connection.")
        sys.exit(1)
    print_success(f"Connected! HTTP {initial_response.status_code}")

    crawled_data = crawl(target_url, session, max_pages=args.max_pages)

    all_findings = []

    if not args.no_sqli or not args.no_xss:
        if args.no_sqli:
            print_warning("SQL Injection scan skipped (--no-sqli).")
        if args.no_xss:
            print_warning("XSS scan skipped (--no-xss).")

        all_findings = run_vulnerability_scan(crawled_data, session, max_threads=args.threads)
    else:
        print_warning("Both SQLi and XSS scans skipped.")

    open_ports = []
    if not args.no_ports:
        open_ports = port_scan(target_url, max_threads=args.threads)
    else:
        print_warning("Port scan skipped (--no-ports).")

   
    scan_duration = time.time() - start_time
    print_summary(all_findings, open_ports, target_url, scan_duration)

    
    if args.output:
        export_report(all_findings, open_ports, target_url, scan_duration, args.output)

    if args.output_txt:
        export_text_report(all_findings, open_ports, target_url, scan_duration, args.output_txt)

    if not args.output and not args.output_txt and all_findings:
        print_info("Tip: Re-run with --output report.json or --output-txt report.txt to save results.")


if __name__ == "__main__":
    main()
