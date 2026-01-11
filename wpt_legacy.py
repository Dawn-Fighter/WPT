#!/usr/bin/env python3
import argparse
import requests
import socket
import ssl
import dns.resolver
import concurrent.futures
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import sys
import re
from datetime import datetime
from tqdm import tqdm
import time
import subprocess
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
import warnings
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class WebScanner:
    def __init__(self, target_url, threads=5, verbose=False):
        self.target_url = target_url if target_url.startswith('http') else f'http://{target_url}'
        self.threads = threads
        self.verbose = verbose
        self.findings = []
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Linux Security Scanner)'
        }
        self.domain = urlparse(self.target_url).netloc
        self.subdomains = set()
        self.setup_selenium()

    def setup_selenium(self):
        """Initialize Selenium for JavaScript analysis"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        self.driver = webdriver.Chrome(options=chrome_options)

    def scan(self):
        """Enhanced main scanning function"""
        print(f"\n[+] Starting comprehensive scan of {self.target_url} at {datetime.now()}")
        
        scan_functions = [
            self.dns_enumeration,
            self.ssl_tls_analysis,
            self.waf_detection,
            self.api_discovery,
            self.javascript_analysis,
            self.cookie_analysis,
            self.form_analysis
        ]
        
        with tqdm(total=len(scan_functions), desc="Scanning Progress", unit="module") as self.progress_bar:
            for scan_function in scan_functions:
                scan_function()
                self.progress_bar.update(1)

        self.generate_report()
        self.driver.quit()

    def dns_enumeration(self):
        """Perform DNS enumeration and subdomain discovery"""
        common_subdomains = ['www', 'mail', 'remote', 'blog', 'webmail', 'server',
                            'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api']

        # DNS record types to check
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

        try:
            # Check main domain DNS records
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    for rdata in answers:
                        self.findings.append({
                            'category': 'DNS Records',
                            'description': f'{record_type} record: {rdata}'
                        })
                except dns.resolver.NoAnswer:
                    continue

            # Subdomain enumeration
            for subdomain in common_subdomains:
                try:
                    hostname = f"{subdomain}.{self.domain}"
                    answers = dns.resolver.resolve(hostname, 'A')
                    self.subdomains.add(hostname)
                    self.findings.append({
                        'category': 'Subdomain Discovery',
                        'description': f'Found subdomain: {hostname}'
                    })
                except:
                    continue

        except Exception as e:
            self.findings.append({
                'category': 'Error',
                'description': f'Error during DNS enumeration: {str(e)}'
            })

    def ssl_tls_analysis(self):
        """Analyze SSL/TLS configuration"""
        if not self.target_url.startswith('https'):
            self.findings.append({
                'category': 'SSL/TLS',
                'description': 'Site does not use HTTPS'
            })
            return

        try:
            hostname = self.domain
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = cert['notAfter']
                    self.findings.append({
                        'category': 'SSL/TLS',
                        'description': f'Certificate expires: {not_after}'
                    })

                    # Check SSL/TLS version
                    version = ssock.version()
                    if version != "TLSv1.3":
                        self.findings.append({
                            'category': 'SSL/TLS',
                            'description': f'Using {version} - Recommend upgrading to TLSv1.3'
                        })

                    # Check cipher suite
                    cipher = ssock.cipher()
                    if 'NULL' in cipher[0] or 'RC4' in cipher[0]:
                        self.findings.append({
                            'category': 'SSL/TLS',
                            'description': f'Weak cipher suite detected: {cipher[0]}'
                        })

        except Exception as e:
            self.findings.append({
                'category': 'Error',
                'description': f'Error during SSL/TLS analysis: {str(e)}'
            })

    def waf_detection(self):
        """Detect presence of Web Application Firewall"""
        waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
            'AWS WAF': ['x-amzn-RequestId', 'x-amz-cf-id'],
            'Akamai': ['akamai-origin-hop'],
            'Imperva': ['incap_ses_', 'visid_incap_'],
            'F5 BIG-IP': ['BigIP', 'F5-TrafficShield']
        }

        try:
            response = self.session.get(self.target_url)
            headers = str(response.headers)
            cookies = str(response.cookies)

            for waf, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature in headers or signature in cookies:
                        self.findings.append({
                            'category': 'WAF Detection',
                            'description': f'Detected {waf} WAF'
                        })
                        break

        except Exception as e:
            self.findings.append({
                'category': 'Error',
                'description': f'Error during WAF detection: {str(e)}'
            })

    def api_discovery(self):
        """Discover and test API endpoints"""
        common_api_paths = ['/api', '/api/v1', '/api/v2', '/rest', '/graphql']
        common_methods = ['GET', 'POST', 'PUT', 'DELETE']

        for path in common_api_paths:
            url = urljoin(self.target_url, path)
            try:
                # Test OPTIONS method for endpoint discovery
                options_response = self.session.options(url)
                if 'Allow' in options_response.headers:
                    self.findings.append({
                        'category': 'API Discovery',
                        'description': f'API endpoint found: {path} - Allowed methods: {options_response.headers["Allow"]}'
                    })

                # Test common methods
                for method in common_methods:
                    response = self.session.request(method, url)
                    if response.status_code != 404:
                        self.findings.append({
                            'category': 'API Discovery',
                            'description': f'API endpoint responds to {method}: {path} (Status: {response.status_code})'
                        })

            except Exception as e:
                continue

    def javascript_analysis(self):
        """Analyze JavaScript for potential vulnerabilities"""
        try:
            self.driver.get(self.target_url)
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            # Collect all script sources
            scripts = self.driver.find_elements(By.TAG_NAME, "script")
            
            for script in scripts:
                # Check inline scripts
                if script.get_attribute("innerHTML"):
                    js_content = script.get_attribute("innerHTML")
                    self.analyze_js_content(js_content)

                # Check external scripts
                src = script.get_attribute("src")
                if src:
                    try:
                        response = self.session.get(src)
                        self.analyze_js_content(response.text)
                    except:
                        continue

        except Exception as e:
            self.findings.append({
                'category': 'Error',
                'description': f'Error during JavaScript analysis: {str(e)}'
            })

    def analyze_js_content(self, content):
        """Analyze JavaScript content for potential vulnerabilities"""
        vulnerable_patterns = {
            'Hardcoded Credentials': r'(?i)(password|apikey|secret|token)\s*[=:]\s*["\'][^"\']+["\']',
            'Unsafe DOM': r'(?i)(innerHTML|outerHTML|document\.write)',
            'Eval Usage': r'(?i)eval\(',
            'Possible XSS': r'(?i)(location\.href|location\.hash|location\.search)',
            'Data Exposure': r'(?i)(console\.log|alert)\(',
        }

        for vuln_type, pattern in vulnerable_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                self.findings.append({
                    'category': 'JavaScript Security',
                    'description': f'Potential {vuln_type} detected in JavaScript'
                })

    def cookie_analysis(self):
        """Analyze cookie security configurations"""
        try:
            response = self.session.get(self.target_url)
            cookies = response.cookies

            for cookie in cookies:
                issues = []
                
                if not cookie.secure:
                    issues.append("Missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("Missing HttpOnly flag")
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("Missing SameSite attribute")
                
                if issues:
                    self.findings.append({
                        'category': 'Cookie Security',
                        'description': f'Cookie "{cookie.name}" has security issues: {", ".join(issues)}'
                    })

        except Exception as e:
            self.findings.append({
                'category': 'Error',
                'description': f'Error during cookie analysis: {str(e)}'
            })

    def form_analysis(self):
        """Analyze form security and input validation"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                # Check form security attributes
                if form.get('method', '').lower() != 'post':
                    self.findings.append({
                        'category': 'Form Security',
                        'description': f'Form using GET method instead of POST'
                    })

                if not form.get('autocomplete') == 'off':
                    self.findings.append({
                        'category': 'Form Security',
                        'description': f'Form autocomplete not disabled'
                    })

                # Check CSRF protection
                csrf_token = form.find('input', {'name': re.compile(r'csrf|token', re.I)})
                if not csrf_token:
                    self.findings.append({
                        'category': 'Form Security',
                        'description': f'No CSRF token found in form'
                    })

                # Check input validation
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_type = input_field.get('type', '')
                    if input_type == 'password' and not input_field.get('pattern'):
                        self.findings.append({
                            'category': 'Form Security',
                            'description': f'Password field without pattern validation'
                        })

                    if input_type == 'email' and not input_field.get('pattern'):
                        self.findings.append({
                            'category': 'Form Security',
                            'description': f'Email field without pattern validation'
                        })

        except Exception as e:
            self.findings.append({
                'category': 'Error',
                'description': f'Error during form analysis: {str(e)}'
            })

    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n=== Comprehensive Security Scan Report ===")
        print(f"Target: {self.target_url}")
        print(f"Scan completed at: {datetime.now()}")
        print("\nFindings Summary:")
        
        # Group findings by category
        findings_by_category = {}
        for finding in self.findings:
            category = finding['category']
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding['description'])

        # Print organized findings
        for category, descriptions in sorted(findings_by_category.items()):
            print(f"\n[*] {category}")
            for description in descriptions:
                print(f"    - {description}")

def print_banner():

	print(r"""
                         ,----,
                ,-.----.         ,/   .`| 
           .---.\    /  \      ,`   .'  : 
          /. ./||   :    \   ;    ;     / 
      .--'.  ' ;|   |  .\ :.'___,/    ,'  
     /__./ \ : |.   :  |: ||    :     |   
 .--'.  '   \' .|   |   \ :;    |.';  ;   
/___/ \ |    ' '|   : .   /`----'  |  |   
;   \  \;      :;   | |`-'     '   :  ;   
 \   ;  `      ||   | ;        |   |  '   
  .   \    .\  ;:   ' |        '   :  |   
   \   \   ' \ |:   : :        ;   |.'    
    :   '  |--" |   | :        '---'      
     \   \ ;    `---'.|                   
      '---"       `---`                   WPT v1.0

   Web Penetration Testing Tool
   --------------------------------
	 """)
   

def main():
    
    print_banner()
    parser = argparse.ArgumentParser(
        description='''
        Advanced Web Security Scanner
        ---------------------------
        Comprehensive security analysis tool for web applications.
        
        Features:
        - DNS enumeration and subdomain discovery
        - SSL/TLS configuration analysis
        - WAF detection
        - API endpoint discovery
        - JavaScript security analysis
        - Cookie security analysis
        - Form input validation testing
        
        Example usage:
            python3 scanner.py example.com -t 10 -v
            python3 scanner.py https://example.com --output report.txt
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=5,
                        help='Number of threads for concurrent checks (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-o', '--output', type=str,
                        help='Save report to specified file')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()

    scanner = WebScanner(args.url, args.threads, args.verbose)
    scanner.scan()

if __name__ == '__main__':
    main()
