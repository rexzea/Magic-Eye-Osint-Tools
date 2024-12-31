import requests
from bs4 import BeautifulSoup
import whois
import pandas as pd
import json
from datetime import datetime
import socket
import dns.resolver
import time
import csv
from urllib.parse import urlparse
import os

class RexzeaHunterOsint:
    def __init__(self):
        self.results = {
            'domain_info': {},
            'web_info': {},
            'dns_info': {},
            'metadata': {}
        }
        
    def analyze_domain(self, domain):
        try:
            w = whois.whois(domain)
            self.results['domain_info'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'organization': w.org
            }
        except Exception as e:
            self.results['domain_info'] = {'error': str(e)}

    def get_dns_info(self, domain):
        try:
            # A record
            a_records = dns.resolver.resolve(domain, 'A')
            # MX record
            mx_records = dns.resolver.resolve(domain, 'MX')
            # TXT record
            txt_records = dns.resolver.resolve(domain, 'TXT')
            
            self.results['dns_info'] = {
                'a_records': [str(record) for record in a_records],
                'mx_records': [str(record) for record in mx_records],
                'txt_records': [str(record) for record in txt_records]
            }
        except Exception as e:
            self.results['dns_info'] = {'error': str(e)}

    def analyze_website(self, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Collect metadata
            metadata = {
                'title': soup.title.string if soup.title else None,
                'meta_description': soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else None,
                'meta_keywords': soup.find('meta', {'name': 'keywords'})['content'] if soup.find('meta', {'name': 'keywords'}) else None,
                'headers': {
                    'h1': [h1.text.strip() for h1 in soup.find_all('h1')],
                    'h2': [h2.text.strip() for h2 in soup.find_all('h2')]
                },
                'links': [{'text': a.text.strip(), 'href': a.get('href')} for a in soup.find_all('a', href=True)],
                'images': [{'src': img.get('src'), 'alt': img.get('alt')} for img in soup.find_all('img')],
                'response_headers': dict(response.headers),
                'status_code': response.status_code
            }
            
            self.results['web_info'] = metadata
            
        except Exception as e:
            self.results['web_info'] = {'error': str(e)}

    def extract_emails(self, text):
        import re
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(email_pattern, text)))

    def save_results(self, filename):
        # save as JSON
        json_filename = f"{filename}_results.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        
        # sav as CSV (flatten structure)
        csv_filename = f"{filename}_results.csv"
        flattened_data = self._flatten_dict(self.results)
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Key', 'Value'])
            for key, value in flattened_data.items():
                writer.writerow([key, value])

    def _flatten_dict(self, d, parent_key='', sep='_'):
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def generate_report(self, target):
        print(f"[*] Starting OSINT analysis for: {target}")
        
        # Parse URL/domain
        parsed_url = urlparse(target)
        domain = parsed_url.netloc if parsed_url.netloc else target
        
        # Run all analysis
        print("[+] Analyze domain information...")
        self.analyze_domain(domain)
        
        print("[+] Collect DNS information...")
        self.get_dns_info(domain)
        
        print("[+] Analyzing websites...")
        self.analyze_website(f"http://{domain}" if not target.startswith(('http://', 'https://')) else target)
        
        # metadata
        self.results['metadata'] = {
            'scan_date': datetime.now().isoformat(),
            'target': target,
            'domain': domain
        }
        
        # save rexult
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"osint_scan_{domain}_{timestamp}"
        self.save_results(filename)
        
        print(f"[+] Analysis complete. Results are saved in a file:")
        print(f"    - {filename}_results.json")
        print(f"    - {filename}_results.csv")

def main():
    # example
    print("""

 ███▄ ▄███▓ ▄▄▄        ▄████  ██▓ ▄████▄     ▓█████▓██   ██▓▓█████ 
▓██▒▀█▀ ██▒▒████▄     ██▒ ▀█▒▓██▒▒██▀ ▀█     ▓█   ▀ ▒██  ██▒▓█   ▀ 
▓██    ▓██░▒██  ▀█▄  ▒██░▄▄▄░▒██▒▒▓█    ▄    ▒███    ▒██ ██░▒███   
▒██    ▒██ ░██▄▄▄▄██ ░▓█  ██▓░██░▒▓▓▄ ▄██▒   ▒▓█  ▄  ░ ▐██▓░▒▓█  ▄ 
▒██▒   ░██▒ ▓█   ▓██▒░▒▓███▀▒░██░▒ ▓███▀ ░   ░▒████▒ ░ ██▒▓░░▒████▒
░ ▒░   ░  ░ ▒▒   ▓▒█░ ░▒   ▒ ░▓  ░ ░▒ ▒  ░   ░░ ▒░ ░  ██▒▒▒ ░░ ▒░ ░
░  ░      ░  ▒   ▒▒ ░  ░   ░  ▒ ░  ░  ▒       ░ ░  ░▓██ ░▒░  ░ ░  ░
░      ░     ░   ▒   ░ ░   ░  ▒ ░░              ░   ▒ ▒ ░░     ░   
       ░         ░  ░      ░  ░  ░ ░            ░  ░░ ░        ░  ░
                                 ░                  ░ ░            
        """)
    print("Osint link finder")
    print ("cr : rexzea")
    print("=" * 50)
    osint = RexzeaHunterOsint()
    target = input("Enter the target domain (example: example.com): ")
    osint.generate_report(target)

if __name__ == "__main__":
    main()