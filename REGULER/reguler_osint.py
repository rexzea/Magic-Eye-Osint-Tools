import requests
from bs4 import BeautifulSoup
import whois
import pandas as pd
from datetime import datetime
import json
import socket
from urllib.parse import urlparse
import time
import re

class RexzeaRegulerOsint:
    def __init__(self):
        self.results = {
            'domain_info': {},
            'web_info': {},
            'contact_info': {},
            'technical_info': {}
        }
    
    def analyze_domain(self, domain):
        try:
            w = whois.whois(domain)
            self.results['domain_info'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'last_updated': str(w.updated_date),
                'status': w.status,
                'name_servers': w.name_servers
            }
        except Exception as e:
            self.results['domain_info'] = {'error': str(e)}

    def get_ip_info(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            self.results['technical_info']['ip'] = ip
            
            # Getting IP geolocation information (example using ip api.com)
            response = requests.get(f'http://ip-api.com/json/{ip}')
            if response.status_code == 200:
                self.results['technical_info']['ip_details'] = response.json()
        except Exception as e:
            self.results['technical_info']['error'] = str(e)

    def scrape_website(self, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            self.results['web_info'] = {
                'title': soup.title.string if soup.title else None,
                'meta_description': soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else None,
                'headers': [h.text for h in soup.find_all(['h1', 'h2', 'h3'])],
                'links': [link.get('href') for link in soup.find_all('a', href=True)],
                'emails': self._extract_emails(response.text)
            }
        except Exception as e:
            self.results['web_info'] = {'error': str(e)}

    def _extract_emails(self, text):
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(email_pattern, text)))

    def save_results(self, filename):
        clean_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        with open(f'{clean_filename}.json', 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        
        # convert results to datframe for CSV
        flat_dict = {}
        for category, data in self.results.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    flat_dict[f"{category}_{key}"] = str(value)
        
        df = pd.DataFrame([flat_dict])
        df.to_csv(f'{clean_filename}.csv', index=False)

def extract_domain(url):
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    return parsed.netloc

def main():
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
    print ("cr : rexzea")
    print("=" * 50)
    url_input = input("Enter the target domain (example: example.com): ").strip()
    
    # domain to url
    domain = extract_domain(url_input)
    if not domain:
        print("Error: Invalid URL")
        return
    
    print(f"\n[*] Target domain: {domain}")
    print("[*] Getting started with information gathering...")
    
    osint = RexzeaRegulerOsint()
    
    print("[+] Analyze domain information...")
    osint.analyze_domain(domain)
    
    print("[+] Collect IP information...")
    osint.get_ip_info(domain)
    
    print("[+] Collect website information...")
    full_url = f"https://{domain}" if not url_input.startswith(('http://', 'https://')) else url_input
    osint.scrape_website(full_url)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"osint_results_{domain}_{timestamp}"
    osint.save_results(filename)
    
    print(f"\n[✓] Analysis complete! The results have been saved in {filename}.json dan {filename}.csv")

if __name__ == "__main__":
    main()