import requests
from bs4 import BeautifulSoup
import pandas as pd
from datetime import datetime
import json
import time
from urllib.parse import urlparse
import socket
import sys
import re
import subprocess
import platform

class RexzeaSpecificOsint:
    def __init__(self):
        self.results = {
            'domain_info': {},
            'web_info': {},
            'ip_info': {},
            'timestamps': {}
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def clean_url(self, url):
        try:
            url = url.strip().rstrip('/')
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if not domain:
                domain = parsed.path.split('/')[0]
                url = f"https://{domain}"
            
            return url, domain
        except Exception as e:
            print(f"Error in cleaning URL: {str(e)}")
            return None, None

    def get_whois_info(self, domain):
        try:
            # extract the main domain
            domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', domain)
            if domain_match:
                domain = domain_match.group(1)
            
            if platform.system() == "Windows":
                # untuk windows
                process = subprocess.Popen(['whois', domain], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE,
                                        shell=True)
            else:
                # untuk linux/unix
                process = subprocess.Popen(['whois', domain], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE)
            
            output, error = process.communicate()
            
            if error:
                print(f"WHOIS Error: {error.decode()}")
                return None
                
            whois_data = output.decode('utf-8', errors='ignore')
            
            # parse WHOIS output
            whois_dict = {}
            key_mappings = {
                'Registrar:': 'registrar',
                'Creation Date:': 'creation_date',
                'Registry Expiry Date:': 'expiration_date',
                'Name Server:': 'name_servers',
                'Status:': 'status',
                'Registrant Email:': 'email'
            }
            
            name_servers = []
            statuses = []
            
            for line in whois_data.split('\n'):
                line = line.strip()
                for key in key_mappings:
                    if line.startswith(key):
                        value = line[len(key):].strip()
                        dict_key = key_mappings[key]
                        
                        if dict_key == 'name_servers':
                            name_servers.append(value)
                        elif dict_key == 'status':
                            statuses.append(value)
                        else:
                            whois_dict[dict_key] = value
            
            if name_servers:
                whois_dict['name_servers'] = name_servers
            if statuses:
                whois_dict['status'] = statuses
            
            return whois_dict
        except Exception as e:
            print(f"Error in WHOIS lookup: {str(e)}")
            return None

    def gather_domain_info(self, domain):
        try:
            whois_info = self.get_whois_info(domain)
            
            if whois_info:
                self.results['domain_info'] = whois_info
                print("Successfully gathered WHOIS information")
                return True
            else:
                response = requests.get(
                    f"https://rdap.verisign.com/com/v1/domain/{domain}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.results['domain_info'] = {
                        'registrar': data.get('entities', [{}])[0].get('vcardArray', [])[1][1][3],
                        'status': data.get('status', []),
                        'events': data.get('events', []),
                        'nameservers': [ns.get('ldhName') for ns in data.get('nameservers', [])]
                    }
                    print("Successfully gathered domain information from RDAP")
                    return True
                else:
                    self.results['domain_info'] = {
                        'error': 'Could not retrieve domain information',
                        'status': 'Domain information unavailable'
                    }
                    return False
                    
        except Exception as e:
            self.results['domain_info'] = {
                'error': f"Could not gather domain info: {str(e)}",
                'status': 'Error in domain lookup'
            }
            return False

    def gather_web_info(self, url):
        try:
            response = requests.get(url, headers=self.headers, timeout=15, verify=True)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    meta_tags[name] = content

            self.results['web_info'] = {
                'title': soup.title.string.strip() if soup.title else None,
                'meta_tags': meta_tags,
                'headers': [h.text.strip() for h in soup.find_all(['h1', 'h2', 'h3']) if h.text.strip()],
                'links': list(set([link.get('href') for link in soup.find_all('a', href=True)])),
                'status_code': response.status_code,
                'server': response.headers.get('Server'),
                'content_type': response.headers.get('Content-Type'),
                'technologies': dict(response.headers)
            }
            return True
        except Exception as e:
            self.results['web_info'] = {
                'error': f"Could not gather web info: {str(e)}"
            }
            return False

    def gather_ip_info(self, domain):
        try:
            ip_addresses = []
            try:
                ip_addresses = socket.gethostbyname_ex(domain)[2]
            except socket.gaierror:
                main_domain = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,}$)', domain)
                if main_domain:
                    ip_addresses = socket.gethostbyname_ex(main_domain.group(1))[2]

            if not ip_addresses:
                raise Exception("No IP addresses found")

            ip_info_list = []
            for ip in ip_addresses:
                response = requests.get(f"https://ipapi.co/{ip}/json/", headers=self.headers, timeout=10)
                if response.status_code == 200:
                    ip_data = response.json()
                    ip_info_list.append({
                        'ip': ip,
                        'country': ip_data.get('country_name'),
                        'region': ip_data.get('region'),
                        'city': ip_data.get('city'),
                        'org': ip_data.get('org'),
                        'isp': ip_data.get('isp'),
                        'latitude': ip_data.get('latitude'),
                        'longitude': ip_data.get('longitude')
                    })
                time.sleep(1)

            self.results['ip_info'] = ip_info_list
            return True
        except Exception as e:
            self.results['ip_info'] = {
                'error': f"Could not gather IP info: {str(e)}"
            }
            return False

    def save_to_file(self, filename, format='json'):
        self.results['timestamps']['scan_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            if format.lower() == 'json':
                with open(f"{filename}.json", 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=4, ensure_ascii=False)
            elif format.lower() == 'csv':
                flat_dict = {}
                for category, data in self.results.items():
                    if isinstance(data, dict):
                        for key, value in data.items():
                            flat_dict[f"{category}_{key}"] = str(value)
                    else:
                        flat_dict[category] = str(data)
                
                df = pd.DataFrame([flat_dict])
                df.to_csv(f"{filename}.csv", index=False)
            
            print(f"\nResults saved to {filename}.{format}")
            return True
        except Exception as e:
            print(f"Error saving results: {str(e)}")
            return False

    def analyze_target(self, target_url):
        print(f"\nStarting analysis of {target_url}...")
        print("=" * 50)

        url, domain = self.clean_url(target_url)
        if not url or not domain:
            print("Invalid URL provided")
            return False

        print(f"Analyzing domain: {domain}")
        print(f"Full URL: {url}")
        print("-" * 50)

        success = True
        steps = [
            ("Gathering domain information...", lambda: self.gather_domain_info(domain)),
            ("Gathering web information...", lambda: self.gather_web_info(url)),
            ("Gathering IP information...", lambda: self.gather_ip_info(domain))
        ]

        results_summary = []
        for step_msg, step_func in steps:
            print(step_msg)
            try:
                step_success = step_func()
                if not step_success:
                    print(f"Warning: {step_msg.strip('.')} completed with errors")
                    results_summary.append(f"✗ {step_msg.strip('.')}")
                else:
                    print(f"Success: {step_msg.strip('.')} completed")
                    results_summary.append(f"✓ {step_msg.strip('.')}")
                success = success and step_success
            except Exception as e:
                print(f"Error: {step_msg.strip('.')} failed - {str(e)}")
                results_summary.append(f"✗ {step_msg.strip('.')} (Error: {str(e)})")
                success = False
            print("-" * 50)

        print("\nAnalysis Summary:")
        for result in results_summary:
            print(result)

        return success

def main():
    try:
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
        print("Osint with high specific domain")
        print ("cr : rexzea")
        print("=" * 50)
        
        target = input("Enter the target domain (example: example.com): ").strip()
        if not target:
            print("Error: Target cannot be empty")
            return

        osint = RexzeaSpecificOsint()
        if osint.analyze_target(target):
            while True:
                save_format = input("\nSelect a save format (json/csv) [default: json]: ").lower().strip()
                if save_format == '':
                    save_format = 'json'
                if save_format in ['json', 'csv']:
                    break
                print("Invalid format. Select 'json' or 'csv'")

            clean_target = re.sub(r'[^\w\-_]', '_', target)
            filename = f"osint_report_{clean_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            if osint.save_to_file(filename, save_format):
                print("\nAnalysis complete! Please check the analysis results file.")
            else:
                print("\nThe analysis is complete, but an error occurred in saving the file.")
        else:
            print("\nSome components of the analysis failed. Please check the results of the analysis above.")

    except KeyboardInterrupt:
        print("\nThe program is stopped by the user.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()