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
import ipaddress
import concurrent.futures
import ssl
import subprocess
import platform

class RexzeaHazardOsint:
    def __init__(self):
        self.start_time = time.time()  
        self.results = {
            'domain_info': {},
            'web_info': {},
            'dns_info': {},
            'network_info': {},
            'ssl_info': {},
            'geolocation_info': {},
            'security_info': {},
            'metadata': {}
        }

    def save_results(self, filename):
        # save as JSON
        json_filename = f"{filename}_results.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        
        # Save as CSV 
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
                'organization': w.org,
                'registrant_country': w.registrant_country,
                'admin_country': w.admin_country,
                'last_updated': str(w.updated_date)
            }
        except Exception as e:
            self.results['domain_info'] = {'error': str(e)}

    def get_network_info(self, domain):
        try:
            # Get all IP addresses (IPv4 and IPv6)
            ip_info = {}
            try:
                ipv4_addresses = [ip.to_text() for ip in dns.resolver.resolve(domain, 'A')]
                ip_info['ipv4_addresses'] = ipv4_addresses
            except:
                ip_info['ipv4_addresses'] = []

            try:
                ipv6_addresses = [ip.to_text() for ip in dns.resolver.resolve(domain, 'AAAA')]
                ip_info['ipv6_addresses'] = ipv6_addresses
            except:
                ip_info['ipv6_addresses'] = []

            #Get detailed information for each IP
            ip_details = []
            for ip in ip_info['ipv4_addresses']:
                ip_data = self.get_ip_details(ip)
                ip_details.append(ip_data)

            self.results['network_info'] = {
                'ip_addresses': ip_info,
                'ip_details': ip_details,
                'reverse_dns': self.get_reverse_dns(ip_info['ipv4_addresses'][0]) if ip_info['ipv4_addresses'] else None
            }
        except Exception as e:
            self.results['network_info'] = {'error': str(e)}

    def get_ip_details(self, ip):
        try:
            # using ip api.com for ip geolocation
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            data = response.json()
            
            return {
                'ip': ip,
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'zip': data.get('zip'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
                'isp': data.get('isp'),
                'organization': data.get('org'),
                'as_number': data.get('as'),
                'as_name': data.get('asname')
            }
        except Exception as e:
            return {'ip': ip, 'error': str(e)}

    def get_ssl_info(self, domain):
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
                sock.connect((domain, 443))
                cert = sock.getpeercert()

            self.results['ssl_info'] = {
                'issuer': dict(x[0] for x in cert['issuer']),
                'subject': dict(x[0] for x in cert['subject']),
                'version': cert['version'],
                'serial_number': cert['serialNumber'],
                'not_before': cert['notBefore'],
                'not_after': cert['notAfter'],
                'san': cert.get('subjectAltName', []),
                'ocsp': cert.get('OCSP', []),
                'crl_distribution_points': cert.get('crlDistributionPoints', [])
            }
        except Exception as e:
            self.results['ssl_info'] = {'error': str(e)}

    def get_security_headers(self, url):
        try:
            response = requests.get(url, verify=True, timeout=10)
            headers = response.headers

            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Feature-Policy': headers.get('Feature-Policy'),
                'Access-Control-Allow-Origin': headers.get('Access-Control-Allow-Origin')
            }

            self.results['security_info']['headers'] = security_headers
        except Exception as e:
            self.results['security_info']['headers'] = {'error': str(e)}

    def get_reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def analyze_ports(self, domain):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        open_ports = {}
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((domain, port))
                if result == 0:
                    open_ports[port] = self.get_service_name(port)
            except:
                pass
            finally:
                sock.close()
            
        self.results['network_info']['open_ports'] = open_ports

    def get_service_name(self, port):
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP (Submission)',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alternate',
            8443: 'HTTPS-Alternate'
        }
        return common_services.get(port, 'Unknown')

    def ping_host(self, domain):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', domain]
            output = subprocess.check_output(command).decode().strip()
            self.results['network_info']['ping_test'] = output
        except Exception as e:
            self.results['network_info']['ping_test'] = str(e)

    def generate_report(self, target):
        print(f"[*] Starting extended OSINT analysis for: {target}")
        
        # parse url/domain
        parsed_url = urlparse(target)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
        
        try:
            # run all analysis
            print("[+] Analyze domain information...")
            self.analyze_domain(domain)
            
            print("[+] Collect network information...")
            self.get_network_info(domain)
            
            print("[+] Analyzing SSL/TLS...")
            self.get_ssl_info(domain)
            
            print("[+] Check open ports...")
            self.analyze_ports(domain)
            
            print("[+] Perform a ping test...")
            self.ping_host(domain)
            
            print("[+] Check security headers...")
            self.get_security_headers(f"https://{domain}")
            
            # metadata
            self.results['metadata'] = {
                'scan_date': datetime.now().isoformat(),
                'target': target,
                'domain': domain,
                'scan_duration': time.time() - self.start_time
            }
            
            # save result
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"enhanced_osint_scan_{domain}_{timestamp}"
            self.save_results(filename)
            
            print(f"\n[+] Analisis selesai. Hasil disimpan dalam file:")
            print(f"    - {filename}_results.json")
            print(f"    - {filename}_results.csv")
            
            # Show summary of results
            self.display_summary()
            
        except Exception as e:
            print(f"\n[-] Error during analysis: {str(e)}")

    def display_summary(self):
        print("\n=== RINGKASAN SCAN OSINT ===")
        
        # domain info
        print("\nDomain Information:")
        if 'error' not in self.results['domain_info']:
            print(f"Registrar: {self.results['domain_info'].get('registrar', 'N/A')}")
            print(f"Organisasi: {self.results['domain_info'].get('organization', 'N/A')}")
            print(f"Negara: {self.results['domain_info'].get('registrant_country', 'N/A')}")
        
        #network info
        print("\nINetwork Information:")
        if 'error' not in self.results['network_info']:
            for ip_detail in self.results['network_info'].get('ip_details', []):
                print(f"\nIP: {ip_detail.get('ip', 'N/A')}")
                print(f"Region: {ip_detail.get('country', 'N/A')}")
                print(f"City: {ip_detail.get('city', 'N/A')}")
                print(f"ISP: {ip_detail.get('isp', 'N/A')}")
        
        # security info
        print("\nSecurity Information:")
        if 'headers' in self.results['security_info']:
            headers = self.results['security_info']['headers']
            print(f"HTTPS: {'Yes' if self.results.get('ssl_info') and 'error' not in self.results['ssl_info'] else 'Tidak'}")
            print(f"Security Headers: {len([h for h in headers.values() if h is not None])} installed")

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
    print("Osint search for important information")
    print ("cr : rexzea")
    print("=" * 50)
    osint = RexzeaHazardOsint()
    target = input("Enter the target domain (example: example.com):")
    osint.generate_report(target)

if __name__ == "__main__":
    main()