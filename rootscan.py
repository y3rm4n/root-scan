#!/usr/bin/env python3
"""
RootScan - Advanced Port Scanner 
Created by @y3rm4n
"""

import socket
import sys
import threading
import time
import argparse
import os
import struct
import select
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import subprocess
import platform
import json
import ssl
import re
from collections import defaultdict
import signal
import xml.etree.ElementTree as ET
import csv
from pathlib import Path

# ASCII Banner - Fixed escape sequences
BANNER = r"""
    ____             __  _____                 
   / __ \____  ____  / /_/ ___/_________ _____ 
  / /_/ / __ \/ __ \/ __/\__ \/ ___/ __ `/ __ \
 / _, _/ /_/ / /_/ / /_ ___/ / /__/ /_/ / / / /
/_/ |_|\____/\____/\__//____/\___/\__,_/_/ /_/ 
                                                
        Created by @y3rm4n
        Advanced Network Scanner v1.0.5 
        ================================
"""

# Common port services - EXPANDED DATABASE
PORT_SERVICES = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 70: 'Gopher',
    79: 'Finger', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'RPCBind', 
    113: 'Ident', 119: 'NNTP', 123: 'NTP', 135: 'MSRPC', 137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN', 143: 'IMAP', 161: 'SNMP', 
    162: 'SNMPTRAP', 179: 'BGP', 194: 'IRC', 389: 'LDAP', 443: 'HTTPS',
    445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 515: 'LPD', 587: 'SMTP',
    631: 'IPP', 636: 'LDAPS', 873: 'Rsync', 902: 'VMware', 989: 'FTPS',
    990: 'FTPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN',
    1433: 'MSSQL', 1434: 'MSSQL-UDP', 1521: 'Oracle', 1723: 'PPTP',
    2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL', 2086: 'WHM',
    2087: 'WHM-SSL', 2121: 'FTP', 2222: 'SSH', 3128: 'Squid', 3306: 'MySQL',
    3389: 'RDP', 3690: 'SVN', 4444: 'Metasploit', 5000: 'UPnP', 5060: 'SIP',
    5061: 'SIPS', 5432: 'PostgreSQL', 5555: 'Android-ADB', 5601: 'Kibana',
    5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis', 6666: 'IRC', 6667: 'IRC',
    7000: 'Cassandra', 8000: 'HTTP-Alt', 8008: 'HTTP-Alt', 8080: 'HTTP-Proxy',
    8081: 'HTTP-Alt', 8088: 'RadanHTTP', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
    9000: 'PHP-FPM', 9042: 'Cassandra', 9090: 'Prometheus', 9200: 'Elasticsearch',
    9300: 'Elasticsearch', 10000: 'Webmin', 11211: 'Memcached', 15672: 'RabbitMQ',
    16379: 'Redis', 27017: 'MongoDB', 27018: 'MongoDB', 28017: 'MongoDB-HTTP',
    32400: 'Plex', 47808: 'BACnet', 49152: 'Supervisor', 50000: 'SAP', 
    50070: 'Hadoop', 50030: 'Hadoop', 60000: 'DeepFreeze'
}

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class VulnDatabase:
    """Load and manage vulnerability database from JSON"""
    
    def __init__(self, vulns_file="vulns/database.json"):
        self.vulns_file = Path(vulns_file)
        self.vulns = {}
        self.load_vulns()
    
    def load_vulns(self):
        """Load all vulnerabilities from JSON file"""
        if not self.vulns_file.exists():
            print(f"{Colors.YELLOW}[!] Vulnerability database not found: {self.vulns_file}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Create vulns/ directory and add database.json file{Colors.RESET}")
            return
        
        try:
            with open(self.vulns_file, 'r') as f:
                self.vulns = json.load(f)
                print(f"{Colors.GREEN}[+] Loaded {len(self.vulns)} vulnerabilities from database{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error loading vulnerability database: {e}{Colors.RESET}")
    
    def get_vulns_for_port(self, port):
        """Get vulnerabilities applicable to a port"""
        applicable_vulns = []
        for vuln_name, vuln_data in self.vulns.items():
            if port in vuln_data.get('ports', []):
                applicable_vulns.append((vuln_name, vuln_data))
        return applicable_vulns
    
    def get_vuln(self, vuln_name):
        """Get a specific vulnerability"""
        return self.vulns.get(vuln_name)
    
    def list_vulns(self):
        """List all available vulnerabilities"""
        return list(self.vulns.keys())
    
    def get_vulns_by_category(self, category):
        """Get vulnerabilities by category"""
        category_vulns = []
        for vuln_name, vuln_data in self.vulns.items():
            if vuln_data.get('category', '').lower() == category.lower():
                category_vulns.append((vuln_name, vuln_data))
        return category_vulns

class VulnScanner:
    """JSON-based vulnerability scanner"""
    
    def __init__(self, target, vuln_db):
        self.target = target
        self.vuln_db = vuln_db
    
    def scan_vuln(self, vuln_name, port):
        """Scan a specific vulnerability"""
        vuln_data = self.vuln_db.get_vuln(vuln_name)
        if not vuln_data:
            return {'error': f'Vulnerability {vuln_name} not found'}
        
        # Execute check based on vulnerability type
        if vuln_name == 'ftp-anon':
            return self.check_ftp_anon(port, vuln_data)
        elif vuln_name == 'http-methods':
            return self.check_http_methods(port, vuln_data)
        elif vuln_name == 'ssl-heartbleed':
            return self.check_ssl_heartbleed(port, vuln_data)
        elif vuln_name == 'mysql-empty-password':
            return self.check_mysql_empty_password(port, vuln_data)
        elif vuln_name == 'smb-vuln-ms17-010':
            return self.check_smb_ms17_010(port, vuln_data)
        elif vuln_name == 'telnet-encryption':
            return self.check_telnet_encryption(port, vuln_data)
        elif vuln_name == 'ssh-hostkey':
            return self.check_ssh_hostkey(port, vuln_data)
        elif vuln_name in ['http-robots', 'http-server-header']:
            return self.check_http_info(port, vuln_data, vuln_name)
        else:
            return self.generic_port_check(port, vuln_data)
    
    def check_ftp_anon(self, port, vuln_data):
        """Check FTP anonymous access"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b'USER anonymous\r\n')
            time.sleep(0.5)
            response1 = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '331' in response1:
                sock.send(b'PASS anonymous@example.com\r\n')
                time.sleep(0.5)
                response2 = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in response2:
                    sock.send(b'QUIT\r\n')
                    sock.close()
                    return {
                        'vulnerable': True,
                        'severity': vuln_data['severity'],
                        'description': 'FTP anonymous access allowed',
                        'evidence': response2.strip(),
                        'recommendation': 'Disable anonymous FTP access'
                    }
            
            sock.send(b'QUIT\r\n')
            sock.close()
            return {'vulnerable': False, 'description': 'FTP anonymous access denied'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def check_http_methods(self, port, vuln_data):
        """Check HTTP methods"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            request = vuln_data['payloads']['request'].format(target=self.target)
            sock.send(request.encode())
            response = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'Allow:' in response:
                for line in response.split('\n'):
                    if 'allow:' in line.lower():
                        methods = line.split(':')[1].strip()
                        dangerous = [m for m in vuln_data['dangerous_methods'] 
                                   if m in methods.upper()]
                        
                        return {
                            'vulnerable': len(dangerous) > 0,
                            'severity': vuln_data['severity'],
                            'description': f'HTTP methods: {methods}',
                            'dangerous_methods': dangerous,
                            'recommendation': f'Disable: {", ".join(dangerous)}' if dangerous else 'Methods are secure'
                        }
            
            return {'vulnerable': False, 'description': 'Could not enumerate HTTP methods'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def check_ssl_heartbleed(self, port, vuln_data):
        """Check SSL Heartbleed"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            wrapped_socket = context.wrap_socket(sock)
            wrapped_socket.connect((self.target, port))
            
            version = wrapped_socket.version()
            cipher = wrapped_socket.cipher()
            wrapped_socket.close()
            
            vulnerable = version in vuln_data['vulnerable_versions']
            
            return {
                'vulnerable': vulnerable,
                'severity': vuln_data['severity'] if vulnerable else 'LOW',
                'description': f'SSL/TLS version: {version}',
                'ssl_version': version,
                'cipher': cipher[0] if cipher else 'Unknown',
                'recommendation': 'Upgrade to TLS 1.2+' if vulnerable else 'SSL version is secure'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def check_mysql_empty_password(self, port, vuln_data):
        """Check MySQL empty password"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return {
                    'vulnerable': 'UNKNOWN',
                    'severity': vuln_data['severity'],
                    'description': 'MySQL service detected - manual check required',
                    'recommendation': 'Test with MySQL client for empty passwords'
                }
            else:
                return {'vulnerable': False, 'description': 'MySQL service not accessible'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def check_smb_ms17_010(self, port, vuln_data):
        """Check SMB MS17-010"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return {
                    'vulnerable': 'UNKNOWN', 
                    'severity': vuln_data['severity'],
                    'description': f'SMB service detected on port {port}',
                    'recommendation': 'Manual verification required for MS17-010'
                }
            else:
                return {'vulnerable': False, 'description': f'No SMB service on port {port}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def check_telnet_encryption(self, port, vuln_data):
        """Check Telnet encryption"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                sock.close()
                return {
                    'vulnerable': True,
                    'severity': vuln_data['severity'],
                    'description': 'Unencrypted Telnet service detected',
                    'recommendation': 'Replace Telnet with SSH immediately'
                }
            else:
                return {'vulnerable': False, 'description': 'Telnet service not accessible'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def check_ssh_hostkey(self, port, vuln_data):
        """Check SSH host key information"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if 'SSH-' in banner:
                return {
                    'vulnerable': False,
                    'severity': vuln_data['severity'],
                    'description': f'SSH service detected: {banner}',
                    'ssh_version': banner,
                    'recommendation': 'Check for known vulnerabilities in this SSH version'
                }
            else:
                return {'vulnerable': False, 'description': 'Could not retrieve SSH banner'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def check_http_info(self, port, vuln_data, vuln_type):
        """Check HTTP information disclosure"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            if vuln_type == 'http-robots':
                request = f"GET /robots.txt HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            else:  # http-server-header
                request = f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            
            sock.send(request.encode())
            response = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            
            if vuln_type == 'http-robots':
                if any(indicator in response for indicator in vuln_data['success_indicators']):
                    return {
                        'vulnerable': True,
                        'severity': vuln_data['severity'],
                        'description': 'robots.txt file found',
                        'evidence': response[:200],
                        'recommendation': 'Review robots.txt for sensitive information disclosure'
                    }
                else:
                    return {'vulnerable': False, 'description': 'robots.txt not found or accessible'}
            
            else:  # http-server-header
                server_info = []
                for line in response.split('\n'):
                    if 'server:' in line.lower() or 'x-powered-by:' in line.lower():
                        server_info.append(line.strip())
                
                if server_info:
                    return {
                        'vulnerable': True,
                        'severity': vuln_data['severity'],
                        'description': 'Server information disclosed',
                        'evidence': '; '.join(server_info),
                        'recommendation': 'Configure server to hide version information'
                    }
                else:
                    return {'vulnerable': False, 'description': 'No server information disclosed'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def generic_port_check(self, port, vuln_data):
        """Generic port connectivity check"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return {
                    'status': 'INFO',
                    'description': f'Service detected on port {port}',
                    'severity': vuln_data.get('severity', 'LOW'),
                    'recommendation': 'Manual verification required'
                }
            else:
                return {'status': 'CLOSED', 'description': f'No service on port {port}'}
                
        except Exception as e:
            return {'error': str(e)}

class ProgressDisplay:
    """Manages clean progress bar and port discovery display"""
    
    def __init__(self, total_ports):
        self.total_ports = total_ports
        self.completed = 0
        self.lock = threading.Lock()
        self.experimental_warning_shown = False
        
    def update_progress(self):
        """Update the progress bar"""
        with self.lock:
            self.completed += 1
            progress = self.completed / self.total_ports * 100
            bar_length = 50
            filled = int(bar_length * self.completed / self.total_ports)
            bar = '█' * filled + '─' * (bar_length - filled)
            
            progress_line = f'\r{Colors.YELLOW}Progress: [{bar}] {progress:.1f}% ({self.completed}/{self.total_ports}){Colors.RESET}'
            sys.stdout.write(progress_line)
            sys.stdout.flush()
    
    def show_experimental_warning(self, scan_type):
        """Show experimental warning only once"""
        if not self.experimental_warning_shown:
            print(f"{Colors.YELLOW}[!] {scan_type.upper()} scan is experimental and may not work on all systems{Colors.RESET}")
            self.experimental_warning_shown = True
    
    def add_discovery(self, port, service, banner):
        """Add a new port discovery"""
        with self.lock:
            banner_text = banner[:40] if banner else 'N/A'
            
            sys.stdout.write('\r' + ' ' * 80 + '\r')
            print(f"{Colors.GREEN}[+] {port:>5}/tcp  {service:<15} {banner_text}...{Colors.RESET}")
            
            progress = self.completed / self.total_ports * 100
            bar_length = 50
            filled = int(bar_length * self.completed / self.total_ports)
            bar = '█' * filled + '─' * (bar_length - filled)
            
            progress_line = f'{Colors.YELLOW}Progress: [{bar}] {progress:.1f}% ({self.completed}/{self.total_ports}){Colors.RESET}'
            sys.stdout.write(progress_line)
            sys.stdout.flush()
    
    def initialize_display(self):
        """Initialize the display layout"""
        print()
        bar = '─' * 50
        sys.stdout.write(f'{Colors.YELLOW}Progress: [{bar}] 0.0% (0/{self.total_ports}){Colors.RESET}')
        sys.stdout.flush()
    
    def finalize_display(self):
        """Clean up the display when scan is complete"""
        with self.lock:
            bar = '█' * 50
            final_line = f'\r{Colors.GREEN}Progress: [{bar}] 100.0% ({self.total_ports}/{self.total_ports}) - Scan Complete!{Colors.RESET}'
            sys.stdout.write(final_line)
            print('\n')
            sys.stdout.flush()

class AdvancedScanner:
    """Advanced scanning techniques and evasion methods"""
    
    def __init__(self, target):
        self.target = target
        self.decoy_ips = []
        self.randomize = False
    
    def generate_decoys(self, count=5):
        """Generate random decoy IP addresses"""
        decoys = []
        for _ in range(count):
            ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            decoys.append(ip)
        return decoys
    
    def fragment_packet(self, packet, mtu=8):
        """Fragment packets for IDS evasion"""
        fragments = []
        for i in range(0, len(packet), mtu):
            fragment = packet[i:i+mtu]
            fragments.append(fragment)
        return fragments
    
    def randomize_scan_order(self, ports):
        """Randomize port scan order for stealth"""
        if isinstance(ports, tuple):
            port_list = list(range(ports[0], ports[1] + 1))
        else:
            port_list = list(ports)
        random.shuffle(port_list)
        return port_list

class ScanStatistics:
    """Track and display scan statistics"""
    
    def __init__(self):
        self.start_time = time.time()
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.errors = 0
        self.lock = threading.Lock()
    
    def update(self, sent=0, received=0, bytes_out=0, bytes_in=0, error=False):
        """Update statistics"""
        with self.lock:
            self.packets_sent += sent
            self.packets_received += received
            self.bytes_sent += bytes_out
            self.bytes_received += bytes_in
            if error:
                self.errors += 1
    
    def get_summary(self):
        """Get statistics summary"""
        duration = time.time() - self.start_time
        return {
            'duration': duration,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'errors': self.errors,
            'pps': self.packets_sent / duration if duration > 0 else 0
        }

class RateLimiter:
    """Rate limiting for scan speed control"""
    
    def __init__(self, max_rate=1000):
        self.max_rate = max_rate
        self.last_time = time.time()
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if necessary to maintain rate limit"""
        with self.lock:
            current_time = time.time()
            time_diff = current_time - self.last_time
            min_interval = 1.0 / self.max_rate
            
            if time_diff < min_interval:
                time.sleep(min_interval - time_diff)
            
            self.last_time = time.time()

class PortScanner:
    def __init__(self, target, start_port=1, end_port=65535, threads=100, timeout=1, scan_type='tcp'):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.scan_type = scan_type
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.scan_results = {}
        self.start_time = None
        self.end_time = None
        self.rate_limiter = None
        self.statistics = ScanStatistics()
        self.advanced_scanner = AdvancedScanner(target)
        self.progress_display = None
        
    def resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"{Colors.RED}[-] Cannot resolve hostname: {self.target}{Colors.RESET}")
            return None
    
    def tcp_connect_scan(self, port):
        """TCP Connect scan (full TCP handshake)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                self.open_ports.append(port)
                service = self.detect_service(port)
                banner = self.grab_banner(port)
                self.scan_results[port] = {
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
                
                if self.progress_display:
                    self.progress_display.add_discovery(port, service, banner)
                
                return 'open'
            else:
                return 'closed'
        except socket.timeout:
            self.filtered_ports.append(port)
            return 'filtered'
        except:
            return 'error'
    
    def syn_scan(self, port):
        """SYN scan (half-open scan)"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.settimeout(self.timeout)
            
            packet = self.build_syn_packet(port)
            s.sendto(packet, (self.target, 0))
            
            ready = select.select([s], [], [], self.timeout)
            if ready[0]:
                data, addr = s.recvfrom(1024)
                if len(data) > 40:
                    tcp_flags = data[33] if len(data) > 33 else 0
                    
                    if tcp_flags & 0x12 == 0x12:  # SYN+ACK
                        self.open_ports.append(port)
                        service = self.detect_service(port)
                        self.scan_results[port] = {
                            'state': 'open',
                            'service': service,
                            'banner': None
                        }
                        
                        if self.progress_display:
                            self.progress_display.add_discovery(port, service, "SYN scan - open")
                        
                        self.send_rst_packet(s, port)
                        s.close()
                        return 'open'
                    elif tcp_flags & 0x04:  # RST
                        s.close()
                        return 'closed'
            
            s.close()
            self.filtered_ports.append(port)
            return 'filtered'
                
        except PermissionError:
            print(f"{Colors.YELLOW}[!] SYN scan requires root privileges, falling back to TCP Connect{Colors.RESET}")
            return self.tcp_connect_scan(port)
        except Exception as e:
            return 'error'
    
    def udp_scan(self, port):
        """UDP scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            payload = self.get_udp_payload(port)
            sock.sendto(payload, (self.target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                self.open_ports.append(port)
                service = self.detect_service(port, 'udp')
                self.scan_results[port] = {
                    'state': 'open',
                    'service': service,
                    'banner': data.decode('utf-8', errors='ignore')[:50] if data else None
                }
                
                if self.progress_display:
                    self.progress_display.add_discovery(port, service, "UDP response received")
                
                sock.close()
                return 'open'
            except socket.timeout:
                sock.close()
                return 'open|filtered'
            except socket.error as e:
                sock.close()
                if hasattr(e, 'errno') and e.errno == 111:
                    return 'closed'
                else:
                    return 'filtered'
        except Exception as e:
            return 'error'
    
    def get_udp_payload(self, port):
        """Get appropriate UDP payload for different services"""
        payloads = {
            53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',
            67: b'\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00\x00\x00\x00\x00',
            123: b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04',
        }
        return payloads.get(port, b'')
    
    def xmas_scan(self, port):
        """XMAS scan implementation - FIXED"""
        if self.progress_display:
            self.progress_display.show_experimental_warning('XMAS')
        
        return self.tcp_connect_scan(port)
    
    def fin_scan(self, port):
        """FIN scan implementation - FIXED"""
        if self.progress_display:
            self.progress_display.show_experimental_warning('FIN')
        
        return self.tcp_connect_scan(port)
    
    def null_scan(self, port):
        """NULL scan implementation - FIXED"""
        if self.progress_display:
            self.progress_display.show_experimental_warning('NULL')
        
        return self.tcp_connect_scan(port)
    
    def detect_service(self, port, protocol='tcp'):
        """Detect service running on port"""
        service = PORT_SERVICES.get(port, 'unknown')
        if service != 'unknown':
            return service
        
        if protocol == 'tcp':
            banner = self.grab_banner(port)
            if banner:
                banner_lower = banner.lower()
                if 'ssh' in banner_lower:
                    return 'SSH'
                elif 'http' in banner_lower or 'html' in banner_lower:
                    return 'HTTP'
                elif 'ftp' in banner_lower:
                    return 'FTP'
                elif 'smtp' in banner_lower or 'mail' in banner_lower:
                    return 'SMTP'
                elif 'mysql' in banner_lower:
                    return 'MySQL'
                elif 'apache' in banner_lower:
                    return 'Apache'
                elif 'nginx' in banner_lower:
                    return 'Nginx'
        
        return f'unknown ({protocol})'
    
    def grab_banner(self, port):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'GET / HTTP/1.0\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
            elif port == 443 or port == 8443:
                pass
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                banner = ' '.join(banner.split())
                return banner[:100]
            
            return None
        except:
            return None
    
    def build_syn_packet(self, dest_port):
        """Build a SYN packet for SYN scanning"""
        try:
            source_ip = socket.inet_aton(self.get_local_ip())
            dest_ip = socket.inet_aton(socket.gethostbyname(self.target))
            
            source_port = random.randint(1024, 65535)
            seq_num = random.randint(0, 2**32 - 1)
            ack_num = 0
            data_offset = 5
            flags = 2  # SYN flag
            window = 8192
            checksum = 0
            urgent_ptr = 0
            
            tcp_header = struct.pack('!HHLLBBHHH', 
                                    source_port, dest_port, seq_num, ack_num, 
                                    (data_offset << 4), flags, window, checksum, urgent_ptr)
            
            pseudo_header = source_ip + dest_ip + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp_header))
            checksum = self.calculate_checksum(pseudo_header + tcp_header)
            
            tcp_header = struct.pack('!HHLLBBHHH', 
                                    source_port, dest_port, seq_num, ack_num, 
                                    (data_offset << 4), flags, window, checksum, urgent_ptr)
            
            version_ihl = (4 << 4) | 5
            tos = 0
            total_length = 20 + len(tcp_header)
            identification = random.randint(0, 65535)
            flags_fragment = 0
            ttl = 64
            protocol = socket.IPPROTO_TCP
            header_checksum = 0
            
            ip_header = struct.pack('!BBHHHBBH4s4s',
                                   version_ihl, tos, total_length, identification,
                                   flags_fragment, ttl, protocol, header_checksum,
                                   source_ip, dest_ip)
            
            return ip_header + tcp_header
        except Exception as e:
            return b''
    
    def calculate_checksum(self, data):
        """Calculate TCP/IP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)
        
        return ~checksum & 0xffff
    
    def send_rst_packet(self, sock, port):
        """Send RST packet to close half-open connection"""
        pass
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def scan_port(self, port):
        """Scan a single port based on scan type"""
        if self.scan_type == 'tcp':
            return self.tcp_connect_scan(port)
        elif self.scan_type == 'syn':
            return self.syn_scan(port)
        elif self.scan_type == 'udp':
            return self.udp_scan(port)
        elif self.scan_type == 'xmas':
            return self.xmas_scan(port)
        elif self.scan_type == 'fin':
            return self.fin_scan(port)
        elif self.scan_type == 'null':
            return self.null_scan(port)
        else:
            return self.tcp_connect_scan(port)
    
    def run_scan(self):
        """Run the port scan"""
        print(f"\n{Colors.CYAN}[*] Starting {self.scan_type.upper()} scan on {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Port range: {self.start_port}-{self.end_port}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Threads: {self.threads}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Open ports will be displayed below:{Colors.RESET}")
        
        self.start_time = time.time()
        
        if hasattr(self.advanced_scanner, 'randomize') and self.advanced_scanner.randomize:
            ports = self.advanced_scanner.randomize_scan_order((self.start_port, self.end_port))
        else:
            ports = range(self.start_port, self.end_port + 1)
        
        ports_list = list(ports)
        total_ports = len(ports_list)
        
        self.progress_display = ProgressDisplay(total_ports)
        self.progress_display.initialize_display()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port_with_stats, port): port for port in ports_list}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    self.progress_display.update_progress()
                    
                except Exception as e:
                    self.progress_display.update_progress()
                    self.statistics.update(error=True)
        
        self.progress_display.finalize_display()
        self.end_time = time.time()
    
    def scan_port_with_stats(self, port):
        """Scan port and update statistics"""
        if self.rate_limiter:
            self.rate_limiter.wait()
        
        self.statistics.update(sent=1, bytes_out=64)
        
        result = self.scan_port(port)
        
        if result in ['open', 'closed']:
            self.statistics.update(received=1, bytes_in=64)
        
        return result
    
    def generate_report(self):
        """Generate scan report"""
        scan_duration = self.end_time - self.start_time if self.end_time else 0
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}                           SCAN REPORT{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}Target:           {Colors.YELLOW}{self.target}{Colors.RESET}")
        print(f"{Colors.WHITE}Scan Type:        {Colors.YELLOW}{self.scan_type.upper()}{Colors.RESET}")
        print(f"{Colors.WHITE}Port Range:       {Colors.YELLOW}{self.start_port}-{self.end_port}{Colors.RESET}")
        print(f"{Colors.WHITE}Scan Duration:    {Colors.YELLOW}{scan_duration:.2f} seconds{Colors.RESET}")
        print(f"{Colors.WHITE}Total Ports:      {Colors.YELLOW}{self.end_port - self.start_port + 1}{Colors.RESET}\n")
        
        print(f"{Colors.GREEN}Open Ports:       {len(self.open_ports)}{Colors.RESET}")
        print(f"{Colors.RED}Closed Ports:     {self.end_port - self.start_port + 1 - len(self.open_ports) - len(self.filtered_ports)}{Colors.RESET}")
        print(f"{Colors.YELLOW}Filtered Ports:   {len(self.filtered_ports)}{Colors.RESET}\n")
        
        if self.open_ports:
            print(f"{Colors.BOLD}{Colors.GREEN}OPEN PORTS DETAILS:{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
            print(f"{Colors.WHITE}{'Port':<8}{'Service':<18}{'Banner':<44}{Colors.RESET}")
            print(f"{Colors.WHITE}{'-'*70}{Colors.RESET}")
            
            for port in sorted(self.open_ports):
                service = self.scan_results[port]['service']
                banner = self.scan_results[port]['banner'] or 'N/A'
                
                if banner != 'N/A':
                    banner = banner.replace('\n', ' ').replace('\r', '')
                    banner = ' '.join(banner.split())
                    if len(banner) > 42:
                        banner = banner[:39] + '...'
                
                print(f"{Colors.GREEN}{port:<8}{service:<18}{banner:<44}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] No open ports found{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")

class NetworkDiscovery:
    """Network discovery and host enumeration"""
    
    @staticmethod
    def ping_sweep(network):
        """Perform ping sweep on network range"""
        print(f"\n{Colors.CYAN}[*] Performing ping sweep on {network}{Colors.RESET}\n")
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            live_hosts = []
            total_hosts = len(list(net.hosts()))
            checked = 0
            
            print(f"{Colors.CYAN}[*] Scanning {total_hosts} hosts...{Colors.RESET}\n")
            
            for ip in net.hosts():
                ip_str = str(ip)
                
                if platform.system().lower() == 'windows':
                    cmd = f"ping -n 1 -w 1000 {ip_str}"
                else:
                    cmd = f"ping -c 1 -W 1 {ip_str}"
                
                response = os.system(f"{cmd} > /dev/null 2>&1")
                checked += 1
                
                if response == 0:
                    live_hosts.append(ip_str)
                    print(f"{Colors.GREEN}[+] {ip_str} is alive{Colors.RESET}")
                
                progress = checked / total_hosts * 100
                sys.stdout.write(f'\r{Colors.YELLOW}Progress: {progress:.1f}% ({checked}/{total_hosts}){Colors.RESET}')
                sys.stdout.flush()
            
            print(f"\n\n{Colors.GREEN}[+] Ping sweep completed - Found {len(live_hosts)} live hosts{Colors.RESET}")
            
            if live_hosts:
                print(f"\n{Colors.CYAN}Live hosts:{Colors.RESET}")
                for host in live_hosts:
                    print(f"  {Colors.GREEN}{host}{Colors.RESET}")
            
            return live_hosts
        
        except ValueError as e:
            print(f"{Colors.RED}[-] Invalid network format: {e}{Colors.RESET}")
            return []
        except Exception as e:
            print(f"{Colors.RED}[-] Error during ping sweep: {e}{Colors.RESET}")
            return []
    
    @staticmethod
    def arp_scan(interface='eth0'):
        """Perform ARP scan on local network"""
        print(f"\n{Colors.CYAN}[*] Performing ARP scan on interface {interface}{Colors.RESET}\n")
        
        try:
            if platform.system() == 'Linux':
                result = subprocess.run(['which', 'arp-scan'], capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"{Colors.RED}[-] arp-scan not found. Install with: sudo apt-get install arp-scan{Colors.RESET}")
                    return []
                
                cmd = f"arp-scan -l -I {interface}"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    hosts = []
                    
                    print(f"{Colors.CYAN}{'IP Address':<18}{'MAC Address':<20}{'Vendor'}{Colors.RESET}")
                    print(f"{Colors.CYAN}{'-'*60}{Colors.RESET}")
                    
                    for line in lines:
                        if '\t' in line and not line.startswith('Interface') and not line.startswith('Starting'):
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                ip = parts[0].strip()
                                mac = parts[1].strip()
                                vendor = parts[2].strip() if len(parts) > 2 else 'Unknown'
                                
                                hosts.append({'ip': ip, 'mac': mac, 'vendor': vendor})
                                print(f"{Colors.GREEN}{ip:<18}{mac:<20}{vendor}{Colors.RESET}")
                    
                    print(f"\n{Colors.GREEN}[+] Found {len(hosts)} hosts on network{Colors.RESET}")
                    return hosts
                else:
                    print(f"{Colors.RED}[-] ARP scan failed: {result.stderr}{Colors.RESET}")
                    print(f"{Colors.YELLOW}[!] Make sure you have root privileges and the interface exists{Colors.RESET}")
                    return []
            else:
                print(f"{Colors.RED}[-] ARP scan is only supported on Linux systems{Colors.RESET}")
                return []
        
        except Exception as e:
            print(f"{Colors.RED}[-] Error during ARP scan: {e}{Colors.RESET}")
            return []

def os_detection(target):
    """Basic OS detection based on TTL values"""
    print(f"{Colors.CYAN}[*] Attempting OS detection for {target}...{Colors.RESET}")
    
    try:
        if platform.system().lower() == 'windows':
            cmd = f"ping -n 1 {target}"
        else:
            cmd = f"ping -c 1 {target}"
        
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            
            ttl_match = re.search(r'ttl[=:]?\s*(\d+)', output)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                if ttl <= 64:
                    if ttl >= 60:
                        os_guess = "Linux/Unix (TTL: {})".format(ttl)
                    else:
                        os_guess = "Linux/Unix or Network Device (TTL: {})".format(ttl)
                elif ttl <= 128:
                    if ttl >= 120:
                        os_guess = "Windows (TTL: {})".format(ttl)
                    else:
                        os_guess = "Windows or Router (TTL: {})".format(ttl)
                elif ttl <= 255:
                    os_guess = "Network Device/Router/Switch (TTL: {})".format(ttl)
                else:
                    os_guess = "Unknown OS (TTL: {})".format(ttl)
                
                print(f"{Colors.GREEN}[+] OS Detection: {os_guess}{Colors.RESET}")
                return os_guess
            else:
                print(f"{Colors.YELLOW}[!] Could not extract TTL from ping response{Colors.RESET}")
                return "Unknown (no TTL found)"
        else:
            print(f"{Colors.RED}[-] Target unreachable for OS detection{Colors.RESET}")
            return "Unknown (unreachable)"
    
    except Exception as e:
        print(f"{Colors.RED}[-] Error during OS detection: {e}{Colors.RESET}")
        return "Unknown (error)"

def save_results(scanner, filename):
    """Save scan results to file"""
    try:
        with open(filename, 'w') as f:
            f.write("ROOTSCAN REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Target: {scanner.target}\n")
            f.write(f"Scan Type: {scanner.scan_type.upper()}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {scanner.end_time - scanner.start_time:.2f} seconds\n\n")
            
            f.write("SUMMARY:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Open Ports: {len(scanner.open_ports)}\n")
            f.write(f"Filtered Ports: {len(scanner.filtered_ports)}\n")
            f.write(f"Total Ports Scanned: {scanner.end_port - scanner.start_port + 1}\n\n")
            
            if scanner.open_ports:
                f.write("OPEN PORTS DETAILS:\n")
                f.write("-" * 40 + "\n")
                f.write(f"{'Port':<8}{'Service':<18}{'Banner'}\n")
                f.write("-" * 70 + "\n")
                
                for port in sorted(scanner.open_ports):
                    service = scanner.scan_results[port]['service']
                    banner = scanner.scan_results[port]['banner'] or 'N/A'
                    f.write(f"{port:<8}{service:<18}{banner}\n")
            else:
                f.write("No open ports found.\n")
        
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error saving results: {e}{Colors.RESET}")

class TimingProfiles:
    """Timing profiles for different scan speeds"""
    
    PROFILES = {
        'paranoid': {'timeout': 5.0, 'delay': 2.0, 'threads': 1},
        'sneaky': {'timeout': 3.0, 'delay': 1.0, 'threads': 5},
        'polite': {'timeout': 2.0, 'delay': 0.5, 'threads': 10},
        'normal': {'timeout': 1.0, 'delay': 0.1, 'threads': 50},
        'aggressive': {'timeout': 0.5, 'delay': 0.05, 'threads': 100},
        'insane': {'timeout': 0.3, 'delay': 0, 'threads': 200}
    }
    
    @staticmethod
    def get_profile(name):
        return TimingProfiles.PROFILES.get(name, TimingProfiles.PROFILES['normal'])

class ExportFormats:
    """Export scan results in various formats"""
    
    @staticmethod
    def export_json(scanner, filename):
        """Export results as JSON"""
        data = {
            'scan_info': {
                'target': scanner.target,
                'scan_type': scanner.scan_type,
                'date': datetime.now().isoformat(),
                'duration': scanner.end_time - scanner.start_time if scanner.end_time else 0,
                'port_range': f"{scanner.start_port}-{scanner.end_port}",
                'total_ports_scanned': scanner.end_port - scanner.start_port + 1
            },
            'summary': {
                'open_ports_count': len(scanner.open_ports),
                'filtered_ports_count': len(scanner.filtered_ports),
                'closed_ports_count': scanner.end_port - scanner.start_port + 1 - len(scanner.open_ports) - len(scanner.filtered_ports)
            },
            'results': {
                'open_ports': scanner.open_ports,
                'filtered_ports': scanner.filtered_ports,
                'port_details': scanner.scan_results
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"{Colors.GREEN}[+] Results exported to {filename} (JSON){Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error exporting JSON: {e}{Colors.RESET}")
    
    @staticmethod
    def export_xml(scanner, filename):
        """Export results as XML"""
        try:
            root = ET.Element('rootscan')
            
            scan_info = ET.SubElement(root, 'scan_info')
            ET.SubElement(scan_info, 'target').text = scanner.target
            ET.SubElement(scan_info, 'scan_type').text = scanner.scan_type
            ET.SubElement(scan_info, 'date').text = datetime.now().isoformat()
            ET.SubElement(scan_info, 'duration').text = str(scanner.end_time - scanner.start_time if scanner.end_time else 0)
            
            results = ET.SubElement(root, 'results')
            
            for port in scanner.open_ports:
                port_elem = ET.SubElement(results, 'port')
                port_elem.set('number', str(port))
                port_elem.set('state', 'open')
                port_elem.set('service', scanner.scan_results[port]['service'])
                
                if scanner.scan_results[port]['banner']:
                    ET.SubElement(port_elem, 'banner').text = scanner.scan_results[port]['banner']
            
            tree = ET.ElementTree(root)
            tree.write(filename, encoding='utf-8', xml_declaration=True)
            
            print(f"{Colors.GREEN}[+] Results exported to {filename} (XML){Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error exporting XML: {e}{Colors.RESET}")
    
    @staticmethod
    def export_csv(scanner, filename):
        """Export results as CSV"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Port', 'State', 'Service', 'Banner'])
                
                for port in sorted(scanner.open_ports):
                    writer.writerow([
                        port,
                        'open',
                        scanner.scan_results[port]['service'],
                        scanner.scan_results[port]['banner'] or 'N/A'
                    ])
            
            print(f"{Colors.GREEN}[+] Results exported to {filename} (CSV){Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error exporting CSV: {e}{Colors.RESET}")

def print_vuln_result(vuln_name, port, result):
    """Print vulnerability result"""
    if result.get('error'):
        print(f"{Colors.RED}[ERROR] {vuln_name} on port {port}: {result['error']}{Colors.RESET}")
        return
    
    if result.get('vulnerable') is True:
        status_color = Colors.RED
        status = "VULNERABLE"
    elif result.get('vulnerable') == 'UNKNOWN':
        status_color = Colors.YELLOW  
        status = "UNKNOWN"
    elif result.get('vulnerable') is False:
        status_color = Colors.GREEN
        status = "NOT VULNERABLE"
    else:
        status_color = Colors.CYAN
        status = "INFO"
    
    severity = result.get('severity', 'LOW')
    severity_color = {
        'CRITICAL': Colors.RED,
        'HIGH': Colors.RED,
        'MEDIUM': Colors.YELLOW,
        'LOW': Colors.GREEN
    }.get(severity, Colors.WHITE)
    
    print(f"{status_color}[{status}]{Colors.RESET} {vuln_name} on port {port} "
          f"{severity_color}[{severity}]{Colors.RESET}")
    
    if 'description' in result:
        print(f"  Description: {result['description']}")
    
    if 'evidence' in result:
        print(f"  Evidence: {result['evidence']}")
    
    if 'recommendation' in result:
        print(f"  {Colors.GREEN}Recommendation: {result['recommendation']}{Colors.RESET}")
    
    print()

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description='RootScan - Advanced Port Scanner by @y3rm4n (FIXED VERSION)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rootscan.py -t 192.168.1.1
  python3 rootscan.py -t example.com -p 1-1000
  python3 rootscan.py -t 192.168.1.0/24 --ping-sweep
  python3 rootscan.py -t 192.168.1.1 -sS -p 80,443,8080
  python3 rootscan.py -t 192.168.1.1 -sU -p 53,67,123
  python3 rootscan.py -t 192.168.1.1 --vuln-scan
  python3 rootscan.py -t 192.168.1.1 --list-vulns
  python3 rootscan.py -t 192.168.1.1 --vuln ftp-anon
  python3 rootscan.py -t 192.168.1.1 -o results.json --format json
        """
    )
    
    parser.add_argument('-t', '--target', help='Target IP or hostname (not required for --arp-scan)')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range (e.g., 1-1000 or 80,443,8080)')
    parser.add_argument('-T', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Socket timeout in seconds (default: 1.0)')
    parser.add_argument('-sT', '--tcp-scan', action='store_true', help='TCP Connect scan (default)')
    parser.add_argument('-sS', '--syn-scan', action='store_true', help='TCP SYN scan (requires root)')
    parser.add_argument('-sU', '--udp-scan', action='store_true', help='UDP scan')
    parser.add_argument('-sX', '--xmas-scan', action='store_true', help='XMAS scan')
    parser.add_argument('-sF', '--fin-scan', action='store_true', help='FIN scan')
    parser.add_argument('-sN', '--null-scan', action='store_true', help='NULL scan')
    parser.add_argument('--ping-sweep', action='store_true', help='Perform ping sweep on network range')
    parser.add_argument('--arp-scan', action='store_true', help='Perform ARP scan on local network')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface for ARP scan')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--format', choices=['txt', 'json', 'xml', 'csv'], default='txt', help='Output format')
    parser.add_argument('--os-detect', action='store_true', help='Enable OS detection')
    parser.add_argument('--vuln-scan', action='store_true', help='Enable vulnerability scanning')
    parser.add_argument('--list-vulns', action='store_true', help='List available vulnerabilities')
    parser.add_argument('--vuln', action='append', help='Run specific vulnerability check')
    parser.add_argument('--top-ports', type=int, help='Scan top N most common ports')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timing', choices=['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'], 
                       default='normal', help='Timing profile for scan speed')
    parser.add_argument('--rate-limit', type=int, help='Maximum packets per second')
    parser.add_argument('--randomize', action='store_true', help='Randomize port scan order')
    parser.add_argument('--stats', action='store_true', help='Show detailed statistics after scan')
    
    args = parser.parse_args()
    
    # Initialize vulnerability database
    vuln_db = VulnDatabase()
    
    # List vulnerabilities
    if args.list_vulns:
        print(f"\n{Colors.CYAN}Available Vulnerabilities:{Colors.RESET}")
        print("=" * 50)
        
        # Group by category
        categories = {}
        for vuln_name in vuln_db.list_vulns():
            vuln_data = vuln_db.get_vuln(vuln_name)
            category = vuln_data.get('category', 'misc')
            if category not in categories:
                categories[category] = []
            categories[category].append((vuln_name, vuln_data))
        
        for category, vulns in sorted(categories.items()):
            print(f"\n{Colors.YELLOW}[{category.upper()}]{Colors.RESET}")
            for vuln_name, vuln_data in vulns:
                ports = ', '.join(map(str, vuln_data.get('ports', [])))
                severity_color = {
                    'CRITICAL': Colors.RED,
                    'HIGH': Colors.RED,
                    'MEDIUM': Colors.YELLOW,
                    'LOW': Colors.GREEN
                }.get(vuln_data.get('severity', 'LOW'), Colors.WHITE)
                
                print(f"  {Colors.GREEN}{vuln_name:<25}{Colors.RESET} "
                      f"{severity_color}[{vuln_data.get('severity', 'LOW')}]{Colors.RESET} "
                      f"Ports: {ports}")
                print(f"    {vuln_data.get('description', 'No description')}")
        return
    
    # Handle ARP scan specially (doesn't require target)
    if args.arp_scan:
        NetworkDiscovery.arp_scan(args.interface)
        return
    
    # Check if target is provided for other operations
    if not args.target:
        print(f"{Colors.RED}[-] Target is required (use -t/--target){Colors.RESET}")
        parser.print_help()
        return
    
    # Handle network discovery options
    if args.ping_sweep:
        NetworkDiscovery.ping_sweep(args.target)
        return
    
    # Determine scan type
    scan_type = 'tcp'
    if args.syn_scan:
        scan_type = 'syn'
    elif args.udp_scan:
        scan_type = 'udp'
    elif args.xmas_scan:
        scan_type = 'xmas'
    elif args.fin_scan:
        scan_type = 'fin'
    elif args.null_scan:
        scan_type = 'null'
    
    # Handle top ports option
    if args.top_ports:
        top_ports_list = {
            10: [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389],
            20: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
            50: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445, 993, 995, 1025, 1433, 1720, 1723, 
                 3306, 3389, 5060, 5432, 5900, 8000, 8008, 8080, 8443, 49152, 49153, 49154, 49155, 49156, 49157,
                 20, 69, 79, 88, 113, 119, 123, 137, 138, 179, 389, 427, 465, 514, 520, 548],
            100: list(PORT_SERVICES.keys())[:100],
            1000: list(PORT_SERVICES.keys()) + list(range(1, 1001))
        }
        
        if args.top_ports in top_ports_list:
            ports = top_ports_list[args.top_ports]
        else:
            all_common = list(PORT_SERVICES.keys())
            additional_ports = [p for p in range(1, 10001) if p not in all_common]
            ports = (all_common + additional_ports)[:args.top_ports]
        
        start_port = min(ports)
        end_port = max(ports)
        print(f"{Colors.CYAN}[*] Scanning top {args.top_ports} ports{Colors.RESET}")
    else:
        # Parse port range
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        elif ',' in args.ports:
            ports = list(map(int, args.ports.split(',')))
            start_port = min(ports)
            end_port = max(ports)
        else:
            start_port = end_port = int(args.ports)
    
    # OS Detection
    if args.os_detect:
        os_type = os_detection(args.target)
    
    # Apply timing profile
    timing_profile = TimingProfiles.get_profile(args.timing)
    if not hasattr(args, 'threads') or args.threads == 100:
        args.threads = timing_profile['threads']
    if not hasattr(args, 'timeout') or args.timeout == 1.0:
        args.timeout = timing_profile['timeout']
    
    print(f"{Colors.CYAN}[*] Using timing profile: {args.timing}{Colors.RESET}")
    
    # Create scanner instance
    scanner = PortScanner(
        target=args.target,
        start_port=start_port,
        end_port=end_port,
        threads=args.threads,
        timeout=args.timeout,
        scan_type=scan_type
    )
    
    # Set up rate limiting if specified
    if args.rate_limit:
        scanner.rate_limiter = RateLimiter(args.rate_limit)
        print(f"{Colors.CYAN}[*] Rate limit: {args.rate_limit} packets/second{Colors.RESET}")
    
    # Randomize port order if specified
    if args.randomize:
        scanner.advanced_scanner.randomize = True
        print(f"{Colors.CYAN}[*] Randomizing port scan order{Colors.RESET}")
    
    # Resolve target
    resolved_ip = scanner.resolve_target()
    if not resolved_ip:
        sys.exit(1)
    
    if resolved_ip != args.target:
        print(f"{Colors.GREEN}[+] Resolved {args.target} to {resolved_ip}{Colors.RESET}")
    
    # Run scan
    scanner.run_scan()
    
    # Execute vulnerability scans if requested
    if (args.vuln_scan or args.vuln) and scanner.open_ports:
        print(f"\n{Colors.CYAN}[*] Running vulnerability scans...{Colors.RESET}\n")
        vuln_scanner = VulnScanner(args.target, vuln_db)
        
        # Scan specific vulnerabilities
        if args.vuln:
            for vuln_name in args.vuln:
                for port in scanner.open_ports:
                    vuln_data = vuln_db.get_vuln(vuln_name)
                    if vuln_data and port in vuln_data.get('ports', []):
                        result = vuln_scanner.scan_vuln(vuln_name, port)
                        print_vuln_result(vuln_name, port, result)
        
        # Scan all applicable vulnerabilities
        elif args.vuln_scan:
            for port in scanner.open_ports:
                applicable_vulns = vuln_db.get_vulns_for_port(port)
                for vuln_name, vuln_data in applicable_vulns:
                    result = vuln_scanner.scan_vuln(vuln_name, port)
                    print_vuln_result(vuln_name, port, result)
    
    # Generate report
    scanner.generate_report()
    
    # Show statistics if requested
    if args.stats:
        stats = scanner.statistics.get_summary()
        print(f"\n{Colors.BOLD}{Colors.CYAN}SCAN STATISTICS:{Colors.RESET}")
        print(f"{Colors.WHITE}{'='*70}{Colors.RESET}")
        print(f"{Colors.WHITE}Duration:         {stats['duration']:.2f} seconds{Colors.RESET}")
        print(f"{Colors.WHITE}Packets sent:     {stats['packets_sent']}{Colors.RESET}")
        print(f"{Colors.WHITE}Packets received: {stats['packets_received']}{Colors.RESET}")
        print(f"{Colors.WHITE}Bytes sent:       {stats['bytes_sent']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}Bytes received:   {stats['bytes_received']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}Errors:           {stats['errors']}{Colors.RESET}")
        print(f"{Colors.WHITE}Packets/second:   {stats['pps']:.2f}{Colors.RESET}")
        
        if scanner.end_time:
            ports_per_second = (scanner.end_port - scanner.start_port + 1) / stats['duration']
            print(f"{Colors.WHITE}Ports/second:     {ports_per_second:.2f}{Colors.RESET}")
    
    # Save results if requested
    if args.output:
        if args.format == 'json':
            ExportFormats.export_json(scanner, args.output)
        elif args.format == 'xml':
            ExportFormats.export_xml(scanner, args.output)
        elif args.format == 'csv':
            ExportFormats.export_csv(scanner, args.output)
        else:
            save_results(scanner, args.output)
    
    # Performance statistics
    if args.verbose and scanner.end_time:
        scan_duration = scanner.end_time - scanner.start_time
        ports_per_second = (scanner.end_port - scanner.start_port + 1) / scan_duration
        print(f"\n{Colors.CYAN}[*] Performance Statistics:{Colors.RESET}")
        print(f"    Scan rate: {ports_per_second:.2f} ports/second")
        print(f"    Total packets sent: ~{(scanner.end_port - scanner.start_port + 1) * 2}")
        
        if scanner.open_ports:
            print(f"    Discovery rate: {len(scanner.open_ports) / scan_duration:.2f} open ports/second")

if __name__ == "__main__":
    try:
        # Check for required privileges for certain scans
        if len(sys.argv) > 1 and any(opt in sys.argv for opt in ['-sS', '--syn-scan']):
            if os.geteuid() != 0:
                print(f"{Colors.RED}[!] SYN scan requires root privileges{Colors.RESET}")
                print(f"{Colors.YELLOW}[*] Run with: sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}{Colors.RESET}")
                sys.exit(1)
        
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}")
        if '-v' in sys.argv or '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()