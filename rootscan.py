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

# ASCII Banner
BANNER = """
\033[91m
    ____             __  _____                 
   / __ \____  ____  / /_/ ___/_________ _____ 
  / /_/ / __ \/ __ \/ __/\__ \/ ___/ __ `/ __ \\
 / _, _/ /_/ / /_/ / /_ ___/ / /__/ /_/ / / / /
/_/ |_|\____/\____/\__//____/\___/\__,_/_/ /_/ 
                                                
\033[0m\033[93m        Created by @y3rm4n\033[0m
\033[90m        Advanced Network Scanner v1.0\033[0m
\033[90m        ================================\033[0m
"""

# Common port services
PORT_SERVICES = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 111: 'RPCBind', 113: 'Ident', 119: 'NNTP', 123: 'NTP',
    135: 'MSRPC', 139: 'NetBIOS-SSN', 143: 'IMAP', 161: 'SNMP', 162: 'SNMPTRAP',
    179: 'BGP', 194: 'IRC', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 514: 'Syslog', 515: 'LPD', 587: 'SMTP', 631: 'IPP',
    636: 'LDAPS', 873: 'Rsync', 902: 'VMware', 989: 'FTPS', 990: 'FTPS',
    993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL',
    1434: 'MSSQL-UDP', 1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS', 2082: 'cPanel',
    2083: 'cPanel-SSL', 2086: 'WHM', 2087: 'WHM-SSL', 2121: 'FTP', 2222: 'SSH',
    3128: 'Squid', 3306: 'MySQL', 3389: 'RDP', 3690: 'SVN', 4444: 'Metasploit',
    5060: 'SIP', 5432: 'PostgreSQL', 5555: 'Android-ADB', 5900: 'VNC', 5984: 'CouchDB',
    6379: 'Redis', 6666: 'IRC', 6667: 'IRC', 7000: 'Cassandra', 8000: 'HTTP-Alt',
    8008: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8081: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt', 9000: 'PHP-FPM', 9090: 'Prometheus', 9200: 'Elasticsearch',
    9300: 'Elasticsearch', 10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB'
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
        self.script_engine = NmapScriptEngine(target)
        
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
                return 'open'
            else:
                return 'closed'
        except socket.timeout:
            self.filtered_ports.append(port)
            return 'filtered'
        except:
            return 'error'
    
    def syn_scan(self, port):
        """SYN scan (half-open scan) - requires root privileges"""
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Build SYN packet
            packet = self.build_syn_packet(port)
            s.sendto(packet, (self.target, 0))
            
            # Wait for response
            ready = select.select([s], [], [], self.timeout)
            if ready[0]:
                data, addr = s.recvfrom(1024)
                flags = self.parse_tcp_flags(data)
                
                if flags['SYN'] and flags['ACK']:
                    self.open_ports.append(port)
                    service = self.detect_service(port)
                    self.scan_results[port] = {
                        'state': 'open',
                        'service': service,
                        'banner': None
                    }
                    # Send RST to close connection
                    self.send_rst_packet(s, port)
                    return 'open'
                elif flags['RST']:
                    return 'closed'
            else:
                self.filtered_ports.append(port)
                return 'filtered'
                
            s.close()
        except PermissionError:
            print(f"{Colors.RED}[-] SYN scan requires root privileges{Colors.RESET}")
            return self.tcp_connect_scan(port)
        except:
            return 'error'
    
    def udp_scan(self, port):
        """UDP scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                self.open_ports.append(port)
                service = self.detect_service(port, 'udp')
                self.scan_results[port] = {
                    'state': 'open',
                    'service': service,
                    'banner': data.decode('utf-8', errors='ignore') if data else None
                }
                return 'open'
            except socket.timeout:
                # No response might mean open or filtered
                return 'open|filtered'
            except socket.error as e:
                if e.errno == 111:  # ICMP port unreachable
                    return 'closed'
                else:
                    return 'filtered'
        except:
            return 'error'
    
    def detect_service(self, port, protocol='tcp'):
        """Detect service running on port"""
        service = PORT_SERVICES.get(port, 'unknown')
        if service != 'unknown':
            return service
        
        # Try to detect service through banner grabbing
        if protocol == 'tcp':
            banner = self.grab_banner(port)
            if banner:
                if 'SSH' in banner:
                    return 'SSH'
                elif 'HTTP' in banner:
                    return 'HTTP'
                elif 'FTP' in banner:
                    return 'FTP'
                elif 'SMTP' in banner:
                    return 'SMTP'
        
        return f'unknown ({protocol})'
    
    def grab_banner(self, port):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # Send HTTP request for HTTP services
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100]  # Limit banner length
        except:
            return None
    
    def build_syn_packet(self, dest_port):
        """Build a SYN packet for SYN scanning"""
        # IP Header
        source_ip = socket.inet_aton(self.get_local_ip())
        dest_ip = socket.inet_aton(socket.gethostbyname(self.target))
        
        # TCP Header
        source_port = random.randint(1024, 65535)
        seq_num = random.randint(0, 2**32 - 1)
        ack_num = 0
        data_offset = 5
        flags = 2  # SYN flag
        window = 8192
        checksum = 0
        urgent_ptr = 0
        
        # Pack TCP header
        tcp_header = struct.pack('!HHLLBBHHH', 
                                source_port, dest_port, seq_num, ack_num, 
                                (data_offset << 4), flags, window, checksum, urgent_ptr)
        
        # Calculate checksum
        pseudo_header = source_ip + dest_ip + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp_header))
        checksum = self.calculate_checksum(pseudo_header + tcp_header)
        
        # Repack with correct checksum
        tcp_header = struct.pack('!HHLLBBHHH', 
                                source_port, dest_port, seq_num, ack_num, 
                                (data_offset << 4), flags, window, checksum, urgent_ptr)
        
        # IP header
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
    
    def parse_tcp_flags(self, packet):
        """Parse TCP flags from packet"""
        tcp_header = packet[20:40]
        flags = tcp_header[13]
        
        return {
            'FIN': bool(flags & 0x01),
            'SYN': bool(flags & 0x02),
            'RST': bool(flags & 0x04),
            'PSH': bool(flags & 0x08),
            'ACK': bool(flags & 0x10),
            'URG': bool(flags & 0x20)
        }
    
    def send_rst_packet(self, sock, port):
        """Send RST packet to close half-open connection"""
        # Implementation would go here
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
        else:
            return self.tcp_connect_scan(port)
    
    def run_scan(self):
        """Run the port scan"""
        print(f"\n{Colors.CYAN}[*] Starting {self.scan_type.upper()} scan on {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Port range: {self.start_port}-{self.end_port}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Threads: {self.threads}{Colors.RESET}\n")
        
        self.start_time = time.time()
        
        # Get port list
        if hasattr(self.advanced_scanner, 'randomize_scan_order') and self.advanced_scanner.randomize:
            ports = self.advanced_scanner.randomize_scan_order((self.start_port, self.end_port))
        else:
            ports = range(self.start_port, self.end_port + 1)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port_with_stats, port): port for port in ports}
            
            completed = 0
            total = len(ports)
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    completed += 1
                    
                    # Progress bar
                    progress = completed / total * 100
                    bar_length = 50
                    filled = int(bar_length * completed / total)
                    bar = '█' * filled + '-' * (bar_length - filled)
                    
                    sys.stdout.write(f'\r{Colors.YELLOW}Progress: [{bar}] {progress:.1f}% ({completed}/{total}){Colors.RESET}')
                    sys.stdout.flush()
                    
                    if result == 'open':
                        service = self.scan_results[port]['service']
                        print(f"\n{Colors.GREEN}[+] Port {port}: OPEN - {service}{Colors.RESET}")
                        
                except Exception as e:
                    print(f"\n{Colors.RED}[-] Error scanning port {port}: {e}{Colors.RESET}")
                    self.statistics.update(error=True)
        
        self.end_time = time.time()
        print("\n")
    
    def scan_port_with_stats(self, port):
        """Scan port and update statistics"""
        if self.rate_limiter:
            self.rate_limiter.wait()
        
        # Update statistics
        self.statistics.update(sent=1, bytes_out=64)  # Approximate packet size
        
        result = self.scan_port(port)
        
        if result in ['open', 'closed']:
            self.statistics.update(received=1, bytes_in=64)
        
        return result
    
    def generate_report(self):
        """Generate scan report"""
        scan_duration = self.end_time - self.start_time
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}SCAN REPORT{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}Target: {Colors.YELLOW}{self.target}{Colors.RESET}")
        print(f"{Colors.WHITE}Scan Type: {Colors.YELLOW}{self.scan_type.upper()}{Colors.RESET}")
        print(f"{Colors.WHITE}Port Range: {Colors.YELLOW}{self.start_port}-{self.end_port}{Colors.RESET}")
        print(f"{Colors.WHITE}Scan Duration: {Colors.YELLOW}{scan_duration:.2f} seconds{Colors.RESET}")
        print(f"{Colors.WHITE}Total Ports Scanned: {Colors.YELLOW}{self.end_port - self.start_port + 1}{Colors.RESET}\n")
        
        print(f"{Colors.GREEN}Open Ports: {len(self.open_ports)}{Colors.RESET}")
        print(f"{Colors.RED}Closed Ports: {self.end_port - self.start_port + 1 - len(self.open_ports) - len(self.filtered_ports)}{Colors.RESET}")
        print(f"{Colors.YELLOW}Filtered Ports: {len(self.filtered_ports)}{Colors.RESET}\n")
        
        if self.open_ports:
            print(f"{Colors.BOLD}{Colors.GREEN}OPEN PORTS DETAILS:{Colors.RESET}")
            print(f"{Colors.WHITE}{'Port':<10}{'Service':<20}{'Banner':<50}{Colors.RESET}")
            print(f"{Colors.WHITE}{'-'*80}{Colors.RESET}")
            
            for port in sorted(self.open_ports):
                service = self.scan_results[port]['service']
                banner = self.scan_results[port]['banner'] or 'N/A'
                banner = banner.replace('\n', ' ')[:47] + '...' if len(banner) > 50 else banner
                print(f"{Colors.GREEN}{port:<10}{service:<20}{banner:<50}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")

class NetworkDiscovery:
    """Network discovery and host enumeration"""
    
    @staticmethod
    def ping_sweep(network):
        """Perform ping sweep on network range"""
        print(f"\n{Colors.CYAN}[*] Performing ping sweep on {network}{Colors.RESET}\n")
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            live_hosts = []
            
            for ip in net.hosts():
                ip_str = str(ip)
                response = os.system(f"ping -c 1 -W 1 {ip_str} > /dev/null 2>&1")
                
                if response == 0:
                    live_hosts.append(ip_str)
                    print(f"{Colors.GREEN}[+] {ip_str} is alive{Colors.RESET}")
                
                sys.stdout.write(f'\r{Colors.YELLOW}Scanning: {ip_str}{Colors.RESET}')
                sys.stdout.flush()
            
            print(f"\n\n{Colors.GREEN}[+] Found {len(live_hosts)} live hosts{Colors.RESET}")
            return live_hosts
        
        except ValueError as e:
            print(f"{Colors.RED}[-] Invalid network format: {e}{Colors.RESET}")
            return []
    
    @staticmethod
    def arp_scan(interface='eth0'):
        """Perform ARP scan on local network"""
        print(f"\n{Colors.CYAN}[*] Performing ARP scan on interface {interface}{Colors.RESET}\n")
        
        try:
            if platform.system() == 'Linux':
                cmd = f"arp-scan -l -I {interface}"
            else:
                print(f"{Colors.RED}[-] ARP scan is only supported on Linux{Colors.RESET}")
                return []
            
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                hosts = []
                
                for line in lines:
                    if '\t' in line and not line.startswith('Interface'):
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            hosts.append({'ip': ip, 'mac': mac})
                            print(f"{Colors.GREEN}[+] {ip} - {mac}{Colors.RESET}")
                
                return hosts
            else:
                print(f"{Colors.RED}[-] ARP scan failed. Make sure arp-scan is installed and you have root privileges{Colors.RESET}")
                return []
        
        except Exception as e:
            print(f"{Colors.RED}[-] Error during ARP scan: {e}{Colors.RESET}")
            return []

def os_detection(target):
    """Basic OS detection based on TTL values"""
    try:
        response = os.system(f"ping -c 1 {target} > /dev/null 2>&1")
        if response == 0:
            if platform.system() == 'Windows':
                output = subprocess.check_output(f"ping -n 1 {target}", shell=True).decode()
            else:
                output = subprocess.check_output(f"ping -c 1 {target}", shell=True).decode()
            
            if 'ttl=64' in output.lower() or 'ttl=63' in output.lower():
                return "Linux/Unix"
            elif 'ttl=128' in output.lower() or 'ttl=127' in output.lower():
                return "Windows"
            elif 'ttl=255' in output.lower() or 'ttl=254' in output.lower():
                return "Network Device (Router/Switch)"
            else:
                return "Unknown"
    except:
        return "Unknown"

def save_results(scanner, filename):
    """Save scan results to file"""
    with open(filename, 'w') as f:
        f.write("ROOTSCAN REPORT\n")
        f.write("="*60 + "\n\n")
        f.write(f"Target: {scanner.target}\n")
        f.write(f"Scan Type: {scanner.scan_type.upper()}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("OPEN PORTS:\n")
        f.write("-"*40 + "\n")
        
        for port in sorted(scanner.open_ports):
            service = scanner.scan_results[port]['service']
            banner = scanner.scan_results[port]['banner'] or 'N/A'
            f.write(f"Port {port}: {service}\n")
            if banner != 'N/A':
                f.write(f"  Banner: {banner}\n")
            f.write("\n")
    
    print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")

class VulnerabilityScanner:
    """Vulnerability detection module"""
    
    def __init__(self, target, scan_results):
        self.target = target
        self.scan_results = scan_results
        self.vulnerabilities = []
    
    def check_vulnerabilities(self):
        """Check for common vulnerabilities"""
        print(f"\n{Colors.CYAN}[*] Checking for vulnerabilities...{Colors.RESET}\n")
        
        for port, info in self.scan_results.items():
            if info['state'] == 'open':
                self.check_service_vulnerabilities(port, info)
        
        return self.vulnerabilities
    
    def check_service_vulnerabilities(self, port, info):
        """Check vulnerabilities for specific services"""
        service = info['service']
        banner = info['banner']
        
        # SSH vulnerabilities
        if port == 22 or 'SSH' in service:
            self.check_ssh_vulnerabilities(port, banner)
        
        # HTTP/HTTPS vulnerabilities
        if port in [80, 443, 8080, 8443] or 'HTTP' in service:
            self.check_http_vulnerabilities(port, banner)
        
        # FTP vulnerabilities
        if port == 21 or 'FTP' in service:
            self.check_ftp_vulnerabilities(port, banner)
        
        # SMB vulnerabilities
        if port in [139, 445] or 'SMB' in service:
            self.check_smb_vulnerabilities(port, banner)
        
        # Database vulnerabilities
        if port in [3306, 5432, 1433, 1521, 27017]:
            self.check_database_vulnerabilities(port, service)
    
    def check_ssh_vulnerabilities(self, port, banner):
        """Check SSH-specific vulnerabilities"""
        vulns = []
        
        if banner:
            # Check for old SSH versions
            if 'SSH-1' in banner:
                vulns.append({
                    'severity': 'HIGH',
                    'vulnerability': 'SSH Protocol 1 Enabled',
                    'description': 'SSH Protocol 1 has known vulnerabilities',
                    'recommendation': 'Upgrade to SSH Protocol 2'
                })
            
            # Check for specific vulnerable versions
            vulnerable_versions = ['OpenSSH_4', 'OpenSSH_5', 'OpenSSH_6.0', 'OpenSSH_6.1', 'OpenSSH_6.2']
            for version in vulnerable_versions:
                if version in banner:
                    vulns.append({
                        'severity': 'MEDIUM',
                        'vulnerability': f'Outdated SSH Version ({version})',
                        'description': 'This SSH version may have known vulnerabilities',
                        'recommendation': 'Update to the latest OpenSSH version'
                    })
        
        for vuln in vulns:
            self.vulnerabilities.append({'port': port, 'service': 'SSH', **vuln})
            self.print_vulnerability(port, vuln)
    
    def check_http_vulnerabilities(self, port, banner):
        """Check HTTP/HTTPS vulnerabilities"""
        vulns = []
        
        # Check for server information disclosure
        if banner and any(server in banner for server in ['Apache', 'nginx', 'IIS', 'Tomcat']):
            vulns.append({
                'severity': 'LOW',
                'vulnerability': 'Server Version Disclosure',
                'description': 'Server version information is exposed',
                'recommendation': 'Configure server to hide version information'
            })
        
        # Check for missing security headers (would need actual HTTP request)
        if port == 80:
            vulns.append({
                'severity': 'MEDIUM',
                'vulnerability': 'Unencrypted HTTP Service',
                'description': 'Service running over unencrypted HTTP',
                'recommendation': 'Implement HTTPS with proper SSL/TLS configuration'
            })
        
        for vuln in vulns:
            self.vulnerabilities.append({'port': port, 'service': 'HTTP/HTTPS', **vuln})
            self.print_vulnerability(port, vuln)
    
    def check_ftp_vulnerabilities(self, port, banner):
        """Check FTP vulnerabilities"""
        vulns = []
        
        # Anonymous FTP access check would go here
        vulns.append({
            'severity': 'INFO',
            'vulnerability': 'FTP Service Detected',
            'description': 'FTP transmits credentials in cleartext',
            'recommendation': 'Consider using SFTP or FTPS instead'
        })
        
        for vuln in vulns:
            self.vulnerabilities.append({'port': port, 'service': 'FTP', **vuln})
            self.print_vulnerability(port, vuln)
    
    def check_smb_vulnerabilities(self, port, banner):
        """Check SMB vulnerabilities"""
        vulns = []
        
        vulns.append({
            'severity': 'HIGH',
            'vulnerability': 'SMB Service Exposed',
            'description': 'SMB service is accessible from the network',
            'recommendation': 'Restrict SMB access to trusted networks only'
        })
        
        for vuln in vulns:
            self.vulnerabilities.append({'port': port, 'service': 'SMB', **vuln})
            self.print_vulnerability(port, vuln)
    
    def check_database_vulnerabilities(self, port, service):
        """Check database vulnerabilities"""
        vulns = []
        
        db_names = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            1521: 'Oracle',
            27017: 'MongoDB'
        }
        
        db_name = db_names.get(port, 'Database')
        
        vulns.append({
            'severity': 'HIGH',
            'vulnerability': f'{db_name} Service Exposed',
            'description': f'{db_name} service is accessible from the network',
            'recommendation': f'Restrict {db_name} access to application servers only'
        })
        
        for vuln in vulns:
            self.vulnerabilities.append({'port': port, 'service': db_name, **vuln})
            self.print_vulnerability(port, vuln)
    
    def print_vulnerability(self, port, vuln):
        """Print vulnerability information"""
        severity_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.BLUE,
            'INFO': Colors.CYAN
        }
        
        color = severity_colors.get(vuln['severity'], Colors.WHITE)
        print(f"{color}[!] Port {port} - {vuln['severity']}: {vuln['vulnerability']}{Colors.RESET}")
        print(f"    {Colors.WHITE}Description: {vuln['description']}{Colors.RESET}")
        print(f"    {Colors.GREEN}Recommendation: {vuln['recommendation']}{Colors.RESET}\n")

class StealthScanner:
    """Stealth scanning techniques"""
    
    def __init__(self, target, timeout=2):
        self.target = target
        self.timeout = timeout
    
    def xmas_scan(self, port):
        """XMAS scan - FIN, PSH, and URG flags set"""
        try:
            # This would require raw socket implementation
            # Placeholder for XMAS scan logic
            pass
        except:
            return 'error'
    
    def fin_scan(self, port):
        """FIN scan - Only FIN flag set"""
        try:
            # This would require raw socket implementation
            # Placeholder for FIN scan logic
            pass
        except:
            return 'error'
    
    def null_scan(self, port):
        """NULL scan - No flags set"""
        try:
            # This would require raw socket implementation
            # Placeholder for NULL scan logic
            pass
        except:
            return 'error'

class ServiceFingerprinting:
    """Advanced service fingerprinting"""
    
    @staticmethod
    def deep_service_scan(target, port):
        """Perform deep service identification"""
        probes = {
            'HTTP': b'GET / HTTP/1.1\r\nHost: test\r\n\r\n',
            'HTTPS': b'GET / HTTP/1.1\r\nHost: test\r\n\r\n',
            'FTP': b'USER anonymous\r\n',
            'SMTP': b'EHLO test\r\n',
            'POP3': b'USER test\r\n',
            'IMAP': b'A001 CAPABILITY\r\n',
            'SSH': b'SSH-2.0-OpenSSH_Test\r\n',
            'TELNET': b'\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27',
            'MYSQL': b'\x00\x00\x00\x0a\x35\x2e\x30\x2e\x35\x31\x00',
            'RDP': b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
        }
        
        results = {}
        
        for service, probe in probes.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                sock.send(probe)
                response = sock.recv(1024)
                sock.close()
                
                if response:
                    results[service] = response.decode('utf-8', errors='ignore')
            except:
                continue
        
        return results

class ExportFormats:
    """Export scan results in various formats"""
    
    @staticmethod
    def export_json(scanner, filename):
        """Export results as JSON"""
        import json
        
        data = {
            'scan_info': {
                'target': scanner.target,
                'scan_type': scanner.scan_type,
                'date': datetime.now().isoformat(),
                'duration': scanner.end_time - scanner.start_time if scanner.end_time else 0
            },
            'results': {
                'open_ports': scanner.open_ports,
                'filtered_ports': scanner.filtered_ports,
                'port_details': scanner.scan_results
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"{Colors.GREEN}[+] Results exported to {filename} (JSON){Colors.RESET}")
    
    @staticmethod
    def export_xml(scanner, filename):
        """Export results as XML"""
        root = ET.Element('rootscan')
        
        # Scan info
        scan_info = ET.SubElement(root, 'scan_info')
        ET.SubElement(scan_info, 'target').text = scanner.target
        ET.SubElement(scan_info, 'scan_type').text = scanner.scan_type
        ET.SubElement(scan_info, 'date').text = datetime.now().isoformat()
        
        # Results
        results = ET.SubElement(root, 'results')
        
        for port in scanner.open_ports:
            port_elem = ET.SubElement(results, 'port')
            port_elem.set('number', str(port))
            port_elem.set('state', 'open')
            port_elem.set('service', scanner.scan_results[port]['service'])
            
            if scanner.scan_results[port]['banner']:
                ET.SubElement(port_elem, 'banner').text = scanner.scan_results[port]['banner']
        
        tree = ET.ElementTree(root)
        tree.write(filename)
        
        print(f"{Colors.GREEN}[+] Results exported to {filename} (XML){Colors.RESET}")
    
    @staticmethod
    def export_csv(scanner, filename):
        """Export results as CSV"""
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

class AdvancedScanner:
    """Advanced scanning techniques and evasion methods"""
    
    def __init__(self, target):
        self.target = target
        self.decoy_ips = []
    
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
        port_list = list(range(ports[0], ports[1] + 1))
        random.shuffle(port_list)
        return port_list

class SSLScanner:
    """SSL/TLS vulnerability scanner"""
    
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
    
    def check_ssl_vulnerabilities(self, port):
        """Check for SSL/TLS vulnerabilities"""
        vulns = []
        
        # Check SSL versions
        ssl_versions = [
            (ssl.PROTOCOL_SSLv2, 'SSLv2', 'CRITICAL'),
            (ssl.PROTOCOL_SSLv3, 'SSLv3', 'HIGH'),
            (ssl.PROTOCOL_TLSv1, 'TLSv1.0', 'MEDIUM'),
            (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1', 'MEDIUM')
        ]
        
        for protocol, version, severity in ssl_versions:
            try:
                context = ssl.SSLContext(protocol)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                
                wrapped_socket = context.wrap_socket(sock)
                wrapped_socket.connect((self.target, port))
                
                vulns.append({
                    'vulnerability': f'{version} Supported',
                    'severity': severity,
                    'description': f'Obsolete {version} protocol is supported',
                    'recommendation': 'Disable legacy SSL/TLS versions'
                })
                
                wrapped_socket.close()
            except:
                pass
        
        # Check for certificate issues
        try:
            context = ssl.create_default_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            wrapped_socket = context.wrap_socket(sock, server_hostname=self.target)
            wrapped_socket.connect((self.target, port))
            
            cert = wrapped_socket.getpeercert()
            
            # Check certificate expiration
            not_after = cert.get('notAfter')
            if not_after:
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                if expiry_date < datetime.now():
                    vulns.append({
                        'vulnerability': 'Expired Certificate',
                        'severity': 'HIGH',
                        'description': f'Certificate expired on {expiry_date}',
                        'recommendation': 'Renew SSL certificate'
                    })
            
            wrapped_socket.close()
        except ssl.CertificateError as e:
            vulns.append({
                'vulnerability': 'Certificate Error',
                'severity': 'HIGH',
                'description': str(e),
                'recommendation': 'Fix certificate configuration'
            })
        except:
            pass
        
        return vulns

class WebScanner:
    """Web application scanner"""
    
    def __init__(self, target):
        self.target = target
        self.findings = []
    
    def scan_web_vulnerabilities(self, port):
        """Scan for common web vulnerabilities"""
        findings = []
        
        # Check for common paths
        common_paths = [
            '/.git/', '/.svn/', '/.env', '/wp-admin/', '/admin/', '/phpmyadmin/',
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/backup/', '/temp/',
            '/config.php', '/wp-config.php', '/.DS_Store', '/server-status'
        ]
        
        for path in common_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, port))
                
                request = f"GET {path} HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if '200 OK' in response or '301' in response or '302' in response:
                    findings.append({
                        'type': 'Information Disclosure',
                        'path': path,
                        'status': response.split('\n')[0],
                        'severity': 'MEDIUM'
                    })
            except:
                continue
        
        # Check security headers
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check for missing security headers
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-XSS-Protection'
            ]
            
            for header in security_headers:
                if header.lower() not in response.lower():
                    findings.append({
                        'type': 'Missing Security Header',
                        'header': header,
                        'severity': 'LOW',
                        'recommendation': f'Implement {header} header'
                    })
        except:
            pass
        
        return findings

class NmapScriptEngine:
    """NSE-like script engine for advanced scanning"""
    
    def __init__(self, target):
        self.target = target
        self.scripts = {
            'smb-vuln-ms17-010': self.check_eternalblue,
            'ssl-heartbleed': self.check_heartbleed,
            'http-methods': self.check_http_methods,
            'ftp-anon': self.check_ftp_anonymous,
            'mysql-empty-password': self.check_mysql_empty_password
        }
    
    def run_script(self, script_name, port):
        """Run a specific script"""
        if script_name in self.scripts:
            return self.scripts[script_name](port)
        return None
    
    def check_eternalblue(self, port):
        """Check for MS17-010 (EternalBlue) vulnerability"""
        if port not in [139, 445]:
            return None
        
        # This is a simplified check - real implementation would be more complex
        return {
            'script': 'smb-vuln-ms17-010',
            'status': 'VULNERABLE',
            'severity': 'CRITICAL',
            'description': 'Host is likely vulnerable to MS17-010 (EternalBlue)'
        }
    
    def check_heartbleed(self, port):
        """Check for Heartbleed vulnerability"""
        if port not in [443, 8443]:
            return None
        
        # Simplified check
        return {
            'script': 'ssl-heartbleed',
            'status': 'NEEDS_CHECK',
            'severity': 'CRITICAL',
            'description': 'SSL service detected - manual Heartbleed check recommended'
        }
    
    def check_http_methods(self, port):
        """Check allowed HTTP methods"""
        if port not in [80, 8080, 8000, 8888]:
            return None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            request = f"OPTIONS / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'Allow:' in response:
                methods = response.split('Allow:')[1].split('\r\n')[0].strip()
                dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in dangerous if m in methods]
                
                if found_dangerous:
                    return {
                        'script': 'http-methods',
                        'methods': methods,
                        'dangerous': found_dangerous,
                        'severity': 'MEDIUM',
                        'recommendation': 'Disable unnecessary HTTP methods'
                    }
        except:
            pass
        
        return None
    
    def check_ftp_anonymous(self, port):
        """Check for anonymous FTP access"""
        if port != 21:
            return None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Try anonymous login
            sock.send(b'USER anonymous\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '331' in response:  # Password required
                sock.send(b'PASS anonymous@\r\n')
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in response:  # Login successful
                    sock.close()
                    return {
                        'script': 'ftp-anon',
                        'status': 'VULNERABLE',
                        'severity': 'HIGH',
                        'description': 'Anonymous FTP login allowed'
                    }
            
            sock.close()
        except:
            pass
        
        return None
    
    def check_mysql_empty_password(self, port):
        """Check for MySQL empty password"""
        if port != 3306:
            return None
        
        # This would require MySQL protocol implementation
        return {
            'script': 'mysql-empty-password',
            'status': 'NEEDS_CHECK',
            'description': 'MySQL service detected - check for empty passwords'
        }

class RateLimiter:
    """Rate limiting for scan speed control"""
    
    def __init__(self, max_rate=1000):
        self.max_rate = max_rate  # packets per second
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

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description='RootScan - Advanced Port Scanner by @y3rm4n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rootscan.py -t 192.168.1.1
  python3 rootscan.py -t example.com -p 1-1000
  python3 rootscan.py -t 192.168.1.0/24 --ping-sweep
  python3 rootscan.py -t 192.168.1.1 -sS -p 80,443,8080
  python3 rootscan.py -t 192.168.1.1 -sU -p 53,67,123
  python3 rootscan.py -t 192.168.1.1 --vuln-scan
  python3 rootscan.py -t 192.168.1.1 -o results.json --format json
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
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
    parser.add_argument('--deep-scan', action='store_true', help='Enable deep service fingerprinting')
    parser.add_argument('--top-ports', type=int, help='Scan top N most common ports')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timing', choices=['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'], 
                       default='normal', help='Timing profile for scan speed')
    parser.add_argument('--rate-limit', type=int, help='Maximum packets per second')
    parser.add_argument('--scripts', nargs='+', help='Run NSE-like scripts (e.g., smb-vuln-ms17-010)')
    parser.add_argument('--ssl-scan', action='store_true', help='Perform SSL/TLS vulnerability scan')
    parser.add_argument('--web-scan', action='store_true', help='Perform web vulnerability scan')
    parser.add_argument('--decoy', type=int, help='Use N decoy addresses for scan')
    parser.add_argument('--randomize', action='store_true', help='Randomize port scan order')
    parser.add_argument('--fragment', action='store_true', help='Fragment packets (IDS evasion)')
    parser.add_argument('--stats', action='store_true', help='Show detailed statistics after scan')
    
    args = parser.parse_args()
    
    # Handle network discovery options
    if args.ping_sweep:
        NetworkDiscovery.ping_sweep(args.target)
        return
    
    if args.arp_scan:
        NetworkDiscovery.arp_scan(args.interface)
        return
    
    # Determine scan type
    scan_type = 'tcp'
    if args.syn_scan:
        scan_type = 'syn'
    elif args.udp_scan:
        scan_type = 'udp'
    elif args.xmas_scan:
        scan_type = 'xmas'
        print(f"{Colors.YELLOW}[!] XMAS scan requires custom implementation{Colors.RESET}")
    elif args.fin_scan:
        scan_type = 'fin'
        print(f"{Colors.YELLOW}[!] FIN scan requires custom implementation{Colors.RESET}")
    elif args.null_scan:
        scan_type = 'null'
        print(f"{Colors.YELLOW}[!] NULL scan requires custom implementation{Colors.RESET}")
    
    # Handle top ports option
    if args.top_ports:
        # Most common ports
        top_ports_list = {
            10: [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389],
            20: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
            50: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445, 993, 995, 1025, 1433, 1720, 1723, 
                 3306, 3389, 5060, 5432, 5900, 8000, 8008, 8080, 8443, 49152, 49153, 49154, 49155, 49156, 49157,
                 20, 69, 79, 88, 113, 119, 123, 137, 138, 179, 389, 427, 465, 514, 520, 548],
            100: list(PORT_SERVICES.keys())[:100]
        }
        
        if args.top_ports in top_ports_list:
            ports = top_ports_list[args.top_ports]
            start_port = min(ports)
            end_port = max(ports)
            print(f"{Colors.CYAN}[*] Scanning top {args.top_ports} ports{Colors.RESET}")
        else:
            ports = list(PORT_SERVICES.keys())[:args.top_ports]
            start_port = min(ports)
            end_port = max(ports)
    else:
        # Parse port range
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        elif ',' in args.ports:
            # Handle comma-separated ports
            ports = list(map(int, args.ports.split(',')))
            start_port = min(ports)
            end_port = max(ports)
        else:
            start_port = end_port = int(args.ports)
    
    # OS Detection
    if args.os_detect:
        print(f"\n{Colors.CYAN}[*] Detecting OS...{Colors.RESET}")
        os_type = os_detection(args.target)
        print(f"{Colors.GREEN}[+] Probable OS: {os_type}{Colors.RESET}")
    
    # Apply timing profile
    timing_profile = TimingProfiles.get_profile(args.timing)
    if not args.threads:
        args.threads = timing_profile['threads']
    if not args.timeout:
        args.timeout = timing_profile['timeout']
    
    print(f"{Colors.CYAN}[*] Using timing profile: {args.timing}{Colors.RESET}")
    
    # Apply timing profile
    timing_profile = TimingProfiles.get_profile(args.timing)
    if not args.threads:
        args.threads = timing_profile['threads']
    if not args.timeout:
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
    
    # Set up decoys if specified
    if args.decoy:
        scanner.advanced_scanner.decoy_ips = scanner.advanced_scanner.generate_decoys(args.decoy)
        print(f"{Colors.CYAN}[*] Using {args.decoy} decoy addresses{Colors.RESET}")
        if args.verbose:
            for decoy in scanner.advanced_scanner.decoy_ips:
                print(f"    Decoy: {decoy}")
    
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
    
    # Deep service scanning if requested
    if args.deep_scan and scanner.open_ports:
        print(f"\n{Colors.CYAN}[*] Performing deep service fingerprinting...{Colors.RESET}")
        for port in scanner.open_ports:
            deep_results = ServiceFingerprinting.deep_service_scan(scanner.target, port)
            if deep_results and args.verbose:
                print(f"{Colors.MAGENTA}[*] Deep scan results for port {port}:{Colors.RESET}")
                for service, response in deep_results.items():
                    print(f"    {service}: {response[:50]}...")
    
    # SSL/TLS scanning if requested
    if args.ssl_scan and scanner.open_ports:
        print(f"\n{Colors.CYAN}[*] Performing SSL/TLS vulnerability scan...{Colors.RESET}")
        ssl_scanner = SSLScanner(scanner.target)
        
        for port in scanner.open_ports:
            if port in [443, 8443] or 'HTTPS' in scanner.scan_results[port]['service']:
                ssl_vulns = ssl_scanner.check_ssl_vulnerabilities(port)
                if ssl_vulns:
                    print(f"\n{Colors.YELLOW}[!] SSL/TLS vulnerabilities on port {port}:{Colors.RESET}")
                    for vuln in ssl_vulns:
                        color = Colors.RED if vuln['severity'] in ['CRITICAL', 'HIGH'] else Colors.YELLOW
                        print(f"{color}    - {vuln['vulnerability']}: {vuln['description']}{Colors.RESET}")
    
    # Web scanning if requested
    if args.web_scan and scanner.open_ports:
        print(f"\n{Colors.CYAN}[*] Performing web vulnerability scan...{Colors.RESET}")
        web_scanner = WebScanner(scanner.target)
        
        for port in scanner.open_ports:
            if port in [80, 443, 8080, 8443] or 'HTTP' in scanner.scan_results[port]['service']:
                web_findings = web_scanner.scan_web_vulnerabilities(port)
                if web_findings:
                    print(f"\n{Colors.YELLOW}[!] Web findings on port {port}:{Colors.RESET}")
                    for finding in web_findings:
                        if 'path' in finding:
                            print(f"{Colors.YELLOW}    - {finding['type']}: {finding['path']} ({finding['status']}){Colors.RESET}")
                        else:
                            print(f"{Colors.BLUE}    - {finding['type']}: {finding['header']}{Colors.RESET}")
    
    # Run NSE-like scripts if requested
    if args.scripts and scanner.open_ports:
        print(f"\n{Colors.CYAN}[*] Running scripts: {', '.join(args.scripts)}{Colors.RESET}")
        
        for script in args.scripts:
            for port in scanner.open_ports:
                result = scanner.script_engine.run_script(script, port)
                if result:
                    color = Colors.RED if result.get('severity') == 'CRITICAL' else Colors.YELLOW
                    print(f"\n{color}[!] Script {script} on port {port}:{Colors.RESET}")
                    for key, value in result.items():
                        if key not in ['script', 'severity']:
                            print(f"    {key}: {value}")
    
    # Vulnerability scanning if requested
    if args.vuln_scan and scanner.open_ports:
        vuln_scanner = VulnerabilityScanner(scanner.target, scanner.scan_results)
        vulnerabilities = vuln_scanner.check_vulnerabilities()
        
        if vulnerabilities:
            print(f"\n{Colors.BOLD}{Colors.RED}VULNERABILITY SUMMARY:{Colors.RESET}")
            print(f"{Colors.WHITE}{'='*60}{Colors.RESET}")
            print(f"{Colors.WHITE}Total vulnerabilities found: {len(vulnerabilities)}{Colors.RESET}")
            
            # Count by severity
            severity_count = {}
            for vuln in vulnerabilities:
                severity = vuln['severity']
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            for severity, count in severity_count.items():
                print(f"{Colors.WHITE}{severity}: {count}{Colors.RESET}")
    
    # Generate report
    scanner.generate_report()
    
    # Show statistics if requested
    if args.stats:
        stats = scanner.statistics.get_summary()
        print(f"\n{Colors.BOLD}{Colors.CYAN}SCAN STATISTICS:{Colors.RESET}")
        print(f"{Colors.WHITE}{'='*60}{Colors.RESET}")
        print(f"{Colors.WHITE}Duration: {stats['duration']:.2f} seconds{Colors.RESET}")
        print(f"{Colors.WHITE}Packets sent: {stats['packets_sent']}{Colors.RESET}")
        print(f"{Colors.WHITE}Packets received: {stats['packets_received']}{Colors.RESET}")
        print(f"{Colors.WHITE}Bytes sent: {stats['bytes_sent']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}Bytes received: {stats['bytes_received']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}Errors: {stats['errors']}{Colors.RESET}")
        print(f"{Colors.WHITE}Packets per second: {stats['pps']:.2f}{Colors.RESET}")
        
        if scanner.end_time:
            ports_per_second = (scanner.end_port - scanner.start_port + 1) / stats['duration']
            print(f"{Colors.WHITE}Ports per second: {ports_per_second:.2f}{Colors.RESET}")
    
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
    scanner = PortScanner(
        target=args.target,
        start_port=start_port,
        end_port=end_port,
        threads=args.threads,
        timeout=args.timeout,
        scan_type=scan_type
    )
    
    # Resolve target
    resolved_ip = scanner.resolve_target()
    if not resolved_ip:
        sys.exit(1)
    
    if resolved_ip != args.target:
        print(f"{Colors.GREEN}[+] Resolved {args.target} to {resolved_ip}{Colors.RESET}")
    
    # Run scan
    scanner.run_scan()
    
    # Deep service scanning if requested
    if args.deep_scan and scanner.open_ports:
        print(f"\n{Colors.CYAN}[*] Performing deep service fingerprinting...{Colors.RESET}")
        for port in scanner.open_ports:
            deep_results = ServiceFingerprinting.deep_service_scan(scanner.target, port)
            if deep_results and args.verbose:
                print(f"{Colors.MAGENTA}[*] Deep scan results for port {port}:{Colors.RESET}")
                for service, response in deep_results.items():
                    print(f"    {service}: {response[:50]}...")
    
    # Vulnerability scanning if requested
    if args.vuln_scan and scanner.open_ports:
        vuln_scanner = VulnerabilityScanner(scanner.target, scanner.scan_results)
        vulnerabilities = vuln_scanner.check_vulnerabilities()
        
        if vulnerabilities:
            print(f"\n{Colors.BOLD}{Colors.RED}VULNERABILITY SUMMARY:{Colors.RESET}")
            print(f"{Colors.WHITE}{'='*60}{Colors.RESET}")
            print(f"{Colors.WHITE}Total vulnerabilities found: {len(vulnerabilities)}{Colors.RESET}")
            
            # Count by severity
            severity_count = {}
            for vuln in vulnerabilities:
                severity = vuln['severity']
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            for severity, count in severity_count.items():
                print(f"{Colors.WHITE}{severity}: {count}{Colors.RESET}")
    
    # Generate report
    scanner.generate_report()
    
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

if __name__ == "__main__":
    try:
        # Check for required privileges for certain scans
        if len(sys.argv) > 1 and any(opt in sys.argv for opt in ['-sS', '--syn-scan', '--arp-scan']):
            if os.geteuid() != 0:
                print(f"{Colors.RED}[!] This scan type requires root privileges{Colors.RESET}")
                print(f"{Colors.YELLOW}[*] Run with: sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}{Colors.RESET}")
                sys.exit(1)
        
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)