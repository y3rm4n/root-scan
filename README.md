# RootScan - Advanced Network Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.5-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/creator-%40y3rm4n-purple.svg" alt="Creator">
  <img src="https://img.shields.io/badge/commands-100%2B-orange.svg" alt="Commands">
</p>


```
    ____             __  _____                 
   / __ \____  ____  / /_/ ___/_________ _____ 
  / /_/ / __ \/ __ \/ __/\__ \/ ___/ __ `/ __ \
 / _, _/ /_/ / /_/ / /_ ___/ / /__/ /_/ / / / /
/_/ |_|\____/\____/\__//____/\___/\__,_/_/ /_/ 
                                                
        Created by @y3rm4n
        Advanced Network Scanner v1.0.5 
```

## 🚀 Key Features

- **🎯 Multiple Scan Types**: TCP Connect, SYN Stealth, UDP, XMAS, FIN, NULL
- **🌐 Network Discovery**: Ping sweep, ARP scan, OS detection
- **🔍 Vulnerability Detection**: 25+ built-in vulnerability checks with JSON database
- **🔬 Service Fingerprinting**: Advanced banner grabbing and service detection
- **⚡ Performance Control**: 6 timing profiles from paranoid to insane
- **🥷 Stealth Features**: Randomization, rate limiting, thread control
- **📊 Extensible Scripts**: NSE-like script system for vulnerability checks
- **📄 Multiple Formats**: Export in TXT, JSON, XML, CSV
- **🛠️ 100+ Combinations**: Comprehensive testing capabilities

## 📋 System Requirements

- **Python**: 3.8 or higher
- **OS**: Linux/Unix (recommended), macOS, Windows
- **Privileges**: Root/sudo (required for SYN scan and ARP scan)
- **Network**: Connectivity access

## 🚀 Quick Installation

### 1. Clone Repository

```bash
git clone https://github.com/y3rm4n/root-scan.git
cd root-scan
```

### 2. Automatic Setup

```bash
# Run setup script (recommended)
chmod +x setup.sh
./setup.sh

# Or manual installation
pip3 install -r requirements.txt --break-system-packages
```

### 3. System Dependencies

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y arp-scan nmap

# CentOS/RHEL/Fedora  
sudo yum install -y arp-scan nmap

# Arch Linux
sudo pacman -S arp-scan nmap

# macOS (Homebrew)
brew install arp-scan nmap
```

### 4. Verify Installation

```bash
python3 rootscan.py --help
python3 rootscan.py --list-vulns
```

## 🎯 Quick Start Guide

### Basic Commands

```bash
# Basic TCP scan
python3 rootscan.py -t 192.168.1.1

# Scan specific ports
python3 rootscan.py -t example.com -p 80,443,8080,22

# Scan port range
python3 rootscan.py -t 192.168.1.1 -p 1-1000

# Top 100 most common ports
python3 rootscan.py -t example.com --top-ports 100
```

### Advanced Scans

```bash
# SYN stealth scan (requires root)
sudo python3 rootscan.py -t example.com -sS

# UDP scan
python3 rootscan.py -t 192.168.1.1 -sU -p 53,67,123,161

# Vulnerability scan
python3 rootscan.py -t example.com --vuln-scan -v

# Complete stealth scan
sudo python3 rootscan.py -t example.com -sS --timing sneaky --randomize
```

### Network Discovery

```bash
# Network ping sweep
python3 rootscan.py -t 192.168.1.0/24 --ping-sweep

# ARP scan (requires root)
sudo python3 rootscan.py --arp-scan -i eth0

# OS detection
python3 rootscan.py -t 192.168.1.1 --os-detect
```

## 📚 Complete Command Reference

### **Basic Arguments**
```bash
-t, --target          # Target IP/hostname (required except --arp-scan)
-p, --ports           # Port range: 1-1000, 80,443,8080 [default: 1-1000]
-T, --threads         # Number of threads [default: 100]
--timeout             # Socket timeout in seconds [default: 1.0]
```

### **Scan Types**
```bash
-sT, --tcp-scan       # TCP Connect scan (default)
-sS, --syn-scan       # TCP SYN scan (requires root)
-sU, --udp-scan       # UDP scan
-sX, --xmas-scan      # XMAS scan (experimental)
-sF, --fin-scan       # FIN scan (experimental)
-sN, --null-scan      # NULL scan (experimental)
```

### **Network Discovery**
```bash
--ping-sweep          # Ping sweep on network range
--arp-scan            # ARP scan on local network (requires root)
-i, --interface       # Network interface for ARP scan [default: eth0]
--os-detect           # OS detection based on TTL values
```

### **Security Analysis**
```bash
--vuln-scan           # Built-in vulnerability scanner
--list-vulns          # List available vulnerabilities
--vuln                # Run specific vulnerability check
```

### **Performance Control**
```bash
--timing              # Timing profile: paranoid, sneaky, polite, normal, aggressive, insane
--rate-limit          # Maximum packets per second
--randomize           # Randomize port scan order
--top-ports           # Scan top N most common ports
```

### **Output and Reporting**
```bash
-o, --output          # Save results to file
--format              # Output format: txt, json, xml, csv [default: txt]
-v, --verbose         # Verbose output
--stats               # Show detailed statistics
```

## 🔍 Vulnerability System

RootScan includes an advanced vulnerability detection system with 25+ checks:

### Vulnerability Categories

- **🌐 HTTP/HTTPS**: HTTP methods, headers, robots.txt, SSL/TLS
- **🗄️ Databases**: MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch
- **🔐 Authentication**: FTP anonymous, SNMP, LDAP, default credentials
- **🖥️ Network Services**: SMB (MS17-010), SSH, Telnet, VNC, RDP
- **☁️ Containers**: Docker API, Kubernetes API
- **📡 Amplification**: NTP, Memcached, DNS

### Using the Vulnerability System

```bash
# List all available vulnerabilities
python3 rootscan.py --list-vulns

# Complete vulnerability scan
python3 rootscan.py -t target.com --vuln-scan

# Specific checks
python3 rootscan.py -t target.com --vuln ftp-anon --vuln ssl-heartbleed

# Combine with other scans
python3 rootscan.py -t target.com --top-ports 1000 --vuln-scan --os-detect
```

## ⚡ Timing Profiles

| Profile | Timeout | Delay | Threads | Use Case |
|---------|---------|-------|---------|----------|
| **paranoid** | 5s | 2s | 1 | Maximum stealth, very slow |
| **sneaky** | 3s | 1s | 5 | High stealth, slow |
| **polite** | 2s | 0.5s | 10 | Polite scanning |
| **normal** | 1s | 0.1s | 50 | Default, balanced |
| **aggressive** | 0.5s | 0.05s | 100 | Fast scanning |
| **insane** | 0.3s | 0s | 200 | Maximum speed |

## 📊 Top Ports Lists

### **Port Categories**
- **Top 10**: 21, 22, 23, 25, 80, 110, 139, 443, 445, 3389
- **Top 20**: Adds 53, 111, 135, 143, 993, 995, 1723, 3306, 5900, 8080
- **Top 50**: Extended with additional common services
- **Top 100**: Comprehensive common port list
- **Top 1000**: All common ports plus extended range

## 🎯 Use Case Examples

### **Web Server Audit**
```bash
python3 rootscan.py -t webserver.com -p 80,443,8080,8443 \
  --vuln-scan --timing normal \
  -o web_audit_$(date +%Y%m%d).json --format json -v
```

### **Internal Network Reconnaissance**
```bash
# Discover live hosts
python3 rootscan.py -t 192.168.1.0/24 --ping-sweep
sudo python3 rootscan.py --arp-scan

# Stealth target scanning
sudo python3 rootscan.py -t 192.168.1.1 -sS --top-ports 1000 \
  --timing sneaky --randomize --os-detect
```

### **Complete Security Audit**
```bash
python3 rootscan.py -t target.com --top-ports 1000 \
  --vuln-scan --os-detect --timing normal --randomize \
  -o security_audit_$(date +%Y%m%d).json --format json \
  --stats -v
```

### **Database Scanning**
```bash
python3 rootscan.py -t db-server.com -p 3306,5432,1433,1521,27017,6379 \
  --vuln mysql-empty-password --vuln postgres-default \
  --vuln mongodb-unauth --vuln redis-unauth -v
```

### **SSL/TLS Verification**
```bash
python3 rootscan.py -t secure-site.com -p 443,993,995,8443 \
  --vuln ssl-heartbleed --vuln ssl-weak-cipher \
  --timing polite -v
```

## 🛡️ Security Considerations

### **Required Permissions**
- **Root/Sudo** for:
  - SYN scan (`-sS`, `--syn-scan`)
  - ARP scan (`--arp-scan`)

### **Experimental Features**
- XMAS scan (`-sX`) - Falls back to TCP Connect
- FIN scan (`-sF`) - Falls back to TCP Connect  
- NULL scan (`-sN`) - Falls back to TCP Connect

### **Performance Recommendations**
- Use `--timing normal` for balanced performance
- Use `--rate-limit` for network-sensitive environments
- Use `--randomize` for stealth scanning
- Adjust `--threads` based on system capabilities

## 📤 Export Formats

### **Export Examples**
```bash
# Export as JSON
python3 rootscan.py -t target.com -o results.json --format json

# Export as XML
python3 rootscan.py -t target.com -o results.xml --format xml

# Export as CSV
python3 rootscan.py -t target.com -o results.csv --format csv

# Traditional text report
python3 rootscan.py -t target.com -o scan_report.txt
```

## 🔧 Troubleshooting

### **Common Errors**

**Error: Permission denied (SYN scan)**
```bash
# Solution: Run with sudo
sudo python3 rootscan.py -t target.com -sS
```

**Error: arp-scan not found**
```bash
# Debian/Ubuntu
sudo apt-get install arp-scan

# CentOS/RHEL
sudo yum install arp-scan
```

**Error: ModuleNotFoundError**
```bash
# Install dependencies
pip3 install -r requirements.txt --break-system-packages
```

### **Performance Optimization**
- For slow networks: `--timing polite --rate-limit 10`
- For massive scans: `--timing aggressive --threads 200`
- For maximum stealth: `--timing paranoid --randomize`

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### **Adding New Vulnerabilities**
Vulnerabilities are defined in `.vulns/database.json`. See documentation for required format.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

This tool is intended for authorized security testing and research purposes only. Usage of RootScan for attacking targets without prior mutual consent is illegal. It is the user's responsibility to obey all applicable local, state, and federal laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 👨‍💻 Author

**Created by @y3rm4n**  
**Enhanced and Fixed by Community**

## 🙏 Acknowledgments

- Inspired by Nmap and other network scanning tools
- Thanks to the security community for vulnerability research
- Project contributors for improvements and fixes

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Remember**: Always ensure you have explicit permission to scan any network or system. Unauthorized scanning may be illegal in your jurisdiction.

### 🔢 Quick Stats
- **Total Commands**: 100+ combinations
- **Scan Types**: 6 different types
- **Vulnerabilities**: 25+ built-in checks
- **Output Formats**: 4 formats (TXT, JSON, XML, CSV)
- **Timing Profiles**: 6 performance levels
- **Port Lists**: 5 predefined common port sets


