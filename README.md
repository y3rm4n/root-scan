# RootScan - Advanced Network Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/creator-%40y3rm4n-purple.svg" alt="Creator">
</p>

```
    ____             __  _____                 
   / __ \____  ____  / /_/ ___/_________ _____ 
  / /_/ / __ \/ __ \/ __/\__ \/ ___/ __ `/ __ \
 / _, _/ /_/ / /_/ / /_ ___/ / /__/ /_/ / / / /
/_/ |_|\____/\____/\__//____/\___/\__,_/_/ /_/ 
                                                
        Created by @y3rm4n
        Advanced Network Scanner v1.0.1
```

## 🎯 Features

- **Multiple Scan Types**: TCP Connect, SYN Stealth, UDP, XMAS, FIN, NULL
- **Network Discovery**: Ping sweep, ARP scan, OS detection
- **Vulnerability Detection**: Built-in vulnerability scanner for common services
- **SSL/TLS Analysis**: Detect SSL/TLS vulnerabilities and misconfigurations
- **Web Security Scanning**: Identify common web application vulnerabilities
- **Service Fingerprinting**: Advanced banner grabbing and service detection
- **IDS Evasion**: Decoy addresses, packet fragmentation, timing control
- **Performance Control**: Timing profiles from paranoid to insane
- **Multiple Output Formats**: TXT, JSON, XML, CSV
- **NSE-like Scripts**: Extensible script engine for custom checks

## 📋 Requirements

- Python 3.8 or higher
- Linux/Unix operating system (recommended)
- Root/sudo privileges (required for SYN scan and some features)
- Network connectivity

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/y3rm4n/root-scan
cd root-scan
```

### 2. Install Dependencies

For systems with PEP 668 restrictions (Debian 12, Ubuntu 23.04+, etc.):

```bash
# Option 1: Using --break-system-packages (recommended for development)
pip3 install -r requirements.txt --break-system-packages

# Option 2: Using virtual environment (recommended for production)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

For older systems:

```bash
pip3 install -r requirements.txt
```

### 3. Install System Dependencies

Some features require additional system packages:

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y nmap arp-scan tcpdump libpcap-dev

# CentOS/RHEL/Fedora
sudo yum install -y nmap arp-scan tcpdump libpcap-devel

# Arch Linux
sudo pacman -S nmap arp-scan tcpdump libpcap
```

### 4. Make Executable (Optional)

```bash
chmod +x rootscan.py
```

## 🔧 Usage Examples

### Basic Scanning

```bash
# Basic TCP scan
python3 rootscan.py -t 192.168.1.1

# Scan specific ports
python3 rootscan.py -t example.com -p 80,443,8080

# Scan port range
python3 rootscan.py -t 192.168.1.1 -p 1-1000

# Scan top 100 most common ports
python3 rootscan.py -t example.com --top-ports 100
```

### Advanced Scanning

```bash
# SYN stealth scan (requires root)
sudo python3 rootscan.py -t example.com -sS

# UDP scan
sudo python3 rootscan.py -t 192.168.1.1 -sU -p 53,67,123,161

# Combined TCP and vulnerability scan
python3 rootscan.py -t example.com --vuln-scan --deep-scan
```

### Network Discovery

```bash
# Ping sweep
python3 rootscan.py -t 192.168.1.0/24 --ping-sweep

# ARP scan (requires root)
sudo python3 rootscan.py --arp-scan -i eth0

# OS detection
python3 rootscan.py -t 192.168.1.1 --os-detect
```

### Security Assessment

```bash
# Full vulnerability assessment
python3 rootscan.py -t example.com --vuln-scan --ssl-scan --web-scan

# SSL/TLS vulnerability scan
python3 rootscan.py -t example.com -p 443,8443 --ssl-scan

# Web application security scan
python3 rootscan.py -t example.com -p 80,443,8080 --web-scan

# Run specific vulnerability scripts
python3 rootscan.py -t 192.168.1.1 --scripts smb-vuln-ms17-010 ssl-heartbleed
```

### Stealth and Evasion

```bash
# Stealth scan with decoys
sudo python3 rootscan.py -t example.com -sS --decoy 5 --randomize

# Slow scan with timing control
python3 rootscan.py -t example.com --timing sneaky

# Rate-limited scan
python3 rootscan.py -t example.com --rate-limit 10

# Fragment packets for IDS evasion
sudo python3 rootscan.py -t example.com -sS --fragment
```

### Output and Reporting

```bash
# Save results to file
python3 rootscan.py -t example.com -o scan_results.txt

# Export as JSON
python3 rootscan.py -t example.com -o results.json --format json

# Export as XML
python3 rootscan.py -t example.com -o results.xml --format xml

# Export as CSV
python3 rootscan.py -t example.com -o results.csv --format csv

# Verbose output with statistics
python3 rootscan.py -t example.com -v --stats
```

### Complete Examples

```bash
# Production web server assessment
python3 rootscan.py -t webserver.com -p 80,443,8080,8443 \
  --vuln-scan --ssl-scan --web-scan --deep-scan \
  -o webserver_audit.json --format json -v

# Internal network scan
sudo python3 rootscan.py -t 192.168.1.0/24 --ping-sweep
sudo python3 rootscan.py -t 192.168.1.1-50 -sS --top-ports 1000 \
  --os-detect --timing aggressive

# Stealth reconnaissance
sudo python3 rootscan.py -t target.com -sS -p 22,80,443,3306,3389 \
  --decoy 10 --randomize --timing paranoid --fragment

# Full security audit
sudo python3 rootscan.py -t target.com -p 1-10000 \
  --vuln-scan --ssl-scan --web-scan --deep-scan \
  --scripts smb-vuln-ms17-010 ftp-anon mysql-empty-password \
  --os-detect --timing normal -o full_audit.json --format json \
  --stats -v
```

## ⚡ Timing Profiles

- **paranoid**: 5s timeout, 2s delay, 1 thread
- **sneaky**: 3s timeout, 1s delay, 5 threads
- **polite**: 2s timeout, 0.5s delay, 10 threads
- **normal**: 1s timeout, 0.1s delay, 50 threads (default)
- **aggressive**: 0.5s timeout, 0.05s delay, 100 threads
- **insane**: 0.3s timeout, no delay, 200 threads

## 🛡️ Available Scripts

- `smb-vuln-ms17-010`: Check for EternalBlue vulnerability
- `ssl-heartbleed`: Check for Heartbleed vulnerability
- `http-methods`: Enumerate HTTP methods
- `ftp-anon`: Check for anonymous FTP access
- `mysql-empty-password`: Check for MySQL empty passwords

## ⚠️ Legal Disclaimer

This tool is intended for authorized security testing and research purposes only. Usage of RootScan for attacking targets without prior mutual consent is illegal. It is the user's responsibility to obey all applicable local, state, and federal laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**Created by @y3rm4n**

## 🙏 Acknowledgments

- Inspired by Nmap and other network scanning tools


## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Remember**: Always ensure you have explicit permission to scan any network or system. Unauthorized scanning may be illegal in your jurisdiction.
