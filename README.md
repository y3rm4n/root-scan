# RootScan - Advanced Network Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.4-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/creator-%40y3rm4n-purple.svg" alt="Creator">
  <img src="https://img.shields.io/badge/commands-83%2B-orange.svg" alt="Commands">
</p>

```
    ____             __  _____                 
   / __ \____  ____  / /_/ ___/_________ _____ 
  / /_/ / __ \/ __ \/ __/\__ \/ ___/ __ `/ __ \
 / _, _/ /_/ / /_/ / /_ ___/ / /__/ /_/ / / / /
/_/ |_|\____/\____/\__//____/\___/\__,_/_/ /_/ 
                                                
        Created by @y3rm4n
        Advanced Network Scanner v1.0.4 (FIXED)
```

## 🎯 Features

- **Multiple Scan Types**: TCP Connect, SYN Stealth, UDP, XMAS, FIN, NULL
- **Network Discovery**: Ping sweep, ARP scan, OS detection
- **Vulnerability Detection**: Built-in vulnerability scanner for common services
- **Service Fingerprinting**: Advanced banner grabbing and service detection
- **Performance Control**: 6 timing profiles from paranoid to insane
- **Stealth Features**: Randomization, rate limiting, thread control
- **NSE-like Scripts**: 5 extensible scripts for vulnerability checks
- **Multiple Output Formats**: TXT, JSON, XML, CSV
- **83+ Command Combinations**: Comprehensive testing capabilities

## 📋 Requirements

- Python 3.8 or higher
- Linux/Unix operating system (recommended)
- Root/sudo privileges (required for SYN scan and ARP scan)
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
sudo apt-get install -y arp-scan

# CentOS/RHEL/Fedora
sudo yum install -y arp-scan

# Arch Linux
sudo pacman -S arp-scan
```

### 4. Make Executable (Optional)

```bash
chmod +x rootscan.py
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
--scripts             # NSE-like scripts (space-separated list)
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

## 🔧 Usage Examples

### **Basic Scanning**

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

### **Advanced Scanning**

```bash
# SYN stealth scan (requires root)
sudo python3 rootscan.py -t example.com -sS

# UDP scan
python3 rootscan.py -t 192.168.1.1 -sU -p 53,67,123,161

# XMAS scan (experimental)
python3 rootscan.py -t 192.168.1.1 -sX

# Combined TCP and vulnerability scan
python3 rootscan.py -t example.com --vuln-scan -v
```

### **Network Discovery**

```bash
# Ping sweep
python3 rootscan.py -t 192.168.1.0/24 --ping-sweep

# ARP scan (requires root)
sudo python3 rootscan.py --arp-scan -i eth0

# OS detection
python3 rootscan.py -t 192.168.1.1 --os-detect
```

### **Security Assessment**

```bash
# Full vulnerability assessment
python3 rootscan.py -t example.com --vuln-scan --os-detect

# Run specific vulnerability scripts
python3 rootscan.py -t 192.168.1.1 --scripts smb-vuln-ms17-010 ssl-heartbleed

# Multiple scripts
python3 rootscan.py -t 192.168.1.1 --scripts smb-vuln-ms17-010 http-methods ftp-anon
```

### **Stealth and Evasion**

```bash
# Stealth scan with randomization
sudo python3 rootscan.py -t example.com -sS --randomize

# Slow scan with stealth timing
python3 rootscan.py -t example.com --timing sneaky

# Rate-limited scan
python3 rootscan.py -t example.com --rate-limit 10

# Complete stealth combination
sudo python3 rootscan.py -t example.com -sS --timing paranoid --randomize --rate-limit 1
```

### **Output and Reporting**

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

### **Complete Examples**

```bash
# Production web server assessment
python3 rootscan.py -t webserver.com -p 80,443,8080,8443 \
  --vuln-scan --scripts http-methods ssl-heartbleed \
  -o webserver_audit.json --format json -v

# Internal network discovery and scan
python3 rootscan.py -t 192.168.1.0/24 --ping-sweep
sudo python3 rootscan.py --arp-scan
sudo python3 rootscan.py -t 192.168.1.1 -sS --top-ports 1000 --os-detect

# Stealth reconnaissance
sudo python3 rootscan.py -t target.com -sS --top-ports 50 \
  --timing sneaky --randomize -v

# Full security audit
python3 rootscan.py -t target.com --top-ports 1000 \
  --vuln-scan --scripts smb-vuln-ms17-010 ssl-heartbleed http-methods ftp-anon mysql-empty-password \
  --os-detect --timing normal --randomize \
  -o full_audit_$(date +%Y%m%d).json --format json \
  --stats -v
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

## 🛡️ Available Scripts

| Script | Target Ports | Description |
|--------|--------------|-------------|
| `smb-vuln-ms17-010` | 139, 445 | Check for EternalBlue vulnerability |
| `ssl-heartbleed` | 443, 8443 | Check for Heartbleed vulnerability |
| `http-methods` | 80, 443, 8080, 8443, 8000, 8888 | Enumerate HTTP methods |
| `ftp-anon` | 21 | Check for anonymous FTP access |
| `mysql-empty-password` | 3306 | Check for MySQL empty passwords |

## 📊 Port Categories

### **Top Ports Lists**
- **Top 10**: 21, 22, 23, 25, 80, 110, 139, 443, 445, 3389
- **Top 20**: Adds 53, 111, 135, 143, 993, 995, 1723, 3306, 5900, 8080
- **Top 50**: Extended with additional common services
- **Top 100**: Comprehensive common port list
- **Top 1000**: All common ports plus extended range

## 🎯 Service-Specific Commands

### **Web Services**
```bash
python3 rootscan.py -t target.com -p 80,443,8080,8443 --scripts http-methods
```

### **Database Services**
```bash
python3 rootscan.py -t target.com -p 3306,5432,1433,1521 --scripts mysql-empty-password
```

### **File Services**
```bash
python3 rootscan.py -t target.com -p 21,22,139,445 --scripts ftp-anon smb-vuln-ms17-010
```

### **Mail Services**
```bash
python3 rootscan.py -t target.com -p 25,110,143,993,995
```

### **SSL/TLS Services**
```bash
python3 rootscan.py -t target.com -p 443,993,995,8443 --scripts ssl-heartbleed
```

## ⚠️ Important Notes

### **Root Privileges Required For:**
- SYN scan (`-sS`, `--syn-scan`)
- ARP scan (`--arp-scan`)

### **Experimental Features:**
- XMAS scan (`-sX`) - Falls back to TCP Connect
- FIN scan (`-sF`) - Falls back to TCP Connect  
- NULL scan (`-sN`) - Falls back to TCP Connect

### **Performance Recommendations:**
- Use `--timing normal` for balanced performance
- Use `--rate-limit` for network-sensitive environments
- Use `--randomize` for stealth scanning
- Adjust `--threads` based on system capabilities

## ⚠️ Legal Disclaimer

This tool is intended for authorized security testing and research purposes only. Usage of RootScan for attacking targets without prior mutual consent is illegal. It is the user's responsibility to obey all applicable local, state, and federal laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**Created by @y3rm4n**  
**Fixed and Enhanced by Claude**

## 🙏 Acknowledgments

- Inspired by Nmap and other network scanning tools
- Thanks to the security community for vulnerability research

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Remember**: Always ensure you have explicit permission to scan any network or system. Unauthorized scanning may be illegal in your jurisdiction.

### 🔢 Quick Stats
- **Total Commands**: 83+ combinations
- **Scan Types**: 6 different types
- **Scripts**: 5 built-in vulnerability scripts
- **Output Formats**: 4 formats (TXT, JSON, XML, CSV)
- **Timing Profiles**: 6 performance levels
- **Port Lists**: 5 predefined common port sets
