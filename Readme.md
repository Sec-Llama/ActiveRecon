# ActiveRecon

Advanced Active Reconnaissance Automation Framework for Security Researchers

## Overview

ActiveRecon is a comprehensive reconnaissance automation tool designed to streamline the information gathering phase of authorized security assessments. Built for efficiency and thoroughness, it orchestrates multiple reconnaissance tools available in Kali Linux to provide structured, actionable intelligence about target systems.

## Features

### Core Capabilities

- **Automated Multi-Phase Reconnaissance**: Sequential execution of host discovery, port scanning, service enumeration, vulnerability assessment, and OS fingerprinting
- **Intelligent Service Detection**: Automatic identification and targeted enumeration of discovered services
- **Parallel Processing**: Configurable threading for optimal scan performance
- **Structured Output**: Organized directory hierarchy for all scan results and artifacts
- **Comprehensive Reporting**: JSON and human-readable reports with prioritized findings and recommendations
- **Tool Chain Integration**: Seamless integration with industry-standard reconnaissance tools

### Supported Protocols and Services

- **Web Services**: HTTP/HTTPS enumeration with directory bruteforcing and vulnerability scanning
- **Network Services**: SMB/NetBIOS, FTP, SSH, Telnet, RDP
- **Database Services**: MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- **Directory Services**: LDAP, Active Directory enumeration
- **DNS Services**: Zone transfers, subdomain enumeration
- **Mail Services**: SMTP, POP3, IMAP enumeration

## Installation

### Prerequisites

```bash
# Debian/Ubuntu/Kali Linux
sudo apt update
sudo apt install python3 python3-pip nmap masscan

# Optional but recommended tools
sudo apt install nikto gobuster dirb enum4linux smbclient whatweb
sudo apt install dnsrecon dnsenum fierce hydra medusa sqlmap
sudo apt install searchsploit wpscan rpcclient ldap-utils

# Install Nuclei (optional)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install ffuf (optional)
go install github.com/ffuf/ffuf@latest
```

### Setup

```bash
# Clone the repository
git clone https://github.com/security-research/ActiveRecon.git
cd ActiveRecon

# Make executable
chmod +x ActiveRecon.py

# Verify installation
./ActiveRecon.py --help
```

## Usage

### Basic Syntax

```bash
./ActiveRecon.py [OPTIONS] <target>
```

### Command Line Options

```
positional arguments:
  target                Target IP, hostname, or CIDR network

optional arguments:
  -h, --help           Show help message and exit
  -o, --output PATH    Specify output directory path
  -t, --threads NUM    Number of threads for parallel operations (default: 10)
  -v, --verbose        Enable verbose output
  -q, --quick          Quick scan - only essential checks
  -f, --full           Full comprehensive scan - all checks
  --skip-auth          Skip authorization check (use with caution)
```

### Scan Modes

#### Quick Scan
Performs essential reconnaissance - TCP top ports and basic service detection
```bash
./ActiveRecon.py -q 192.168.1.1
```

#### Standard Scan
Default mode - comprehensive TCP scanning with service enumeration
```bash
./ActiveRecon.py target.com
```

#### Full Comprehensive Scan
Complete reconnaissance including all TCP/UDP ports and extensive enumeration
```bash
sudo ./ActiveRecon.py -f -v target.com
```

### Advanced Usage Examples

```bash
# Scan entire subnet with custom output directory
./ActiveRecon.py -o /opt/recon/client1 192.168.1.0/24

# Full scan with maximum threads for speed
sudo ./ActiveRecon.py -f -t 20 10.10.10.1

# Verbose scan with specific output location
./ActiveRecon.py -v -o ~/assessments/target target.domain.com

# Quick scan for time-sensitive assessments
./ActiveRecon.py -q --skip-auth internal-host.local
```

## Output Structure

ActiveRecon creates an organized directory structure for all findings:

```
ActiveRecon_<target>_<timestamp>/
├── 01_host_discovery/
│   ├── ping_sweep.txt
│   └── live_hosts.xml
├── 02_port_scanning/
│   ├── tcp/
│   │   ├── top1000_tcp.txt
│   │   ├── top1000_tcp.xml
│   │   ├── top1000_tcp.gnmap
│   │   └── all_tcp.txt
│   └── udp/
│       └── top100_udp.txt
├── 03_service_enumeration/
│   ├── service_scan.txt
│   ├── smb/
│   ├── web/
│   ├── ssh/
│   └── ftp/
├── 04_vulnerability_assessment/
│   ├── nmap_vulns.txt
│   └── nuclei_results.txt
├── 05_web_enumeration/
│   └── port_<port>/
│       ├── nikto.txt
│       ├── gobuster.txt
│       └── whatweb.txt
├── 06_dns_enumeration/
│   ├── dnsrecon.txt
│   └── zone_transfer.txt
├── 07_os_detection/
│   └── os_detection.txt
├── 08_exploits/
│   ├── searchsploit_results.json
│   └── exploit_summary.txt
├── 09_reports/
│   ├── scan_log.txt
│   ├── full_report.json
│   └── executive_summary.txt
└── 10_raw_output/
```

## Reconnaissance Phases

### Phase 1: Host Discovery
- ICMP echo requests
- TCP SYN to ports 80, 443
- TCP ACK to ports 80, 443
- Network sweep for CIDR ranges

### Phase 2: Port Scanning
- TCP SYN scan (top 1000 or all 65535 ports)
- UDP scan (top 100 ports)
- Service version detection
- Default script scan

### Phase 3: Service Enumeration
- Protocol-specific enumeration based on discovered services
- Banner grabbing and version detection
- Default credential checks
- Service-specific vulnerability checks

### Phase 4: Vulnerability Assessment
- Nmap vulnerability scripts
- Searchsploit database queries
- Nuclei template scanning
- CVE correlation

### Phase 5: OS Detection
- TCP/IP fingerprinting
- Service-based OS detection
- SMB OS discovery

## Report Generation

### Executive Summary
Human-readable report containing:
- Target information and scan metadata
- Open ports summary (TCP/UDP)
- Identified services with versions
- Operating system detection results
- Prioritized vulnerabilities (CRITICAL/HIGH/MEDIUM/LOW)
- Actionable recommendations
- Suggested next steps

### JSON Report
Machine-parseable complete results including:
- Complete port lists
- Service details and versions
- Vulnerability findings
- Exploitation suggestions
- Raw tool outputs references

## Security Considerations

### Authorization
ActiveRecon includes built-in authorization checks. Only use this tool on:
- Systems you own
- Systems you have explicit written permission to test
- Authorized penetration testing engagements

### Detection
This tool performs active reconnaissance that will be detected by:
- Intrusion Detection Systems (IDS)
- Security Information and Event Management (SIEM) systems
- Host-based monitoring solutions
- Network traffic analysis tools

### Legal Compliance
Users are responsible for ensuring compliance with:
- Local and federal laws
- Organization security policies
- Penetration testing rules of engagement
- Bug bounty program scope

## Performance Optimization

### Threading
Adjust thread count based on network conditions:
```bash
# Conservative (stable networks)
-t 5

# Standard (default)
-t 10

# Aggressive (local networks)
-t 20
```

### Scan Timing
The tool automatically adjusts timing templates based on scan type:
- Quick scans: T4 (aggressive)
- Standard scans: T4 (aggressive)
- Full scans: T3 (normal)

### Network Considerations
- Use lower thread counts for remote targets
- Increase threads for local network assessments
- Consider bandwidth limitations
- Monitor for rate limiting or blocking

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Some scans require root privileges
sudo ./ActiveRecon.py target
```

**Tools Not Found**
```bash
# Check tool availability
./ActiveRecon.py target -v
# Install missing tools using apt or manual installation
```

**Scan Timeouts**
```bash
# Increase timeout values in the script
# Or use quick scan mode for faster results
./ActiveRecon.py -q target
```

### Debug Mode
Enable verbose output for troubleshooting:
```bash
./ActiveRecon.py -v target
```

## Tool Integration

ActiveRecon automatically detects and utilizes available tools:

### Required
- Python 3.6+
- Nmap

### Recommended
- masscan - High-speed port scanning
- nikto - Web vulnerability scanner
- gobuster - Directory/file bruteforcer
- enum4linux - SMB enumeration
- searchsploit - Exploit database search

### Optional
- nuclei - Template-based vulnerability scanner
- wpscan - WordPress vulnerability scanner
- sqlmap - SQL injection tool
- hydra - Password brute-forcing
- dnsenum - DNS enumeration
- fierce - Domain scanner

## Contributing

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/ActiveRecon.git
cd ActiveRecon

# Create feature branch
git checkout -b feature/enhancement

# Make changes and test
./ActiveRecon.py test-target -v

# Submit pull request
```

### Contribution Guidelines
- Follow PEP 8 style guidelines
- Add comprehensive error handling
- Document new features
- Include relevant tool integrations
- Test against various target types

## Version History

### v1.0.0 (Current)
- Initial release
- Multi-phase reconnaissance automation
- Comprehensive tool integration
- Structured reporting system
- Intelligent service enumeration

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Disclaimer

This tool is provided for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors assume no liability for misuse or damage caused by this tool.

## Support

### Documentation
- Check the comprehensive inline documentation
- Review example commands and use cases
- Examine generated reports for understanding output

### Reporting Issues
When reporting issues, include:
- Operating system and version
- Python version
- Complete error messages
- Verbose output (-v flag)
- Target type (IP/hostname/CIDR)

## Acknowledgments

ActiveRecon leverages the excellent work of numerous open-source security tools and the broader information security community. Special recognition to the maintainers of Nmap, Masscan, and the Kali Linux project.

---

**ActiveRecon** - Automating reconnaissance for the next generation of security researchers

For updates and additional resources, visit the project repository.
