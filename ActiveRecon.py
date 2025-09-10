#!/usr/bin/env python3
"""
ActiveRecon - Advanced Active Reconnaissance Automation Tool
Author: Michael Dahan (@Sec-Llama)
Version: 1.0.0
Purpose: Automate active reconnaissance for authorized security assessments
"""

import os
import sys
import json
import time
import subprocess
import argparse
import threading
import re
import socket
import ipaddress
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
import xml.etree.ElementTree as ET

class Colors:
    """Terminal color codes for output formatting"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ActiveRecon:
    """Main reconnaissance automation class"""
    
    def __init__(self, target: str, output_dir: str = None, verbose: bool = False, 
                 threads: int = 10, scan_type: str = 'full'):
        self.target = target
        self.verbose = verbose
        self.threads = threads
        self.scan_type = scan_type
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Validate target
        self.target_type = self._validate_target(target)
        
        # Setup output directory structure
        if output_dir:
            self.base_dir = Path(output_dir)
        else:
            self.base_dir = Path(f"ActiveRecon_{self._sanitize_filename(target)}_{self.timestamp}")
        
        self._setup_directory_structure()
        
        # Results storage
        self.results = {
            'target': target,
            'scan_start': datetime.now().isoformat(),
            'ports': {'tcp': {}, 'udp': {}},
            'services': {},
            'vulnerabilities': [],
            'recommendations': [],
            'web_apps': [],
            'dns_info': {},
            'os_detection': {}
        }
        
        # Tool availability check
        self.available_tools = self._check_available_tools()
    
    def _validate_target(self, target: str) -> str:
        """Validate and classify target (IP, CIDR, or hostname)"""
        try:
            # Check if IP address
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            try:
                # Check if CIDR network
                ipaddress.ip_network(target, strict=False)
                return 'cidr'
            except ValueError:
                # Assume hostname/domain
                try:
                    socket.gethostbyname(target)
                    return 'hostname'
                except socket.gaierror:
                    print(f"{Colors.FAIL}Error: Invalid target '{target}'{Colors.ENDC}")
                    sys.exit(1)
    
    def _sanitize_filename(self, name: str) -> str:
        """Sanitize filename for directory creation"""
        return re.sub(r'[^\w\s-]', '_', name).strip()
    
    def _setup_directory_structure(self):
        """Create organized directory structure for results"""
        directories = [
            self.base_dir / "01_host_discovery",
            self.base_dir / "02_port_scanning" / "tcp",
            self.base_dir / "02_port_scanning" / "udp",
            self.base_dir / "03_service_enumeration",
            self.base_dir / "04_vulnerability_assessment",
            self.base_dir / "05_web_enumeration",
            self.base_dir / "06_dns_enumeration",
            self.base_dir / "07_os_detection",
            self.base_dir / "08_exploits",
            self.base_dir / "09_reports",
            self.base_dir / "10_raw_output"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Create main log file
        self.log_file = self.base_dir / "09_reports" / "scan_log.txt"
        self.log_file.touch()
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check which tools are available on the system"""
        tools = {
            'nmap': 'nmap --version',
            'masscan': 'masscan --version',
            'nikto': 'nikto -Version',
            'gobuster': 'gobuster version',
            'dirb': 'dirb',
            'wpscan': 'wpscan --version',
            'enum4linux': 'enum4linux',
            'smbclient': 'smbclient --version',
            'rpcclient': 'rpcclient --version',
            'ldapsearch': 'ldapsearch -VV',
            'whatweb': 'whatweb --version',
            'searchsploit': 'searchsploit --version',
            'hydra': 'hydra -h',
            'medusa': 'medusa -h',
            'sqlmap': 'sqlmap --version',
            'dnsenum': 'dnsenum --version',
            'dnsrecon': 'dnsrecon -h',
            'fierce': 'fierce -h',
            'nuclei': 'nuclei -version',
            'ffuf': 'ffuf -V'
        }
        
        available = {}
        for tool, cmd in tools.items():
            try:
                subprocess.run(cmd.split(), capture_output=True, timeout=2)
                available[tool] = True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                available[tool] = False
        
        return available
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages to file and optionally to console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
        
        if self.verbose or level in ["WARNING", "ERROR", "SUCCESS"]:
            color = Colors.ENDC
            if level == "WARNING":
                color = Colors.WARNING
            elif level == "ERROR":
                color = Colors.FAIL
            elif level == "SUCCESS":
                color = Colors.GREEN
            elif level == "INFO":
                color = Colors.CYAN
            
            print(f"{color}[{level}] {message}{Colors.ENDC}")
    
    def run_command(self, command: List[str], output_file: Path = None, 
                   timeout: int = 300) -> Tuple[bool, str]:
        """Execute system command and capture output"""
        try:
            self.log(f"Running: {' '.join(command)}", "INFO")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = result.stdout + result.stderr
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
            
            return (result.returncode == 0, output)
            
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {' '.join(command)}", "WARNING")
            return (False, "Command timed out")
        except Exception as e:
            self.log(f"Error running command: {str(e)}", "ERROR")
            return (False, str(e))
    
    def phase1_host_discovery(self):
        """Phase 1: Host Discovery"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Phase 1: Host Discovery{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        if not self.available_tools.get('nmap'):
            self.log("Nmap not available, skipping host discovery", "WARNING")
            return
        
        output_dir = self.base_dir / "01_host_discovery"
        
        # Ping sweep for network targets
        if self.target_type == 'cidr':
            self.log("Performing ping sweep on network", "INFO")
            cmd = ['nmap', '-sn', '-PE', '-PS80,443', '-PA80,443', self.target,
                   '-oN', str(output_dir / 'ping_sweep.txt'),
                   '-oX', str(output_dir / 'ping_sweep.xml')]
            success, output = self.run_command(cmd)
            
            if success:
                self.log("Host discovery completed", "SUCCESS")
                self._parse_live_hosts(output_dir / 'ping_sweep.xml')
        else:
            # Single host verification
            self.log(f"Verifying host: {self.target}", "INFO")
            cmd = ['nmap', '-sn', '-PE', '-PS80,443', '-PA80,443', self.target,
                   '-oN', str(output_dir / 'host_check.txt')]
            success, output = self.run_command(cmd)
            
            if "Host is up" in output:
                self.log(f"Host {self.target} is alive", "SUCCESS")
            else:
                self.log(f"Host {self.target} appears to be down or blocking pings", "WARNING")
    
    def phase2_port_scanning(self):
        """Phase 2: Comprehensive Port Scanning"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Phase 2: Port Scanning{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        if not self.available_tools.get('nmap'):
            self.log("Nmap not available, skipping port scanning", "WARNING")
            return
        
        tcp_dir = self.base_dir / "02_port_scanning" / "tcp"
        udp_dir = self.base_dir / "02_port_scanning" / "udp"
        
        # TCP Port Scanning
        self.log("Starting TCP port scan", "INFO")
        
        # Quick scan of top ports
        cmd = ['nmap', '-sS', '-T4', '--top-ports', '1000', self.target,
               '-oN', str(tcp_dir / 'top1000_tcp.txt'),
               '-oX', str(tcp_dir / 'top1000_tcp.xml'),
               '-oG', str(tcp_dir / 'top1000_tcp.gnmap')]
        success, output = self.run_command(cmd, timeout=600)
        
        if success:
            self._parse_nmap_results(tcp_dir / 'top1000_tcp.xml', 'tcp')
        
        # Full TCP scan based on scan type
        if self.scan_type in ['full', 'comprehensive']:
            self.log("Starting full TCP port scan (65535 ports)", "INFO")
            cmd = ['nmap', '-sS', '-T4', '-p-', self.target,
                   '-oN', str(tcp_dir / 'all_tcp.txt'),
                   '-oX', str(tcp_dir / 'all_tcp.xml'),
                   '-oG', str(tcp_dir / 'all_tcp.gnmap')]
            success, output = self.run_command(cmd, timeout=1800)
            
            if success:
                self._parse_nmap_results(tcp_dir / 'all_tcp.xml', 'tcp')
        
        # UDP Port Scanning (top ports only due to time constraints)
        if self.scan_type in ['full', 'comprehensive']:
            self.log("Starting UDP port scan (top 100 ports)", "INFO")
            cmd = ['sudo', 'nmap', '-sU', '-T4', '--top-ports', '100', self.target,
                   '-oN', str(udp_dir / 'top100_udp.txt'),
                   '-oX', str(udp_dir / 'top100_udp.xml')]
            success, output = self.run_command(cmd, timeout=900)
            
            if success:
                self._parse_nmap_results(udp_dir / 'top100_udp.xml', 'udp')
    
    def phase3_service_enumeration(self):
        """Phase 3: Service Detection and Enumeration"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Phase 3: Service Enumeration{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        if not self.results['ports']['tcp']:
            self.log("No open TCP ports found, skipping service enumeration", "WARNING")
            return
        
        service_dir = self.base_dir / "03_service_enumeration"
        
        # Get list of open ports
        open_ports = list(self.results['ports']['tcp'].keys())
        port_string = ','.join(map(str, open_ports))
        
        # Service version detection
        self.log(f"Detecting services on ports: {port_string}", "INFO")
        cmd = ['nmap', '-sV', '-sC', '-T4', '-p', port_string, self.target,
               '-oN', str(service_dir / 'service_scan.txt'),
               '-oX', str(service_dir / 'service_scan.xml')]
        success, output = self.run_command(cmd, timeout=900)
        
        if success:
            self._parse_service_results(service_dir / 'service_scan.xml')
        
        # Enumerate specific services
        self._enumerate_specific_services()
    
    def _enumerate_specific_services(self):
        """Enumerate specific services based on detected ports"""
        service_dir = self.base_dir / "03_service_enumeration"
        
        for port, info in self.results['ports']['tcp'].items():
            service = info.get('service', '').lower()
            
            # Web services
            if port in [80, 443, 8080, 8443] or 'http' in service:
                self._enumerate_web(port, service_dir)
            
            # SMB/NetBIOS
            elif port in [139, 445] or 'netbios' in service or 'microsoft-ds' in service:
                self._enumerate_smb(service_dir)
            
            # SSH
            elif port == 22 or 'ssh' in service:
                self._enumerate_ssh(port, service_dir)
            
            # FTP
            elif port == 21 or 'ftp' in service:
                self._enumerate_ftp(port, service_dir)
            
            # DNS
            elif port == 53 or 'domain' in service:
                self._enumerate_dns(service_dir)
            
            # LDAP
            elif port in [389, 636] or 'ldap' in service:
                self._enumerate_ldap(port, service_dir)
            
            # MySQL
            elif port == 3306 or 'mysql' in service:
                self._enumerate_mysql(port, service_dir)
            
            # PostgreSQL
            elif port == 5432 or 'postgresql' in service:
                self._enumerate_postgresql(port, service_dir)
            
            # RDP
            elif port == 3389 or 'ms-wbt-server' in service:
                self._enumerate_rdp(port, service_dir)
    
    def _enumerate_web(self, port: int, output_dir: Path):
        """Enumerate web services"""
        web_dir = self.base_dir / "05_web_enumeration" / f"port_{port}"
        web_dir.mkdir(parents=True, exist_ok=True)
        
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{self.target}:{port}"
        
        self.log(f"Enumerating web service on port {port}", "INFO")
        
        # WhatWeb fingerprinting
        if self.available_tools.get('whatweb'):
            cmd = ['whatweb', '-a', '3', url, '--log-verbose',
                   str(web_dir / 'whatweb.txt')]
            self.run_command(cmd, timeout=120)
        
        # Nikto vulnerability scanning
        if self.available_tools.get('nikto'):
            cmd = ['nikto', '-h', url, '-o', str(web_dir / 'nikto.txt'),
                   '-Format', 'txt', '-Tuning', 'x']
            self.run_command(cmd, timeout=600)
        
        # Directory enumeration with Gobuster
        if self.available_tools.get('gobuster'):
            wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
            if os.path.exists(wordlist):
                cmd = ['gobuster', 'dir', '-u', url, '-w', wordlist,
                       '-o', str(web_dir / 'gobuster.txt'), '-t', '20',
                       '-x', 'php,html,txt,js,asp,aspx']
                self.run_command(cmd, timeout=900)
        
        # Alternative with ffuf
        elif self.available_tools.get('ffuf'):
            wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt'
            if os.path.exists(wordlist):
                cmd = ['ffuf', '-u', f"{url}/FUZZ", '-w', wordlist,
                       '-o', str(web_dir / 'ffuf.json'), '-of', 'json',
                       '-t', '20', '-mc', '200,204,301,302,307,401,403']
                self.run_command(cmd, timeout=600)
        
        self.results['web_apps'].append({'port': port, 'url': url})
    
    def _enumerate_smb(self, output_dir: Path):
        """Enumerate SMB/NetBIOS services"""
        smb_dir = output_dir / "smb"
        smb_dir.mkdir(exist_ok=True)
        
        self.log("Enumerating SMB/NetBIOS services", "INFO")
        
        # enum4linux
        if self.available_tools.get('enum4linux'):
            cmd = ['enum4linux', '-a', self.target]
            self.run_command(cmd, output_file=smb_dir / 'enum4linux.txt', timeout=300)
        
        # smbclient listing
        if self.available_tools.get('smbclient'):
            cmd = ['smbclient', '-L', f'//{self.target}', '-N']
            self.run_command(cmd, output_file=smb_dir / 'smbclient_list.txt', timeout=60)
        
        # rpcclient
        if self.available_tools.get('rpcclient'):
            commands = ['enumdomusers', 'enumdomgroups', 'getdompwinfo']
            for rpc_cmd in commands:
                cmd = ['rpcclient', '-U', '""', '-N', self.target, '-c', rpc_cmd]
                self.run_command(cmd, output_file=smb_dir / f'rpcclient_{rpc_cmd}.txt', timeout=60)
    
    def _enumerate_ssh(self, port: int, output_dir: Path):
        """Enumerate SSH service"""
        ssh_dir = output_dir / "ssh"
        ssh_dir.mkdir(exist_ok=True)
        
        self.log(f"Enumerating SSH on port {port}", "INFO")
        
        # SSH audit script
        cmd = ['nmap', '-p', str(port), '--script', 'ssh-auth-methods,ssh2-enum-algos',
               self.target, '-oN', str(ssh_dir / 'ssh_enum.txt')]
        self.run_command(cmd, timeout=120)
    
    def _enumerate_ftp(self, port: int, output_dir: Path):
        """Enumerate FTP service"""
        ftp_dir = output_dir / "ftp"
        ftp_dir.mkdir(exist_ok=True)
        
        self.log(f"Enumerating FTP on port {port}", "INFO")
        
        # FTP enumeration scripts
        cmd = ['nmap', '-p', str(port), '--script', 
               'ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor',
               self.target, '-oN', str(ftp_dir / 'ftp_enum.txt')]
        self.run_command(cmd, timeout=120)
    
    def _enumerate_dns(self, output_dir: Path):
        """Enumerate DNS service"""
        dns_dir = self.base_dir / "06_dns_enumeration"
        dns_dir.mkdir(exist_ok=True)
        
        self.log("Enumerating DNS", "INFO")
        
        # dnsrecon
        if self.available_tools.get('dnsrecon'):
            cmd = ['dnsrecon', '-d', self.target, '-t', 'std']
            self.run_command(cmd, output_file=dns_dir / 'dnsrecon.txt', timeout=180)
        
        # dnsenum
        elif self.available_tools.get('dnsenum'):
            cmd = ['dnsenum', '--enum', self.target]
            self.run_command(cmd, output_file=dns_dir / 'dnsenum.txt', timeout=180)
        
        # Zone transfer attempt
        cmd = ['nmap', '--script', 'dns-zone-transfer', '-p', '53',
               self.target, '-oN', str(dns_dir / 'zone_transfer.txt')]
        self.run_command(cmd, timeout=120)
    
    def _enumerate_ldap(self, port: int, output_dir: Path):
        """Enumerate LDAP service"""
        ldap_dir = output_dir / "ldap"
        ldap_dir.mkdir(exist_ok=True)
        
        self.log(f"Enumerating LDAP on port {port}", "INFO")
        
        # LDAP enumeration
        cmd = ['nmap', '-p', str(port), '--script', 
               'ldap-rootdse,ldap-search',
               self.target, '-oN', str(ldap_dir / 'ldap_enum.txt')]
        self.run_command(cmd, timeout=180)
        
        # ldapsearch
        if self.available_tools.get('ldapsearch'):
            cmd = ['ldapsearch', '-x', '-h', self.target, '-s', 'base']
            self.run_command(cmd, output_file=ldap_dir / 'ldapsearch_base.txt', timeout=60)
    
    def _enumerate_mysql(self, port: int, output_dir: Path):
        """Enumerate MySQL service"""
        mysql_dir = output_dir / "mysql"
        mysql_dir.mkdir(exist_ok=True)
        
        self.log(f"Enumerating MySQL on port {port}", "INFO")
        
        cmd = ['nmap', '-p', str(port), '--script',
               'mysql-enum,mysql-info,mysql-empty-password',
               self.target, '-oN', str(mysql_dir / 'mysql_enum.txt')]
        self.run_command(cmd, timeout=120)
    
    def _enumerate_postgresql(self, port: int, output_dir: Path):
        """Enumerate PostgreSQL service"""
        pgsql_dir = output_dir / "postgresql"
        pgsql_dir.mkdir(exist_ok=True)
        
        self.log(f"Enumerating PostgreSQL on port {port}", "INFO")
        
        cmd = ['nmap', '-p', str(port), '--script',
               'pgsql-brute',
               self.target, '-oN', str(pgsql_dir / 'pgsql_enum.txt')]
        self.run_command(cmd, timeout=120)
    
    def _enumerate_rdp(self, port: int, output_dir: Path):
        """Enumerate RDP service"""
        rdp_dir = output_dir / "rdp"
        rdp_dir.mkdir(exist_ok=True)
        
        self.log(f"Enumerating RDP on port {port}", "INFO")
        
        cmd = ['nmap', '-p', str(port), '--script',
               'rdp-enum-encryption,rdp-ntlm-info',
               self.target, '-oN', str(rdp_dir / 'rdp_enum.txt')]
        self.run_command(cmd, timeout=120)
    
    def phase4_vulnerability_assessment(self):
        """Phase 4: Vulnerability Assessment"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Phase 4: Vulnerability Assessment{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        vuln_dir = self.base_dir / "04_vulnerability_assessment"
        
        # Nmap vulnerability scripts
        if self.results['ports']['tcp']:
            open_ports = list(self.results['ports']['tcp'].keys())
            port_string = ','.join(map(str, open_ports))
            
            self.log("Running vulnerability detection scripts", "INFO")
            cmd = ['nmap', '--script', 'vuln', '-p', port_string,
                   self.target, '-oN', str(vuln_dir / 'nmap_vulns.txt')]
            self.run_command(cmd, timeout=900)
        
        # Searchsploit for detected services
        if self.available_tools.get('searchsploit'):
            self._run_searchsploit()
        
        # Nuclei scanning
        if self.available_tools.get('nuclei'):
            self.log("Running Nuclei vulnerability scanner", "INFO")
            cmd = ['nuclei', '-u', f'http://{self.target}', '-severity', 'critical,high,medium',
                   '-o', str(vuln_dir / 'nuclei_results.txt')]
            self.run_command(cmd, timeout=600)
    
    def _run_searchsploit(self):
        """Search for exploits using searchsploit"""
        exploit_dir = self.base_dir / "08_exploits"
        
        self.log("Searching for exploits with searchsploit", "INFO")
        
        # Search for exploits based on detected services
        searches = set()
        for port, info in self.results['services'].items():
            if info.get('product'):
                searches.add(info['product'])
            if info.get('version'):
                searches.add(f"{info.get('product', '')} {info['version']}")
        
        all_results = []
        for search_term in searches:
            if search_term:
                cmd = ['searchsploit', search_term, '--json']
                success, output = self.run_command(cmd, timeout=30)
                if success and output:
                    try:
                        results = json.loads(output)
                        if results.get('RESULTS_EXPLOIT'):
                            all_results.extend(results['RESULTS_EXPLOIT'])
                    except json.JSONDecodeError:
                        pass
        
        # Save exploit results
        if all_results:
            with open(exploit_dir / 'searchsploit_results.json', 'w') as f:
                json.dump(all_results, f, indent=2)
            
            # Create readable summary
            with open(exploit_dir / 'exploit_summary.txt', 'w') as f:
                f.write("POTENTIAL EXPLOITS FOUND\n")
                f.write("="*60 + "\n\n")
                for exploit in all_results[:20]:  # Limit to top 20
                    f.write(f"Title: {exploit.get('Title', 'N/A')}\n")
                    f.write(f"Path: {exploit.get('Path', 'N/A')}\n")
                    f.write(f"Date: {exploit.get('Date', 'N/A')}\n")
                    f.write("-"*40 + "\n")
            
            self.results['vulnerabilities'].append({
                'source': 'searchsploit',
                'count': len(all_results),
                'high_priority': all_results[:5]
            })
    
    def phase5_os_detection(self):
        """Phase 5: Operating System Detection"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Phase 5: OS Detection{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        os_dir = self.base_dir / "07_os_detection"
        
        self.log("Detecting operating system", "INFO")
        
        cmd = ['sudo', 'nmap', '-O', '-sV', '--osscan-guess', self.target,
               '-oN', str(os_dir / 'os_detection.txt'),
               '-oX', str(os_dir / 'os_detection.xml')]
        success, output = self.run_command(cmd, timeout=300)
        
        if success:
            self._parse_os_detection(os_dir / 'os_detection.xml')
    
    def _parse_nmap_results(self, xml_file: Path, protocol: str):
        """Parse Nmap XML results"""
        if not xml_file.exists():
            return
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    port_id = int(port.get('portid'))
                    state = port.find('state').get('state')
                    
                    if state == 'open':
                        service = port.find('service')
                        if service is not None:
                            service_info = {
                                'state': state,
                                'service': service.get('name', 'unknown'),
                                'product': service.get('product', ''),
                                'version': service.get('version', ''),
                                'extrainfo': service.get('extrainfo', '')
                            }
                        else:
                            service_info = {'state': state, 'service': 'unknown'}
                        
                        self.results['ports'][protocol][port_id] = service_info
        
        except ET.ParseError as e:
            self.log(f"Error parsing XML file {xml_file}: {str(e)}", "ERROR")
    
    def _parse_service_results(self, xml_file: Path):
        """Parse service detection results"""
        if not xml_file.exists():
            return
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    port_id = int(port.get('portid'))
                    service = port.find('service')
                    
                    if service is not None:
                        self.results['services'][port_id] = {
                            'name': service.get('name', 'unknown'),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', ''),
                            'ostype': service.get('ostype', ''),
                            'method': service.get('method', '')
                        }
        
        except ET.ParseError as e:
            self.log(f"Error parsing service XML: {str(e)}", "ERROR")
    
    def _parse_os_detection(self, xml_file: Path):
        """Parse OS detection results"""
        if not xml_file.exists():
            return
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                os_matches = []
                for osmatch in host.findall('.//osmatch'):
                    os_matches.append({
                        'name': osmatch.get('name'),
                        'accuracy': osmatch.get('accuracy')
                    })
                
                if os_matches:
                    self.results['os_detection'] = {
                        'matches': os_matches[:3],  # Top 3 matches
                        'best_guess': os_matches[0]['name'] if os_matches else 'Unknown'
                    }
        
        except ET.ParseError as e:
            self.log(f"Error parsing OS detection XML: {str(e)}", "ERROR")
    
    def _parse_live_hosts(self, xml_file: Path):
        """Parse live hosts from ping sweep"""
        if not xml_file.exists():
            return
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            live_hosts = []
            for host in root.findall('.//host'):
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    address = host.find('address')
                    if address is not None:
                        live_hosts.append(address.get('addr'))
            
            self.results['live_hosts'] = live_hosts
            self.log(f"Found {len(live_hosts)} live hosts", "SUCCESS")
        
        except ET.ParseError as e:
            self.log(f"Error parsing live hosts: {str(e)}", "ERROR")
    
    def generate_recommendations(self):
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Port-based recommendations
        critical_ports = {
            23: "Telnet detected - Use SSH instead",
            21: "FTP detected - Use SFTP/SCP instead",
            139: "NetBIOS detected - Potential for SMB attacks",
            445: "SMB detected - Check for EternalBlue vulnerability",
            3389: "RDP detected - Use VPN and restrict access",
            1433: "MSSQL detected - Check for weak sa password",
            3306: "MySQL detected - Check for anonymous access",
            5432: "PostgreSQL detected - Verify authentication settings",
            27017: "MongoDB detected - Check for authentication",
            6379: "Redis detected - Check for authentication",
            11211: "Memcached detected - Potential for amplification attacks"
        }
        
        for port, recommendation in critical_ports.items():
            if port in self.results['ports']['tcp']:
                recommendations.append({
                    'severity': 'HIGH',
                    'category': 'Service',
                    'finding': f"Port {port} open",
                    'recommendation': recommendation
                })
        
        # Service version recommendations
        for port, service in self.results['services'].items():
            if service.get('version'):
                recommendations.append({
                    'severity': 'MEDIUM',
                    'category': 'Version',
                    'finding': f"{service['product']} {service['version']} on port {port}",
                    'recommendation': f"Check for updates and known vulnerabilities for {service['product']} {service['version']}"
                })
        
        # Web application recommendations
        for web_app in self.results['web_apps']:
            recommendations.append({
                'severity': 'MEDIUM',
                'category': 'Web',
                'finding': f"Web application on port {web_app['port']}",
                'recommendation': "Perform detailed web application testing (SQLi, XSS, etc.)"
            })
        
        # OS-based recommendations
        if self.results['os_detection']:
            os_name = self.results['os_detection'].get('best_guess', '').lower()
            if 'windows' in os_name:
                if 'xp' in os_name or '2003' in os_name or '2000' in os_name:
                    recommendations.append({
                        'severity': 'CRITICAL',
                        'category': 'OS',
                        'finding': f"Outdated Windows OS: {os_name}",
                        'recommendation': "Urgent: Upgrade to supported Windows version"
                    })
            elif 'linux' in os_name:
                if 'kernel 2.' in os_name:
                    recommendations.append({
                        'severity': 'HIGH',
                        'category': 'OS',
                        'finding': f"Outdated Linux kernel detected",
                        'recommendation': "Update to latest stable kernel version"
                    })
        
        self.results['recommendations'] = recommendations
        return recommendations
    
    def generate_report(self):
        """Generate final reconnaissance report"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Generating Final Report{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        report_dir = self.base_dir / "09_reports"
        
        # Generate recommendations
        recommendations = self.generate_recommendations()
        
        # JSON Report
        self.results['scan_end'] = datetime.now().isoformat()
        with open(report_dir / 'full_report.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Human-readable report
        report_file = report_dir / 'executive_summary.txt'
        with open(report_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write(" "*20 + "ACTIVERECON - RECONNAISSANCE REPORT\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Start: {self.results['scan_start']}\n")
            f.write(f"Scan End: {self.results['scan_end']}\n")
            f.write(f"Output Directory: {self.base_dir}\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*40 + "\n")
            tcp_count = len(self.results['ports']['tcp'])
            udp_count = len(self.results['ports']['udp'])
            f.write(f"Total Open TCP Ports: {tcp_count}\n")
            f.write(f"Total Open UDP Ports: {udp_count}\n")
            f.write(f"Identified Services: {len(self.results['services'])}\n")
            f.write(f"Web Applications Found: {len(self.results['web_apps'])}\n")
            
            if self.results['os_detection']:
                f.write(f"Operating System: {self.results['os_detection'].get('best_guess', 'Unknown')}\n")
            
            f.write("\n")
            
            # Open Ports Summary
            f.write("OPEN PORTS\n")
            f.write("-"*40 + "\n")
            
            if self.results['ports']['tcp']:
                f.write("TCP Ports:\n")
                for port, info in sorted(self.results['ports']['tcp'].items()):
                    f.write(f"  {port}/tcp - {info.get('service', 'unknown')}")
                    if info.get('version'):
                        f.write(f" ({info.get('product', '')} {info.get('version', '')})")
                    f.write("\n")
            
            if self.results['ports']['udp']:
                f.write("\nUDP Ports:\n")
                for port, info in sorted(self.results['ports']['udp'].items()):
                    f.write(f"  {port}/udp - {info.get('service', 'unknown')}\n")
            
            f.write("\n")
            
            # Services Detected
            if self.results['services']:
                f.write("SERVICES DETECTED\n")
                f.write("-"*40 + "\n")
                for port, service in sorted(self.results['services'].items()):
                    f.write(f"Port {port}:\n")
                    f.write(f"  Service: {service.get('name', 'unknown')}\n")
                    if service.get('product'):
                        f.write(f"  Product: {service['product']}\n")
                    if service.get('version'):
                        f.write(f"  Version: {service['version']}\n")
                    if service.get('extrainfo'):
                        f.write(f"  Extra Info: {service['extrainfo']}\n")
                    f.write("\n")
            
            # Recommendations
            if recommendations:
                f.write("RECOMMENDATIONS\n")
                f.write("-"*40 + "\n")
                
                # Sort by severity
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
                sorted_recs = sorted(recommendations, 
                                   key=lambda x: severity_order.get(x['severity'], 99))
                
                for rec in sorted_recs:
                    f.write(f"[{rec['severity']}] {rec['category']}: {rec['finding']}\n")
                    f.write(f"  → {rec['recommendation']}\n\n")
            
            # Next Steps
            f.write("SUGGESTED NEXT STEPS\n")
            f.write("-"*40 + "\n")
            f.write("1. Review all findings in detail\n")
            f.write("2. Prioritize vulnerabilities by severity\n")
            f.write("3. Perform manual verification of automated findings\n")
            f.write("4. Conduct detailed exploitation testing (if authorized)\n")
            f.write("5. Document all findings for remediation\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("Report generated by ActiveRecon v1.0.0\n")
            f.write("="*80 + "\n")
        
        print(f"{Colors.GREEN}Report generated: {report_file}{Colors.ENDC}")
        
        # Display summary to console
        print(f"\n{Colors.CYAN}Scan completed successfully!{Colors.ENDC}")
        print(f"Results saved to: {self.base_dir}")
        print(f"\nQuick Summary:")
        print(f"  - Open TCP Ports: {tcp_count}")
        print(f"  - Open UDP Ports: {udp_count}")
        print(f"  - Services Identified: {len(self.results['services'])}")
        
        if recommendations:
            critical = [r for r in recommendations if r['severity'] == 'CRITICAL']
            high = [r for r in recommendations if r['severity'] == 'HIGH']
            
            if critical:
                print(f"{Colors.FAIL}  - CRITICAL Issues: {len(critical)}{Colors.ENDC}")
            if high:
                print(f"{Colors.WARNING}  - HIGH Priority Issues: {len(high)}{Colors.ENDC}")
    
    def run(self):
        """Execute all reconnaissance phases"""
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}  ACTIVERECON - Advanced Reconnaissance Tool{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"\nTarget: {Colors.CYAN}{self.target}{Colors.ENDC}")
        print(f"Scan Type: {Colors.CYAN}{self.scan_type}{Colors.ENDC}")
        print(f"Output Directory: {Colors.CYAN}{self.base_dir}{Colors.ENDC}")
        
        # Display available tools
        print(f"\n{Colors.BLUE}Available Tools:{Colors.ENDC}")
        for tool, available in self.available_tools.items():
            status = f"{Colors.GREEN}✓{Colors.ENDC}" if available else f"{Colors.FAIL}✗{Colors.ENDC}"
            print(f"  {status} {tool}")
        
        print(f"\n{Colors.WARNING}Starting reconnaissance...{Colors.ENDC}\n")
        
        try:
            # Execute phases based on scan type
            if self.scan_type != 'quick':
                self.phase1_host_discovery()
            
            self.phase2_port_scanning()
            
            if self.scan_type != 'quick':
                self.phase3_service_enumeration()
                self.phase4_vulnerability_assessment()
                self.phase5_os_detection()
            
            # Generate final report
            self.generate_report()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Scan interrupted by user{Colors.ENDC}")
            self.log("Scan interrupted by user", "WARNING")
            self.generate_report()
        except Exception as e:
            print(f"\n{Colors.FAIL}Error during scan: {str(e)}{Colors.ENDC}")
            self.log(f"Fatal error: {str(e)}", "ERROR")
            raise

def validate_target_authorization():
    """Ensure user has authorization to scan target"""
    print(f"{Colors.WARNING}{'='*60}{Colors.ENDC}")
    print(f"{Colors.WARNING}LEGAL NOTICE{Colors.ENDC}")
    print(f"{Colors.WARNING}{'='*60}{Colors.ENDC}")
    print("This tool performs active reconnaissance that may be detected")
    print("by intrusion detection systems and may be illegal if performed")
    print("without proper authorization.")
    print("\nOnly use this tool on:")
    print("  - Systems you own")
    print("  - Systems you have explicit written permission to test")
    print(f"{Colors.WARNING}{'='*60}{Colors.ENDC}")
    
    response = input("\nDo you have authorization to scan the target? (yes/no): ")
    if response.lower() != 'yes':
        print(f"{Colors.FAIL}Exiting. Only scan authorized targets.{Colors.ENDC}")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='ActiveRecon - Advanced Active Reconnaissance Automation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:     %(prog)s 192.168.1.1
  Network scan:   %(prog)s 192.168.1.0/24
  Quick scan:     %(prog)s -q target.com
  Full scan:      %(prog)s -f -t 20 target.com
  Custom output:  %(prog)s -o /path/to/results target.com
        """
    )
    
    parser.add_argument('target', help='Target IP, hostname, or CIDR network')
    parser.add_argument('-o', '--output', help='Output directory path')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads for parallel operations (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-q', '--quick', action='store_true',
                       help='Quick scan - only essential checks')
    parser.add_argument('-f', '--full', action='store_true',
                       help='Full comprehensive scan - all checks')
    parser.add_argument('--skip-auth', action='store_true',
                       help='Skip authorization check (use with caution)')
    
    args = parser.parse_args()
    
    # Determine scan type
    if args.quick:
        scan_type = 'quick'
    elif args.full:
        scan_type = 'comprehensive'
    else:
        scan_type = 'full'
    
    # Check for root/sudo privileges for certain scans
    if scan_type in ['full', 'comprehensive'] and os.geteuid() != 0:
        print(f"{Colors.WARNING}Note: Some scans require root privileges for best results{Colors.ENDC}")
        print(f"{Colors.WARNING}Consider running with sudo for comprehensive scanning{Colors.ENDC}\n")
    
    # Authorization check
    if not args.skip_auth:
        validate_target_authorization()
    
    # Initialize and run scanner
    try:
        scanner = ActiveRecon(
            target=args.target,
            output_dir=args.output,
            verbose=args.verbose,
            threads=args.threads,
            scan_type=scan_type
        )
        scanner.run()
    except Exception as e:
        print(f"{Colors.FAIL}Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
