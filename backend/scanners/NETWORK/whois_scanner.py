import asyncio
import json
import re
import socket
from typing import Dict, Any, List, Optional
from datetime import datetime
from ..base import ScannerBase
import httpx
from urllib.parse import urlparse

# Try to import python-whois library for better parsing
try:
    import whois
    WHOIS_LIBRARY_AVAILABLE = True
except ImportError:
    WHOIS_LIBRARY_AVAILABLE = False
    whois = None

# Try to import dateutil for date parsing
try:
    from dateutil import parser as date_parser
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False
    date_parser = None

class WHOISScanner(ScannerBase):
    """Enhanced WHOIS scanner with proper field mapping and date normalization"""
    
    def __init__(self, target: str, timeout: int = None):
        super().__init__(target, timeout)
        # Extract domain from target URL
        if target.startswith(('http://', 'https://')):
            parsed_url = urlparse(target)
            self.domain = parsed_url.netloc
        else:
            self.domain = target
        
        # Remove port if present
        if ':' in self.domain:
            self.domain = self.domain.split(':')[0]
        
        # Comprehensive field mapping for different TLDs and registrars
        self.field_mappings = {
            'creation_date': [
                'creation date', 'created on', 'registered on', 'created', 'registered',
                'registration date', 'domain registration date', 'registered date',
                'created date', 'domain created', 'registration time'
            ],
            'expiry_date': [
                'expiry date', 'expires on', 'expiration date', 'expires', 'expiration',
                'expiry', 'registry expiry date', 'expiration time', 'expires date',
                'domain expiration', 'expiry time'
            ],
            'registrar': [
                'registrar', 'sponsoring registrar', 'registrar name', 'registrar iana id',
                'registrar organization', 'registrar whois server'
            ],
            'nameservers': [
                'name server', 'nserver', 'nameservers', 'dns', 'name servers',
                'nameserver', 'dns servers', 'name servers'
            ],
            'status': [
                'status', 'domain status', 'state', 'domain state', 'registration status'
            ],
            'admin_contact': [
                'admin contact', 'administrative contact', 'admin', 'administrative',
                'admin email', 'administrative email'
            ],
            'tech_contact': [
                'tech contact', 'technical contact', 'technical', 'tech',
                'tech email', 'technical email'
            ],
            'registrant': [
                'registrant', 'registrant contact', 'registrant name', 'registrant organization',
                'registrant email', 'owner', 'domain owner'
            ]
        }
        
        # Privacy protection service indicators
        self.privacy_services = [
            'whoisguard', 'domains by proxy', 'privacyprotect', 'contactprivacy.com',
            'redacted for privacy', 'privacy service', 'whois privacy', 'privacy protection',
            'whois privacy protection service', 'privacy protection service', 'whoisguard inc',
            'domainsbyproxy.com', 'privacyprotect.org', 'whoisprivacyprotector.com'
        ]
    
    async def scan(self) -> Dict[str, Any]:
        """Execute enhanced WHOIS scan with asyncwhois"""
        try:
            # Send progress update
            if self.connection_manager and self.scan_id:
                await self.connection_manager.send_progress(
                    self.scan_id, 
                    10, 
                    "whois",
                    current_activity="Initializing WHOIS lookup"
                )
            
            # Try asyncwhois first (non-blocking)
            try:
                import asyncwhois
                
                if self.connection_manager and self.scan_id:
                    await self.connection_manager.send_progress(
                        self.scan_id, 
                        30, 
                        "whois",
                        current_activity=f"Performing async WHOIS lookup for {self.domain}"
                    )
                
                # Perform async lookup - handle library version differences
                if hasattr(asyncwhois, 'aio_lookup'):
                    result = await asyncwhois.aio_lookup(self.domain)
                else:
                    # Newer versions use 'lookup' which is awaitable
                    result = await asyncwhois.lookup(self.domain)
                self.raw_output = result.query_output
                
                # Parse structured data from asyncwhois if available
                # asyncwhois returns a parsed dict in result.parser_output
                self.parsed_data_from_lib = result.parser_output
                
            except ImportError:
                print("[*] asyncwhois not installed, falling back to python-whois/custom")
                # Fallback to existing logic
                if WHOIS_LIBRARY_AVAILABLE:
                    self.raw_output = await self._whois_library_lookup()
                else:
                    self.raw_output = await self._custom_whois_lookup()
            except Exception as e:
                print(f"[*] asyncwhois failed: {e}, falling back")
                # Try custom WHOIS first
                self.raw_output = await self._custom_whois_lookup()
                
                # CRITICAL FIX: If WHOIS returns rate limit/retirement error, try RDAP
                if self.raw_output and any(phrase in self.raw_output.lower() for phrase in [
                    "rate limit exceeded", "rdap service instead", "this whois server is being retired",
                    "whois server is being retired", "try again after"
                ]):
                    print("[*] WHOIS rate limited/retired, trying RDAP...")
                    rdap_output = await self._rdap_lookup()
                    if rdap_output and "RDAP lookup failed" not in rdap_output and len(rdap_output.strip()) > 0:
                        self.raw_output = rdap_output
                        print("[*] RDAP lookup successful")
                    else:
                        print("[*] RDAP lookup also failed, using error message")
            
            # Send progress update
            if self.connection_manager and self.scan_id:
                await self.connection_manager.send_progress(
                    self.scan_id, 
                    70, 
                    "whois",
                    current_activity="Parsing WHOIS results"
                )
            
            self.parsed_result = self.parse_output()
            
            # CRITICAL: Ensure raw_data is included in the result
            # Fix: Wrap raw_output string in dictionary structure for consistency
            if 'raw_data' not in self.parsed_result:
                self.parsed_result['raw_data'] = {
                    'raw_whois_output': self.raw_output,
                    'timestamp': datetime.now().isoformat()
                }
            elif isinstance(self.parsed_result.get('raw_data'), str):
                # If raw_data is a string (from parse_output), wrap it in a dict
                self.parsed_result['raw_data'] = {
                    'raw_whois_output': self.parsed_result['raw_data'],
                    'timestamp': datetime.now().isoformat()
                }
            
            # Send final progress update
            if self.connection_manager and self.scan_id:
                await self.connection_manager.send_progress(
                    self.scan_id, 
                    100, 
                    "whois",
                    current_activity="WHOIS lookup completed"
                )
                
            return self.parsed_result
            
        except Exception as e:
            # Send error update
            if self.connection_manager and self.scan_id:
                await self.connection_manager.send_progress(
                    self.scan_id, 
                    0, 
                    "whois",
                    current_activity=f"WHOIS lookup failed: {str(e)}"
                )
            raise Exception(f"WHOIS lookup failed: {str(e)}")
    
    async def _whois_library_lookup(self) -> str:
        """Use python-whois library for accurate parsing"""
        def sync_whois_lookup():
            try:
                w = whois.whois(self.domain)
                # Convert whois object to structured dict
                whois_dict = {}
                
                # Extract all available fields
                if hasattr(w, 'domain_name'):
                    whois_dict['domain_name'] = w.domain_name
                if hasattr(w, 'registrar'):
                    whois_dict['registrar'] = w.registrar
                if hasattr(w, 'creation_date'):
                    whois_dict['creation_date'] = w.creation_date
                if hasattr(w, 'expiration_date'):
                    whois_dict['expiry_date'] = w.expiration_date
                if hasattr(w, 'updated_date'):
                    whois_dict['updated_date'] = w.updated_date
                if hasattr(w, 'name_servers'):
                    whois_dict['nameservers'] = w.name_servers
                if hasattr(w, 'status'):
                    whois_dict['status'] = w.status
                if hasattr(w, 'emails'):
                    whois_dict['emails'] = w.emails
                if hasattr(w, 'dnssec'):
                    whois_dict['dnssec'] = w.dnssec
                if hasattr(w, 'name'):
                    whois_dict['registrant_name'] = w.name
                if hasattr(w, 'org'):
                    whois_dict['registrant_org'] = w.org
                if hasattr(w, 'country'):
                    whois_dict['country'] = w.country
                
                # Convert to string format for compatibility
                result_lines = []
                for key, value in whois_dict.items():
                    if value:
                        if isinstance(value, list):
                            for item in value:
                                result_lines.append(f"{key.replace('_', ' ').title()}: {item}")
                        else:
                            result_lines.append(f"{key.replace('_', ' ').title()}: {value}")
                
                return "\n".join(result_lines) if result_lines else str(w.text) if hasattr(w, 'text') else ""
            except Exception as e:
                raise Exception(f"python-whois lookup failed: {str(e)}")
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, sync_whois_lookup)
    
    async def _custom_whois_lookup(self) -> str:
        """Custom WHOIS lookup using proper WHOIS protocol"""
        try:
            # Step 1: Query IANA/InterNIC to get the registrar's WHOIS server
            # This is the proper WHOIS protocol - query root servers first
            root_servers = [
                "whois.iana.org",
                "whois.internic.net",
                "whois.verisign-grs.com"
            ]
            
            registrar_whois_server = None
            
            for root_server in root_servers:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(None)  # No timeout - wait indefinitely
                    sock.connect((root_server, 43))
                    
                    query = f"{self.domain}\r\n"
                    sock.send(query.encode())
                    
                    response = b""
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                    
                    sock.close()
                    
                    whois_data = response.decode('utf-8', errors='ignore')
                    
                    # Extract registrar WHOIS server from response
                    # Look for patterns like "Registrar WHOIS Server: whois.godaddy.com"
                    for line in whois_data.split('\n'):
                        line_lower = line.lower()
                        if 'registrar whois server' in line_lower or ('whois server' in line_lower and 'registrar' in line_lower):
                            # Extract server name
                            if ':' in line:
                                server = line.split(':', 1)[1].strip()
                                if server and server not in ['whois.iana.org', 'whois.internic.net', 'whois.verisign-grs.com']:
                                    registrar_whois_server = server
                                    break
                    
                    # If we found the registrar server, break
                    if registrar_whois_server:
                        break
                        
                except Exception as e:
                    continue
            
            # Step 2: Query the registrar's WHOIS server directly
            if registrar_whois_server:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(None)  # No timeout - wait indefinitely
                    sock.connect((registrar_whois_server, 43))
                    
                    query = f"{self.domain}\r\n"
                    sock.send(query.encode())
                    
                    response = b""
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                    
                    sock.close()
                    
                    whois_data = response.decode('utf-8', errors='ignore')
                    
                    if whois_data and "No match" not in whois_data and "not found" not in whois_data.lower():
                        return whois_data
                        
                except Exception as e:
                    # If registrar server fails, continue to fallback
                    pass
            
            # Step 3: Fallback - try direct query to common WHOIS servers
            fallback_servers = [
                "whois.verisign-grs.com",  # For .com/.net
                "whois.pir.org",  # For .org
                "whois.afilias.net",  # For various TLDs
            ]
            
            for server in fallback_servers:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(None)  # No timeout - wait indefinitely
                    sock.connect((server, 43))
                    
                    query = f"{self.domain}\r\n"
                    sock.send(query.encode())
                    
                    response = b""
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                    
                    sock.close()
                    
                    whois_data = response.decode('utf-8', errors='ignore')
                    
                    if whois_data and "No match" not in whois_data and "not found" not in whois_data.lower():
                        return whois_data
                        
                except Exception as e:
                    continue
            
            # Final fallback: Use web-based WHOIS API
            return await self._web_whois_lookup()
            
        except Exception as e:
            return f"WHOIS lookup failed: {str(e)}"
    
    async def _web_whois_lookup(self) -> str:
        """Fallback web-based WHOIS lookup"""
        try:
            # Use the scanner's timeout setting (None or 0 means no timeout)
            client_timeout = None if (self.timeout is None or self.timeout == 0) else httpx.Timeout(self.timeout)
            async with httpx.AsyncClient(timeout=client_timeout) as client:
                # Try multiple web WHOIS services
                services = [
                    f"https://whois.net/whois/{self.domain}",
                    f"https://www.whois.com/whois/{self.domain}",
                    f"https://whois.domaintools.com/{self.domain}"
                ]
                
                for service in services:
                    try:
                        response = await client.get(service)
                        if response.status_code == 200:
                            # Extract WHOIS data from HTML (simplified)
                            content = response.text
                            if "Domain Name:" in content or "Registrar:" in content:
                                return self._extract_whois_from_html(content)
                    except:
                        continue
                
                # If all web services fail, return basic domain info
                return self._generate_basic_domain_info()
                
        except Exception as e:
            return f"Web WHOIS lookup failed: {str(e)}"
    
    async def _rdap_lookup(self) -> str:
        """RDAP (Registration Data Access Protocol) lookup as fallback for retired WHOIS servers"""
        try:
            # RDAP endpoints for different TLDs
            rdap_servers = {
                'com': 'https://rdap.verisign.com/com/v1/domain/',
                'net': 'https://rdap.verisign.com/net/v1/domain/',
                'org': 'https://rdap.org.org/domain/',
                'io': 'https://rdap.nic.io/domain/',
                'co': 'https://rdap.nic.co/domain/',
                'info': 'https://rdap.afilias.net/domain/',
                'biz': 'https://rdap.afilias.net/domain/',
            }
            
            # Extract TLD
            tld = self.domain.split('.')[-1].lower()
            
            # Try RDAP lookup with TLD-specific server
            if tld in rdap_servers:
                rdap_url = f"{rdap_servers[tld]}{self.domain}"
                try:
                    # Proper timeout handling - None or 0 means no timeout
                    client_timeout = None if (self.timeout is None or self.timeout == 0) else httpx.Timeout(self.timeout)
                    async with httpx.AsyncClient(timeout=client_timeout) as client:
                        response = await client.get(rdap_url, headers={'Accept': 'application/rdap+json'})
                        if response.status_code == 200:
                            rdap_data = response.json()
                            # Convert RDAP JSON to WHOIS-like format
                            return self._rdap_to_whois_format(rdap_data)
                except Exception as e:
                    print(f"[*] RDAP lookup failed for {tld}: {e}")
            
            # Fallback: Try IANA RDAP bootstrap or generic RDAP services
            bootstrap_urls = [
                f"https://rdap.org/domain/{self.domain}",
                f"https://rdap.iana.org/domain/{self.domain}",
            ]
            
            for bootstrap_url in bootstrap_urls:
                try:
                    # Proper timeout handling - None or 0 means no timeout
                    client_timeout = None if (self.timeout is None or self.timeout == 0) else httpx.Timeout(self.timeout)
                    async with httpx.AsyncClient(timeout=client_timeout) as client:
                        response = await client.get(bootstrap_url, headers={'Accept': 'application/rdap+json'})
                        if response.status_code == 200:
                            rdap_data = response.json()
                            return self._rdap_to_whois_format(rdap_data)
                except Exception as e:
                    continue
            
            return ""
        except Exception as e:
            return f"RDAP lookup failed: {str(e)}"
    
    def _rdap_to_whois_format(self, rdap_data: Dict) -> str:
        """Convert RDAP JSON response to WHOIS-like text format"""
        lines = []
        
        try:
            # Domain name
            if 'domainName' in rdap_data:
                lines.append(f"Domain Name: {rdap_data['domainName']}")
            
            # Registry Domain ID
            if 'handle' in rdap_data:
                lines.append(f"Registry Domain ID: {rdap_data['handle']}")
            
            # Dates from events
            if 'events' in rdap_data:
                for event in rdap_data['events']:
                    event_action = event.get('eventAction', '').lower()
                    event_date = event.get('eventDate', '')
                    if event_date:
                        if event_action == 'registration':
                            lines.append(f"Creation Date: {event_date}")
                        elif event_action == 'expiration':
                            lines.append(f"Registry Expiry Date: {event_date}")
                        elif event_action in ['last changed', 'last update', 'last modified']:
                            lines.append(f"Updated Date: {event_date}")
            
            # Registrar information from entities
            if 'entities' in rdap_data:
                for entity in rdap_data['entities']:
                    roles = [r.lower() for r in entity.get('roles', [])]
                    if 'registrar' in roles:
                        if 'vcardArray' in entity:
                            vcard = entity['vcardArray']
                            if len(vcard) > 1 and isinstance(vcard[1], list):
                                registrar_name = None
                                registrar_org = None
                                registrar_url = None
                                registrar_iana_id = None
                                
                                for prop in vcard[1]:
                                    if isinstance(prop, list) and len(prop) >= 4:
                                        prop_type = prop[0].lower()
                                        prop_value = prop[3]
                                        
                                        if prop_type == 'fn':
                                            registrar_name = prop_value
                                        elif prop_type == 'org':
                                            registrar_org = prop_value
                                        elif prop_type == 'url':
                                            registrar_url = prop_value
                                        elif prop_type == 'uid' and 'iana' in str(prop_value).lower():
                                            registrar_iana_id = prop_value
                                
                                if registrar_name:
                                    lines.append(f"Registrar: {registrar_name}")
                                if registrar_org:
                                    lines.append(f"Registrar Organization: {registrar_org}")
                                if registrar_url:
                                    lines.append(f"Registrar URL: {registrar_url}")
                                if registrar_iana_id:
                                    lines.append(f"Registrar IANA ID: {registrar_iana_id}")
            
            # Name servers
            if 'nameservers' in rdap_data:
                for ns in rdap_data['nameservers']:
                    if 'ldhName' in ns:
                        lines.append(f"Name Server: {ns['ldhName']}")
            
            # Domain status
            if 'status' in rdap_data:
                for status in rdap_data['status']:
                    if isinstance(status, str):
                        lines.append(f"Domain Status: {status}")
            
            # DNSSEC
            if 'secureDNS' in rdap_data:
                secure_dns = rdap_data['secureDNS']
                if isinstance(secure_dns, dict):
                    dnssec = secure_dns.get('delegationSigned', False)
                    lines.append(f"DNSSEC: {'signed' if dnssec else 'unsigned'}")
            
            # Public IDs (if available)
            if 'publicIds' in rdap_data:
                for pub_id in rdap_data['publicIds']:
                    if isinstance(pub_id, dict):
                        identifier = pub_id.get('identifier', '')
                        identifier_type = pub_id.get('type', '')
                        if identifier and identifier_type:
                            lines.append(f"{identifier_type}: {identifier}")
            
        except Exception as e:
            print(f"[*] Error converting RDAP to WHOIS format: {e}")
        
        return "\n".join(lines) if lines else ""
    
    def _extract_whois_from_html(self, html_content: str) -> str:
        """Extract WHOIS data from HTML content"""
        # Simple extraction of common WHOIS fields
        patterns = {
            'domain_name': r'Domain Name:\s*([^\n\r]+)',
            'registrar': r'Registrar:\s*([^\n\r]+)',
            'creation_date': r'Creation Date:\s*([^\n\r]+)',
            'expiry_date': r'Expiry Date:\s*([^\n\r]+)',
            'nameservers': r'Name Server:\s*([^\n\r]+)',
            'status': r'Status:\s*([^\n\r]+)'
        }
        
        extracted_data = []
        for field, pattern in patterns.items():
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                extracted_data.append(f"{field.replace('_', ' ').title()}: {matches[0]}")
        
        return "\n".join(extracted_data) if extracted_data else "WHOIS data extracted from web"
    
    def _generate_basic_domain_info(self) -> str:
        """Generate basic domain information when WHOIS fails - DO NOT generate fake data"""
        # Return empty instead of fake "Unknown" data to prevent inaccurate reports
        return f"Domain Name: {self.domain}\nNote: WHOIS lookup failed - no data available"
    
    def parse_output(self) -> Dict[str, Any]:
        """Parse WHOIS output into structured format with improved parsing for real data"""
        findings = []
        domain_info = {}
        
        try:
            # CRITICAL FIX: Detect rate limit and RDAP retirement errors
            if not self.raw_output:
                return {
                    "scanner": "whois",
                    "target": self.domain,
                    "findings": [],
                    "domain_info": {},
                    "privacy_protected": False,
                    "raw_data": {
                        "raw_whois_output": "",
                        "error": "No WHOIS data available",
                        "timestamp": datetime.now().isoformat()
                    },
                    "message": "No WHOIS data available"
                }
            
            # Check for error messages (rate limit, RDAP retirement, etc.)
            raw_lower = self.raw_output.lower()
            error_phrases = [
                "whois lookup failed",
                "rate limit exceeded",
                "rdap service instead",
                "this whois server is being retired",
                "try again after",
                "whois server is being retired"
            ]
            
            if any(phrase in raw_lower for phrase in error_phrases):
                error_type = "rate_limit" if "rate limit" in raw_lower else "server_retired"
                return {
                    "scanner": "whois",
                    "target": self.domain,
                    "findings": [],
                    "domain_info": {
                        "error": self.raw_output.strip(),
                        "error_type": error_type
                    },
                    "privacy_protected": False,
                    "raw_data": {
                        "raw_whois_output": self.raw_output,
                        "error_type": error_type,
                        "timestamp": datetime.now().isoformat()
                    },
                    "message": f"WHOIS lookup failed: {error_type.replace('_', ' ').title()}"
                }
            
            if "WHOIS lookup failed" in self.raw_output:
                return {
                    "scanner": "whois",
                    "target": self.domain,
                    "findings": [],
                    "domain_info": {},
                    "privacy_protected": False,
                    "raw_data": {
                        "raw_whois_output": self.raw_output,  # CRITICAL: Include raw output
                        "error": "WHOIS lookup failed",
                        "timestamp": datetime.now().isoformat()
                    },
                    "message": "No WHOIS data available"
                }
            
            # Parse WHOIS data with improved logic
            if hasattr(self, 'parsed_data_from_lib') and self.parsed_data_from_lib:
                # Use data already parsed by asyncwhois
                domain_info = self.parsed_data_from_lib
                # Ensure keys are lowercase for consistency
                domain_info = {k.lower(): v for k, v in domain_info.items()}
            else:
                # IMPROVED: Parse raw WHOIS output with better field extraction
                lines = self.raw_output.split('\n')
                
                for line in lines:
                    line = line.strip()
                    # Skip comments, empty lines, and metadata lines
                    if not line or line.startswith('%') or line.startswith('#') or line.startswith('>>>'):
                        continue
                    
                    # Handle key-value pairs with colon separator
                    if ':' in line:
                        try:
                            key, value = line.split(':', 1)
                            key = key.strip().lower()
                            value = value.strip()
                            
                            # Skip invalid values
                            if not value or value in ['N/A', 'Not Available', 'Not Disclosed', 'Unknown', 'NONE', '']:
                                continue
                            
                            # IMPROVED: Better field name normalization
                            # Map common variations to standard field names
                            if 'domain name' in key:
                                domain_info['domain_name'] = value
                            elif 'registrar' in key and 'whois server' not in key and 'iana id' not in key and 'abuse' not in key and 'url' not in key:
                                domain_info['registrar'] = value
                            elif 'registrar whois server' in key:
                                domain_info['registrar_whois_server'] = value
                            elif 'registrar url' in key:
                                domain_info['registrar_url'] = value
                            elif 'registrar iana id' in key:
                                domain_info['registrar_iana_id'] = value
                            elif 'creation date' in key or 'created' in key:
                                domain_info['creation_date'] = value
                            elif 'expiry date' in key or 'expiration date' in key or 'registry expiry' in key:
                                domain_info['expiry_date'] = value
                            elif 'updated date' in key or 'last updated' in key:
                                domain_info['updated_date'] = value
                            elif 'name server' in key or 'nserver' in key:
                                if 'nameservers' not in domain_info:
                                    domain_info['nameservers'] = []
                                if value and value not in domain_info['nameservers']:
                                    domain_info['nameservers'].append(value)
                            elif 'domain status' in key or ('status' in key and 'domain' in key):
                                if 'domain_status' not in domain_info:
                                    domain_info['domain_status'] = []
                                if value and value not in domain_info['domain_status']:
                                    domain_info['domain_status'].append(value)
                            elif 'dnssec' in key:
                                domain_info['dnssec'] = value
                            elif 'registry domain id' in key:
                                domain_info['registry_domain_id'] = value
                            else:
                                # Store other fields as-is
                                if key not in domain_info:
                                    domain_info[key] = value
                                elif isinstance(domain_info[key], list):
                                    if value not in domain_info[key]:
                                        domain_info[key].append(value)
                                        
                        except ValueError:
                            continue
            
            # Map fields using comprehensive field mapping
            mapped_info = self._map_whois_fields(domain_info)
            
            # Normalize dates
            mapped_info = self._normalize_dates(mapped_info)
            
            # Detect privacy protection
            privacy_protected = self._detect_privacy_protection(mapped_info, domain_info)
            mapped_info['privacy_protected'] = privacy_protected
            
            # Extract key information and create findings
            findings.extend(self._analyze_registrar_info(mapped_info))
            findings.extend(self._analyze_dates(mapped_info))
            findings.extend(self._analyze_nameservers(mapped_info))
            findings.extend(self._analyze_contact_info(mapped_info, privacy_protected))
            
            # If no specific findings, add general domain info
            if not findings:
                findings.append({
                    "title": "Domain Information Retrieved",
                    "description": f"WHOIS data retrieved for domain {self.domain}",
                    "severity": "info",
                    "endpoint": self.domain,
                    "evidence": "WHOIS lookup completed successfully",
                    "recommendation": "Review domain registration details for security implications"
                })
            
            return {
                "scanner": "whois",
                "target": self.domain,
                "findings": [self.normalize_finding(finding) for finding in findings],
                "domain_info": mapped_info,
                "privacy_protected": privacy_protected,
                "raw_data": {
                    "raw_whois_output": self.raw_output,  # CRITICAL: Include raw WHOIS output for PDF generation
                    "timestamp": datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            raise Exception(f"Failed to parse WHOIS output: {str(e)}")
    
    def _map_whois_fields(self, domain_info: Dict[str, Any]) -> Dict[str, Any]:
        """Map various field name variations to standardized field names"""
        mapped = {}
        
        for standard_field, variations in self.field_mappings.items():
            for key, value in domain_info.items():
                if any(var in key for var in variations):
                    if standard_field == 'nameservers':
                        # Handle multi-value nameservers
                        if standard_field not in mapped:
                            mapped[standard_field] = []
                        if isinstance(value, list):
                            mapped[standard_field].extend(value)
                        else:
                            if value not in mapped[standard_field]:
                                mapped[standard_field].append(value)
                    else:
                        # Single value fields - use first valid match
                        if standard_field not in mapped or not mapped[standard_field]:
                            mapped[standard_field] = value
        
        # Also copy any unmapped fields that might be useful
        for key, value in domain_info.items():
            if key not in mapped and value:
                mapped[key] = value
        
        return mapped
    
    def _normalize_dates(self, domain_info: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize date formats to ISO format"""
        date_fields = ['creation_date', 'expiry_date', 'updated_date']
        
        for field in date_fields:
            if field in domain_info:
                date_value = domain_info[field]
                if date_value:
                    normalized = self._normalize_date(date_value)
                    if normalized:
                        domain_info[field] = normalized
        
        return domain_info
    
    def _normalize_date(self, date_value: Any) -> Optional[str]:
        """Normalize date to ISO format (YYYY-MM-DD) - handles ISO format with Z suffix"""
        if not date_value:
            return None
        
        # If already a datetime object
        if isinstance(date_value, datetime):
            return date_value.strftime('%Y-%m-%d')
        
        # If it's a list, take the first valid date
        if isinstance(date_value, list):
            for item in date_value:
                normalized = self._normalize_date(item)
                if normalized:
                    return normalized
            return None
        
        date_str = str(date_value).strip()
        
        # Handle ISO format with Z suffix (e.g., "2025-10-29T14:30:39Z")
        if 'T' in date_str and ('Z' in date_str or '+' in date_str or date_str.count('-') >= 2):
            try:
                # Extract date part before T
                date_part = date_str.split('T')[0]
                # Validate it's YYYY-MM-DD format
                if re.match(r'^\d{4}-\d{2}-\d{2}$', date_part):
                    return date_part
            except:
                pass
        
        # Try dateutil parser if available
        if DATEUTIL_AVAILABLE:
            try:
                parsed_date = date_parser.parse(date_str)
                return parsed_date.strftime('%Y-%m-%d')
            except:
                pass
        
        # Try common date patterns
        date_patterns = [
            r'(\d{4}-\d{2}-\d{2})',  # YYYY-MM-DD
            r'(\d{2}/\d{2}/\d{4})',  # DD/MM/YYYY or MM/DD/YYYY
            r'(\d{2}-\d{2}-\d{4})',  # DD-MM-YYYY
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, date_str)
            if match:
                date_part = match.group(1)
                try:
                    if DATEUTIL_AVAILABLE:
                        parsed = date_parser.parse(date_part)
                        return parsed.strftime('%Y-%m-%d')
                except:
                    pass
        
        # Return original if can't parse
        return date_str
    
    def _detect_privacy_protection(self, mapped_info: Dict[str, Any], raw_info: Dict[str, Any]) -> bool:
        """Detect privacy protection with improved logic"""
        # Check registrar name for privacy services
        registrar = str(mapped_info.get('registrar', '')).lower()
        if any(service in registrar for service in self.privacy_services):
            return True
        
        # Check contact fields for privacy indicators
        contact_fields = ['admin_contact', 'tech_contact', 'registrant', 'emails']
        for field in contact_fields:
            value = str(mapped_info.get(field, '')).lower()
            if any(service in value for service in self.privacy_services):
                return True
        
        # Check raw domain_info for privacy indicators
        for key, value in raw_info.items():
            value_str = str(value).lower()
            if any(indicator in value_str for indicator in ['privacy', 'protected', 'proxy', 'anonymized', 'redacted']):
                if any(service in value_str for service in self.privacy_services):
                    return True
        
        # Check for common privacy protection patterns
        privacy_patterns = [
            r'whoisguard',
            r'domains?\s*by\s*proxy',
            r'privacy\s*protect',
            r'contactprivacy',
            r'redacted\s*for\s*privacy'
        ]
        
        all_text = ' '.join(str(v).lower() for v in raw_info.values())
        for pattern in privacy_patterns:
            if re.search(pattern, all_text):
                return True
        
        return False
    
    def _analyze_registrar_info(self, domain_info: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze registrar information"""
        findings = []
        
        registrar = domain_info.get('registrar', '').lower()
        
        if registrar and registrar != 'unknown':
            findings.append({
                "title": "Domain Registrar Information",
                "description": f"Domain registered with: {domain_info.get('registrar', 'Unknown')}",
                "severity": "info",
                "endpoint": self.domain,
                "evidence": f"Registrar: {domain_info.get('registrar', 'Unknown')}",
                "recommendation": "Verify registrar legitimacy and reputation"
            })
        
        return findings
    
    def _analyze_dates(self, domain_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze domain registration and expiration dates"""
        findings = []
        
        # Check registration date (using mapped field)
        reg_date = domain_info.get('creation_date')
        if reg_date and reg_date not in ['unknown', 'N/A', 'Not Available']:
            findings.append({
                "title": "Domain Registration Date",
                "description": f"Domain registered on: {reg_date}",
                "severity": "info",
                "endpoint": self.domain,
                "evidence": f"Registration Date: {reg_date}",
                "recommendation": "Consider domain age in security assessment"
            })
        
        # Check expiration date (using mapped field)
        exp_date = domain_info.get('expiry_date')
        if exp_date and exp_date not in ['unknown', 'N/A', 'Not Available']:
            # Check if domain is expiring soon (within 30 days)
            try:
                if DATEUTIL_AVAILABLE:
                    exp_datetime = date_parser.parse(str(exp_date))
                    days_until_expiry = (exp_datetime - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        severity = "high"
                        description = f"Domain EXPIRED on: {exp_date} ({abs(days_until_expiry)} days ago)"
                        recommendation = "URGENT: Domain has expired - risk of domain takeover"
                    elif days_until_expiry <= 30:
                        severity = "medium"
                        description = f"Domain expires on: {exp_date} (in {days_until_expiry} days)"
                        recommendation = "Domain expiring soon - renew immediately to prevent takeover"
                    else:
                        severity = "info"
                        description = f"Domain expires on: {exp_date}"
                        recommendation = "Monitor domain expiration to prevent takeover"
                    
                    findings.append({
                        "title": "Domain Expiration Date",
                        "description": description,
                        "severity": severity,
                        "endpoint": self.domain,
                        "evidence": f"Expiration Date: {exp_date}",
                        "recommendation": recommendation
                    })
                else:
                    findings.append({
                        "title": "Domain Expiration Date",
                        "description": f"Domain expires on: {exp_date}",
                        "severity": "info",
                        "endpoint": self.domain,
                        "evidence": f"Expiration Date: {exp_date}",
                        "recommendation": "Monitor domain expiration to prevent takeover"
                    })
            except Exception:
                # If date parsing fails, still add finding with original date
                findings.append({
                    "title": "Domain Expiration Date",
                    "description": f"Domain expires on: {exp_date}",
                    "severity": "info",
                    "endpoint": self.domain,
                    "evidence": f"Expiration Date: {exp_date}",
                    "recommendation": "Monitor domain expiration to prevent takeover"
                })
        
        return findings
    
    def _analyze_nameservers(self, domain_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze nameserver information"""
        findings = []
        
        # Extract nameservers (handle both mapped and raw fields)
        nameservers = []
        
        # Check mapped nameservers field (list)
        if 'nameservers' in domain_info:
            ns_value = domain_info['nameservers']
            if isinstance(ns_value, list):
                nameservers.extend(ns_value)
            else:
                nameservers.append(ns_value)
        
        # Also check raw fields
        for key, value in domain_info.items():
            if ('nameserver' in key.lower() or 'nserver' in key.lower() or 'dns' in key.lower()) and key != 'nameservers':
                if isinstance(value, list):
                    nameservers.extend(value)
                else:
                    if value not in nameservers:
                        nameservers.append(value)
        
        # Remove duplicates and clean
        nameservers = list(set([str(ns).strip() for ns in nameservers if ns and str(ns).strip()]))
        
        if nameservers:
            findings.append({
                "title": "Nameserver Information",
                "description": f"Domain uses {len(nameservers)} nameserver(s): {', '.join(nameservers)}",
                "severity": "info",
                "endpoint": self.domain,
                "evidence": f"Nameservers: {', '.join(nameservers)}",
                "recommendation": "Verify nameserver configuration and security"
            })
        
        return findings
    
    def _analyze_contact_info(self, domain_info: Dict[str, Any], privacy_protected: bool) -> List[Dict[str, Any]]:
        """Analyze contact information"""
        findings = []
        
        if privacy_protected:
            findings.append({
                "title": "Domain Privacy Protection Enabled",
                "description": "Domain registration uses privacy protection service to hide contact information",
                "severity": "info",
                "endpoint": self.domain,
                "evidence": "Privacy protection detected in WHOIS data",
                "recommendation": "Privacy protection is a good security practice"
            })
        else:
            # Check if contact information is actually exposed
            has_contact_info = any(
                field in domain_info for field in ['admin_contact', 'tech_contact', 'registrant', 'emails']
            )
            
            if has_contact_info:
                findings.append({
                    "title": "Public Contact Information Exposed",
                    "description": "Domain contact information is publicly visible in WHOIS data",
                    "severity": "low",
                    "endpoint": self.domain,
                    "evidence": "Contact information exposed in WHOIS data",
                    "recommendation": "Consider enabling domain privacy protection to prevent information disclosure"
                })
        
        return findings