"""
Professional Debug Endpoint Scanner
Detects exposed debug interfaces, development endpoints, admin panels
"""

import requests
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Optional, Dict
import re
import json
from datetime import datetime

from .vulnerability_models import (
    InfoDisclosureVulnerability,
    InfoDisclosureSeverity, 
    InfoDisclosureType,
    CVE_DATABASE
)

logger = logging.getLogger(__name__)

class DebugEndpointScanner:
    """Professional scanner for debug endpoint detection"""
    
    def __init__(self, base_url: str, timeout: int = None):
        """Initialize debug endpoint scanner"""
        self.base_url = base_url.rstrip('/')
        self.base_url_normalized = self._normalize_url(self.base_url)
        # Reduce timeout from 3s to 1.5s for faster failures
        self.timeout = timeout if timeout is not None else 1.5
        # Connection timeout (separate from read timeout)
        self.connect_timeout = 1.0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities: List[InfoDisclosureVulnerability] = []
        
        # Comprehensive debug endpoint patterns
        self.debug_endpoints = self._initialize_debug_endpoints()
        
        # Debug response patterns
        self.debug_patterns = {
            'stack_trace': [
                r'Traceback \(most recent call last\)',
                r'at\s+[\w.$]+\([^)]*\)',
                r'Exception in thread',
                r'java\.lang\.\w+Exception',
                r'System\.Exception',
                r'Fatal error:.*in.*on line',
                r'Warning:.*in.*on line',
                r'Notice:.*in.*on line'
            ],
            'debug_info': [
                r'DEBUG:\s*.*',
                r'TRACE:\s*.*',
                r'Development Mode',
                r'Debug Mode.*Enabled',
                r'\_\_debug\_\_.*=.*true',
                r'debug\s*:\s*true',
                r'environment\s*:\s*development'
            ],
            'system_info': [
                r'PHP Version',
                r'Apache/[\d.]+',
                r'nginx/[\d.]+',
                r'Server Software:',
                r'Operating System:',
                r'Python/[\d.]+',
                r'Node\.js/[\d.]+'
            ],
            'database_info': [
                r'mysql\s+version',
                r'postgresql\s+version',
                r'mongodb\s+version',
                r'Database:\s*\w+',
                r'Connection String:',
                r'Database Error:',
                r'SQL Query:'
            ],
            'credentials': [
                r'username\s*[:=]\s*["\']?([^"\'\s]+)',
                r'password\s*[:=]\s*["\']?([^"\'\s]+)',
                r'api_key\s*[:=]\s*["\']?([^"\'\s]+)',
                r'secret\s*[:=]\s*["\']?([^"\'\s]+)',
                r'token\s*[:=]\s*["\']?([^"\'\s]+)'
            ],
            'file_paths': [
                r'/var/www/\w+',
                r'/home/\w+',
                r'C:\\\\[^\\s]+',
                r'/usr/local/\w+',
                r'/opt/\w+'
            ]
        }
    
    def _initialize_debug_endpoints(self) -> Dict[str, List[str]]:
        """Initialize comprehensive debug endpoint patterns"""
        return {
            'debug_interfaces': [
                'debug', 'debug.php', 'debug.jsp', 'debug.aspx',
                'phpinfo.php', 'info.php', 'test.php', 'dev.php',
                'admin/debug', 'admin/phpinfo', 'admin/info',
                '_debug', '__debug__', 'debug-console', 'debug/console',
                'debugger', 'debug-mode', 'development'
            ],
            'admin_panels': [
                'admin', 'admin.php', 'admin/', 'admin/index.php',
                'administrator', 'backend', 'control', 'panel',
                'manage', 'dashboard', 'cpanel', 'wp-admin',
                'admin/login', 'admin/dashboard', 'admin/panel'
            ],
            'development_endpoints': [
                'dev', 'development', 'test', 'testing', 'stage', 'staging',
                'dev.php', 'test.php', 'dev/', 'test/', 'stage/',
                'development/', 'localhost', 'dev-api', 'test-api',
                'api/dev', 'api/test', 'api/debug'
            ],
            'error_pages': [
                'error', 'error.php', 'error/', 'errors/', 'exception',
                'traceback', 'trace', 'debug-trace', 'stack-trace',
                '500.html', '404.html', 'error-handler', 'exception-handler'
            ],
            'configuration_endpoints': [
                'config', 'configuration', 'settings', 'preferences',
                'config.php', 'settings.php', 'config/', 'settings/',
                'env', 'environment', '.env', 'config.json',
                'web.config', 'app.config'
            ],
            'monitoring_endpoints': [
                'status', 'health', 'metrics', 'monitor', 'stats',
                'status.php', 'health.php', 'metrics.php', 'stats.php',
                'server-status', 'server-info', 'system-info',
                'performance', 'profiler', 'benchmark'
            ],
            'api_debug_endpoints': [
                'api/debug', 'api/test', 'api/dev', 'api/status',
                'api/health', 'api/info', 'api/version', 'api/config',
                'rest/debug', 'rest/test', 'graphql/debug',
                'swagger', 'api-docs', 'openapi.json'
            ],
            'framework_specific': [
                # Django
                '__debug__', 'debug-toolbar', 'admin/', 'api-auth/',
                # Flask  
                'debug', 'debugtoolbar', '/profiler',
                # Laravel
                'debugbar', '_debugbar', 'telescope', 'horizon',
                # Spring
                'actuator', 'actuator/health', 'actuator/info', 'actuator/env',
                # Express.js
                'debug', 'dev', 'development',
                # ASP.NET
                'trace.axd', 'elmah.axd', 'glimpse.axd'
            ]
        }
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison"""
        try:
            parsed = urlparse(url)
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
            return normalized.lower()
        except:
            return url.lower().rstrip('/')
    
    def _is_redirect_to_homepage(self, test_url: str, final_url: str, response_content: str) -> bool:
        """Check if redirect goes to homepage (false positive detection)"""
        try:
            final_url_normalized = self._normalize_url(final_url)
            if final_url_normalized == self.base_url_normalized:
                logger.debug(f"False positive detected: {test_url} redirects to homepage")
                return True
            
            final_parsed = urlparse(final_url)
            if final_parsed.path in ['/', '', '/index.html', '/index.php', '/index.htm']:
                logger.debug(f"False positive detected: {test_url} redirects to root")
                return True
            
            return False
        except Exception as e:
            logger.debug(f"Error checking redirect: {e}")
            return False
    
    def scan_debug_endpoints(self) -> List[InfoDisclosureVulnerability]:
        """Comprehensive debug endpoint scanning"""
        logger.info("🔍 Starting comprehensive debug endpoint scan...")
        
        self.vulnerabilities = []
        
        # Scan different debug categories
        self._scan_debug_interfaces()
        self._scan_admin_panels()
        self._scan_development_endpoints()
        self._scan_error_pages()
        self._scan_configuration_endpoints()
        self._scan_monitoring_endpoints()
        self._scan_api_debug_endpoints()
        self._scan_framework_specific()
        self._scan_custom_debug_paths()
        
        logger.info(f"✅ Debug endpoint scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _scan_debug_interfaces(self) -> None:
        """Scan for exposed debug interfaces"""
        logger.info("🐛 Scanning debug interfaces...")
        
        for endpoint in self.debug_endpoints['debug_interfaces']:
            self._test_debug_endpoint(endpoint, InfoDisclosureType.DEBUG_ENDPOINT)
    
    def _scan_admin_panels(self) -> None:
        """Scan for exposed admin panels"""
        logger.info("👤 Scanning admin panels...")
        
        for endpoint in self.debug_endpoints['admin_panels']:
            self._test_debug_endpoint(endpoint, InfoDisclosureType.DEBUG_ENDPOINT)
    
    def _scan_development_endpoints(self) -> None:
        """Scan for development endpoints"""
        logger.info("🔧 Scanning development endpoints...")
        
        for endpoint in self.debug_endpoints['development_endpoints']:
            self._test_debug_endpoint(endpoint, InfoDisclosureType.DEBUG_ENDPOINT)
    
    def _scan_error_pages(self) -> None:
        """Scan for error page information disclosure"""
        logger.info("❌ Scanning error pages...")
        
        for endpoint in self.debug_endpoints['error_pages']:
            self._test_debug_endpoint(endpoint, InfoDisclosureType.ERROR_MESSAGE)
    
    def _scan_configuration_endpoints(self) -> None:
        """Scan for configuration endpoints"""
        logger.info("⚙️ Scanning configuration endpoints...")
        
        for endpoint in self.debug_endpoints['configuration_endpoints']:
            self._test_debug_endpoint(endpoint, InfoDisclosureType.CONFIG_FILE)
    
    def _scan_monitoring_endpoints(self) -> None:
        """Scan for monitoring/status endpoints"""
        logger.info("📊 Scanning monitoring endpoints...")
        
        for endpoint in self.debug_endpoints['monitoring_endpoints']:
            self._test_debug_endpoint(endpoint, InfoDisclosureType.DEBUG_ENDPOINT)
    
    def _scan_api_debug_endpoints(self) -> None:
        """Scan for API debug endpoints"""
        logger.info("🔌 Scanning API debug endpoints...")
        
        for endpoint in self.debug_endpoints['api_debug_endpoints']:
            self._test_debug_endpoint(endpoint, InfoDisclosureType.DEBUG_ENDPOINT)
    
    def _scan_framework_specific(self) -> None:
        """Scan for framework-specific debug endpoints"""
        logger.info("🏗️ Scanning framework-specific endpoints...")
        
        for endpoint in self.debug_endpoints['framework_specific']:
            self._test_debug_endpoint(endpoint, InfoDisclosureType.DEBUG_ENDPOINT)
    
    def _scan_custom_debug_paths(self) -> None:
        """Scan for custom debug paths with parameters"""
        logger.info("🎯 Scanning custom debug paths...")
        
        # Test debug parameters
        debug_params = [
            '?debug=1', '?debug=true', '?test=1', '?dev=1',
            '?trace=1', '?verbose=1', '?log=debug', '?mode=debug',
            '?show_errors=1', '?display_errors=1'
        ]
        
        base_paths = ['', 'index.php', 'index.jsp', 'index.aspx', 'home']
        
        for base_path in base_paths:
            for param in debug_params:
                test_url = urljoin(self.base_url + '/', base_path + param)
                self._test_parameterized_debug(test_url)
    
    def _test_debug_endpoint(self, endpoint: str, vuln_type: InfoDisclosureType) -> None:
        """Test individual debug endpoint"""
        
        test_url = urljoin(self.base_url + '/', endpoint)
        
        try:
            response = self.session.get(
                test_url, 
                timeout=(self.connect_timeout, self.timeout),  # Connection + read timeout
                allow_redirects=True,
                stream=True
            )
            
            # Safe Content Reading: Read only first 10KB
            try:
                content_chunk = next(response.iter_content(10240, decode_unicode=False), b'')
                response.close()
                
                # Decode
                encoding = response.encoding or 'utf-8'
                try:
                    content_preview = content_chunk.decode(encoding, errors='replace')
                except Exception:
                    content_preview = content_chunk.decode('utf-8', errors='replace')

                # Check if redirects to homepage
                if response.url:
                    if self._is_redirect_to_homepage(test_url, response.url, content_preview):
                        return  # Don't mark as vulnerability if redirects to homepage
                
                if self._is_debug_endpoint(response, endpoint, content_preview):
                    vulnerability = self._create_debug_vulnerability(
                        test_url, response, endpoint, vuln_type
                    )
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Debug endpoint exposed: {test_url}")
                        
            except Exception as e:
                logger.debug(f"Error reading content for {test_url}: {e}")
                return

        except requests.RequestException:
            pass
    
    def _test_parameterized_debug(self, test_url: str) -> None:
        """Test parameterized debug endpoints"""
        
        try:
            response = self.session.get(
                test_url, 
                timeout=(self.connect_timeout, self.timeout),  # Connection + read timeout
                stream=True
            )
            
            # Safe Content Reading
            try:
                content_chunk = next(response.iter_content(10240, decode_unicode=False), b'')
                response.close()
                
                encoding = response.encoding or 'utf-8'
                try:
                    content_preview = content_chunk.decode(encoding, errors='replace')
                except Exception:
                    content_preview = content_chunk.decode('utf-8', errors='replace')

                # Check if redirects to homepage
                if response.url:
                    if self._is_redirect_to_homepage(test_url, response.url, content_preview):
                        return  # Don't mark as vulnerability if redirects to homepage
                
                if self._is_debug_response(response, content_preview):
                    vulnerability = self._create_debug_vulnerability(
                        test_url, response, "parameterized_debug", InfoDisclosureType.DEBUG_ENDPOINT
                    )
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"🚨 Debug parameter exposed: {test_url}")

            except Exception as e:
                logger.debug(f"Error reading content for {test_url}: {e}")
                return
                    
        except requests.RequestException:
            pass
    
    def _is_debug_endpoint(self, response: requests.Response, endpoint: str, content_preview: str = None) -> bool:
        """Check if endpoint exposes debug information"""
        
        # Check status code
        if response.status_code not in [200, 401, 403]:
            return False
        
        # Special case for admin panels - 401/403 also indicates existence
        if 'admin' in endpoint and response.status_code in [401, 403]:
            return True
        
        return self._is_debug_response(response, content_preview)
    
    def _is_debug_response(self, response: requests.Response, content_preview: str = None) -> bool:
        """Check if response contains debug information"""
        
        if content_preview is not None:
             content = content_preview.lower()
        else:
             # Fallback if no preview passed (should not happen with new calls)
             content = response.text.lower()
        
        # Check for debug patterns in content
        for category, patterns in self.debug_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        
        # Check response headers for debug info
        debug_headers = [
            'x-debug', 'x-trace', 'x-powered-by', 'server',
            'x-php-version', 'x-aspnet-version'
        ]
        
        for header in debug_headers:
            if header in response.headers:
                return True
        
        # Check for common debug page indicators
        debug_indicators = [
            'phpinfo()', 'debug mode', 'development mode',
            'stack trace', 'error trace', 'exception details',
            'server information', 'system information',
            'configuration details', 'environment variables',
            'database connection', 'session information'
        ]
        
        return any(indicator in content for indicator in debug_indicators)
    
    def _create_debug_vulnerability(
        self,
        url: str,
        response: requests.Response, 
        endpoint: str,
        vuln_type: InfoDisclosureType
    ) -> Optional[InfoDisclosureVulnerability]:
        """Create debug endpoint vulnerability with CVE integration"""
        
        # Analyze content for severity assessment
        content = response.text[:10000]  # First 10KB for analysis
        severity = self._assess_debug_severity(content, endpoint, response)
        
        # Get CVE information
        cve_info = self._get_cve_info(vuln_type, severity)
        
        # Extract sensitive information
        sensitive_info = self._extract_debug_info(content, response)
        
        vulnerability = InfoDisclosureVulnerability(
            id=f"DEBUG-{vuln_type.value}-{hash(url) % 10000}",
            type=vuln_type,
            severity=severity,
            url=url,
            evidence=f"Debug endpoint accessible: {endpoint}",
            sensitive_data=sensitive_info,
            exposure_method="Direct access to debug/development endpoint",
            risk_description=self._get_debug_risk_description(vuln_type, severity),
            business_impact=self._get_debug_business_impact(severity),
            remediation=self._get_debug_remediation(vuln_type),
            cwe_id=self._get_debug_cwe(vuln_type),
            owasp_category="A05:2021 – Security Misconfiguration",
            confidence="HIGH",
            cve_references=cve_info['cve_references'],
            cvss_score=cve_info['cvss_score'],
            cvss_vector=self._build_cvss_vector(cve_info),
            exploit_complexity=cve_info['exploit_complexity'],
            attack_vector=cve_info['attack_vector'],
            privileges_required="NONE",
            user_interaction="NONE",
            timestamp=datetime.now().isoformat()
        )
        
        return vulnerability
    
    def _assess_debug_severity(self, content: str, endpoint: str, response: requests.Response) -> InfoDisclosureSeverity:
        """Assess debug endpoint severity"""
        
        content_lower = content.lower()
        
        # Critical indicators
        critical_indicators = [
            'password', 'secret', 'private_key', 'api_key',
            'database.*password', 'root.*password', 'admin.*password',
            'connection string', 'jwt_secret', 'encryption_key'
        ]
        
        # High severity indicators
        high_indicators = [
            'phpinfo()', 'server information', 'system information',
            'environment variables', 'configuration details',
            'database connection', 'file system', 'stack trace'
        ]
        
        # Check for critical content
        for indicator in critical_indicators:
            if re.search(indicator, content_lower):
                return InfoDisclosureSeverity.CRITICAL
        
        # Check for high severity content
        for indicator in high_indicators:
            if re.search(indicator, content_lower):
                return InfoDisclosureSeverity.HIGH
        
        # Check endpoint type for severity
        if any(keyword in endpoint.lower() for keyword in ['admin', 'phpinfo', 'debug']):
            return InfoDisclosureSeverity.HIGH
        
        # Check response code
        if response.status_code == 200 and len(content) > 1000:
            return InfoDisclosureSeverity.MEDIUM
        
        return InfoDisclosureSeverity.LOW
    
    def _extract_debug_info(self, content: str, response: requests.Response) -> str:
        """Extract debug information from response"""
        
        info_samples = []
        
        # Extract specific debug information
        debug_extracts = {
            'system_info': r'(PHP Version|Apache/|nginx/|Server Software:).*',
            'database_info': r'(mysql|postgresql|mongodb).*version.*',
            'file_paths': r'(/var/www/|/home/|C:\\\\)[^\\s]+',
            'credentials': r'(username|password|api_key|secret)\s*[:=]\s*[^\\s]+'
        }
        
        content_sample = content[:5000]  # First 5KB
        
        for category, pattern in debug_extracts.items():
            matches = re.finditer(pattern, content_sample, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                sample = match.group(0)[:100]  # Limit sample length
                info_samples.append(f"{category}: {sample}")
                if len(info_samples) >= 5:  # Limit samples
                    break
            if len(info_samples) >= 5:
                break
        
        # Add header information
        debug_headers = []
        for header in ['Server', 'X-Powered-By', 'X-Debug']:
            if header in response.headers:
                debug_headers.append(f"{header}: {response.headers[header]}")
        
        if debug_headers:
            info_samples.extend(debug_headers)
        
        return '; '.join(info_samples) if info_samples else "Debug information exposed"
    
    def _get_cve_info(self, vuln_type: InfoDisclosureType, severity: InfoDisclosureSeverity) -> Dict:
        """Get CVE information for vulnerability type and severity"""
        
        cve_category = "DEBUG_ENDPOINT"
        
        if vuln_type == InfoDisclosureType.ERROR_MESSAGE:
            cve_category = "ERROR_MESSAGE"
        elif vuln_type == InfoDisclosureType.CONFIG_FILE:
            cve_category = "BACKUP_FILE"
        
        return CVE_DATABASE.get(cve_category, {}).get(severity.value, {
            "cve_references": [],
            "cvss_score": 5.0,
            "attack_vector": "NETWORK", 
            "exploit_complexity": "MEDIUM"
        })
    
    def _get_debug_risk_description(self, vuln_type: InfoDisclosureType, severity: InfoDisclosureSeverity) -> str:
        """Get risk description for debug vulnerabilities"""
        
        descriptions = {
            InfoDisclosureType.DEBUG_ENDPOINT: {
                InfoDisclosureSeverity.CRITICAL: "Debug endpoint exposes system credentials, configuration secrets, and administrative access",
                InfoDisclosureSeverity.HIGH: "Debug endpoint reveals system information, file paths, and application internals",
                InfoDisclosureSeverity.MEDIUM: "Debug endpoint discloses application configuration and development information",
                InfoDisclosureSeverity.LOW: "Debug endpoint provides minimal system information disclosure"
            },
            InfoDisclosureType.ERROR_MESSAGE: {
                InfoDisclosureSeverity.CRITICAL: "Error messages expose database credentials, file paths, and system secrets",
                InfoDisclosureSeverity.HIGH: "Error messages reveal application structure and sensitive file paths",
                InfoDisclosureSeverity.MEDIUM: "Error messages disclose application internals and stack traces",
                InfoDisclosureSeverity.LOW: "Error messages provide limited application information"
            }
        }
        
        return descriptions.get(vuln_type, {}).get(severity, 
            "Debug endpoint may expose sensitive application information")
    
    def _get_debug_business_impact(self, severity: InfoDisclosureSeverity) -> str:
        """Get business impact for debug vulnerabilities"""
        
        impacts = {
            InfoDisclosureSeverity.CRITICAL: "Complete application compromise, credential theft, administrative access",
            InfoDisclosureSeverity.HIGH: "Significant information disclosure, potential system access, data exposure",
            InfoDisclosureSeverity.MEDIUM: "Application reconnaissance, development information disclosure",
            InfoDisclosureSeverity.LOW: "Limited information disclosure for reconnaissance purposes"
        }
        
        return impacts.get(severity, "Debug information disclosure with potential security impact")
    
    def _get_debug_remediation(self, vuln_type: InfoDisclosureType) -> str:
        """Get remediation advice for debug vulnerabilities"""
        
        remediations = {
            InfoDisclosureType.DEBUG_ENDPOINT: "Disable debug endpoints in production, implement access controls, remove development interfaces",
            InfoDisclosureType.ERROR_MESSAGE: "Implement custom error pages, disable detailed error messages, log errors securely",
            InfoDisclosureType.CONFIG_FILE: "Remove configuration endpoints, implement secure configuration management"
        }
        
        return remediations.get(vuln_type, "Remove debug endpoints and implement secure error handling")
    
    def _get_debug_cwe(self, vuln_type: InfoDisclosureType) -> str:
        """Get appropriate CWE for debug vulnerability type"""
        
        cwe_mapping = {
            InfoDisclosureType.DEBUG_ENDPOINT: "CWE-489",  # Active Debug Code
            InfoDisclosureType.ERROR_MESSAGE: "CWE-209",   # Information Exposure Through Error Messages
            InfoDisclosureType.CONFIG_FILE: "CWE-200"      # Information Exposure
        }
        
        return cwe_mapping.get(vuln_type, "CWE-200")
    
    def _build_cvss_vector(self, cve_info: Dict) -> str:
        """Build CVSS vector string"""
        
        return f"CVSS:3.1/AV:{cve_info['attack_vector'][0]}/AC:{cve_info['exploit_complexity'][0]}/PR:N/UI:N/S:U/C:H/I:N/A:N"