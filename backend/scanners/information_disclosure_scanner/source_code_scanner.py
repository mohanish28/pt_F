"""
Professional Source Code Scanner
Detects exposed source code, comments, version control files
"""

import requests
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Optional, Dict, Set
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .vulnerability_models import (
    InfoDisclosureVulnerability,
    InfoDisclosureSeverity,
    InfoDisclosureType,
    CVE_DATABASE
)

logger = logging.getLogger(__name__)

class SourceCodeScanner:
    """Professional scanner for source code exposure detection"""
    
    def __init__(self, base_url: str, timeout: int = None):
        """Initialize source code scanner"""
        self.base_url = base_url.rstrip('/')
        self.base_url_normalized = self._normalize_url(self.base_url)
        # Reduce timeout from 3s to 1.5s for faster failures
        self.timeout = timeout if timeout is not None else 1.5
        # Connection timeout (separate from read timeout)
        self.connect_timeout = 1.0
        # Use connection pooling for better performance
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        self.session = requests.Session()
        # Configure connection pooling - DISABLE RETRIES for faster failure
        adapter = HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=Retry(total=0)  # NO RETRIES - fail fast
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities: List[InfoDisclosureVulnerability] = []
        
        # Source code patterns
        self.source_patterns = self._initialize_source_patterns()
        
        # Sensitive comment patterns
        self.comment_patterns = {
            'credentials': [
                r'(?i)password\s*[:=]\s*["\']([^"\']+)["\']',
                r'(?i)api[_-]?key\s*[:=]\s*["\']([^"\']+)["\']',
                r'(?i)secret\s*[:=]\s*["\']([^"\']+)["\']',
                r'(?i)token\s*[:=]\s*["\']([^"\']+)["\']',
                r'(?i)private[_-]?key\s*[:=]\s*["\']([^"\']+)["\']'
            ],
            'todo_comments': [
                r'(?i)todo.*(?:fix|hack|bug|remove|delete).*',
                r'(?i)fixme.*',
                r'(?i)hack.*',
                r'(?i)temporary.*(?:fix|solution).*',
                r'(?i)remove.*(?:before|production).*'
            ],
            'debug_comments': [
                r'(?i)debug.*(?:only|mode|info).*',
                r'(?i)test.*(?:only|mode|data).*',
                r'(?i)development.*(?:only|mode).*',
                r'(?i)remove.*(?:debug|test).*'
            ],
            'security_comments': [
                r'(?i)security.*(?:issue|problem|vulnerability).*',
                r'(?i)vulnerable.*',
                r'(?i)insecure.*',
                r'(?i)unsafe.*',
                r'(?i)bypass.*(?:security|auth).*'
            ]
        }
    
    def _initialize_source_patterns(self) -> Dict[str, List[str]]:
        """Initialize source code file patterns"""
        return {
            'source_files': [
                # Web languages
                'index.php.bak', 'config.php.bak', 'functions.php.bak',
                'index.jsp.bak', 'web.xml.bak', 'struts.xml.bak',
                'index.aspx.bak', 'web.config.bak', 'global.asax.bak',
                'app.js.bak', 'server.js.bak', 'package.json.bak',
                'main.py.bak', 'settings.py.bak', 'urls.py.bak',
                
                # Source extensions
                '.php~', '.jsp~', '.aspx~', '.js~', '.py~',
                '.php.orig', '.jsp.orig', '.aspx.orig', '.js.orig',
                '.php.old', '.jsp.old', '.aspx.old', '.js.old',
                '.php.backup', '.jsp.backup', '.aspx.backup'
            ],
            'config_files': [
                'web.config', 'app.config', 'database.yml', 'config.yml',
                '.env', 'environment.js', 'config.json', 'settings.json',
                'composer.json', 'package.json', 'requirements.txt',
                'Gemfile', 'pom.xml', 'build.gradle', 'webpack.config.js'
            ],
            'version_control': [
                '.git/', '.git/config', '.git/HEAD', '.git/index',
                '.git/logs/HEAD', '.git/refs/heads/master',
                '.svn/', '.svn/entries', '.svn/wc.db',
                '.hg/', '.hg/store/00manifest.i',
                '.bzr/', '.bzr/branch/branch.conf',
                'CVS/', 'CVS/Entries', 'CVS/Root'
            ],
            'editor_files': [
                '.vscode/', '.idea/', '.eclipse/', '.netbeans/',
                'Thumbs.db', '.DS_Store', 'desktop.ini',
                '*.swp', '*.swo', '*~', '#*#', '.#*'
            ],
            'documentation': [
                'README.md', 'INSTALL.md', 'TODO.txt', 'CHANGELOG.md',
                'docs/', 'documentation/', 'manual/', 'guide/',
                'API.md', 'SECURITY.md', 'CONTRIBUTING.md'
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
            # Method 1: Check if final URL is the base URL
            final_url_normalized = self._normalize_url(final_url)
            if final_url_normalized == self.base_url_normalized:
                logger.debug(f"False positive detected: {test_url} redirects to homepage")
                return True
            
            # Method 2: Check if final URL path is root or empty
            final_parsed = urlparse(final_url)
            if final_parsed.path in ['/', '', '/index.html', '/index.php', '/index.htm']:
                logger.debug(f"False positive detected: {test_url} redirects to root")
                return True
            
            # Method 3: Check if content matches homepage content (simple check)
            if len(response_content) > 100:
                # If content is HTML and looks like homepage
                if '<html' in response_content.lower() and '<body' in response_content.lower():
                    # Check if it's likely the homepage by checking for common homepage elements
                    homepage_indicators = ['<title>', 'home', 'welcome', 'index']
                    if any(indicator in response_content.lower()[:500] for indicator in homepage_indicators):
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"Error checking redirect: {e}")
            return False
    
    def scan_source_code(self) -> List[InfoDisclosureVulnerability]:
        """Comprehensive source code exposure scanning"""
        logger.info("🔍 Starting comprehensive source code exposure scan...")
        
        self.vulnerabilities = []
        
        # Scan different source categories
        self._scan_source_files()
        self._scan_config_files()
        self._scan_version_control()
        self._scan_editor_files()
        self._scan_documentation()
        self._scan_common_paths()
        self._scan_comment_disclosure()
        
        logger.info(f"✅ Source code scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _scan_source_files(self) -> None:
        """Scan for exposed source code files"""
        logger.info("📝 Scanning source code files...")
        
        for pattern in self.source_patterns['source_files']:
            self._test_source_file(pattern, InfoDisclosureType.SOURCE_CODE)
            # Early exit if vulnerabilities found
            if self.vulnerabilities:
                return
    
    def _scan_config_files(self) -> None:
        """Scan for exposed configuration files"""
        logger.info("⚙️ Scanning configuration files...")
        
        for pattern in self.source_patterns['config_files']:
            self._test_source_file(pattern, InfoDisclosureType.CONFIG_FILE)
            # Early exit if vulnerabilities found
            if self.vulnerabilities:
                return
    
    def _scan_version_control(self) -> None:
        """Scan for exposed version control files"""
        logger.info("🔧 Scanning version control files...")
        
        for pattern in self.source_patterns['version_control']:
            self._test_source_file(pattern, InfoDisclosureType.SOURCE_CODE)
            # Early exit if vulnerabilities found
            if self.vulnerabilities:
                return
    
    def _scan_editor_files(self) -> None:
        """Scan for exposed editor temporary files"""
        logger.info("✏️ Scanning editor temporary files...")
        
        for pattern in self.source_patterns['editor_files']:
            if not pattern.startswith('.'):  # Skip directory patterns
                self._test_source_file(pattern, InfoDisclosureType.SOURCE_CODE)
                # Early exit if vulnerabilities found
                if self.vulnerabilities:
                    return
    
    def _scan_documentation(self) -> None:
        """Scan for exposed documentation"""
        logger.info("📚 Scanning documentation files...")
        
        for pattern in self.source_patterns['documentation']:
            if not pattern.endswith('/'):  # Skip directory patterns
                self._test_source_file(pattern, InfoDisclosureType.SOURCE_CODE)
                # Early exit if vulnerabilities found
                if self.vulnerabilities:
                    return
    
    def _scan_common_paths(self) -> None:
        """Scan common source code paths"""
        logger.info("📁 Scanning common source paths...")
        
        common_paths = [
            'src/', 'source/', 'app/', 'application/', 'lib/', 'libs/',
            'includes/', 'inc/', 'classes/', 'models/', 'controllers/',
            'views/', 'templates/', 'assets/', 'resources/', 'public/',
            'private/', 'protected/', 'secure/', 'admin/', 'api/'
        ]
        
        # Test for directory listings
        for path in common_paths:
            self._test_directory_access(path)
            # Early exit if vulnerabilities found
            if self.vulnerabilities:
                return
    
    def _scan_comment_disclosure(self) -> None:
        """Scan for sensitive information in comments"""
        logger.info("💬 Scanning for sensitive comments...")
        
        # Test main pages for comment disclosure
        main_pages = ['', 'index.html', 'index.php', 'index.jsp', 'home.html']
        
        for page in main_pages:
            self._test_comment_disclosure(page)
    
    def _test_source_file(self, file_pattern: str, vuln_type: InfoDisclosureType) -> None:
        """Test individual source file for exposure"""
        
        # REDUCED: Only test 2 paths instead of 6 (root + one backup path)
        test_paths = [
            '',  # Root
            'backup/'  # One backup path
        ]
        
        # PARALLELIZE: Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for path in test_paths:
                test_url = urljoin(self.base_url + '/', path + file_pattern)
                future = executor.submit(self._test_single_url, test_url, file_pattern, vuln_type)
                futures.append(future)
            
            # Process results as they complete
            for future in as_completed(futures):
                try:
                    vulnerability = future.result(timeout=self.timeout + 1)
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"🚨 Source file exposed: {vulnerability.url}")
                        # Cancel remaining tasks if vulnerability found
                        for remaining_future in futures:
                            if not remaining_future.done():
                                remaining_future.cancel()
                        return
                except Exception as e:
                    logger.debug(f"Error testing URL: {e}")
                    continue
    
    def _test_single_url(self, test_url: str, file_pattern: str, vuln_type: InfoDisclosureType) -> Optional[InfoDisclosureVulnerability]:
        """Test a single URL for source file exposure"""
        try:
            # First, check without following redirects
            response_no_redirect = self.session.get(
                test_url, 
                timeout=(self.connect_timeout, self.timeout),  # Connection + read timeout
                allow_redirects=False,
                stream=True
            )
            
            # If redirect (3xx), follow it and verify
            if response_no_redirect.status_code in [301, 302, 303, 307, 308]:
                redirect_url = response_no_redirect.headers.get('Location', '')
                # Close original response if redirecting
                response_no_redirect.close()
                
                if redirect_url:
                    if not redirect_url.startswith('http'):
                        redirect_url = urljoin(test_url, redirect_url)
                    
                    try:
                        response = self.session.get(
                            redirect_url,
                            timeout=(self.connect_timeout, self.timeout),
                            allow_redirects=False,
                            stream=True
                        )
                        final_url = redirect_url
                    except Exception:
                        # Failed to follow, use original (re-requesting to be safe or just return)
                        # For simplicity, if redirect follow fails, we abort
                        return None
                else:
                    response = response_no_redirect
                    final_url = test_url
            else:
                response = response_no_redirect
                final_url = test_url
            
            # CRITICAL: Verify it's not a redirect to homepage
            if response.status_code == 200:
                # Safe Content Reading
                try:
                    content_chunk = next(response.iter_content(10240, decode_unicode=False), b'')
                    response.close()
                    
                    encoding = response.encoding or 'utf-8'
                    try:
                        content_preview = content_chunk.decode(encoding, errors='replace')
                    except Exception:
                        content_preview = content_chunk.decode('utf-8', errors='replace')

                    if self._is_redirect_to_homepage(test_url, final_url, content_preview):
                        # False positive - redirects to homepage
                        return None
                    
                    if self._is_source_accessible(response, content_preview, file_pattern):
                        vulnerability = self._create_source_vulnerability(
                            test_url, response, file_pattern, vuln_type
                        )
                        return vulnerability
                        
                except Exception as e:
                    logger.debug(f"Error reading content for {test_url}: {e}")
                    return None
                        
        except requests.RequestException:
            pass
        
        return None
    
    def _test_directory_access(self, directory: str) -> None:
        """Test directory access for source code exposure"""
        
        test_url = urljoin(self.base_url + '/', directory)
        
        try:
            response = self.session.get(
                test_url, 
                timeout=(self.connect_timeout, self.timeout),  # Connection + read timeout
                allow_redirects=True,
                stream=True
            )
            
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
                
                if self._is_directory_listing(response, content_preview):
                    vulnerability = self._create_directory_vulnerability(test_url, response, content_preview)
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Source directory exposed: {test_url}")
            
            except Exception as e:
                logger.debug(f"Error reading content for {test_url}: {e}")
                
        except requests.RequestException:
            pass
    
    def _test_comment_disclosure(self, page: str) -> None:
        """Test page for sensitive comment disclosure"""
        
        test_url = urljoin(self.base_url + '/', page)
        
        try:
            response = self.session.get(
                test_url, 
                timeout=(self.connect_timeout, self.timeout),  # Connection + read timeout
                allow_redirects=True,
                stream=True
            )
            
            try:
                content_chunk = next(response.iter_content(10240, decode_unicode=False), b'')
                response.close()
                
                encoding = response.encoding or 'utf-8'
                try:
                    content_preview = content_chunk.decode(encoding, errors='replace')
                except Exception:
                    content_preview = content_chunk.decode('utf-8', errors='replace')

                # Check if redirects to homepage
                if response.url and response.url != test_url:
                    if self._is_redirect_to_homepage(test_url, response.url, content_preview):
                        return  # Don't mark as vulnerability if redirects to homepage
                
                if response.status_code == 200:
                    comments = self._extract_html_comments(content_preview)
                    sensitive_comments = self._analyze_comments(comments)
                    
                    if sensitive_comments:
                        vulnerability = self._create_comment_vulnerability(
                            test_url, response, sensitive_comments
                        )
                        if vulnerability:
                            self.vulnerabilities.append(vulnerability)
                            logger.warning(f"Sensitive comments found: {test_url}")
                            
            except Exception as e:
                logger.debug(f"Error reading content for {test_url}: {e}")
        
        except requests.RequestException:
            pass
                        
        except requests.RequestException:
            pass
    
    def _is_source_accessible(self, response: requests.Response, content_preview: str, file_pattern: str) -> bool:
        """Check if source file is accessible and contains source code"""
        
        if response.status_code != 200:
            return False
        
        content = content_preview
        
        # Check content length (source files are usually substantial)
        if len(content) < 50:
            return False
        
        # Check for source code indicators
        source_indicators = [
            '<?php', '<%', '<script>', '<html>', 'function',
            'class ', 'import ', 'require', 'include',
            'def ', 'public class', 'private ', 'protected ',
            'var ', 'const ', 'let ', '$_', 'session',
            'password', 'database', 'connection'
        ]
        
        content_lower = content.lower()
        
        # Check for source code patterns
        has_source = any(indicator.lower() in content_lower for indicator in source_indicators)
        
        # Check file extension for source files
        source_extensions = ['.php', '.jsp', '.aspx', '.js', '.py', '.rb', '.java']
        has_source_ext = any(ext in file_pattern.lower() for ext in source_extensions)
        
        return has_source or has_source_ext
    
    def _is_directory_listing(self, response: requests.Response, content_preview: str = None) -> bool:
        """Check if response shows directory listing with source files"""
        
        if response.status_code != 200:
            return False
        
        if content_preview is not None:
             content = content_preview.lower()
        else:
             content = response.text.lower()
        
        # Directory listing indicators
        listing_indicators = [
            'index of /', 'directory listing', 'parent directory',
            '<title>index of', '[dir]', '[file]'
        ]
        
        has_listing = any(indicator in content for indicator in listing_indicators)
        
        # Check for source file links
        source_pattern = r'href="[^"]*\.(php|jsp|aspx|js|py|rb|java|config|yml|xml)"'
        has_source_files = bool(re.search(source_pattern, content, re.IGNORECASE))
        
        return has_listing and has_source_files
    
    def _extract_html_comments(self, content: str) -> List[str]:
        """Extract HTML comments from content"""
        
        # Match HTML comments
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, content, re.DOTALL | re.IGNORECASE)
        
        # Match JavaScript comments
        js_comment_pattern = r'//\s*(.+?)(?:\n|$)'
        js_comments = re.findall(js_comment_pattern, content, re.MULTILINE)
        
        # Match CSS comments
        css_comment_pattern = r'/\*(.*?)\*/'
        css_comments = re.findall(css_comment_pattern, content, re.DOTALL)
        
        all_comments = comments + js_comments + css_comments
        
        # Filter out empty and very short comments
        return [comment.strip() for comment in all_comments if len(comment.strip()) > 10]
    
    def _analyze_comments(self, comments: List[str]) -> Dict[str, List[str]]:
        """Analyze comments for sensitive information"""
        
        sensitive_comments = {
            'credentials': [],
            'todo_comments': [],
            'debug_comments': [],
            'security_comments': []
        }
        
        for comment in comments:
            for category, patterns in self.comment_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, comment, re.IGNORECASE):
                        sensitive_comments[category].append(comment)
                        break
        
        # Return only categories with findings
        return {k: v for k, v in sensitive_comments.items() if v}
    
    def _create_source_vulnerability(
        self,
        url: str,
        response: requests.Response,
        file_pattern: str,
        vuln_type: InfoDisclosureType
    ) -> Optional[InfoDisclosureVulnerability]:
        """Create source code vulnerability with CVE integration"""
        
        content = response.text[:10000]  # First 10KB for analysis
        severity = self._assess_source_severity(content, file_pattern)
        
        # Get CVE information
        cve_info = self._get_cve_info(vuln_type, severity)
        
        # Extract sensitive information
        sensitive_info = self._extract_source_info(content)
        
        vulnerability = InfoDisclosureVulnerability(
            id=f"SOURCE-{vuln_type.value}-{hash(url) % 10000}",
            type=vuln_type,
            severity=severity,
            url=url,
            evidence=f"Source file accessible: {file_pattern}",
            sensitive_data=sensitive_info,
            exposure_method="Direct access to source code file",
            risk_description=self._get_source_risk_description(vuln_type, severity),
            business_impact=self._get_source_business_impact(severity),
            remediation=self._get_source_remediation(vuln_type),
            cwe_id="CWE-540",  # Inclusion of Sensitive Information in Source Code
            owasp_category="A01:2021 – Broken Access Control",
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
    
    def _create_directory_vulnerability(
        self, 
        url: str, 
        response: requests.Response,
        content_preview: str = None # Added param
    ) -> Optional[InfoDisclosureVulnerability]:
        """Create directory listing vulnerability"""
        
        severity = InfoDisclosureSeverity.MEDIUM
        cve_info = self._get_cve_info(InfoDisclosureType.DIRECTORY_LISTING, severity)
        
        # Extract source files from listing
        text_to_search = content_preview if content_preview else response.text
        source_pattern = r'href="([^"]*\.(php|jsp|aspx|js|py|rb|java|config|yml|xml))"'
        source_files = re.findall(source_pattern, text_to_search, re.IGNORECASE)
        exposed_files = [match[0] for match in source_files[:10]]  # Limit to 10 files
        
        vulnerability = InfoDisclosureVulnerability(
            id=f"DIR-SOURCE-{hash(url) % 10000}",
            type=InfoDisclosureType.DIRECTORY_LISTING,
            severity=severity,
            url=url,
            evidence=f"Directory listing exposes {len(exposed_files)} source files",
            sensitive_data=f"Exposed source files: {', '.join(exposed_files)}",
            exposure_method="Web server directory listing enabled",
            risk_description="Directory listing reveals source code and configuration files",
            business_impact="Attackers can download source code and discover vulnerabilities",
            remediation="Disable directory listing and secure source code files",
            cwe_id="CWE-548",
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
    
    def _create_comment_vulnerability(
        self,
        url: str,
        response: requests.Response,
        sensitive_comments: Dict[str, List[str]]
    ) -> Optional[InfoDisclosureVulnerability]:
        """Create comment disclosure vulnerability"""
        
        # Assess severity based on comment types
        severity = InfoDisclosureSeverity.LOW
        if 'credentials' in sensitive_comments:
            severity = InfoDisclosureSeverity.HIGH
        elif 'security_comments' in sensitive_comments:
            severity = InfoDisclosureSeverity.MEDIUM
        
        cve_info = self._get_cve_info(InfoDisclosureType.SOURCE_CODE, severity)
        
        # Format comment evidence
        comment_evidence = []
        for category, comments in sensitive_comments.items():
            for comment in comments[:2]:  # Limit to 2 per category
                comment_evidence.append(f"{category}: {comment[:100]}")
        
        vulnerability = InfoDisclosureVulnerability(
            id=f"COMMENT-{hash(url) % 10000}",
            type=InfoDisclosureType.SOURCE_CODE,
            severity=severity,
            url=url,
            evidence="Sensitive information in HTML/JavaScript comments",
            sensitive_data='; '.join(comment_evidence),
            exposure_method="HTML/JavaScript comments in page source",
            risk_description="Comments contain sensitive development information",
            business_impact="Information disclosure aids reconnaissance and attack planning",
            remediation="Remove sensitive comments from production code",
            cwe_id="CWE-615",  # Inclusion of Sensitive Information in Source Code Comments
            owasp_category="A01:2021 – Broken Access Control",
            confidence="MEDIUM",
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
    
    def _assess_source_severity(self, content: str, file_pattern: str) -> InfoDisclosureSeverity:
        """Assess source code severity"""
        
        content_lower = content.lower()
        
        # Critical indicators
        critical_patterns = [
            'password', 'secret', 'private_key', 'api_key',
            'database.*password', 'connection.*string'
        ]
        
        # High severity indicators
        high_patterns = [
            'mysql_connect', 'pg_connect', 'mongodb://',
            'smtp.*password', 'ftp.*password', 'session'
        ]
        
        # Check for critical content
        for pattern in critical_patterns:
            if re.search(pattern, content_lower):
                return InfoDisclosureSeverity.CRITICAL
        
        # Check for high severity content
        for pattern in high_patterns:
            if re.search(pattern, content_lower):
                return InfoDisclosureSeverity.HIGH
        
        # Check file type
        critical_files = ['config', 'database', 'password', 'secret']
        if any(keyword in file_pattern.lower() for keyword in critical_files):
            return InfoDisclosureSeverity.HIGH
        
        return InfoDisclosureSeverity.MEDIUM
    
    def _extract_source_info(self, content: str) -> str:
        """Extract sensitive information from source code"""
        
        samples = []
        
        # Extract credential patterns
        credential_patterns = [
            r'password\s*[:=]\s*["\']([^"\']+)["\']',
            r'api_key\s*[:=]\s*["\']([^"\']+)["\']',
            r'secret\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        content_sample = content[:5000]  # First 5KB
        
        for pattern in credential_patterns:
            matches = re.finditer(pattern, content_sample, re.IGNORECASE)
            for match in matches:
                samples.append(f"Credential: {match.group(0)[:50]}")
                if len(samples) >= 3:
                    break
            if len(samples) >= 3:
                break
        
        return '; '.join(samples) if samples else "Source code contains sensitive information"
    
    def _get_cve_info(self, vuln_type: InfoDisclosureType, severity: InfoDisclosureSeverity) -> Dict:
        """Get CVE information for vulnerability type and severity"""
        
        return CVE_DATABASE.get("BACKUP_FILE", {}).get(severity.value, {
            "cve_references": [],
            "cvss_score": 5.0,
            "attack_vector": "NETWORK",
            "exploit_complexity": "MEDIUM"
        })
    
    def _get_source_risk_description(self, vuln_type: InfoDisclosureType, severity: InfoDisclosureSeverity) -> str:
        """Get risk description for source code vulnerabilities"""
        
        descriptions = {
            InfoDisclosureSeverity.CRITICAL: "Source code exposure reveals credentials, secrets, and critical system information",
            InfoDisclosureSeverity.HIGH: "Source code exposure reveals application logic, configuration, and database connections",
            InfoDisclosureSeverity.MEDIUM: "Source code exposure reveals application structure and development information",
            InfoDisclosureSeverity.LOW: "Source code exposure provides reconnaissance information for attackers"
        }
        
        return descriptions.get(severity, "Source code exposure may reveal sensitive application information")
    
    def _get_source_business_impact(self, severity: InfoDisclosureSeverity) -> str:
        """Get business impact for source code vulnerabilities"""
        
        impacts = {
            InfoDisclosureSeverity.CRITICAL: "Complete application compromise through credential theft and system access",
            InfoDisclosureSeverity.HIGH: "Significant security exposure through application logic and configuration disclosure",
            InfoDisclosureSeverity.MEDIUM: "Information disclosure enabling targeted attacks and reconnaissance",
            InfoDisclosureSeverity.LOW: "Limited information disclosure for attack planning purposes"
        }
        
        return impacts.get(severity, "Source code disclosure with potential security implications")
    
    def _get_source_remediation(self, vuln_type: InfoDisclosureType) -> str:
        """Get remediation advice for source code vulnerabilities"""
        
        return "Remove source code files from web-accessible directories, implement secure deployment processes, disable directory listing"
    
    def _build_cvss_vector(self, cve_info: Dict) -> str:
        """Build CVSS vector string"""
        
        return f"CVSS:3.1/AV:{cve_info['attack_vector'][0]}/AC:{cve_info['exploit_complexity'][0]}/PR:N/UI:N/S:U/C:H/I:N/A:N"