"""
Enhanced Backup File Scanner with Redirect Verification and Performance Optimizations
Detects exposed backup files, database dumps, configuration backups
"""

import requests
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Optional, Dict, Set
import re
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from .vulnerability_models import (
    InfoDisclosureVulnerability, 
    InfoDisclosureSeverity,
    InfoDisclosureType,
    CVE_DATABASE
)

logger = logging.getLogger(__name__)

class BackupFileScanner:
    """Enhanced scanner for backup file exposure detection with redirect verification"""
    
    def __init__(self, base_url: str, timeout: int = None, max_workers: int = 10):
        """Initialize backup file scanner"""
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout or 5  # Default 5 seconds to prevent hanging
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities: List[InfoDisclosureVulnerability] = []
        
        # Store homepage content hash for redirect verification
        self.homepage_hash = self._get_homepage_hash()
        
        # Normalize base URL for comparison
        self.base_url_normalized = self._normalize_url(self.base_url)
        
        # Comprehensive backup file patterns
        self.backup_patterns = self._initialize_backup_patterns()
        
        # Sensitive content patterns
        self.sensitive_patterns = {
            'database': [
                r'CREATE TABLE',
                r'INSERT INTO', 
                r'mysql_connect',
                r'pg_connect',
                r'mongodb://',
                r'DATABASE_URL'
            ],
            'credentials': [
                r'password\s*[:=]\s*["\']?([^"\'\s]+)',
                r'api_key\s*[:=]\s*["\']?([^"\'\s]+)',
                r'secret\s*[:=]\s*["\']?([^"\'\s]+)',
                r'token\s*[:=]\s*["\']?([^"\'\s]+)',
                r'private_key',
                r'-----BEGIN.*KEY-----'
            ],
            'configuration': [
                r'smtp_password',
                r'aws_secret_key',
                r'google_api_key',
                r'stripe_secret_key',
                r'paypal_secret',
                r'github_token'
            ],
            'personal_data': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Credit card pattern
                r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'  # Phone
            ]
        }
    
    def _initialize_backup_patterns(self) -> Dict[str, List[str]]:
        """Initialize comprehensive backup file patterns"""
        return {
            'database_backups': [
                'backup.sql', 'database.sql', 'dump.sql', 'db.sql',
                'mysql.sql', 'postgres.sql', 'mongodb.json', 'data.sql',
                'backup.db', 'database.db', 'sqlite.db', 'app.db',
                '{domain}.sql', 'users.sql', 'accounts.sql', 'admin.sql',
                'backup_{date}.sql', 'db_backup.sql', 'full_backup.sql'
            ],
            'config_backups': [
                'config.php.bak', 'wp-config.php.bak', 'settings.py.bak',
                '.env.backup', '.env.old', '.env.bak', 'environment.backup',
                'config.json.bak', 'settings.json.backup', 'app.config.bak',
                'web.config.bak', 'nginx.conf.bak', 'apache.conf.backup',
                'database.yml.backup', 'secrets.yml.bak'
            ],
            'application_backups': [
                'backup.zip', 'backup.tar.gz', 'backup.rar', 'site.zip',
                'www.zip', 'public_html.zip', 'htdocs.zip', 'webroot.zip',
                'application.zip', 'source.zip', 'code.zip', 'project.zip',
                '{domain}.zip', '{domain}.tar.gz', 'website_backup.zip'
            ],
            'log_backups': [
                'access.log.backup', 'error.log.bak', 'application.log.old',
                'debug.log.backup', 'auth.log.bak', 'security.log.old',
                'system.log.backup', 'audit.log.bak', 'transaction.log.old'
            ],
            'version_control': [
                '.git/config', '.git/HEAD', '.git/index', '.git/logs/HEAD',
                '.svn/entries', '.svn/wc.db', '.hg/store/00manifest.i',
                '.bzr/branch/branch.conf', 'CVS/Entries', 'CVS/Root'
            ],
            'temporary_files': [
                'temp.sql', 'tmp.db', 'cache.backup', 'session.backup',
                'upload.tmp', 'import.tmp', 'export.tmp', 'migration.tmp',
                '~temp.sql', '#backup#', '.backup~', 'backup.tmp'
            ]
        }
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison (remove trailing slashes, lowercase)"""
        try:
            parsed = urlparse(url)
            normalized = f"{parsed.scheme}://{parsed.netloc.lower()}"
            path = parsed.path.rstrip('/').lower()
            if path:
                normalized += path
            return normalized
        except Exception:
            return url.lower().rstrip('/')
    
    def _get_homepage_hash(self) -> Optional[str]:
        """Get content hash of homepage for redirect verification"""
        try:
            response = self.session.get(
                self.base_url, 
                timeout=self.timeout,
                allow_redirects=True
            )
            if response.status_code == 200:
                # Hash first 1KB of content for quick comparison
                content_sample = response.text[:1024]
                return hashlib.md5(content_sample.encode()).hexdigest()
        except Exception as e:
            logger.debug(f"Failed to get homepage hash: {e}")
        return None
    
    def _is_redirect_to_homepage(self, test_url: str, final_url: str, response_content: str) -> bool:
        """
        CRITICAL: Verify if redirect goes to homepage (false positive detection)
        
        Returns True if the response is actually the homepage, False if it's a real backup file
        """
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
            
            # Method 3: Content hash comparison (most reliable)
            if self.homepage_hash and response_content:
                content_sample = response_content[:1024]
                content_hash = hashlib.md5(content_sample.encode()).hexdigest()
                if content_hash == self.homepage_hash:
                    logger.debug(f"False positive detected: {test_url} content matches homepage")
                    return True
            
            # Method 4: Check if response contains homepage indicators but no backup content
            homepage_indicators = [
                '<html', '<body', '<head', '<title',
                'DOCTYPE html', 'html lang', 'meta charset'
            ]
            content_lower = response_content[:500].lower() if response_content else ''
            has_html_structure = any(indicator in content_lower for indicator in homepage_indicators)
            
            # If it has HTML structure but no backup content, likely homepage
            if has_html_structure and not self._contains_backup_content(response_content[:2000] if response_content else ''):
                # Check if URL in response matches base URL
                if self.base_url.lower() in (response_content[:500].lower() if response_content else ''):
                    logger.debug(f"False positive detected: {test_url} appears to be homepage HTML")
                    return True
        except Exception as e:
            logger.debug(f"Error in redirect verification: {e}")
        
        return False
    
    def scan_backup_files(self) -> List[InfoDisclosureVulnerability]:
        """Comprehensive backup file scanning with performance optimizations"""
        logger.info("🔍 Starting comprehensive backup file scan...")
        start_time = time.time()
        
        self.vulnerabilities = []
        
        # Scan different backup categories with rate limiting
        categories = [
            (self._scan_database_backups, "database backups"),
            (self._scan_config_backups, "config backups"),
            (self._scan_application_backups, "application backups"),
            (self._scan_log_backups, "log backups"),
            (self._scan_version_control, "version control"),
            (self._scan_temporary_files, "temporary files"),
            (self._scan_common_directories, "directories"),
            (self._scan_parameterized_backups, "parameterized backups")
        ]
        
        for scan_func, category_name in categories:
            try:
                logger.debug(f"Scanning {category_name}...")
                scan_func()
                # Small delay between categories to avoid overwhelming server
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error scanning {category_name}: {e}")
                continue
        
        elapsed = time.time() - start_time
        logger.info(f"✅ Backup scan completed in {elapsed:.2f}s. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _scan_database_backups(self) -> None:
        """Scan for exposed database backup files"""
        logger.info("🗄️ Scanning database backup files...")
        
        for pattern in self.backup_patterns['database_backups']:
            self._test_backup_file(pattern, InfoDisclosureType.DATABASE_DUMP)
    
    def _scan_config_backups(self) -> None:
        """Scan for exposed configuration backup files"""
        logger.info("⚙️ Scanning configuration backup files...")
        
        for pattern in self.backup_patterns['config_backups']:
            self._test_backup_file(pattern, InfoDisclosureType.CONFIG_FILE)
    
    def _scan_application_backups(self) -> None:
        """Scan for exposed application backup files"""
        logger.info("📦 Scanning application backup files...")
        
        for pattern in self.backup_patterns['application_backups']:
            self._test_backup_file(pattern, InfoDisclosureType.BACKUP_FILE)
    
    def _scan_log_backups(self) -> None:
        """Scan for exposed log backup files"""
        logger.info("📋 Scanning log backup files...")
        
        for pattern in self.backup_patterns['log_backups']:
            self._test_backup_file(pattern, InfoDisclosureType.LOG_EXPOSURE)
    
    def _scan_version_control(self) -> None:
        """Scan for exposed version control files"""
        logger.info("🔧 Scanning version control files...")
        
        for pattern in self.backup_patterns['version_control']:
            self._test_backup_file(pattern, InfoDisclosureType.SOURCE_CODE)
    
    def _scan_temporary_files(self) -> None:
        """Scan for exposed temporary files"""
        logger.info("🗂️ Scanning temporary backup files...")
        
        for pattern in self.backup_patterns['temporary_files']:
            self._test_backup_file(pattern, InfoDisclosureType.BACKUP_FILE)
    
    def _scan_common_directories(self) -> None:
        """Scan common backup directories"""
        logger.info("📁 Scanning backup directories...")
        
        backup_dirs = [
            'backup/', 'backups/', 'bak/', 'old/', 'tmp/', 'temp/',
            'archive/', 'archives/', 'dump/', 'dumps/', 'export/',
            'db_backup/', 'database_backup/', 'config_backup/',
            'site_backup/', 'www_backup/', 'public_backup/'
        ]
        
        for backup_dir in backup_dirs:
            self._test_directory_listing(backup_dir)
    
    def _scan_parameterized_backups(self) -> None:
        """Scan for parameterized backup files"""
        logger.info("🎯 Scanning parameterized backup files...")
        
        # Extract domain for parameterized patterns
        domain = urlparse(self.base_url).netloc.replace('www.', '').split('.')[0]
        
        # Date-based backups
        dates = ['2024', '2023', '2022', 'latest', 'current', 'old']
        
        parameterized_patterns = [
            f'{domain}.sql',
            f'{domain}_backup.sql', 
            f'{domain}.zip',
            f'backup_{domain}.zip',
            f'{domain}_db.sql'
        ]
        
        for pattern in parameterized_patterns:
            self._test_backup_file(pattern, InfoDisclosureType.DATABASE_DUMP)
        
        # Date-based patterns
        for date in dates:
            patterns = [
                f'backup_{date}.sql',
                f'db_backup_{date}.sql',
                f'{domain}_{date}.zip',
                f'backup_{date}.zip'
            ]
            for pattern in patterns:
                self._test_backup_file(pattern, InfoDisclosureType.BACKUP_FILE)
    
    def _test_backup_file_single(self, test_url: str, file_pattern: str, vuln_type: InfoDisclosureType) -> Optional[InfoDisclosureVulnerability]:
        """Test single backup file URL with redirect verification"""
        try:
            # First, check without following redirects
                timeout=self.timeout, 
                allow_redirects=False,
                stream=True
            )
            
            # If redirect (3xx), follow it and verify
            if response_no_redirect.status_code in [301, 302, 303, 307, 308]:
                # Follow redirect once
                redirect_url = response_no_redirect.headers.get('Location', '')
                if redirect_url:
                    if not redirect_url.startswith('http'):
                        redirect_url = urljoin(test_url, redirect_url)
                    
                    try:
                            timeout=self.timeout,
                            allow_redirects=False,
                            stream=True
                        )
                        final_url = redirect_url
                    except Exception:
                        # If redirect fails, use original response
                        response = response_no_redirect
                        final_url = test_url
                else:
                    response = response_no_redirect
                    final_url = test_url
            else:
                response = response_no_redirect
                final_url = test_url
            
            # CRITICAL: Verify it's not a redirect to homepage
            # CRITICAL: Verify it's not a redirect to homepage
            if response.status_code == 200:
                # Safe Content Reading: Read only first 10KB to avoid OOM on large files
                try:
                    content_chunk = next(response.iter_content(10240, decode_unicode=False), b'')
                    # Explicitly close to stop further downloading
                    response.close()
                    
                    # Decode with fallback
                    encoding = response.encoding or 'utf-8'
                    try:
                        content_preview = content_chunk.decode(encoding, errors='replace')
                    except Exception:
                        content_preview = content_chunk.decode('utf-8', errors='replace')

                    if self._is_redirect_to_homepage(test_url, final_url, content_preview):
                        # False positive - redirects to homepage
                        return None
                        
                    # Check if backup is accessible using the preview
                    if self._is_backup_accessible(response, content_preview):
                        vulnerability = self._create_backup_vulnerability(
                            test_url, response, file_pattern, vuln_type
                        )
                        if vulnerability:
                            logger.warning(f"🚨 Backup file exposed: {test_url}")
                            return vulnerability
                            
                except Exception as e:
                    logger.debug(f"Error reading content for {test_url}: {e}")
                    return None
                        
        except requests.Timeout:
            logger.debug(f"Timeout checking {test_url}")
        except requests.RequestException as e:
            logger.debug(f"Request failed for {test_url}: {e}")
        except Exception as e:
            logger.debug(f"Error checking {test_url}: {e}")
        
        return None
    
    def _test_backup_file(self, file_pattern: str, vuln_type: InfoDisclosureType) -> None:
        """Test backup file with concurrent requests and early exit"""
        
        # Test multiple locations
        test_urls = [
            urljoin(self.base_url + '/', file_pattern),
            urljoin(self.base_url + '/backup/', file_pattern),
            urljoin(self.base_url + '/backups/', file_pattern),
            urljoin(self.base_url + '/admin/', file_pattern),
            urljoin(self.base_url + '/data/', file_pattern)
        ]
        
        # Use concurrent requests with early exit
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(test_urls))) as executor:
            future_to_url = {
                executor.submit(self._test_backup_file_single, url, file_pattern, vuln_type): url
                for url in test_urls
            }
            
            # Process results as they complete
            for future in as_completed(future_to_url):
                try:
                    vulnerability = future.result(timeout=self.timeout + 2)
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)
                        # Early exit: found valid backup, cancel remaining tasks
                        for remaining_future in future_to_url:
                            if not remaining_future.done():
                                remaining_future.cancel()
                        return
                except Exception as e:
                    logger.debug(f"Error processing result: {e}")
                    continue
    
    def _test_directory_listing(self, directory: str) -> None:
        """Test for directory listing exposure"""
        
        test_url = urljoin(self.base_url + '/', directory)
        
        try:
            response = self.session.get(test_url, timeout=self.timeout)
            
            if self._is_directory_listing(response):
                vulnerability = self._create_directory_vulnerability(test_url, response)
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)
                    logger.warning(f"🚨 Directory listing exposed: {test_url}")
                    
        except requests.RequestException:
            pass
    
    def _is_backup_accessible(self, response: requests.Response, content_preview: str) -> bool:
        """Check if backup file is accessible and contains sensitive data (using preview content)"""
        
        # Check status code
        if response.status_code != 200:
            return False
        
        # Check content type indicators
        content_type = response.headers.get('Content-Type', '').lower()
        
        backup_content_types = [
            'application/sql',
            'text/sql', 
            'application/zip',
            'application/x-gzip',
            'application/x-tar',
            'application/octet-stream',
            'text/plain'
        ]
        
        # Check if content type suggests backup
        type_match = any(ct in content_type for ct in backup_content_types)
        
        # Check content length (backup files are usually substantial)
        try:
            content_length = int(response.headers.get('Content-Length', 0))
            if content_length == 0:
                 # If no content length, use the chunk size as proxy (if chunk is full 10KB, likely large)
                 content_length = len(content_preview)
        except:
            content_length = 0
            
        size_check = content_length > 100  # Minimum size for meaningful backup
        
        # Check content for backup indicators using the PREVIEW content
        content_check = self._contains_backup_content(content_preview)
        
        return (type_match or size_check) and content_check
    
    def _is_directory_listing(self, response: requests.Response) -> bool:
        """Check if response shows directory listing"""
        
        if response.status_code != 200:
            return False
        
        # Common directory listing indicators
        listing_indicators = [
            'Index of /',
            'Directory Listing',
            'Parent Directory',
            '<title>Index of',
            'Directory contents',
            '[DIR]',
            'apache/',
            'nginx/'
        ]
        
        content = response.text.lower()
        
        # Check for directory listing patterns
        has_indicators = any(indicator.lower() in content for indicator in listing_indicators)
        
        # Check for file links pattern
        file_pattern = r'<a\s+href="[^"]*\.(sql|zip|bak|backup|old|tmp)"'
        has_files = bool(re.search(file_pattern, content, re.IGNORECASE))
        
        return has_indicators or has_files
    
    def _contains_backup_content(self, content: str) -> bool:
        """Check if content contains backup-related data"""
        
        if not content or len(content) < 50:
            return False
        
        # Check for sensitive patterns
        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        
        # Check for common backup file headers
        backup_headers = [
            'mysqldump',
            'pg_dump', 
            'sqlite',
            '-- Database:',
            '-- Table structure',
            'CREATE DATABASE',
            'DROP TABLE',
            'INSERT INTO',
            'UPDATE SET',
            'DELETE FROM'
        ]
        
        content_lower = content.lower()
        return any(header.lower() in content_lower for header in backup_headers)
    
    def _create_backup_vulnerability(
        self, 
        url: str, 
        response: requests.Response, 
        file_pattern: str,
        vuln_type: InfoDisclosureType
    ) -> Optional[InfoDisclosureVulnerability]:
        """Create backup file vulnerability with CVE integration"""
        
        # Analyze content for severity assessment
        content = response.text[:10000]  # First 10KB for analysis
        severity = self._assess_backup_severity(content, file_pattern)
        
        # Get CVE information
        cve_info = self._get_cve_info(vuln_type, severity)
        
        # Extract sensitive data samples
        sensitive_samples = self._extract_sensitive_samples(content)
        
        vulnerability = InfoDisclosureVulnerability(
            id=f"BACKUP-{vuln_type.value}-{hash(url) % 10000}",
            type=vuln_type,
            severity=severity,
            url=url,
            evidence=f"Backup file accessible: {file_pattern}",
            sensitive_data=sensitive_samples,
            exposure_method="Direct URL access to backup file",
            risk_description=self._get_backup_risk_description(vuln_type, severity),
            business_impact=self._get_business_impact(severity),
            remediation=self._get_backup_remediation(vuln_type),
            cwe_id="CWE-200",
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
        response: requests.Response
    ) -> Optional[InfoDisclosureVulnerability]:
        """Create directory listing vulnerability"""
        
        severity = InfoDisclosureSeverity.MEDIUM
        cve_info = self._get_cve_info(InfoDisclosureType.DIRECTORY_LISTING, severity)
        
        # Extract file list from directory listing
        file_matches = re.findall(r'href="([^"]*\.(sql|zip|bak|backup|old|tmp|log))"', 
                                 response.text, re.IGNORECASE)
        exposed_files = [match[0] for match in file_matches[:10]]  # Limit to 10 files
        
        vulnerability = InfoDisclosureVulnerability(
            id=f"DIR-LISTING-{hash(url) % 10000}",
            type=InfoDisclosureType.DIRECTORY_LISTING,
            severity=severity,
            url=url,
            evidence=f"Directory listing exposed with {len(exposed_files)} sensitive files",
            sensitive_data=f"Exposed files: {', '.join(exposed_files)}",
            exposure_method="Web server directory listing enabled",
            risk_description="Directory listing reveals backup files and sensitive data",
            business_impact="Attackers can enumerate and download sensitive backup files",
            remediation="Disable directory listing and move backup files to secure location",
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
    
    def _assess_backup_severity(self, content: str, file_pattern: str) -> InfoDisclosureSeverity:
        """Assess backup file severity based on content and type"""
        
        # Critical indicators
        critical_patterns = [
            r'password\s*[:=]\s*["\']?([^"\'\s]{6,})',  # Passwords
            r'private_key',  # Private keys
            r'secret_key',   # Secret keys
            r'api_secret',   # API secrets
            r'root.*password',  # Root passwords
            r'admin.*password', # Admin passwords
        ]
        
        # High severity indicators  
        high_patterns = [
            r'CREATE TABLE.*users?',  # User tables
            r'INSERT INTO.*users?',   # User data
            r'email.*password',       # Email/password combos
            r'credit.*card',          # Credit card data
            r'social.*security',      # SSN data
        ]
        
        content_lower = content.lower()
        
        # Check for critical content
        for pattern in critical_patterns:
            if re.search(pattern, content_lower):
                return InfoDisclosureSeverity.CRITICAL
        
        # Check for high severity content
        for pattern in high_patterns:
            if re.search(pattern, content_lower):
                return InfoDisclosureSeverity.HIGH
        
        # Check file type for severity
        if any(ext in file_pattern.lower() for ext in ['.sql', '.db']):
            return InfoDisclosureSeverity.HIGH
        
        if any(ext in file_pattern.lower() for ext in ['.zip', '.tar.gz']):
            return InfoDisclosureSeverity.MEDIUM
        
        return InfoDisclosureSeverity.LOW
    
    def _extract_sensitive_samples(self, content: str) -> str:
        """Extract sensitive data samples for evidence"""
        
        samples = []
        
        # Extract credential patterns
        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content[:5000], re.IGNORECASE)
                for match in matches:
                    sample = match.group(0)[:100]  # Limit sample length
                    if len(sample) > 10:  # Skip very short matches
                        samples.append(f"{category.title()}: {sample}")
                    if len(samples) >= 5:  # Limit total samples
                        break
                if len(samples) >= 5:
                    break
            if len(samples) >= 5:
                break
        
        return '; '.join(samples) if samples else "Backup file contains sensitive data"
    
    def _get_cve_info(self, vuln_type: InfoDisclosureType, severity: InfoDisclosureSeverity) -> Dict:
        """Get CVE information for vulnerability type and severity"""
        
        # Map vulnerability types to CVE categories
        cve_category = "BACKUP_FILE"  # Default
        
        if vuln_type in [InfoDisclosureType.DEBUG_ENDPOINT]:
            cve_category = "DEBUG_ENDPOINT"
        elif vuln_type in [InfoDisclosureType.ERROR_MESSAGE, InfoDisclosureType.STACK_TRACE]:
            cve_category = "ERROR_MESSAGE"
        
        return CVE_DATABASE.get(cve_category, {}).get(severity.value, {
            "cve_references": [],
            "cvss_score": 5.0,
            "attack_vector": "NETWORK",
            "exploit_complexity": "MEDIUM"
        })
    
    def _get_backup_risk_description(self, vuln_type: InfoDisclosureType, severity: InfoDisclosureSeverity) -> str:
        """Get risk description based on vulnerability type and severity"""
        
        descriptions = {
            InfoDisclosureType.DATABASE_DUMP: {
                InfoDisclosureSeverity.CRITICAL: "Database backup contains sensitive user data, credentials, and system information accessible without authentication",
                InfoDisclosureSeverity.HIGH: "Database backup exposes user data and application configuration details",
                InfoDisclosureSeverity.MEDIUM: "Database backup reveals application structure and partial data",
                InfoDisclosureSeverity.LOW: "Database schema information disclosed through backup file"
            },
            InfoDisclosureType.CONFIG_FILE: {
                InfoDisclosureSeverity.CRITICAL: "Configuration backup contains database credentials, API keys, and system secrets",
                InfoDisclosureSeverity.HIGH: "Configuration backup exposes application settings and connection strings",
                InfoDisclosureSeverity.MEDIUM: "Configuration backup reveals application architecture",
                InfoDisclosureSeverity.LOW: "Configuration backup contains non-sensitive application settings"
            },
            InfoDisclosureType.BACKUP_FILE: {
                InfoDisclosureSeverity.CRITICAL: "Application backup contains source code, credentials, and sensitive data",
                InfoDisclosureSeverity.HIGH: "Application backup exposes source code and configuration",
                InfoDisclosureSeverity.MEDIUM: "Application backup reveals application structure",
                InfoDisclosureSeverity.LOW: "Application backup contains development files"
            }
        }
        
        return descriptions.get(vuln_type, {}).get(severity, 
            "Backup file exposure may reveal sensitive information")
    
    def _get_business_impact(self, severity: InfoDisclosureSeverity) -> str:
        """Get business impact based on severity"""
        
        impacts = {
            InfoDisclosureSeverity.CRITICAL: "Complete system compromise, data breach, regulatory violations, reputation damage",
            InfoDisclosureSeverity.HIGH: "Significant data exposure, potential system access, compliance issues",
            InfoDisclosureSeverity.MEDIUM: "Information disclosure, reconnaissance for further attacks",
            InfoDisclosureSeverity.LOW: "Limited information disclosure, minimal business impact"
        }
        
        return impacts.get(severity, "Information disclosure with potential business impact")
    
    def _get_backup_remediation(self, vuln_type: InfoDisclosureType) -> str:
        """Get remediation advice for backup vulnerability type"""
        
        remediations = {
            InfoDisclosureType.DATABASE_DUMP: "Remove database backups from web-accessible directories, implement access controls, encrypt backups",
            InfoDisclosureType.CONFIG_FILE: "Move configuration backups to secure location, implement proper access controls, encrypt sensitive configurations",
            InfoDisclosureType.BACKUP_FILE: "Remove backup files from public directories, implement secure backup storage, use proper access controls",
            InfoDisclosureType.LOG_EXPOSURE: "Move log files to secure location, implement log rotation and access controls",
            InfoDisclosureType.SOURCE_CODE: "Remove version control directories from web root, implement proper deployment processes",
            InfoDisclosureType.DIRECTORY_LISTING: "Disable directory listing, implement proper web server configuration"
        }
        
        return remediations.get(vuln_type, "Remove sensitive files from web-accessible locations and implement access controls")
    
    def _build_cvss_vector(self, cve_info: Dict) -> str:
        """Build CVSS vector string"""
        
        return f"CVSS:3.1/AV:{cve_info['attack_vector'][0]}/AC:{cve_info['exploit_complexity'][0]}/PR:N/UI:N/S:U/C:H/I:N/A:N"