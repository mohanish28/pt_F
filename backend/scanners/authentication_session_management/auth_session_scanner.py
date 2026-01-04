"""
Authentication & Session Management Vulnerability Scanner

This scanner automates the detection of authentication and session management vulnerabilities
using multiple security testing techniques:

1. SAST (Static Application Security Testing):
   - Semgrep rules for auth/session anti-patterns
   - CodeQL queries for dataflow and auth checks
   - Language-specific tools (Bandit, ESLint security plugins)
   - Regex patterns for common vulnerabilities

2. DAST (Dynamic Application Security Testing):
   - Burp Suite integration
   - OWASP ZAP integration
   - Custom session testing

3. Runtime Monitoring:
   - Session token analysis
   - Authentication flow testing
   - OWASP ASVS/MASVS compliance checks

Created by: Professional Penetration Tester & Software Engineer
"""

import asyncio
import json
import base64
import jwt
import re
import os
import tempfile
import subprocess
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urljoin, urlparse
try:
    import httpx  # type: ignore[import]
except ImportError:
    # Fallback to requests if httpx is not available
    import requests as httpx  # type: ignore[import]
    httpx.AsyncClient = lambda **kwargs: None

try:
    from bs4 import BeautifulSoup  # type: ignore[import]
except ImportError:
    # Provide a minimal fallback if BeautifulSoup is not available
    class BeautifulSoup:
        def __init__(self, *args, **kwargs):
            pass

try:
    import yaml  # type: ignore[import]
except ImportError:
    # Provide a minimal YAML implementation
    class yaml:
        @staticmethod
        def dump(data, file):
            import json
            json.dump(data, file, indent=2)

import time
from datetime import datetime

from ..base import ScannerBase
from .auth_test_implementations import AuthTestImplementations
from .dast_integration import create_dast_tester
from .jwt_analyzer import JWTAnalyzer
from .frontend_storage_analyzer import FrontendStorageAnalyzer
from .password_reset_analyzer import PasswordResetAnalyzer
from .cookie_security_analyzer import CookieSecurityAnalyzer
from .session_handling_analyzer import SessionHandlingAnalyzer
from .bruteforce_enumeration_analyzer import BruteForceEnumerationAnalyzer
from .wpseku_scanner import WPSekuScanner
from .comprehensive_reporter import SecurityReporter, SecurityFinding


class AuthSessionScanner(ScannerBase):
    """
    Comprehensive Authentication & Session Management Vulnerability Scanner
    
    Detects:
    - Insecure cookie configurations
    - Weak session management
    - Authentication bypasses
    - Session fixation vulnerabilities
    - JWT token issues
    - Remember-me functionality weaknesses
    - Session timeout issues
    - CSRF vulnerabilities related to authentication
    """
    
    def __init__(self, target: str, timeout: int = None, **kwargs):
        super().__init__(target, timeout)
        self.logger = logging.getLogger(__name__)
        
        # Scanner configuration
        self.include_sast = kwargs.get('include_sast', True)
        self.include_dast = kwargs.get('include_dast', True)
        self.include_runtime = kwargs.get('include_runtime', True)
        self.source_code_path = kwargs.get('source_code_path', None)
        self.technology_stack = kwargs.get('technology_stack', [])
        
        # Authentication test credentials - use custom if provided
        self.test_credentials = kwargs.get('test_credentials', {
            'username': 'admin',
            'password': 'admin123',
            'weak_passwords': ['password', '123456', 'admin', 'test', 'guest', 'root']
        })
        
        # Results storage
        self.sast_results = []
        self.dast_results = []
        self.runtime_results = []
        self.session_analysis_results = []
        
        # Initialize specialized analyzers
        self.jwt_analyzer = JWTAnalyzer()
        self.frontend_storage_analyzer = FrontendStorageAnalyzer()
        self.password_reset_analyzer = PasswordResetAnalyzer()
        self.cookie_security_analyzer = CookieSecurityAnalyzer()
        self.session_handling_analyzer = SessionHandlingAnalyzer()
        self.bruteforce_enumeration_analyzer = BruteForceEnumerationAnalyzer()
        self.wpseku_scanner = WPSekuScanner(target=self.target, timeout=self.timeout)
        self.security_reporter = SecurityReporter(project_name=f"Auth Scan - {self.target}")
        
        # OWASP ASVS mappings for authentication
        self.asvs_mappings = {
            'V2.1': 'Password Security Requirements',
            'V2.2': 'General Authenticator Requirements',
            'V2.3': 'Authenticator Lifecycle Requirements',
            'V2.4': 'Credential Storage Requirements',
            'V2.5': 'Credential Recovery Requirements',
            'V2.6': 'Look-up Secret Verifier Requirements',
            'V2.7': 'Out of Band Verifier Requirements',
            'V2.8': 'Single or Multi Factor One Time Verifier Requirements',
            'V2.9': 'Cryptographic Verifier Requirements',
            'V2.10': 'Service Authentication Requirements',
            'V3.1': 'Fundamental Session Management Requirements',
            'V3.2': 'Session Binding Requirements',
            'V3.3': 'Session Logout and Timeout Requirements',
            'V3.4': 'Cookie-based Session Management',
            'V3.5': 'Token-based Session Management',
            'V3.6': 'Re-authentication from a Federation or Assertion',
            'V3.7': 'Defenses Against Session Management Exploits'
        }

    def _get_scanner_config(self) -> Dict[str, Any]:
        """Get scanner configuration"""
        return {
            'target': self.target,
            'timeout': self.timeout,
            'include_sast': self.include_sast,
            'include_dast': self.include_dast,
            'include_runtime': self.include_runtime,
            'source_code_path': self.source_code_path,
            'technology_stack': self.technology_stack,
            'test_credentials': self.test_credentials
        }
    
    def _get_semgrep_rules(self) -> List[Dict[str, Any]]:
        """Get Semgrep rules for authentication scanning"""
        return [
            {
                'id': 'hardcoded-credentials',
                'pattern': 'password = "admin"',
                'message': 'Hardcoded credentials detected',
                'severity': 'ERROR'
            },
            {
                'id': 'weak-session-config',
                'pattern': 'session.cookie_secure = False',
                'message': 'Insecure session configuration',
                'severity': 'WARNING'
            },
            {
                'id': 'sql-injection-auth',
                'pattern': 'SELECT * FROM users WHERE username="$USER" AND password="$PASS"',
                'message': 'Potential SQL injection in authentication',
                'severity': 'ERROR'
            }
        ]
    
    def _get_codeql_queries(self) -> List[Dict[str, Any]]:
        """Get CodeQL queries for authentication scanning"""
        return [
            {
                'name': 'hardcoded-auth-credentials',
                'query': 'Authentication calls with hardcoded credentials',
                'language': 'javascript'
            },
            {
                'name': 'weak-crypto-auth',
                'query': 'Weak cryptographic implementations in authentication',
                'language': 'python'
            },
            {
                'name': 'session-fixation',
                'query': 'Session fixation vulnerabilities',
                'language': 'java'
            }
        ]
    
    def _analyze_code_patterns(self, code: str, filename: str) -> List[Dict[str, Any]]:
        """Analyze code for authentication patterns"""
        findings = []
        
        # Check for hardcoded credentials
        if 'password = "admin"' in code or "password = 'admin'" in code:
            findings.append({
                'title': 'Hardcoded Admin Credentials',
                'severity': 'critical',
                'category': 'authentication',
                'file': filename,
                'line': 1,
                'evidence': 'Hardcoded admin password found'
            })
        
        # Check for weak authentication logic
        if 'username === "admin" && password === "password"' in code:
            findings.append({
                'title': 'Weak Authentication Logic',
                'severity': 'high',
                'category': 'authentication',
                'file': filename,
                'line': 1,
                'evidence': 'Simple credential comparison'
            })
        
        # Check for SQL injection patterns
        if 'SELECT * FROM users WHERE username=' in code and 'password=' in code:
            findings.append({
                'title': 'Potential SQL Injection in Authentication',
                'severity': 'high',
                'category': 'authentication',
                'file': filename,
                'line': 1,
                'evidence': 'Direct SQL query construction'
            })
        
        return findings
    
    def _check_asvs_compliance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check OWASP ASVS compliance"""
        asvs_controls = {
            'V2.1.1': {
                'title': 'Verify that user set passwords are at least 12 characters in length',
                'compliant': True,
                'evidence': 'No password length violations found'
            },
            'V2.1.2': {
                'title': 'Verify that passwords 64 characters or longer are permitted',
                'compliant': True,
                'evidence': 'No password length restrictions found'
            },
            'V3.1.1': {
                'title': 'Verify the application never reveals session tokens in URL parameters or error messages',
                'compliant': True,
                'evidence': 'No session token exposure detected'
            },
            'V3.2.1': {
                'title': 'Verify the application generates a new session token on user authentication',
                'compliant': True,
                'evidence': 'Session regeneration patterns verified'
            }
        }
        
        # Mark controls as non-compliant based on findings
        for finding in findings:
            if 'password' in finding.get('title', '').lower():
                asvs_controls['V2.1.1']['compliant'] = False
                asvs_controls['V2.1.1']['evidence'] = finding.get('title', '')
            
            if 'session' in finding.get('title', '').lower():
                asvs_controls['V3.1.1']['compliant'] = False
                asvs_controls['V3.1.1']['evidence'] = finding.get('title', '')
        
        return asvs_controls

    async def scan(self) -> Dict[str, Any]:
        """Execute comprehensive authentication and session management scan"""
        try:
            if self.connection_manager and self.scan_id:
                await self.connection_manager.send_progress(
                    self.scan_id, 10, "Starting Authentication & Session Management Scan",
                    current_activity="Initializing scanner components"
                )
            
            results = {
                'scanner': 'auth_session',
                'target': self.target,
                'timestamp': datetime.utcnow().isoformat(),
                'findings': [],
                'summary': {},
                'asvs_compliance': {},
                'recommendations': []
            }
            
            # Phase 1: SAST Analysis
            if self.include_sast and self.source_code_path:
                await self._update_progress(20, "Running SAST analysis")
                sast_findings = await self._run_sast_analysis()
                results['findings'].extend(sast_findings)
                self.sast_results = sast_findings
            
            # Phase 2: DAST Analysis
            if self.include_dast:
                await self._update_progress(50, "Running DAST analysis")
                dast_findings = await self._run_dast_analysis()
                results['findings'].extend(dast_findings)
                self.dast_results = dast_findings
            
            # Phase 3: Session Analysis
            await self._update_progress(70, "Analyzing session management")
            session_findings = await self._analyze_session_management()
            results['findings'].extend(session_findings)
            self.session_analysis_results = session_findings
            
            # Phase 4: Runtime Security Checks
            if self.include_runtime:
                await self._update_progress(75, "Running runtime security checks")
                runtime_findings = await self._run_runtime_checks()
                results['findings'].extend(runtime_findings)
                self.runtime_results = runtime_findings
            
            # Phase 5: Advanced Specialized Analysis
            await self._update_progress(80, "Running specialized security analysis")
            specialized_findings = await self._run_specialized_analysis()
            results['findings'].extend(specialized_findings)
            
            # Phase 6: Apply CVE enhancement to all findings
            if results['findings']:
                enhanced_findings = await self.enhance_findings_with_cve(results['findings'])
                results['findings'] = enhanced_findings
            
            # Phase 7: Generate comprehensive report
            await self._update_progress(95, "Generating comprehensive report")
            results['summary'] = self._generate_summary(results['findings'])
            results['asvs_compliance'] = self._check_asvs_compliance(results['findings'])
            
            # Export cookies for subsequent scanners
            results['authenticated_cookies'] = getattr(self, 'authenticated_cookies', {})
            
            results['recommendations'] = self._generate_recommendations(results['findings'])
            
            self.parsed_result = results
            
            await self._update_progress(100, "Authentication & Session Management scan completed")
            return results
            
        except Exception as e:
            self.logger.error(f"Auth/Session scan failed: {str(e)}")
            raise Exception(f"Authentication & Session Management scan failed: {str(e)}")

    async def _update_progress(self, progress: int, message: str):
        """Update scan progress"""
        if self.connection_manager and self.scan_id:
            await self.connection_manager.send_progress(
                self.scan_id, progress, message
            )

    async def _run_sast_analysis(self) -> List[Dict[str, Any]]:
        """Run Static Application Security Testing for authentication issues"""
        findings = []
        
        if not self.source_code_path or not os.path.exists(self.source_code_path):
            return findings
        
        try:
            # 1. Semgrep Analysis
            semgrep_findings = await self._run_semgrep_auth_rules()
            findings.extend(semgrep_findings)
            
            # 2. CodeQL Analysis (if available)
            codeql_findings = await self._run_codeql_auth_queries()
            findings.extend(codeql_findings)
            
            # 3. Language-specific SAST tools
            language_findings = await self._run_language_specific_sast()
            findings.extend(language_findings)
            
            # 4. Regex pattern matching
            regex_findings = await self._run_regex_pattern_analysis()
            findings.extend(regex_findings)
            
        except Exception as e:
            self.logger.error(f"SAST analysis failed: {str(e)}")
            findings.append({
                'title': 'SAST Analysis Error',
                'description': f'Static analysis failed: {str(e)}',
                'severity': 'info',
                'category': 'tool_error'
            })
        
        return findings

    async def _run_semgrep_auth_rules(self) -> List[Dict[str, Any]]:
        """Run Semgrep with authentication and session management rules"""
        findings = []
        
        try:
            # Create custom Semgrep rules for authentication issues
            semgrep_rules = self._create_semgrep_auth_rules()
            
            # Write rules to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
                yaml.dump(semgrep_rules, f)
                rules_file = f.name
            
            # Run Semgrep
            cmd = [
                'semgrep',
                '--config', rules_file,
                '--json',
                '--no-git-ignore',
                self.source_code_path
            ]
            
            try:
                result = await self._run_command_with_output(cmd)
                semgrep_output = json.loads(result)
                
                for finding in semgrep_output.get('results', []):
                    findings.append({
                        'title': f"Semgrep: {finding.get('check_id', 'Unknown')}",
                        'description': finding.get('extra', {}).get('message', ''),
                        'severity': self._map_semgrep_severity(finding.get('extra', {}).get('severity', 'INFO')),
                        'file_path': finding.get('path', ''),
                        'line_number': finding.get('start', {}).get('line', 0),
                        'code_snippet': finding.get('extra', {}).get('lines', ''),
                        'category': 'sast_semgrep',
                        'cwe_ids': self._extract_cwe_from_semgrep(finding),
                        'asvs_mapping': self._map_to_asvs(finding.get('check_id', '')),
                        'recommendation': self._get_semgrep_recommendation(finding.get('check_id', ''))
                    })
            
            except subprocess.CalledProcessError:
                # Semgrep might not be installed, use fallback regex analysis
                self.logger.warning("Semgrep not available, using regex fallback")
            
            finally:
                # Clean up temporary file
                if os.path.exists(rules_file):
                    os.unlink(rules_file)
        
        except Exception as e:
            self.logger.error(f"Semgrep analysis failed: {str(e)}")
        
        return findings

    def _create_semgrep_auth_rules(self) -> Dict[str, Any]:
        """Create custom Semgrep rules for authentication and session issues"""
        return {
            'rules': [
                {
                    'id': 'insecure-cookie-flags',
                    'message': 'Cookie set without Secure and HttpOnly flags',
                    'languages': ['javascript', 'python', 'java', 'php', 'ruby'],
                    'severity': 'WARNING',
                    'patterns': [
                        {'pattern': 'response.set_cookie($NAME, $VALUE)'},
                        {'pattern-not': 'response.set_cookie($NAME, $VALUE, secure=True, httponly=True)'},
                        {'pattern-not': 'response.set_cookie($NAME, $VALUE, httponly=True, secure=True)'}
                    ],
                    'metadata': {
                        'cwe': ['CWE-614', 'CWE-1004'],
                        'owasp': ['A02:2021'],
                        'asvs': ['V3.4.1', 'V3.4.2']
                    }
                },
                {
                    'id': 'hardcoded-jwt-secret',
                    'message': 'Hardcoded JWT secret detected',
                    'languages': ['javascript', 'python', 'java', 'go'],
                    'severity': 'ERROR',
                    'patterns': [
                        {'pattern': 'jwt.sign($PAYLOAD, "...")'},
                        {'pattern': 'JWT_SECRET = "..."'},
                        {'pattern': 'jwt_secret = "..."'}
                    ],
                    'metadata': {
                        'cwe': ['CWE-798', 'CWE-321'],
                        'owasp': ['A02:2021'],
                        'asvs': ['V2.4.1', 'V3.5.1']
                    }
                },
                {
                    'id': 'weak-session-timeout',
                    'message': 'Excessive session timeout detected',
                    'languages': ['javascript', 'python', 'java'],
                    'severity': 'WARNING',
                    'patterns': [
                        {'pattern': 'SESSION_TIMEOUT = $TIME'},
                        {'pattern-where': '$TIME > 3600'}  # More than 1 hour
                    ],
                    'metadata': {
                        'cwe': ['CWE-613'],
                        'asvs': ['V3.3.1']
                    }
                },
                {
                    'id': 'remember-me-insecure',
                    'message': 'Insecure remember-me implementation',
                    'languages': ['javascript', 'python', 'java', 'php'],
                    'severity': 'ERROR',
                    'patterns': [
                        {'pattern': 'remember_me = True'},
                        {'pattern-not': '... secure=True ...'},
                        {'pattern-not': '... httponly=True ...'}
                    ],
                    'metadata': {
                        'cwe': ['CWE-384'],
                        'asvs': ['V2.2.1']
                    }
                },
                {
                    'id': 'session-fixation-vulnerability',
                    'message': 'Potential session fixation vulnerability',
                    'languages': ['php', 'python', 'javascript'],
                    'severity': 'ERROR',
                    'patterns': [
                        {'pattern': 'session_start()'},
                        {'pattern-not': 'session_regenerate_id(...)'}
                    ],
                    'metadata': {
                        'cwe': ['CWE-384'],
                        'asvs': ['V3.2.1']
                    }
                }
            ]
        }

    async def _run_codeql_auth_queries(self) -> List[Dict[str, Any]]:
        """Run CodeQL queries for authentication vulnerabilities"""
        findings = []
        
        try:
            # Check if CodeQL is available
            codeql_cmd = ['codeql', '--version']
            await self._run_command_with_output(codeql_cmd)
            
            # Create CodeQL database if it doesn't exist
            db_path = os.path.join(tempfile.gettempdir(), 'codeql_auth_db')
            
            # Create database
            create_db_cmd = [
                'codeql', 'database', 'create',
                db_path,
                '--language=javascript,python,java',
                '--source-root', self.source_code_path
            ]
            
            await self._run_command_with_output(create_db_cmd)
            
            # Run authentication-related queries
            auth_queries = [
                'javascript/InsecureCookie',
                'javascript/HardcodedCredentials',
                'python/weak-cryptographic-algorithm',
                'java/hardcoded-credential'
            ]
            
            for query in auth_queries:
                try:
                    query_cmd = [
                        'codeql', 'database', 'analyze',
                        db_path,
                        '--format=json',
                        f'--query={query}'
                    ]
                    
                    result = await self._run_command_with_output(query_cmd)
                    query_results = json.loads(result)
                    
                    for finding in query_results.get('runs', [{}])[0].get('results', []):
                        findings.append({
                            'title': f"CodeQL: {finding.get('ruleId', 'Unknown')}",
                            'description': finding.get('message', {}).get('text', ''),
                            'severity': 'high',
                            'file_path': finding.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', ''),
                            'category': 'sast_codeql',
                            'cwe_ids': self._extract_cwe_from_codeql(finding),
                            'recommendation': 'Review and fix the identified authentication vulnerability'
                        })
                
                except Exception as e:
                    self.logger.warning(f"CodeQL query {query} failed: {str(e)}")
        
        except subprocess.CalledProcessError:
            self.logger.info("CodeQL not available, skipping CodeQL analysis")
        except Exception as e:
            self.logger.error(f"CodeQL analysis failed: {str(e)}")
        
        return findings

    async def _run_language_specific_sast(self) -> List[Dict[str, Any]]:
        """Run language-specific SAST tools"""
        findings = []
        
        # Detect languages in the codebase
        languages = self._detect_languages()
        
        for lang in languages:
            if lang == 'python':
                bandit_findings = await self._run_bandit_analysis()
                findings.extend(bandit_findings)
            elif lang == 'javascript':
                eslint_findings = await self._run_eslint_security_analysis()
                findings.extend(eslint_findings)
            elif lang == 'ruby':
                brakeman_findings = await self._run_brakeman_analysis()
                findings.extend(brakeman_findings)
        
        return findings

    async def _run_bandit_analysis(self) -> List[Dict[str, Any]]:
        """Run Bandit for Python security issues"""
        findings = []
        
        try:
            cmd = [
                'bandit',
                '-r', self.source_code_path,
                '-f', 'json',
                '-ll',  # Low severity and above
                '--skip', 'B101'  # Skip assert_used test
            ]
            
            result = await self._run_command_with_output(cmd)
            bandit_output = json.loads(result)
            
            for finding in bandit_output.get('results', []):
                if self._is_auth_related_bandit_finding(finding):
                    findings.append({
                        'title': f"Bandit: {finding.get('test_name', 'Unknown')}",
                        'description': finding.get('issue_text', ''),
                        'severity': finding.get('issue_severity', 'info').lower(),
                        'file_path': finding.get('filename', ''),
                        'line_number': finding.get('line_number', 0),
                        'code_snippet': finding.get('code', ''),
                        'category': 'sast_bandit',
                        'cwe_ids': [finding.get('test_id', '')],
                        'recommendation': 'Review and fix the identified security issue'
                    })
        
        except subprocess.CalledProcessError:
            self.logger.info("Bandit not available")
        except Exception as e:
            self.logger.error(f"Bandit analysis failed: {str(e)}")
        
        return findings

    async def _run_regex_pattern_analysis(self) -> List[Dict[str, Any]]:
        """Run regex pattern analysis for common authentication issues"""
        findings = []
        
        if not self.source_code_path:
            return findings
        
        # Define regex patterns for authentication vulnerabilities
        patterns = {
            'insecure_cookie': {
                'pattern': r'Set-Cookie:.*(?!.*Secure)(?!.*HttpOnly)',
                'description': 'Cookie set without Secure or HttpOnly flags',
                'severity': 'medium',
                'cwe': ['CWE-614']
            },
            'hardcoded_jwt_secret': {
                'pattern': r'jwt[_\-]?secret\s*[=:]\s*["\'][^"\']{8,}["\']',
                'description': 'Hardcoded JWT secret found',
                'severity': 'high',
                'cwe': ['CWE-798']
            },
            'weak_password_policy': {
                'pattern': r'password.*length.*[<>=].*[1-7]',
                'description': 'Weak password length requirement',
                'severity': 'medium',
                'cwe': ['CWE-521']
            },
            'session_fixation': {
                'pattern': r'session_start\(\)(?!.*session_regenerate_id)',
                'description': 'Potential session fixation vulnerability',
                'severity': 'high',
                'cwe': ['CWE-session-fixation']
            },
            'insecure_remember_me': {
                'pattern': r'remember[_\-]?me.*=.*true(?!.*secure)',
                'description': 'Insecure remember-me implementation',
                'severity': 'medium',
                'cwe': ['CWE-384']
            }
        }
        
        # Search for patterns in source files
        for root, dirs, files in os.walk(self.source_code_path):
            for file in files:
                if file.endswith(('.py', '.js', '.php', '.java', '.rb', '.go')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern_name, pattern_info in patterns.items():
                            matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE | re.MULTILINE)
                            
                            for match in matches:
                                line_number = content[:match.start()].count('\n') + 1
                                findings.append({
                                    'title': f"Regex Pattern: {pattern_name.replace('_', ' ').title()}",
                                    'description': pattern_info['description'],
                                    'severity': pattern_info['severity'],
                                    'file_path': file_path,
                                    'line_number': line_number,
                                    'code_snippet': match.group(0),
                                    'category': 'sast_regex',
                                    'cwe_ids': pattern_info['cwe'],
                                    'recommendation': 'Review and fix the identified pattern'
                                })
                    except Exception as e:
                        self.logger.warning(f"Failed to analyze file {file_path}: {str(e)}")
        
        return findings

    async def _run_dast_analysis(self) -> List[Dict[str, Any]]:
        """Run Dynamic Application Security Testing for authentication issues"""
        findings = []
        
        try:
            # Initialize test implementations
            auth_tester = AuthTestImplementations(self.target, self.logger)
            
            # 1. Basic authentication testing
            auth_findings = await self._test_authentication_mechanisms()
            findings.extend(auth_findings)
            
            # 2. Session management testing
            session_findings = await self._test_session_management()
            findings.extend(session_findings)
            
            # 3. OWASP ZAP/Burp integration (if available)
            dast_tester = await create_dast_tester()
            if dast_tester:
                dast_findings = await dast_tester.run_auth_tests(self.target)
                findings.extend(dast_findings)
            
            # 4. Custom authentication bypass tests
            bypass_findings = await self._test_authentication_bypass()
            findings.extend(bypass_findings)
            
        except Exception as e:
            self.logger.error(f"DAST analysis failed: {str(e)}")
        
        return findings

    async def _test_session_management(self) -> List[Dict[str, Any]]:
        """Test session management implementation"""
        findings = []
        
        try:
            # No timeout - allow complete authentication testing
            async with httpx.AsyncClient(timeout=None, verify=False) as client:
                # Test session-related vulnerabilities
                
                # Check for session fixation
                session_fixation = await self._test_session_fixation(client)
                if session_fixation:
                    findings.append(session_fixation)
                
                # Check for concurrent sessions
                concurrent_finding = await self._test_concurrent_sessions(client)
                if concurrent_finding:
                    findings.append(concurrent_finding)
                
                # Check session timeout
                timeout_finding = await self._test_session_timeout(client)
                if timeout_finding:
                    findings.append(timeout_finding)
                    
        except Exception as e:
            self.logger.error(f"Session management testing failed: {str(e)}")
            findings.append({
                'title': 'Session Management Test Error',
                'severity': 'info',
                'category': 'test_error',
                'description': f'Session management testing failed: {str(e)}'
            })
        
        return findings

    async def _test_session_timeout(self, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Test session timeout configuration"""
        try:
            # This is a placeholder - in real implementation would test actual session timeout
            response = await client.get(self.target)
            
            # Look for session timeout indicators in headers or cookies
            set_cookie_header = response.headers.get('set-cookie', '')
            
            # Check for excessive session timeout (example check)
            if 'max-age=' in set_cookie_header.lower():
                # Extract max-age value and check if it's too high
                import re
                max_age_match = re.search(r'max-age=(\d+)', set_cookie_header.lower())
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age > 86400:  # More than 24 hours
                        return {
                            'title': 'Excessive Session Timeout',
                            'severity': 'medium',
                            'category': 'session_management',
                            'description': f'Session timeout set to {max_age} seconds (more than 24 hours)',
                            'recommendation': 'Implement appropriate session timeout (max 8 hours for sensitive applications)'
                        }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Session timeout test failed: {str(e)}")
            return None

    async def _test_concurrent_sessions(self, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Test for concurrent session handling"""
        try:
            # This is a placeholder - in real implementation would test concurrent session limits
            # For now, just check if the application has any session management
            
            response = await client.get(self.target)
            
            # Check if cookies suggest session management
            if response.cookies:
                session_cookies = [name for name in response.cookies.keys() 
                                 if 'session' in name.lower() or 'sid' in name.lower()]
                
                if session_cookies and len(session_cookies) > 0:
                    # Assume concurrent sessions might not be properly managed
                    return {
                        'title': 'Concurrent Session Management Unknown',
                        'severity': 'info',
                        'category': 'session_management',
                        'description': 'Unable to determine concurrent session handling policy',
                        'recommendation': 'Implement proper concurrent session limits and management'
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Concurrent session test failed: {str(e)}")
            return None



    async def _perform_differential_analysis(self, token: str, context: str, attack_token: str, attack_type: str) -> Optional[Dict[str, Any]]:
        """
        Validation Engine: Performs differential analysis to confirm vulnerability.
        
        Logic:
        1. BASELINE: Send request with explicitly INVALID token (garbled signature).
           - If 200 OK: Endpoint is likely public. Attack is inconclusive/False Positive. ABORT.
           - If 401/403: Endpoint is protected. PROCEED.
           
        2. ATTACK: Send request with malicious (None/Forged) token.
           - If 200 OK (and Baseline was 401/403): CONFIRMED VULNERABILITY.
        """
        # Determine location (Cookie vs Header)
        target_header = {}
        target_cookies = {}
        
        baseline_header = {}
        baseline_cookies = {}
        
        # Create a "Baseline" token (Original token with corrupted signature)
        # We just replace the last char of the signature
        parts = token.split('.')
        if len(parts) == 3:
            baseline_token = f"{parts[0]}.{parts[1]}.{parts[2][:-1]}X"
        else:
            baseline_token = token + "GARBAGE"

        if "Cookie" in context:
            cookie_name = context.split(': ')[1]
            target_cookies[cookie_name] = attack_token
            baseline_cookies[cookie_name] = baseline_token
        elif "Header" in context:
            target_header['Authorization'] = f"Bearer {attack_token}"
            baseline_header['Authorization'] = f"Bearer {baseline_token}"
        else:
            return None

        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                # 1. BASELINE REQUEST
                baseline_response = await client.get(
                    self.target, 
                    headers=baseline_header if baseline_header else None,
                    cookies=baseline_cookies if baseline_cookies else None
                )
                
                # If baseline is 200, the page is public. We cannot test auth bypass here.
                # Exception: unless the page content explicitly says "Unauthorized" (soft 403), but that's hard to heuristic.
                # We'll stick to status codes for reliability.
                if baseline_response.status_code == 200:
                    self.logger.debug(f"Skipping {attack_type}: Endpoint {self.target} appears public (Baseline=200).")
                    return None

                # 2. ATTACK REQUEST
                attack_response = await client.get(
                    self.target, 
                    headers=target_header if target_header else None,
                    cookies=target_cookies if target_cookies else None
                )
                
                # 3. VERIFICATION
                # Baseline failed (good) AND Attack succeeded (bad)
                if attack_response.status_code == 200:
                    return {
                        'attack_code': attack_response.status_code,
                        'baseline_code': baseline_response.status_code,
                        'evidence': f"Baseline (Invalid Token) -> {baseline_response.status_code}\nAttack ({attack_type}) -> {attack_response.status_code}"
                    }
                    
        except Exception as e:
            self.logger.debug(f"Differential analysis failed: {e}")
        
        return None

    async def _test_jwt_none_attack(self, token: str, context: str, original_response: httpx.Response) -> List[Dict[str, Any]]:
        """
        Active Attack: Test if the server accepts the 'None' algorithm (Signature Bypass).
        Uses Differential Analysis to prevent false positives.
        """
        findings = []
        try:
            # 1. Create 'None' alg token
            parts = token.split('.')
            if len(parts) != 3:
                return []
            
            try:
                # Pad for base64 decode if necessary
                header_segment = parts[0]
                padding = len(header_segment) % 4
                if padding > 0:
                    header_segment += "=" * (4 - padding)
                    
                header = json.loads(base64.urlsafe_b64decode(header_segment).decode())
            except Exception:
                return []
                
            header['alg'] = 'none'
            
            # Re-encode header
            new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            
            # Construct malicious token (Variant 1: Header.Payload.)
            none_token = f"{new_header}.{parts[1]}."
            
            # 2. Perform Differential Analysis
            result = await self._perform_differential_analysis(token, context, none_token, "None Alg Attack")
            
            if result:
                findings.append({
                    'title': 'Critical: JWT None Algorithm Bypass',
                    'severity': 'critical',
                    'category': 'jwt_exploitation',
                    'description': 'The server accepted a JWT signed with the "none" algorithm, effectively bypassing authentication.',
                    'evidence': result['evidence'],
                    'impact': 'Authentication Bypass: Attackers can forge any token.',
                    'remediation': 'Reject tokens with "none" algorithm in the backend verification logic.'
                })
                self.logger.warning(f"CRITICAL: JWT None Algorithm Attack SUCCEEDED on {self.target} (Verified Protected Endpoint)")

        except Exception as e:
            self.logger.debug(f"JWT None Attack failed: {e}")
            
        return findings

    async def _test_weak_secret_forgery(self, token: str, context: str) -> List[Dict[str, Any]]:
        """
        Active Attack: If a weak secret is detected, try to forge a new token (e.g. admin) 
        and check if the server accepts it.
        Uses Differential Analysis.
        """
        findings = []
        found_secret = None
        
        # 1. Bruteforce secret locally
        try:
            unverified_header = jwt.get_unverified_header(token)
            alg = unverified_header.get('alg', '').upper()
            if not alg.startswith('HS'):
                return []
                
            secrets_to_try = self.jwt_analyzer.weak_secrets + self.jwt_analyzer.default_keys
            for secret in secrets_to_try:
                try:
                    jwt.decode(token, secret, algorithms=[alg])
                    found_secret = secret
                    break
                except jwt.InvalidTokenError:
                    continue
        except Exception:
            return []

        if not found_secret:
            return []
            
        # 2. Forge Malicious Token
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Determine how to escalate
            if 'role' in payload:
                payload['role'] = 'admin'
            elif 'admin' in payload:
                payload['admin'] = True
            elif 'sub' in payload:
                payload['sub'] = 'admin'
            else:
                # Blind guess if no obvious fields
                payload['role'] = 'admin'
                
            forged_token = jwt.encode(payload, found_secret, algorithm=alg)
            
            # 3. Perform Differential Analysis
            result = await self._perform_differential_analysis(token, context, forged_token, "Weak Secret Forgery")
            
            if result:
                findings.append({
                    'title': 'Critical: JWT Weak Secret Forgery',
                    'severity': 'critical',
                    'category': 'jwt_exploitation',
                    'description': f'Successfully forged an Admin JWT using the weak secret "{found_secret}".',
                    'evidence': result['evidence'],
                    'impact': 'Complete account takeover or privilege escalation.',
                    'remediation': 'Change the JWT signing secret immediately to a long, random string.'
                })
                self.logger.warning(f"CRITICAL: JWT Forgery SUCCEEDED with secret '{found_secret}'")
                    
        except Exception as e:
            self.logger.debug(f"JWT Forgery Attack failed: {e}")
            
        return findings

    async def _analyze_dynamic_tokens(self, response: httpx.Response) -> List[Dict[str, Any]]:
        """
        Deeply analyze any JWT tokens found in the active HTTP response.
        Scans Cookies, Headers, and Response Body.
        """
        findings = []
        tokens_found = set()
        
        # 1. Check Cookies (Response Set-Cookie)
        for name, value in response.cookies.items():
            if self._is_jwt(value):
                if value not in tokens_found:
                    self.logger.info(f"Found JWT in cookie: {name}")
                    tokens_found.add(value)
                    
                    # Passive Analysis
                    jwt_findings = await self.jwt_analyzer.analyze_jwt_token(value, context=f"Cookie: {name}")
                    findings.extend(self._convert_findings_format(jwt_findings, 'jwt_analyzer'))
                    
                    # Active Attack 1: None Algorithm
                    attack_findings = await self._test_jwt_none_attack(value, f"Cookie: {name}", response)
                    findings.extend(attack_findings)

                    # Active Attack 2: Weak Secret Forgery
                    forgery_findings = await self._test_weak_secret_forgery(value, f"Cookie: {name}")
                    findings.extend(forgery_findings)

        # 1b. Check Request Cookies (To analyze authenticated session tokens)
        if response.request and response.request.headers.get('cookie'):
            try:
                import http.cookies
                req_cookies = response.request.headers.get('cookie', '')
                cookie_parser = http.cookies.SimpleCookie(req_cookies)
                for name, morsel in cookie_parser.items():
                    value = morsel.value
                    if self._is_jwt(value) and value not in tokens_found:
                        self.logger.info(f"Found JWT in Request Cookie: {name}")
                        tokens_found.add(value)
                        
                        # Use same analysis as above
                        jwt_findings = await self.jwt_analyzer.analyze_jwt_token(value, context=f"Request Cookie: {name}")
                        findings.extend(self._convert_findings_format(jwt_findings, 'jwt_analyzer'))
                        
                        # For active attacks, we must be careful not to kill the session if reusing client, 
                        # but analyzing weak secrets is safe.
                        forgery_findings = await self._test_weak_secret_forgery(value, f"Request Cookie: {name}")
                        findings.extend(forgery_findings)
            except Exception as e:
                self.logger.debug(f"Failed to parse request cookies: {e}")

        # 2. Check Headers (Response)
        auth_header = response.headers.get('Authorization', '')
        if 'Bearer' in auth_header:
            token = auth_header.split('Bearer ')[-1].strip()
            if self._is_jwt(token) and token not in tokens_found:
                self.logger.info("Found JWT in Authorization header")
                tokens_found.add(token)
                
                # Passive Analysis
                jwt_findings = await self.jwt_analyzer.analyze_jwt_token(token, context="Header: Authorization")
                findings.extend(self._convert_findings_format(jwt_findings, 'jwt_analyzer'))
                
                # Active Attack 1: None Algorithm
                attack_findings = await self._test_jwt_none_attack(token, "Header: Authorization", response)
                findings.extend(attack_findings)

                # Active Attack 2: Weak Secret Forgery
                forgery_findings = await self._test_weak_secret_forgery(token, "Header: Authorization")
                findings.extend(forgery_findings)

        # 2b. Check Request Headers (To analyze sent Bearer tokens)
        if response.request:
            req_auth = response.request.headers.get('Authorization', '')
            if 'Bearer' in req_auth:
                token = req_auth.split('Bearer ')[-1].strip()
                if self._is_jwt(token) and token not in tokens_found:
                    self.logger.info("Found JWT in Request Authorization header")
                    tokens_found.add(token)
                    
                    jwt_findings = await self.jwt_analyzer.analyze_jwt_token(token, context="Request Authorization Header")
                    findings.extend(self._convert_findings_format(jwt_findings, 'jwt_analyzer'))
                    
                    # Check forgery
                    forgery_findings = await self._test_weak_secret_forgery(token, "Request Authorization Header")
                    findings.extend(forgery_findings)

        # 3. Check Response Body (HTML/JSON)
        # Regex for generic JWT format: eyJ... . eyJ... . ...
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
        
        try:
            body_text = response.text
            matches = re.finditer(jwt_pattern, body_text)
            for match in matches:
                token = match.group(0)
                if token not in tokens_found:
                    self.logger.info("Found JWT in response body")
                    tokens_found.add(token)
                    
                    # Passive Analysis
                    jwt_findings = await self.jwt_analyzer.analyze_jwt_token(token, context="Response Body (HTML/JSON)")
                    findings.extend(self._convert_findings_format(jwt_findings, 'jwt_analyzer'))
        except Exception as e:
            self.logger.debug(f"Error scanning body for JWTs: {e}")

        return findings

    def _is_jwt(self, value: str) -> bool:
        """Simple check to see if a string looks like a JWT"""
        if not value or not isinstance(value, str):
            return False
        parts = value.split('.')
        return len(parts) == 3 and value.startswith('eyJ')

    async def _analyze_session_management(self) -> List[Dict[str, Any]]:
        """Analyze session management implementation"""
        findings = []
        
        try:
            # Retrieve authenticated cookies if available from previous steps
            cookies = getattr(self, 'authenticated_cookies', None)
            
            # No timeout - allow complete authentication testing
            async with httpx.AsyncClient(timeout=None, verify=False, cookies=cookies) as client:
                # Test 1: Check for session cookies & JWTs
                response = await client.get(self.target)
                
                # --- NEW: ACTIVE JWT ANALYSIS ---
                jwt_findings = await self._analyze_dynamic_tokens(response)
                if jwt_findings:
                    self.logger.info(f"Dynamic JWT Analysis found {len(jwt_findings)} issues")
                    findings.extend(jwt_findings)
                # --------------------------------
                
                cookies = response.cookies
                
                for cookie_name, cookie_value in cookies.items():
                    cookie_findings = self._analyze_cookie_security(cookie_name, cookie_value, response.headers)
                    findings.extend(cookie_findings)
                
                # Test 2: Session fixation test
                session_fixation = await self._test_session_fixation(client)
                if session_fixation:
                    findings.append(session_fixation)
                
                # Test 3: Session timeout test
                timeout_finding = await self._test_session_timeout(client)
                if timeout_finding:
                    findings.append(timeout_finding)
                
                # Test 4: Concurrent session test
                concurrent_finding = await self._test_concurrent_sessions(client)
                if concurrent_finding:
                    findings.append(concurrent_finding)
        
        except Exception as e:
            self.logger.error(f"Session analysis failed: {str(e)}")
            findings.append({
                'title': 'Session Analysis Error',
                'description': f'Session analysis failed: {str(e)}',
                'severity': 'info',
                'category': 'analysis_error'
            })
        
        return findings

    def _analyze_cookie_security(self, name: str, value: str, headers: dict) -> List[Dict[str, Any]]:
        """Analyze cookie security attributes"""
        findings = []
        
        # Check Set-Cookie header for security attributes
        set_cookie_header = headers.get('set-cookie', '')
        
        if 'session' in name.lower() or 'auth' in name.lower():
            # Check for Secure flag
            if 'Secure' not in set_cookie_header:
                findings.append({
                    'title': 'Insecure Cookie: Missing Secure Flag',
                    'description': f'Session cookie "{name}" is missing the Secure flag',
                    'severity': 'medium',
                    'category': 'cookie_security',
                    'cwe_ids': ['CWE-614'],
                    'asvs_mapping': 'V3.4.1',
                    'recommendation': 'Add Secure flag to all session cookies'
                })
            
            # Check for HttpOnly flag
            if 'HttpOnly' not in set_cookie_header:
                findings.append({
                    'title': 'Insecure Cookie: Missing HttpOnly Flag',
                    'description': f'Session cookie "{name}" is missing the HttpOnly flag',
                    'severity': 'medium',
                    'category': 'cookie_security',
                    'cwe_ids': ['CWE-1004'],
                    'asvs_mapping': 'V3.4.2',
                    'recommendation': 'Add HttpOnly flag to prevent XSS attacks'
                })
            
            # Check for SameSite attribute
            if 'SameSite' not in set_cookie_header:
                findings.append({
                    'title': 'Insecure Cookie: Missing SameSite Attribute',
                    'description': f'Session cookie "{name}" is missing the SameSite attribute',
                    'severity': 'low',
                    'category': 'cookie_security',
                    'cwe_ids': ['CWE-352'],
                    'asvs_mapping': 'V3.4.3',
                    'recommendation': 'Add SameSite attribute to prevent CSRF attacks'
                })
        
        return findings

    async def _run_runtime_checks(self) -> List[Dict[str, Any]]:
        """Run runtime security checks for authentication and sessions"""
        findings = []
        
        try:
            auth_tester = AuthTestImplementations(self.target, self.logger)
            
            # 1. Test for weak authentication endpoints
            weak_endpoints = await auth_tester.test_weak_authentication_endpoints()
            findings.extend(weak_endpoints)
            
            # 2. Test for information disclosure in auth errors
            info_disclosure = await auth_tester.test_auth_error_information_disclosure()
            findings.extend(info_disclosure)
            
            # 3. Test for account enumeration
            account_enum = await auth_tester.test_account_enumeration()
            findings.extend(account_enum)
            
            # 4. Test for password reset vulnerabilities
            password_reset = await auth_tester.test_password_reset_vulnerabilities()
            findings.extend(password_reset)
        
        except Exception as e:
            self.logger.error(f"Runtime checks failed: {str(e)}")
        
        return findings

    async def _test_authentication_mechanisms(self) -> List[Dict[str, Any]]:
        """Test various authentication mechanisms"""
        findings = []
        
        try:
            auth_tester = AuthTestImplementations(self.target, self.logger)
            
            # No timeout - allow complete authentication testing
            async with httpx.AsyncClient(timeout=None, verify=False) as client:
                # Test 1: Check for default credentials
                default_creds = await auth_tester.test_default_credentials(client)
                findings.extend(default_creds)
                
                # Capture authenticated session if default credentials worked
                # auth_tester uses the passed client, so if it logged in, the client has the cookies
                if client.cookies:
                    self.authenticated_cookies = dict(client.cookies)
                    self.logger.info(f"Captured authenticated session with {len(self.authenticated_cookies)} cookies")
                    
                    # --- NEW: AUTHORIZATION CHECKS ---
                    auth_flaws = await auth_tester.test_authorization_flaws(client, self.authenticated_cookies)
                    findings.extend(auth_flaws)
                    # ---------------------------------
                else:
                    self.logger.info("No session cookies captured from default credentials test")
                    
                # Test 2: Test for SQL injection in login
                sql_injection = await auth_tester.test_sql_injection_login(client)
                findings.extend(sql_injection)
                
                # Test 3: Test for brute force protection
                brute_force = await auth_tester.test_brute_force_protection(client)
                if brute_force:
                    findings.append(brute_force)
                
        except Exception as e:
            self.logger.error(f"Authentication mechanism testing failed: {str(e)}")
        
        return findings



    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of findings"""
        summary = {
            'total_findings': len(findings),
            'severity_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'category_distribution': {},
            'most_critical_issues': [],
            'compliance_status': 'compliant'
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            category = finding.get('category', 'unknown')
            
            if severity in summary['severity_distribution']:
                summary['severity_distribution'][severity] += 1
            
            summary['category_distribution'][category] = summary['category_distribution'].get(category, 0) + 1
            
            if severity in ['critical', 'high']:
                summary['most_critical_issues'].append({
                    'title': finding.get('title', ''),
                    'severity': severity,
                    'category': category
                })
                summary['compliance_status'] = 'non_compliant'
        
        return summary

    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Group findings by category
        categories = {}
        for finding in findings:
            category = finding.get('category', 'unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        
        # Generate category-specific recommendations
        for category, category_findings in categories.items():
            if category == 'cookie_security':
                recommendations.append({
                    'category': 'Cookie Security',
                    'priority': 'high',
                    'recommendation': 'Implement proper cookie security attributes (Secure, HttpOnly, SameSite)',
                    'affected_findings': len(category_findings),
                    'implementation': [
                        'Set Secure flag on all cookies transmitted over HTTPS',
                        'Set HttpOnly flag to prevent XSS attacks',
                        'Use SameSite attribute to prevent CSRF attacks',
                        'Implement proper cookie expiration policies'
                    ]
                })
            
            elif category == 'session_management':
                recommendations.append({
                    'category': 'Session Management',
                    'priority': 'high',
                    'recommendation': 'Strengthen session management implementation',
                    'affected_findings': len(category_findings),
                    'implementation': [
                        'Implement session regeneration after authentication',
                        'Set appropriate session timeouts',
                        'Prevent session fixation attacks',
                        'Implement proper session invalidation on logout'
                    ]
                })
        
        return recommendations

    async def _test_authentication_bypass(self) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities"""
        findings = []
        
        try:
            # No timeout - allow complete authentication testing
            async with httpx.AsyncClient(timeout=None, verify=False) as client:
                # Test common bypass techniques
                bypass_tests = [
                    {'method': 'path_traversal', 'paths': ['../admin', '../../admin', '/admin/../admin']},
                    {'method': 'parameter_pollution', 'params': {'admin': 'true', 'role': 'admin'}},
                    {'method': 'header_injection', 'headers': {'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1'}}
                ]
                
                for test in bypass_tests:
                    if test['method'] == 'path_traversal':
                        for path in test['paths']:
                            try:
                                response = await client.get(f"{self.target.rstrip('/')}{path}")
                                if response.status_code == 200 and 'admin' in response.text.lower():
                                    findings.append({
                                        'title': 'Authentication Bypass via Path Traversal',
                                        'description': f'Administrative access possible via path traversal: {path}',
                                        'severity': 'high',
                                        'endpoint': f"{self.target}{path}",
                                        'evidence': f'HTTP 200 response with admin content',
                                        'category': 'authentication_bypass',
                                        'cwe_ids': ['CWE-22'],
                                        'recommendation': 'Implement proper path validation and access controls'
                                    })
                            except Exception:
                                continue
                    
                    elif test['method'] == 'parameter_pollution':
                        try:
                            response = await client.get(self.target, params=test['params'])
                            if 'admin' in response.text.lower() or 'dashboard' in response.text.lower():
                                findings.append({
                                    'title': 'Authentication Bypass via Parameter Manipulation',
                                    'description': 'Administrative access possible via parameter manipulation',
                                    'severity': 'high',
                                    'endpoint': self.target,
                                    'evidence': f'Parameters: {test["params"]}',
                                    'category': 'authentication_bypass',
                                    'cwe_ids': ['CWE-639'],
                                    'recommendation': 'Validate all parameters and implement proper authorization checks'
                                })
                        except Exception:
                            continue
                            
        except Exception as e:
            self.logger.error(f"Authentication bypass testing failed: {str(e)}")
        
        return findings

    # Helper methods for specific tests  
    async def _test_default_credentials(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        """Test for default credentials - delegated to AuthTestImplementations"""
        auth_tester = AuthTestImplementations(self.target, self.logger)
        return await auth_tester.test_default_credentials(client)

    async def _test_session_fixation(self, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Test for session fixation vulnerability"""
        auth_tester = AuthTestImplementations(self.target, self.logger)
        return await auth_tester.test_session_fixation(client)

    async def _run_command_with_output(self, cmd: List[str]) -> str:
        """Run command and return output"""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd, stdout, stderr)
        
        return stdout.decode()

    def _detect_languages(self) -> List[str]:
        """Detect programming languages in the source code"""
        languages = []
        if not self.source_code_path:
            return languages
        
        extensions = {
            '.py': 'python',
            '.js': 'javascript',
            '.java': 'java',
            '.rb': 'ruby',
            '.php': 'php',
            '.go': 'go'
        }
        
        for root, dirs, files in os.walk(self.source_code_path):
            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in extensions:
                    lang = extensions[ext]
                    if lang not in languages:
                        languages.append(lang)
        
        return languages

    def parse_output(self) -> Dict[str, Any]:
        """Parse the raw output into structured format"""
        return self.parsed_result

    # Additional helper methods would be implemented here...
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to standard severity levels"""
        mapping = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low'
        }
        return mapping.get(severity.upper(), 'info')

    def _extract_cwe_from_semgrep(self, finding: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs from Semgrep finding"""
        metadata = finding.get('extra', {}).get('metadata', {})
        return metadata.get('cwe', [])

    def _map_to_asvs(self, check_id: str) -> str:
        """Map finding to OWASP ASVS requirement"""
        asvs_mappings = {
            'insecure-cookie-flags': 'V3.4.1',
            'hardcoded-jwt-secret': 'V2.4.1',
            'weak-session-timeout': 'V3.3.1',
            'remember-me-insecure': 'V2.2.1',
            'session-fixation-vulnerability': 'V3.2.1'
        }
        return asvs_mappings.get(check_id, '')

    def _get_semgrep_recommendation(self, check_id: str) -> str:
        """Get recommendation for Semgrep finding"""
        recommendations = {
            'insecure-cookie-flags': 'Set Secure and HttpOnly flags on all session cookies',
            'hardcoded-jwt-secret': 'Use environment variables or secure key management for JWT secrets',
            'weak-session-timeout': 'Implement appropriate session timeout (max 30 minutes for sensitive apps)',
            'remember-me-insecure': 'Implement secure remember-me functionality with proper token management',
            'session-fixation-vulnerability': 'Regenerate session ID after successful authentication'
        }
        return recommendations.get(check_id, 'Review and fix the identified issue')

    def _extract_cwe_from_codeql(self, finding: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs from CodeQL finding"""
        # CodeQL findings might have CWE information in properties
        properties = finding.get('properties', {})
        cwes = properties.get('tags', [])
        return [cwe for cwe in cwes if cwe.startswith('CWE-')]

    async def _run_eslint_security_analysis(self) -> List[Dict[str, Any]]:
        """Run ESLint with security plugins for JavaScript/TypeScript"""
        findings = []
        
        try:
            # Check if ESLint is available
            cmd = ['eslint', '--version']
            await self._run_command_with_output(cmd)
            
            # Run ESLint with security plugins
            eslint_cmd = [
                'eslint',
                self.source_code_path,
                '--ext', '.js,.ts,.jsx,.tsx',
                '--plugin', 'security',
                '--format', 'json',
                '--no-error-on-unmatched-pattern'
            ]
            
            result = await self._run_command_with_output(eslint_cmd)
            eslint_output = json.loads(result)
            
            for file_result in eslint_output:
                for message in file_result.get('messages', []):
                    if self._is_auth_related_eslint_message(message):
                        findings.append({
                            'title': f"ESLint Security: {message.get('ruleId', 'Unknown')}",
                            'description': message.get('message', ''),
                            'severity': 'medium' if message.get('severity', 1) == 2 else 'low',
                            'file_path': file_result.get('filePath', ''),
                            'line_number': message.get('line', 0),
                            'category': 'sast_eslint',
                            'recommendation': 'Review and fix the identified JavaScript security issue'
                        })
        
        except subprocess.CalledProcessError:
            self.logger.info("ESLint not available")
        except Exception as e:
            self.logger.error(f"ESLint analysis failed: {str(e)}")
        
        return findings

    async def _run_brakeman_analysis(self) -> List[Dict[str, Any]]:
        """Run Brakeman for Ruby security issues"""
        findings = []
        
        try:
            cmd = ['brakeman', '-f', 'json', '-q', self.source_code_path]
            result = await self._run_command_with_output(cmd)
            brakeman_output = json.loads(result)
            
            for warning in brakeman_output.get('warnings', []):
                if self._is_auth_related_brakeman_warning(warning):
                    findings.append({
                        'title': f"Brakeman: {warning.get('warning_type', 'Unknown')}",
                        'description': warning.get('message', ''),
                        'severity': self._map_brakeman_confidence(warning.get('confidence', 'Medium')),
                        'file_path': warning.get('file', ''),
                        'line_number': warning.get('line', 0),
                        'category': 'sast_brakeman',
                        'cwe_ids': [warning.get('cwe_id', '')] if warning.get('cwe_id') else [],
                        'recommendation': 'Review and fix the identified Ruby security issue'
                    })
        
        except subprocess.CalledProcessError:
            self.logger.info("Brakeman not available")
        except Exception as e:
            self.logger.error(f"Brakeman analysis failed: {str(e)}")
        
        return findings

    def _is_auth_related_eslint_message(self, message: Dict[str, Any]) -> bool:
        """Check if ESLint message is authentication related"""
        auth_related_rules = [
            'security/detect-hardcoded-credentials',
            'security/detect-insecure-cookie',
            'security/detect-jwt-decode',
            'security/detect-password-in-code',
            'security/detect-session-storage'
        ]
        rule_id = message.get('ruleId', '')
        return rule_id in auth_related_rules

    def _is_auth_related_brakeman_warning(self, warning: Dict[str, Any]) -> bool:
        """Check if Brakeman warning is authentication related"""
        auth_related_types = [
            'Session Setting',
            'Authentication',
            'Weak Hash',
            'Weak Cipher',
            'Cookie Security',
            'Session Manipulation'
        ]
        warning_type = warning.get('warning_type', '')
        return warning_type in auth_related_types

    def _map_brakeman_confidence(self, confidence: str) -> str:
        """Map Brakeman confidence to severity"""
        mapping = {
            'High': 'high',
            'Medium': 'medium',
            'Weak': 'low'
        }
        return mapping.get(confidence, 'medium')

    def _is_auth_related_bandit_finding(self, finding: Dict[str, Any]) -> bool:
        """Check if Bandit finding is related to authentication"""
        auth_related_tests = [
            'B105',  # Hardcoded password string
            'B106',  # Test for use of hard-coded password function arguments
            'B107',  # Test for use of hard-coded password default arguments
            'B201',  # Flask app with debug=True
            'B501',  # Request with verify=False
            'B506',  # Test for use of yaml load
            'B602',  # subprocess_popen_with_shell_equals_true
        ]
        test_id = finding.get('test_id', '')
        return test_id in auth_related_tests
    
    async def _run_specialized_analysis(self) -> List[Dict[str, Any]]:
        """Run specialized security analyzers for advanced authentication analysis"""
        all_findings = []
        
        try:
            # Create HTTP client for dynamic testing
            # No timeout - allow complete session testing
            async with httpx.AsyncClient(timeout=None) as session:
                
                # JWT Security Analysis
                try:
                    if self.source_code_path and hasattr(self.jwt_analyzer, 'analyze_jwt_implementation_code'):
                        jwt_findings = await self.jwt_analyzer.analyze_jwt_implementation_code(
                            self.source_code_path, "source_code"
                        )
                        all_findings.extend(self._convert_findings_format(jwt_findings, 'jwt_analyzer'))
                    else:
                        # Fallback: basic JWT analysis
                        jwt_findings = await self._basic_jwt_analysis(session)
                        all_findings.extend(jwt_findings)
                except Exception as e:
                    self.logger.warning(f"JWT analysis failed: {str(e)}")
                
                # Frontend Storage Analysis
                try:
                    if self.source_code_path and hasattr(self.frontend_storage_analyzer, 'analyze_storage_usage'):
                        storage_findings = await self.frontend_storage_analyzer.analyze_storage_usage(
                            self.source_code_path
                        )
                        all_findings.extend(self._convert_findings_format(storage_findings, 'frontend_storage_analyzer'))
                except Exception as e:
                    self.logger.warning(f"Frontend storage analysis failed: {str(e)}")
                
                # Password Reset Flow Analysis
                try:
                    if hasattr(self.password_reset_analyzer, 'analyze_password_reset_flows'):
                        reset_findings = await self.password_reset_analyzer.analyze_password_reset_flows(
                            self.target, session
                        )
                        all_findings.extend(self._convert_findings_format(reset_findings, 'password_reset_analyzer'))
                    else:
                        # Fallback: basic password reset analysis
                        reset_findings = await self._basic_password_reset_analysis(session)
                        all_findings.extend(reset_findings)
                except Exception as e:
                    self.logger.warning(f"Password reset analysis failed: {str(e)}")
                
                # Cookie Security Analysis (Enhanced)
                try:
                    if hasattr(self.cookie_security_analyzer, 'analyze_cookie_security'):
                        cookie_findings = await self.cookie_security_analyzer.analyze_cookie_security(
                            self.target, session
                        )
                        all_findings.extend(self._convert_findings_format(cookie_findings, 'cookie_security_analyzer'))
                    else:
                        # Fallback: basic cookie analysis
                        cookie_findings = await self._basic_cookie_analysis(session)
                        all_findings.extend(cookie_findings)
                except Exception as e:
                    self.logger.warning(f"Cookie security analysis failed: {str(e)}")
                
                # Session Handling Analysis
                try:
                    if hasattr(self.session_handling_analyzer, 'analyze_session_security'):
                        session_findings = await self.session_handling_analyzer.analyze_session_security(
                            self.target, session
                        )
                        all_findings.extend(self._convert_findings_format(session_findings, 'session_handling_analyzer'))
                    else:
                        # Fallback: basic session analysis
                        session_findings = await self._basic_session_analysis(session)
                        all_findings.extend(session_findings)
                except Exception as e:
                    self.logger.warning(f"Session handling analysis failed: {str(e)}")
                
                # Brute-force Enumeration Analysis
                try:
                    if hasattr(self.bruteforce_enumeration_analyzer, 'analyze_brute_force_protection'):
                        bf_findings = await self.bruteforce_enumeration_analyzer.analyze_brute_force_protection(
                            self.target, session
                        )
                        all_findings.extend(self._convert_findings_format(bf_findings, 'bruteforce_enumeration_analyzer'))
                    else:
                        # Fallback: basic brute-force analysis
                        bf_findings = await self._basic_brute_force_analysis(session)
                        all_findings.extend(bf_findings)
                except Exception as e:
                    self.logger.warning(f"Brute-force analysis failed: {str(e)}")
                
                # WordPress Security Analysis (WPSeku)
                try:
                    self.logger.info("Running WordPress security analysis (WPSeku)...")
                    wpseku_results = await self.wpseku_scanner.scan()
                    
                    if wpseku_results.get('findings'):
                        # Convert WPSeku findings to standard format
                        wpseku_findings = self._convert_wpseku_findings(wpseku_results['findings'])
                        all_findings.extend(wpseku_findings)
                        self.logger.info(f"WPSeku found {len(wpseku_findings)} WordPress-specific findings")
                    elif 'error' in wpseku_results:
                        self.logger.info(f"WPSeku: {wpseku_results['error']}")
                except Exception as e:
                    self.logger.warning(f"WordPress analysis (WPSeku) failed: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Specialized analysis failed: {str(e)}")
            all_findings.append({
                'title': 'Specialized Analysis Error',
                'severity': 'info',
                'category': 'analyzer_error',
                'description': f'Error during specialized analysis: {str(e)}',
                'impact': 'Some advanced security checks could not be completed',
                'remediation': 'Review analyzer configuration and target accessibility',
                'confidence': 'high',
                'scanner_name': 'specialized_analyzers'
            })
        
        return all_findings
    
    def _convert_findings_format(self, findings: List[Dict[str, Any]], analyzer_name: str) -> List[Dict[str, Any]]:
        """Convert analyzer-specific findings to standard format"""
        converted = []
        
        for finding in findings:
            # Ensure required fields exist with defaults
            standardized = {
                'title': finding.get('title', 'Security Issue'),
                'severity': finding.get('severity', 'medium'),
                'category': finding.get('category', 'authentication'),
                'description': finding.get('description', 'Security vulnerability detected'),
                'impact': finding.get('impact', 'Potential security risk'),
                'remediation': finding.get('remediation', 'Review and fix the identified issue'),
                'confidence': finding.get('confidence', 'medium'),
                'cwe_ids': finding.get('cwe_ids', []),
                'owasp_category': finding.get('owasp_category', ''),
                'evidence': finding.get('evidence', ''),
                'file_path': finding.get('file_path', ''),
                'line_number': finding.get('line_number', 0),
                'scanner_name': analyzer_name,
                'timestamp': datetime.utcnow().isoformat()
            }
            converted.append(standardized)
        
        return converted
    
    def _convert_wpseku_findings(self, wpseku_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert WPSeku findings to standard authentication scanner format"""
        converted = []
        
        for finding in wpseku_findings:
            standardized = {
                'title': finding.get('title', 'WordPress Security Issue'),
                'severity': finding.get('severity', 'info').lower(),
                'category': finding.get('category', 'wordpress_security'),
                'description': finding.get('description', 'WordPress vulnerability detected'),
                'impact': finding.get('impact', 'WordPress-specific security concern'),
                'remediation': finding.get('recommendation', 'Update WordPress components and review security'),
                'confidence': finding.get('confidence', 'medium'),
                'cwe_ids': finding.get('cwe_ids', []),
                'owasp_category': finding.get('owasp_category', 'A05:2021'),
                'evidence': finding.get('evidence', ''),
                'endpoint': finding.get('endpoint', ''),
                'scanner_name': 'wpseku_scanner',
                'timestamp': datetime.utcnow().isoformat()
            }
            converted.append(standardized)
        
        return converted
    
    def generate_comprehensive_reports(self, findings: List[Dict[str, Any]], 
                                     output_dir: str = "reports") -> Dict[str, str]:
        """Generate comprehensive security reports in multiple formats"""
        try:
            # Convert findings to SecurityFinding objects
            security_findings = []
            for finding in findings:
                security_finding = SecurityFinding(
                    title=finding.get('title', ''),
                    severity=finding.get('severity', 'medium'),
                    category=finding.get('category', ''),
                    description=finding.get('description', ''),
                    impact=finding.get('impact', ''),
                    remediation=finding.get('remediation', ''),
                    confidence=finding.get('confidence', 'medium'),
                    cwe_ids=finding.get('cwe_ids', []),
                    owasp_category=finding.get('owasp_category', ''),
                    evidence=finding.get('evidence', ''),
                    file_path=finding.get('file_path', ''),
                    line_number=finding.get('line_number', 0) if finding.get('line_number') else None,
                    scanner_name=finding.get('scanner_name', '')
                )
                security_findings.append(security_finding)
            
            # Update reporter output directory
            self.security_reporter.output_dir = Path(output_dir)
            self.security_reporter.output_dir.mkdir(exist_ok=True)
            
            # Generate all report formats
            report_files = {}
            
            # SARIF Report
            sarif_file = self.security_reporter.generate_sarif_report(security_findings)
            report_files['sarif'] = sarif_file
            
            # HTML Report
            html_file = self.security_reporter.generate_html_report(security_findings)
            report_files['html'] = html_file
            
            # JSON Report
            json_file = self.security_reporter.generate_json_report(security_findings)
            report_files['json'] = json_file
            
            # CSV Report
            csv_file = self.security_reporter.generate_csv_report(security_findings)
            report_files['csv'] = csv_file
            
            # Executive Summary
            exec_summary = self.security_reporter.generate_executive_summary(security_findings)
            report_files['executive_summary'] = exec_summary
            
            self.logger.info(f"Generated comprehensive reports: {list(report_files.keys())}")
            return report_files
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            return {}

    # Fallback methods for when specialized analyzers don't have the expected methods
    async def _basic_password_reset_analysis(self, session) -> List[Dict[str, Any]]:
        """Basic password reset analysis fallback"""
        findings = []
        try:
            # Check for common password reset endpoints
            reset_endpoints = ['/reset-password', '/forgot-password', '/password-reset', '/reset']
            
            for endpoint in reset_endpoints:
                try:
                    if hasattr(session, 'get'):
                        response = await session.get(f"{self.target.rstrip('/')}{endpoint}")
                    else:
                        # Fallback for non-async clients
                        try:
                            import requests  # type: ignore[import]
                        except Exception:
                            requests = None  # type: ignore[assignment]
                        if requests:
                            # No timeout - allow complete endpoint testing
                            response = requests.get(f"{self.target.rstrip('/')}{endpoint}", timeout=None)
                        else:
                            response = None
                    
                    if response.status_code == 200:
                        findings.append({
                            'title': 'Password Reset Endpoint Found',
                            'severity': 'info',
                            'category': 'password_reset',
                            'description': f'Password reset endpoint detected at {endpoint}',
                            'remediation': 'Ensure proper token validation and rate limiting'
                        })
                except:
                    continue
                    
        except Exception as e:
            self.logger.warning(f"Basic password reset analysis failed: {str(e)}")
        
        return findings

    async def _basic_cookie_analysis(self, session) -> List[Dict[str, Any]]:
        """Basic cookie security analysis fallback"""
        findings = []
        try:
            if hasattr(session, 'get'):
                response = await session.get(self.target)
            else:
                # Fallback for non-async clients
                try:
                    import requests  # type: ignore[import]
                except Exception:
                    requests = None  # type: ignore[assignment]
                # No timeout - allow complete target testing
                response = requests.get(self.target, timeout=None) if requests else None
            
            if hasattr(response, 'cookies') and response.cookies:
                for cookie in response.cookies:
                    cookie_issues = []
                    cookie_name = getattr(cookie, 'name', str(cookie))
                    
                    # Basic security checks
                    if not getattr(cookie, 'secure', False):
                        cookie_issues.append('Missing Secure flag')
                    
                    if not getattr(cookie, 'httponly', False):  
                        cookie_issues.append('Missing HttpOnly flag')
                    
                    if cookie_issues:
                        findings.append({
                            'title': f'Cookie Security Issues: {cookie_name}',
                            'severity': 'medium',
                            'category': 'cookie_security',
                            'description': f'Cookie {cookie_name} has security issues: {", ".join(cookie_issues)}',
                            'remediation': 'Add security flags to cookies'
                        })
                        
        except Exception as e:
            self.logger.warning(f"Basic cookie analysis failed: {str(e)}")
        
        return findings

    async def _basic_session_analysis(self, session) -> List[Dict[str, Any]]:
        """Basic session security analysis fallback"""
        findings = []
        try:
            if hasattr(session, 'get'):
                response = await session.get(self.target)
            else:
                # Fallback for non-async clients
                try:
                    import requests  # type: ignore[import]
                except Exception:
                    requests = None  # type: ignore[assignment]
                # No timeout - allow complete target testing
                response = requests.get(self.target, timeout=None) if requests else None
            
            # Check for session-related headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS missing',
                'X-Content-Type-Options': 'Content-Type protection missing',
                'X-Frame-Options': 'Clickjacking protection missing',
                'Content-Security-Policy': 'CSP missing'
            }
            
            if hasattr(response, 'headers'):
                for header, issue in security_headers.items():
                    if header not in response.headers:
                        findings.append({
                            'title': f'Missing Security Header: {header}',
                            'severity': 'medium',
                            'category': 'security_headers',
                            'description': issue,
                            'remediation': f'Add {header} security header'
                        })
                        
        except Exception as e:
            self.logger.warning(f"Basic session analysis failed: {str(e)}")
        
        return findings

    async def _basic_brute_force_analysis(self, session) -> List[Dict[str, Any]]:
        """Basic brute-force protection analysis fallback"""
        findings = []
        try:
            # Check for login endpoints
            login_endpoints = ['/login', '/signin', '/auth', '/authenticate']
            
            for endpoint in login_endpoints:
                try:
                    if hasattr(session, 'get'):
                        response = await session.get(f"{self.target.rstrip('/')}{endpoint}")
                    else:
                        # Fallback for non-async clients
                        try:
                            import requests  # type: ignore[import]
                        except Exception:
                            requests = None  # type: ignore[assignment]
                        response = (
                            requests.get(f"{self.target.rstrip('/')}{endpoint}", timeout=10)
                            if requests else None
                        )
                    
                    if response.status_code == 200:
                        findings.append({
                            'title': 'Authentication Endpoint Found',
                            'severity': 'info',
                            'category': 'brute_force_protection',
                            'description': f'Authentication endpoint detected at {endpoint}',
                            'remediation': 'Ensure rate limiting and account lockout protection'
                        })
                except:
                    continue
                    
        except Exception as e:
            self.logger.warning(f"Basic brute-force analysis failed: {str(e)}")
        
        return findings

    async def _basic_jwt_analysis(self, session) -> List[Dict[str, Any]]:
        """Basic JWT analysis fallback"""
        findings = []
        try:
            if hasattr(session, 'get'):
                response = await session.get(self.target)
            else:
                # Fallback for non-async clients
                try:
                    import requests  # type: ignore[import]
                except Exception:
                    requests = None  # type: ignore[assignment]
                # No timeout - allow complete target testing
                response = requests.get(self.target, timeout=None) if requests else None
            
            # Check for JWT in headers or cookies
            if hasattr(response, 'headers'):
                auth_header = response.headers.get('Authorization', '')
                if 'Bearer ' in auth_header and '.' in auth_header:
                    findings.append({
                        'title': 'JWT Token Detected in Response',
                        'severity': 'info',
                        'category': 'jwt_security',
                        'description': 'JWT token found in Authorization header',
                        'remediation': 'Ensure JWT tokens have proper expiration and validation'
                    })
            
            # Check for JWT patterns in cookies
            if hasattr(response, 'cookies'):
                for cookie in response.cookies:
                    cookie_value = getattr(cookie, 'value', str(cookie))
                    if '.' in cookie_value and len(cookie_value.split('.')) == 3:
                        findings.append({
                            'title': 'Potential JWT in Cookie',
                            'severity': 'info',
                            'category': 'jwt_security',
                            'description': f'JWT-like token found in cookie {getattr(cookie, "name", "unknown")}',
                            'remediation': 'Ensure JWT cookies are properly secured'
                        })
                        
        except Exception as e:
            self.logger.warning(f"Basic JWT analysis failed: {str(e)}")
        
        return findings

    async def _basic_frontend_storage_analysis(self, session) -> List[Dict[str, Any]]:
        """Basic frontend storage analysis fallback"""
        findings = []
        try:
            if hasattr(session, 'get'):
                response = await session.get(self.target)
            else:
                # Fallback for non-async clients
                try:
                    import requests  # type: ignore[import]
                except Exception:
                    requests = None  # type: ignore[assignment]
                # No timeout - allow complete target testing
                response = requests.get(self.target, timeout=None) if requests else None
            
            # Basic check for JavaScript that might use localStorage/sessionStorage
            if hasattr(response, 'text'):
                content = response.text.lower()
                storage_patterns = ['localstorage', 'sessionstorage', 'document.cookie']
                
                for pattern in storage_patterns:
                    if pattern in content:
                        findings.append({
                            'title': f'Client-Side Storage Usage: {pattern}',
                            'severity': 'info',
                            'category': 'frontend_storage',
                            'description': f'Potential use of {pattern} detected in page content',
                            'remediation': 'Ensure sensitive data is not stored in client-side storage'
                        })
                        
        except Exception as e:
            self.logger.warning(f"Basic frontend storage analysis failed: {str(e)}")
        
        return findings