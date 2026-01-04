"""
Authentication & Session Management Test Implementations

This module contains specific test implementations for various authentication
and session management vulnerabilities.
"""

import asyncio
import json
import re
import time
from typing import Dict, Any, List, Optional, Tuple
import httpx
from bs4 import BeautifulSoup
import logging


class AuthTestImplementations:
    """Implementation of specific authentication and session tests"""
    
    def __init__(self, target: str, logger: logging.Logger, custom_credentials: Optional[Dict] = None):
        self.target = target
        self.logger = logger
        
        # Use custom credentials if provided, otherwise use common weak passwords for testing
        if custom_credentials:
            self.test_credentials = custom_credentials
        else:
            # Common weak passwords found in real-world applications
            self.test_credentials = {
                'username': 'admin',
                'password': 'admin123',
                'weak_passwords': ['password', '123456', 'admin', 'test', 'guest', 'root']
            }

    async def test_default_credentials(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        """Test for default/weak credentials"""
        findings = []
        
        # Common default credential combinations
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('guest', 'guest'),
            ('guest123', 'guest123'),
            ('test', 'test'),
            ('demo', 'demo'),
            ('user', 'user'),
            ('admin', ''),  # Empty password
            ('', 'admin'),  # Empty username
        ]
        
        # Try to find login endpoints
        login_endpoints = await self._discover_login_endpoints(client)
        
        for endpoint in login_endpoints:
            for username, password in default_creds:
                try:
                    # Test credentials
                    auth_result = await self._test_credentials(client, endpoint, username, password)
                    
                    if auth_result['success']:
                        findings.append({
                            'title': 'Default Credentials Found',
                            'description': f'Default credentials "{username}:{password}" work on {endpoint}',
                            'severity': 'critical',
                            'endpoint': endpoint,
                            'evidence': f'Username: {username}, Password: {password}',
                            'category': 'authentication',
                            'cwe_ids': ['CWE-798'],
                            'asvs_mapping': 'V2.1.1',
                            'recommendation': 'Change default credentials and enforce strong password policy'
                        })
                        break  # Don't test more creds for this endpoint if one works
                
                except Exception as e:
                    self.logger.debug(f"Error testing credentials {username}:{password} on {endpoint}: {str(e)}")
                
                # Rate limiting - don't overwhelm the server
                await asyncio.sleep(0.5)
        
        return findings

    async def test_sql_injection_login(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        """Test for SQL injection in login forms"""
        findings = []
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "') OR ('1'='1",
            "' UNION SELECT 1,2,3--",
            "admin'; DROP TABLE users;--"
        ]
        
        login_endpoints = await self._discover_login_endpoints(client)
        
        for endpoint in login_endpoints:
            for payload in sql_payloads:
                try:
                    # Test with SQL injection payload
                    result = await self._test_credentials(client, endpoint, payload, "password")
                    
                    # Check for SQL injection indicators in response
                    if self._check_sql_injection_indicators(result['response']):
                        findings.append({
                            'title': 'SQL Injection in Authentication',
                            'description': f'SQL injection vulnerability detected in login form at {endpoint}',
                            'severity': 'critical',
                            'endpoint': endpoint,
                            'evidence': f'Payload: {payload}',
                            'category': 'authentication',
                            'cwe_ids': ['CWE-89'],
                            'asvs_mapping': 'V5.1.1',
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        break  # One positive is enough for this endpoint
                
                except Exception as e:
                    self.logger.debug(f"Error testing SQL injection with payload {payload}: {str(e)}")
                
                await asyncio.sleep(0.3)
        
        return findings

    async def test_brute_force_protection(self, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Test for brute force protection mechanisms"""
        login_endpoints = await self._discover_login_endpoints(client)
        
        if not login_endpoints:
            return None
        
        endpoint = login_endpoints[0]  # Test the first login endpoint found
        
        # Attempt multiple failed logins
        failed_attempts = 0
        max_attempts = 10
        
        start_time = time.time()
        
        for i in range(max_attempts):
            try:
                result = await self._test_credentials(
                    client, endpoint, 
                    f"testuser{i}", f"wrongpassword{i}"
                )
                
                failed_attempts += 1
                
                # Check if we're being rate limited or blocked
                if result['response'].status_code == 429:  # Too Many Requests
                    # Good - there's rate limiting
                    return None
                
                # Check response time - if it increases significantly, might indicate rate limiting
                response_time = time.time() - start_time
                if response_time > (i * 2):  # Exponential backoff detection
                    return None
                
                await asyncio.sleep(0.1)  # Small delay between attempts
                
            except Exception as e:
                self.logger.debug(f"Error in brute force test attempt {i}: {str(e)}")
        
        # If we made it through all attempts without being blocked
        return {
            'title': 'No Brute Force Protection',
            'description': f'No brute force protection detected after {failed_attempts} failed login attempts',
            'severity': 'medium',
            'endpoint': endpoint,
            'evidence': f'Completed {failed_attempts} failed login attempts without being blocked',
            'category': 'authentication',
            'cwe_ids': ['CWE-307'],
            'asvs_mapping': 'V2.2.1',
            'recommendation': 'Implement account lockout, rate limiting, and CAPTCHA after failed attempts'
        }

    async def test_session_fixation(self, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Test for session fixation vulnerability"""
        try:
            # Step 1: Get initial session
            initial_response = await client.get(self.target)
            initial_cookies = dict(initial_response.cookies)
            
            if not initial_cookies:
                return None  # No session cookies to test
            
            # Step 2: Try to authenticate (if we can find a login endpoint)
            login_endpoints = await self._discover_login_endpoints(client)
            
            if not login_endpoints:
                return None
            
            # Use test credentials to authenticate
            auth_result = await self._test_credentials(
                client, login_endpoints[0], 
                self.test_credentials['username'], 
                self.test_credentials['password']
            )
            
            if not auth_result['success']:
                return None  # Can't test session fixation without successful auth
            
            # Step 3: Check if session ID changed after authentication
            post_auth_cookies = dict(auth_result['response'].cookies)
            
            # Compare session IDs
            for cookie_name, initial_value in initial_cookies.items():
                if 'session' in cookie_name.lower() or 'sess' in cookie_name.lower():
                    post_auth_value = post_auth_cookies.get(cookie_name)
                    
                    if post_auth_value == initial_value:
                        return {
                            'title': 'Session Fixation Vulnerability',
                            'description': f'Session ID "{cookie_name}" not regenerated after authentication',
                            'severity': 'high',
                            'endpoint': login_endpoints[0],
                            'evidence': f'Session ID remained: {initial_value}',
                            'category': 'session_management',
                            'cwe_ids': ['CWE-384'],
                            'asvs_mapping': 'V3.2.1',
                            'recommendation': 'Regenerate session ID after successful authentication'
                        }
        
        except Exception as e:
            self.logger.debug(f"Session fixation test failed: {str(e)}")
        
        return None

    async def test_session_timeout(self, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Test session timeout implementation"""
        try:
            # Try to authenticate first
            login_endpoints = await self._discover_login_endpoints(client)
            
            if not login_endpoints:
                return None
            
            auth_result = await self._test_credentials(
                client, login_endpoints[0],
                self.test_credentials['username'],
                self.test_credentials['password']
            )
            
            if not auth_result['success']:
                return None
            
            # Get authenticated session cookies
            session_cookies = dict(auth_result['response'].cookies)
            
            # Try to access a protected resource immediately (should work)
            protected_response = await client.get(
                f"{self.target}/dashboard", 
                cookies=session_cookies
            )
            
            initial_access_works = protected_response.status_code not in [401, 403]
            
            if not initial_access_works:
                return None  # Can't test timeout if initial access fails
            
            # Check Session Timeout Configuration via Headers first (Static Analysis)
            # This is more accurate for "24h+" checks than waiting
            cookies = auth_result['response'].headers.get_list('set-cookie')
            for cookie in cookies:
                if 'session' in cookie.lower() or 'sid' in cookie.lower():
                    # Parse Max-Age
                    import re
                    max_age_match = re.search(r'Max-Age=(\d+)', cookie, re.IGNORECASE)
                    if max_age_match:
                        seconds = int(max_age_match.group(1))
                        if seconds > 86400: # > 24 Hours
                             return {
                                'title': 'Excessive Session Timeout (>24 Hours)',
                                'description': f'Session cookie configured to last {seconds} seconds ({seconds/3600:.1f} hours).',
                                'severity': 'high',
                                'endpoint': login_endpoints[0],
                                'evidence': f'Set-Cookie: {cookie}',
                                'category': 'session_management',
                                'cwe_ids': ['CWE-613'],
                                'recommendation': 'Reduce session timeout to a reasonable window (e.g., 30-60 minutes)'
                            }
                    
                    # Check for Expires far in future
                    # (Simplified check: if it doesn't have Max-Age/Expires, it might be a session cookie 
                    # that dies on browser close, which is usually fine, or persistent "Remember Me")

            # Dynamic Check: Short wait to ensure immediate revocation isn't happening unpredictably
            # (Keeping the original 5s logic as a sanity check for extremely short timeouts)
            await asyncio.sleep(5)  
            
            delayed_response = await client.get(
                f"{self.target}/dashboard",
                cookies=session_cookies
            )
            
            if delayed_response.status_code not in [401, 403]:
                 # If we didn't find the explicit header but it's still alive, we report "Unknown/Long"
                 pass 
                 # We assume regular session cookies are session-bound unless headers say otherwise.
                 # No implicit finding here to avoid false positives.

            return None
        
        except Exception as e:
            self.logger.debug(f"Session timeout test failed: {str(e)}")
        
        return None

    async def test_concurrent_sessions(self, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Test if multiple concurrent sessions are allowed"""
        try:
            login_endpoints = await self._discover_login_endpoints(client)
            
            if not login_endpoints:
                return None
            
            # Try to establish multiple concurrent sessions (simulating high load/abuse)
            max_sessions = 20  # Limit to 20 to avoid accidental DoS but prove the point
            successful_sessions = []
            clients = []
            
            try:
                for i in range(max_sessions):
                    # Create a new client for each session
                    new_client = httpx.AsyncClient(timeout=None, verify=False)
                    clients.append(new_client)
                    
                    # Authenticate
                    auth_result = await self._test_credentials(
                        new_client, login_endpoints[0],
                        self.test_credentials['username'],
                        self.test_credentials['password']
                    )
                    
                    if auth_result['success']:
                        successful_sessions.append(auth_result)
                    
                    # Small delay to prevent overwhelming the server
                    await asyncio.sleep(0.2)
                
                # Check how many sessions are still active
                active_sessions = 0
                test_url = f"{self.target}/dashboard"
                
                for session_data, session_client in zip(successful_sessions, clients[:len(successful_sessions)]):
                    try:
                        # Verify session is still alive
                        check_response = await session_client.get(test_url, cookies=dict(session_data['response'].cookies))
                        if check_response.status_code == 200:
                            active_sessions += 1
                    except Exception:
                        pass
                
                if active_sessions > 5:  # Arbitrary threshold for "Unlimited"
                    await self._cleanup_clients(clients)
                    return {
                        'title': 'No Concurrent Session Limit (Resource Exhaustion Risk)',
                        'description': f'Successfully established {active_sessions} concurrent sessions for a single user. No device limit detected.',
                        'severity': 'medium',
                        'endpoint': login_endpoints[0],
                        'evidence': f'Created {active_sessions} active sessions simultaneously',
                        'category': 'session_management',
                        'cwe_ids': ['CWE-613'],
                        'asvs_mapping': 'V3.1.3',
                        'recommendation': 'Implement strict concurrent session limits (e.g., max 5 devices) to prevent resource exhaustion'
                    }
                    
            finally:
                await self._cleanup_clients(clients)
        
        except Exception as e:
            self.logger.debug(f"Concurrent session test failed: {str(e)}")
        
        return None

    async def test_weak_authentication_endpoints(self) -> List[Dict[str, Any]]:
        """Test for weak authentication endpoints"""
        findings = []
        
        try:
            # No timeout - allow complete authentication testing
            async with httpx.AsyncClient(timeout=None, verify=False) as client:
                # Common weak authentication endpoints
                weak_endpoints = [
                    '/admin',
                    '/admin/admin',
                    '/administrator',
                    '/login',
                    '/admin/login',
                    '/wp-admin',
                    '/phpmyadmin',
                    '/cpanel',
                    '/webmail',
                    '/mailman/admin',
                    '/manager/html',
                    '/tomcat/manager'
                ]
                
                for endpoint in weak_endpoints:
                    try:
                        full_url = f"{self.target.rstrip('/')}{endpoint}"
                        response = await client.get(full_url)
                        
                        if response.status_code == 200:
                            # Check if it's actually an admin/login page
                            content = response.text.lower()
                            if any(keyword in content for keyword in ['login', 'password', 'username', 'admin']):
                                findings.append({
                                    'title': 'Exposed Administrative Interface',
                                    'description': f'Administrative interface found at {endpoint}',
                                    'severity': 'medium',
                                    'endpoint': full_url,
                                    'evidence': f'HTTP 200 response with authentication form',
                                    'category': 'authentication',
                                    'cwe_ids': ['CWE-200'],
                                    'asvs_mapping': 'V4.1.3',
                                    'recommendation': 'Restrict access to administrative interfaces and use strong authentication'
                                })
                    
                    except Exception as e:
                        self.logger.debug(f"Error testing endpoint {endpoint}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Weak endpoint testing failed: {str(e)}")
        
        return findings

    async def test_auth_error_information_disclosure(self) -> List[Dict[str, Any]]:
        """Test for information disclosure in authentication error messages"""
        findings = []
        
        try:
            # No timeout - allow complete authentication testing
            async with httpx.AsyncClient(timeout=None, verify=False) as client:
                login_endpoints = await self._discover_login_endpoints(client)
                
                for endpoint in login_endpoints:
                    # Test with valid username, invalid password
                    result1 = await self._test_credentials(client, endpoint, "admin", "wrongpassword")
                    
                    # Test with invalid username, invalid password  
                    result2 = await self._test_credentials(client, endpoint, "nonexistentuser", "wrongpassword")
                    
                    # Compare error messages
                    error1 = self._extract_error_message(result1['response'])
                    error2 = self._extract_error_message(result2['response'])
                    
                    if error1 != error2 and error1 and error2:
                        findings.append({
                            'title': 'Username Enumeration via Error Messages',
                            'description': 'Different error messages reveal valid usernames',
                            'severity': 'medium',
                            'endpoint': endpoint,
                            'evidence': f'Valid user error: "{error1}", Invalid user error: "{error2}"',
                            'category': 'authentication',
                            'cwe_ids': ['CWE-204'],
                            'asvs_mapping': 'V2.2.2',
                            'recommendation': 'Use generic error messages that do not reveal username validity'
                        })
        
        except Exception as e:
            self.logger.error(f"Error message testing failed: {str(e)}")
        
        return findings

    async def test_account_enumeration(self) -> List[Dict[str, Any]]:
        """Test for account enumeration vulnerabilities"""
        findings = []
        
        try:
            # No timeout - allow complete authentication testing
            async with httpx.AsyncClient(timeout=None, verify=False) as client:
                # Test different endpoints for account enumeration
                enumeration_endpoints = [
                    '/forgot-password',
                    '/reset-password', 
                    '/password-reset',
                    '/user/exists',
                    '/api/user/check'
                ]
                
                common_usernames = ['admin', 'administrator', 'root', 'test', 'guest', 'user']
                
                for endpoint in enumeration_endpoints:
                    try:
                        full_url = f"{self.target.rstrip('/')}{endpoint}"
                        
                        # Test with likely valid and invalid usernames
                        responses = {}
                        
                        for username in common_usernames:
                            response = await client.post(full_url, data={'username': username})
                            responses[username] = {
                                'status_code': response.status_code,
                                'response_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                                'content_length': len(response.content),
                                'error_message': self._extract_error_message(response)
                            }
                            await asyncio.sleep(0.2)
                        
                        # Analyze responses for enumeration indicators
                        if self._analyze_enumeration_responses(responses):
                            findings.append({
                                'title': 'Account Enumeration Vulnerability',
                                'description': f'Account enumeration possible via {endpoint}',
                                'severity': 'medium',
                                'endpoint': full_url,
                                'evidence': 'Different responses for valid/invalid usernames',
                                'category': 'authentication',
                                'cwe_ids': ['CWE-204'],
                                'asvs_mapping': 'V2.2.2',
                                'recommendation': 'Ensure consistent responses for all username queries'
                            })
                    
                    except Exception as e:
                        self.logger.debug(f"Error testing enumeration endpoint {endpoint}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Account enumeration testing failed: {str(e)}")
        
        return findings

    async def test_password_reset_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Test for password reset vulnerabilities"""
        findings = []
        
        try:
            # No timeout - allow complete authentication testing
            async with httpx.AsyncClient(timeout=None, verify=False) as client:
                # Look for password reset functionality
                reset_endpoints = await self._discover_password_reset_endpoints(client)
                
                for endpoint in reset_endpoints:
                    # Test for token predictability
                    tokens = []
                    
                    for i in range(3):
                        response = await client.post(endpoint, data={'email': f'test{i}@example.com'})
                        token = self._extract_reset_token(response)
                        if token:
                            tokens.append(token)
                        await asyncio.sleep(1)
                    
                    if len(tokens) >= 2:
                        # Analyze token patterns
                        if self._analyze_token_patterns(tokens):
                            findings.append({
                                'title': 'Predictable Password Reset Tokens',
                                'description': 'Password reset tokens follow predictable patterns',
                                'severity': 'high',
                                'endpoint': endpoint,
                                'evidence': f'Token pattern detected in: {tokens}',
                                'category': 'authentication',
                                'cwe_ids': ['CWE-330'],
                                'asvs_mapping': 'V2.5.1',
                                'recommendation': 'Use cryptographically secure random token generation'
                            })
        
        except Exception as e:
            self.logger.error(f"Password reset testing failed: {str(e)}")
        
        return findings

    # Helper methods
    async def _discover_login_endpoints(self, client: httpx.AsyncClient) -> List[str]:
        """Discover login endpoints on the target"""
        endpoints = []
        
        common_paths = [
            '/login',
            '/admin/login',
            '/user/login',
            '/auth/login',
            '/signin',
            '/admin',
            '/wp-admin',
            '/administrator'
        ]
        
        for path in common_paths:
            try:
                full_url = f"{self.target.rstrip('/')}{path}"
                response = await client.get(full_url)
                
                if response.status_code == 200:
                    # Check if page contains login form
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        inputs = form.find_all('input')
                        input_types = [inp.get('type', '').lower() for inp in inputs]
                        
                        if 'password' in input_types:
                            endpoints.append(full_url)
                            break
            
            except Exception as e:
                self.logger.debug(f"Error checking endpoint {path}: {str(e)}")
        
        return endpoints

    async def _test_credentials(self, client: httpx.AsyncClient, endpoint: str, username: str, password: str) -> Dict[str, Any]:
        """Test credentials against a login endpoint"""
        try:
            # First, get the login page to extract form details
            login_page = await client.get(endpoint)
            soup = BeautifulSoup(login_page.text, 'html.parser')
            
            # Find login form
            forms = soup.find_all('form')
            login_form = None
            
            for form in forms:
                inputs = form.find_all('input')
                input_types = [inp.get('type', '').lower() for inp in inputs]
                if 'password' in input_types:
                    login_form = form
                    break
            
            if not login_form:
                return {'success': False, 'error': 'No login form found', 'response': login_page}
            
            # Extract form action and method
            action = login_form.get('action', '')
            method = login_form.get('method', 'post').lower()
            
            if action:
                if action.startswith('/'):
                    form_url = f"{self.target.rstrip('/')}{action}"
                else:
                    form_url = f"{endpoint}/{action}"
            else:
                form_url = endpoint
            
            # Build form data
            form_data = {}
            
            for inp in login_form.find_all('input'):
                name = inp.get('name', '')
                input_type = inp.get('type', '').lower()
                value = inp.get('value', '')
                
                if input_type == 'password':
                    form_data[name] = password
                elif input_type in ['text', 'email'] and any(keyword in name.lower() for keyword in ['user', 'login', 'email']):
                    form_data[name] = username
                elif input_type == 'hidden':
                    form_data[name] = value
            
            # Submit form
            if method == 'get':
                response = await client.get(form_url, params=form_data)
            else:
                response = await client.post(form_url, data=form_data)
            
            # Determine if login was successful
            success = self._determine_login_success(response, username)
            
            return {
                'success': success,
                'response': response,
                'form_data': form_data
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e), 'response': None}

    def _determine_login_success(self, response: httpx.Response, username: str) -> bool:
        """Determine if login was successful based on response"""
        # Check status code
        if response.status_code == 302:  # Redirect usually indicates success
            return True
        
        # Check response content
        content_lower = response.text.lower()
        
        # Success indicators
        success_indicators = [
            'welcome',
            'dashboard',
            'logout',
            'profile',
            f'hello {username.lower()}',
            'authenticated',
            'successful'
        ]
        
        # Failure indicators
        failure_indicators = [
            'invalid',
            'incorrect',
            'failed',
            'error',
            'wrong',
            'denied',
            'forbidden'
        ]
        
        # Check for success indicators
        for indicator in success_indicators:
            if indicator in content_lower:
                return True
        
        # Check for failure indicators
        for indicator in failure_indicators:
            if indicator in content_lower:
                return False
        
        # If no clear indicators, assume failure
        return False

    def _check_sql_injection_indicators(self, response: httpx.Response) -> bool:
        """Check response for SQL injection indicators"""
        if not response:
            return False
        
        content = response.text.lower()
        
        # Common SQL error indicators
        sql_errors = [
            'mysql_fetch_array',
            'ora-01756',
            'microsoft ole db provider',
            'unclosed quotation mark',
            'quoted string not properly terminated',
            'syntax error in string in query expression',
            'data type mismatch',
            'cfquery error',
            'sqlite_exception',
            'postgresql query failed',
            'warning: pg_exec',
            'valid postgresql result',
            'npgsql.npgsqlexception',
            'driver][sql server]',
            'ole db provider for sql server'
        ]
        
        for error in sql_errors:
            if error in content:
                return True
        
        return False

    def _extract_error_message(self, response: httpx.Response) -> str:
        """Extract error message from response"""
        if not response:
            return ""
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for common error containers
        error_selectors = [
            '.error',
            '.alert-danger',
            '.message',
            '.notification',
            '#error',
            '[class*="error"]'
        ]
        
        for selector in error_selectors:
            error_element = soup.select_one(selector)
            if error_element:
                return error_element.get_text().strip()
        
        # Fallback: look for text containing common error words
        text = response.text.lower()
        error_patterns = [
            r'error[:\s]+([^<\n\.]+)',
            r'invalid[:\s]+([^<\n\.]+)', 
            r'incorrect[:\s]+([^<\n\.]+)',
            r'failed[:\s]+([^<\n\.]+)'
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1).strip()
        
        return ""

    def _analyze_enumeration_responses(self, responses: Dict[str, Dict]) -> bool:
        """Analyze responses to detect enumeration vulnerabilities"""
        if len(responses) < 2:
            return False
        
        # Compare response characteristics
        status_codes = set(resp['status_code'] for resp in responses.values())
        content_lengths = set(resp['content_length'] for resp in responses.values())
        error_messages = set(resp['error_message'] for resp in responses.values())
        
        # If all responses are identical, no enumeration
        if len(status_codes) == 1 and len(content_lengths) == 1 and len(error_messages) == 1:
            return False
        
        # If there are differences, potential enumeration
        return True

    async def _discover_password_reset_endpoints(self, client: httpx.AsyncClient) -> List[str]:
        """Discover password reset endpoints"""
        endpoints = []
        
        reset_paths = [
            '/forgot-password',
            '/reset-password',
            '/password-reset',
            '/auth/forgot',
            '/user/forgot',
            '/forgot'
        ]
        
        for path in reset_paths:
            try:
                full_url = f"{self.target.rstrip('/')}{path}"
                response = await client.get(full_url)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['reset', 'forgot', 'recover']):
                        endpoints.append(full_url)
            
            except Exception as e:
                self.logger.debug(f"Error checking reset endpoint {path}: {str(e)}")
        
        return endpoints

    def _extract_reset_token(self, response: httpx.Response) -> Optional[str]:
        """Extract password reset token from response"""
        if not response:
            return None
        
        # Look for tokens in various places
        content = response.text
        
        # Common token patterns
        token_patterns = [
            r'token[=:]\s*([a-zA-Z0-9]+)',
            r'reset[_-]?token[=:]\s*([a-zA-Z0-9]+)',
            r'/reset/([a-zA-Z0-9]+)',
            r'token=([a-zA-Z0-9]+)'
        ]
        
        for pattern in token_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

    def _analyze_token_patterns(self, tokens: List[str]) -> bool:
        """Analyze tokens for predictable patterns"""
        if len(tokens) < 2:
            return False
        
        # Check for sequential patterns
        try:
            # Try to convert to integers and check sequence
            int_tokens = [int(token) for token in tokens]
            differences = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
            
            # If differences are consistent, it's sequential
            if len(set(differences)) == 1:
                return True
        except ValueError:
            pass
        
        # Check for timestamp-based patterns
        import time
        current_time = int(time.time())
        
        for token in tokens:
            try:
                token_int = int(token)
                # If token is close to current timestamp, it might be time-based
                if abs(token_int - current_time) < 86400:  # Within 24 hours
                    return True
            except ValueError:
                pass
        
        # Check for simple incremental patterns
        if all(len(token) == len(tokens[0]) for token in tokens):
            # Same length tokens might indicate simple incrementing
            return True
        
        return False

    async def test_authorization_flaws(self, client: httpx.AsyncClient, session_cookies: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test for Authorization Flaws (Broken Access Control & IDOR)"""
        findings = []
        try:
            # 1. Admin Access Check
            # Try to access sensitive endpoints with guest credentials
            sensitive_endpoints = [
                '/admin', '/dashboard', '/settings', '/users', '/config',
                '/api/admin', '/api/users', '/profile/1'
            ]
            
            for endpoint in sensitive_endpoints:
                full_url = f"{self.target.rstrip('/')}{endpoint}"
                try:
                    response = await client.get(full_url, cookies=session_cookies)
                    
                    # Logic: If we get 200 OK and content doesn't look like a login redirect or error
                    if response.status_code == 200:
                        content = response.text.lower()
                        # Filters to avoid false positives (e.g. custom 404 pages returning 200, or login pages)
                        if 'login' not in content and 'access denied' not in content and 'unauthorized' not in content:
                            findings.append({
                                'title': 'Broken Access Control (Admin Access)',
                                'description': f'Low privilege user (guest123) can access protected endpoint: {endpoint}',
                                'severity': 'high',
                                'endpoint': full_url,
                                'evidence': f'HTTP 200 Response on protected resource',
                                'category': 'authorization',
                                'cwe_ids': ['CWE-285'],
                                'recommendation': 'Implement Role-Based Access Control (RBAC) to restrict access.'
                            })
                except Exception:
                    pass
            
            # 2. IDOR Check (Simple Pattern Matching)
            # Try to access user ID 1 (Admin) assuming we are a different user
            idor_patterns = [
                '/profile?id=1', '/user?id=1', '/account?id=1',
                '/api/user/1', '/api/profile/1', '/api/account/1',
                '/users/1', '/profiles/1', '/accounts/1'
            ]
            
            for endpoint in idor_patterns:
                full_url = f"{self.target.rstrip('/')}{endpoint}"
                try:
                    response = await client.get(full_url, cookies=session_cookies)
                    if response.status_code == 200:
                         content = response.text.lower()
                         if 'admin' in content or 'root' in content or 'superuser' in content:
                             findings.append({
                                'title': 'Insecure Direct Object Reference (IDOR)',
                                'description': f'Access to user ID 1 (Admin) successful via: {endpoint}',
                                'severity': 'critical',
                                'endpoint': full_url,
                                'evidence': f'HTTP 200 Response containing "admin" keyword',
                                'category': 'authorization',
                                'cwe_ids': ['CWE-639'],
                                'recommendation': 'Implement ownership checks on all object access requests.'
                            })
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"Authorization checks failed: {str(e)}")
            
        return findings

    async def _cleanup_clients(self, clients: List[httpx.AsyncClient]):
        """Helper to close multiple async clients"""
        for client in clients:
            try:
                await client.aclose()
            except Exception:
                pass