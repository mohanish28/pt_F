#!/usr/bin/env python3
"""
Unified File Upload Vulnerability Scanner (Professional Pentesting Edition)
===========================================================================

Comprehensive file upload security testing framework orchestrating multiple
specialized scanners to identify all classes of file upload vulnerabilities.

This is the single entry point for professional-grade file upload testing,
combining techniques used by expert penetration testers worldwide.

Orchestrates:
1. UnrestrictedUploadScanner - File type validation bypass
2. MaliciousFileScanner - Remote code execution via file upload  
3. PathTraversalUploadScanner - Directory traversal attacks

Features:
- Intelligent target analysis
- Dynamic scanner selection
- Comprehensive vulnerability coverage
- Professional-grade testing techniques
- Detailed evidence collection
- Actionable remediation guidance

CWE Coverage: CWE-22, CWE-73, CWE-79, CWE-94, CWE-97, CWE-434, CWE-502, CWE-611
OWASP: A01:2021, A03:2021, A05:2021, A08:2021

Author: BreachScan Professional Pentesting Framework
Version: 2.0.0
"""

import asyncio
import logging
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse

from ..base import ScannerBase

# Import specialized scanners
try:
    from .unrestricted_upload_scanner import UnrestrictedUploadScanner
except ImportError:
    UnrestrictedUploadScanner = None

try:
    from .malicious_file_scanner import MaliciousFileScanner
except ImportError:
    MaliciousFileScanner = None

try:
    from .path_traversal_upload_scanner import PathTraversalUploadScanner
except ImportError:
    PathTraversalUploadScanner = None


class FileUploadScanner(ScannerBase):
    """
    Unified File Upload Vulnerability Scanner
    
    Professional-grade comprehensive file upload security testing.
    Single entry point orchestrating 3 specialized scanners.
    
    Usage:
        scanner = FileUploadScanner(target="https://example.com")
        results = await scanner.scan()
    """
    
    def __init__(self, target: str, timeout: int = None, **kwargs):
        """
        Initialize unified file upload scanner
        
        Args:
            target: Target URL to test
            timeout: Maximum scan duration (seconds)
            **kwargs: Configuration options
                
                # Scanner Enable/Disable
                enable_unrestricted: Test unrestricted upload (default: True)
                enable_malicious: Test malicious file execution (default: True)
                enable_path_traversal: Test path traversal (default: True)
                
                # Test Mode
                test_mode: 'passive', 'normal', 'aggressive' (default: 'aggressive')
                
                # Specific Configuration
                max_payloads: Maximum payloads per test (default: None - all)
        """
        super().__init__(target, timeout)
        
        self.logger = logging.getLogger(__name__)
        
        # Generate scan ID
        self.scan_id = hashlib.md5(f"{target}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        
        # Configuration
        self.config = {
            'enable_unrestricted': kwargs.get('enable_unrestricted', True),
            'enable_malicious': kwargs.get('enable_malicious', True),
            'enable_path_traversal': kwargs.get('enable_path_traversal', True),
            'test_mode': kwargs.get('test_mode', 'aggressive'),
            'max_payloads': kwargs.get('max_payloads', None),
        }
        
        # Results storage
        self.all_findings = []
        self.scanner_results = {}
        self.scanner_errors = {}
        
        # Session configuration
        self.session_cookies = kwargs.get('session_cookies', {})
        self.auth_headers = kwargs.get('auth_headers', {})
        
        # Target analysis
        self.target_info = self._analyze_target(target)
    
    def _analyze_target(self, target: str) -> Dict[str, Any]:
        """Analyze target URL to optimize testing"""
        
        parsed = urlparse(target)
        
        return {
            'url': target,
            'scheme': parsed.scheme,
            'hostname': parsed.hostname,
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'path': parsed.path,
            'has_upload_path': any(keyword in parsed.path.lower() 
                                   for keyword in ['upload', 'file', 'attach', 'media']),
        }
    
    async def scan(self) -> Dict[str, Any]:
        """
        Execute comprehensive file upload vulnerability scan
        
        Returns:
            Dict containing aggregated results from all scanners
        """
        try:
            self.logger.info("="*80)
            self.logger.info("FILE UPLOAD VULNERABILITY SCAN - Professional Edition")
            self.logger.info("="*80)
            self.logger.info(f"Scan ID: {self.scan_id}")
            self.logger.info(f"Target: {self.target}")
            self.logger.info(f"Test Mode: {self.config['test_mode'].upper()}")
            
            scan_start_time = datetime.now()
            
            # Determine which scanners to run
            scanners_to_run = self._determine_scanners()
            enabled_count = sum(1 for enabled in scanners_to_run.values() if enabled)
            
            self.logger.info(f"\nEnabled Scanners: {enabled_count}/3")
            for scanner_name, enabled in scanners_to_run.items():
                status = "ENABLED" if enabled else "DISABLED"
                self.logger.info(f"  - {scanner_name}: {status}")
            
            if enabled_count == 0:
                self.logger.warning("No scanners enabled!")
                return self._generate_empty_results()
            
            self.logger.info("\n" + "="*80)
            self.logger.info("STARTING SCAN")
            self.logger.info("="*80 + "\n")
            
            # Run enabled scanners
            if scanners_to_run.get('unrestricted'):
                await self._run_unrestricted_upload_scanner()
            
            if scanners_to_run.get('malicious'):
                await self._run_malicious_file_scanner()
            
            if scanners_to_run.get('path_traversal'):
                await self._run_path_traversal_scanner()
            
            scan_duration = (datetime.now() - scan_start_time).total_seconds()
            
            # Generate comprehensive results
            results = self._generate_summary(scan_duration, scanners_to_run)
            
            self.logger.info("\n" + "="*80)
            self.logger.info("FILE UPLOAD VULNERABILITY SCAN COMPLETE")
            self.logger.info("="*80)
            self.logger.info(f"Total Findings: {len(self.all_findings)}")
            self.logger.info(f"Scan Duration: {scan_duration:.2f}s")
            self.logger.info("="*80 + "\n")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Unified scan failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return self._generate_error_results(str(e))
    
    def _determine_scanners(self) -> Dict[str, bool]:
        """Determine which scanners to run based on configuration"""
        
        scanners = {}
        
        # Unrestricted Upload Scanner
        if self.config['enable_unrestricted'] and UnrestrictedUploadScanner:
            scanners['unrestricted'] = True
        else:
            scanners['unrestricted'] = False
            if self.config['enable_unrestricted'] and not UnrestrictedUploadScanner:
                self.logger.warning("UnrestrictedUploadScanner not available (import error)")
        
        # Malicious File Scanner
        if self.config['enable_malicious'] and MaliciousFileScanner:
            scanners['malicious'] = True
        else:
            scanners['malicious'] = False
            if self.config['enable_malicious'] and not MaliciousFileScanner:
                self.logger.warning("MaliciousFileScanner not available (import error)")
        
        # Path Traversal Scanner
        if self.config['enable_path_traversal'] and PathTraversalUploadScanner:
            scanners['path_traversal'] = True
        else:
            scanners['path_traversal'] = False
            if self.config['enable_path_traversal'] and not PathTraversalUploadScanner:
                self.logger.warning("PathTraversalUploadScanner not available (import error)")
        
        return scanners
    
    async def _run_unrestricted_upload_scanner(self):
        """Execute unrestricted upload scanner"""
        try:
            self.logger.info("[1/3] Running Unrestricted Upload Scanner...")
            self.logger.info("-" * 80)
            
            scanner = UnrestrictedUploadScanner(
                target_url=self.target,
                timeout=self.timeout // 3,
                test_mode=self.config['test_mode'],
                session_cookies=self.session_cookies
            )
            
            result = await scanner.scan()
            
            self.scanner_results['unrestricted'] = result
            
            # Extract findings
            findings = result.get('findings', [])
            self.all_findings.extend(findings)
            
            self.logger.info(f"Unrestricted Upload Scanner: {len(findings)} findings")
            self._log_severity_summary(findings)
            
        except Exception as e:
            self.logger.error(f"Unrestricted Upload Scanner error: {str(e)}")
            self.scanner_errors['unrestricted'] = str(e)
    
    async def _run_malicious_file_scanner(self):
        """Execute malicious file scanner"""
        try:
            self.logger.info("\n[2/3] Running Malicious File Execution Scanner...")
            self.logger.info("-" * 80)
            
            scanner = MaliciousFileScanner(
                target_url=self.target,
                timeout=self.timeout // 3,
                test_mode=self.config['test_mode'],
                session_cookies=self.session_cookies
            )
            
            result = await scanner.scan()
            
            self.scanner_results['malicious'] = result
            
            # Extract findings
            findings = result.get('findings', [])
            self.all_findings.extend(findings)
            
            self.logger.info(f"Malicious File Scanner: {len(findings)} findings")
            self._log_severity_summary(findings)
            
        except Exception as e:
            self.logger.error(f"Malicious File Scanner error: {str(e)}")
            self.scanner_errors['malicious'] = str(e)
    
    async def _run_path_traversal_scanner(self):
        """Execute path traversal scanner"""
        try:
            self.logger.info("\n[3/3] Running Path Traversal Upload Scanner...")
            self.logger.info("-" * 80)
            
            scanner = PathTraversalUploadScanner(
                target_url=self.target,
                timeout=self.timeout // 3,
                test_mode=self.config['test_mode'],
                session_cookies=self.session_cookies
            )
            
            result = await scanner.scan()
            
            self.scanner_results['path_traversal'] = result
            
            # Extract findings
            findings = result.get('findings', [])
            self.all_findings.extend(findings)
            
            self.logger.info(f"Path Traversal Scanner: {len(findings)} findings")
            self._log_severity_summary(findings)
            
        except Exception as e:
            self.logger.error(f"Path Traversal Scanner error: {str(e)}")
            self.scanner_errors['path_traversal'] = str(e)
    
    def _log_severity_summary(self, findings: List[Dict]):
        """Log severity summary for findings"""
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            self.logger.info("  Severity Breakdown:")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    self.logger.info(f"    {severity.upper():10s}: {count}")
    
    def _generate_summary(self, scan_duration: float, scanners_run: Dict[str, bool]) -> Dict[str, Any]:
        """Generate comprehensive scan summary"""
        
        # Count findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        technique_counts = {}
        cwe_counts = {}
        
        for finding in self.all_findings:
            # Severity
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Technique
            technique = finding.get('technique', 'unknown')
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
            
            # CWE
            cwe = finding.get('cwe', 'unknown')
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts)
        
        # Determine risk level
        risk_level = self._get_risk_level(risk_score, severity_counts)
        
        successful_scanners = list(self.scanner_results.keys())
        failed_scanners = list(self.scanner_errors.keys())
        
        return {
            'scanner': 'unified_file_upload',
            'scan_id': self.scan_id,
            'target': self.target,
            'target_info': self.target_info,
            'timestamp': datetime.utcnow().isoformat(),
            
            'summary': {
                'total_findings': len(self.all_findings),
                'severity_distribution': severity_counts,
                'technique_distribution': technique_counts,
                'cwe_distribution': cwe_counts,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'scan_duration_seconds': scan_duration
            },
            
            'scanners': {
                'enabled': [name for name, enabled in scanners_run.items() if enabled],
                'successful': successful_scanners,
                'failed': failed_scanners,
                'total_enabled': sum(1 for enabled in scanners_run.values() if enabled),
                'total_successful': len(successful_scanners),
                'total_failed': len(failed_scanners)
            },
            
            'findings': self.all_findings,
            'scanner_results': self.scanner_results,
            'errors': self.scanner_errors if self.scanner_errors else None
        }
    
    def _generate_empty_results(self) -> Dict[str, Any]:
        """Generate empty results when no scanners enabled"""
        return {
            'scanner': 'unified_file_upload',
            'scan_id': self.scan_id,
            'target': self.target,
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {'total_findings': 0},
            'scanners': {'enabled': [], 'successful': [], 'failed': []},
            'findings': [],
            'note': 'No scanners enabled'
        }
    
    def _generate_error_results(self, error_message: str) -> Dict[str, Any]:
        """Generate error results"""
        return {
            'scanner': 'unified_file_upload',
            'scan_id': self.scan_id,
            'target': self.target,
            'timestamp': datetime.utcnow().isoformat(),
            'error': error_message,
            'findings': self.all_findings,
            'scanner_results': self.scanner_results
        }
    
    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate overall risk score (0-100)"""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        
        total_findings = sum(severity_counts.values())
        if total_findings == 0:
            return 0.0
        
        weighted_sum = sum(severity_counts.get(s, 0) * w for s, w in weights.items())
        max_score = total_findings * weights['critical']
        
        return round((weighted_sum / max_score) * 100, 2) if max_score > 0 else 0.0
    
    def _get_risk_level(self, risk_score: float, severity_counts: Dict[str, int]) -> str:
        """Determine risk level based on score and findings"""
        
        if severity_counts.get('critical', 0) > 0:
            return 'CRITICAL'
        elif risk_score >= 70:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 10:
            return 'LOW'
        else:
            return 'INFO'
    
    def print_results(self):
        """Print formatted results to console"""
        print("\n" + "="*80)
        print("FILE UPLOAD VULNERABILITY SCAN RESULTS")
        print("="*80)
        print(f"Scan ID: {self.scan_id}")
        print(f"Target: {self.target}")
        print("="*80)
        
        # Scanner status
        print("\nSCANNER STATUS:")
        print("-"*80)
        for scanner_name, result in self.scanner_results.items():
            findings_count = len(result.get('findings', []))
            print(f"  {scanner_name.replace('_', ' ').title():30s}: SUCCESS ({findings_count} findings)")
        
        for scanner_name, error in self.scanner_errors.items():
            print(f"  {scanner_name.replace('_', ' ').title():30s}: FAILED ({error[:50]}...)")
        
        # Summary
        if self.all_findings:
            print(f"\nTotal Findings: {len(self.all_findings)}")
            
            # Severity distribution
            severity_counts = {}
            for finding in self.all_findings:
                severity = finding.get('severity', 'info').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print("\nSeverity Distribution:")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    print(f"  {severity.upper():10s}: {count:3d}")
            
            # Risk score
            risk_score = self._calculate_risk_score(severity_counts)
            risk_level = self._get_risk_level(risk_score, severity_counts)
            print(f"\nRisk Score: {risk_score}/100 ({risk_level})")
            
            # Top findings
            print("\nTop Critical Findings:")
            critical_findings = [f for f in self.all_findings if f.get('severity', '').lower() == 'critical']
            for i, finding in enumerate(critical_findings[:5], 1):
                print(f"  {i}. {finding.get('title', 'Unknown')}")
                print(f"     Technique: {finding.get('technique', 'Unknown')}")
                print(f"     CWE: {finding.get('cwe', 'Unknown')}")
        else:
            print("\nNo findings detected.")
        
        print("\n" + "="*80)
    
    def parse_output(self) -> Dict[str, Any]:
        """Parse output (required by ScannerBase)"""
        return self.scanner_results if self.scanner_results else {}


# Aliases for compatibility
FileUploadVulnerabilityScanner = FileUploadScanner
UnifiedFileUploadScanner = FileUploadScanner


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Unified File Upload Vulnerability Scanner")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--unrestricted", action="store_true", default=True, help="Enable unrestricted upload tests")
    parser.add_argument("--malicious", action="store_true", default=True, help="Enable malicious file tests")
    parser.add_argument("--path-traversal", action="store_true", default=True, help="Enable path traversal tests")
    parser.add_argument("--test-mode", choices=['passive', 'normal', 'aggressive'], default='aggressive', help="Test mode")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    async def main():
        scanner = FileUploadScanner(
            target=args.target,
            test_mode=args.test_mode
        )
        results = await scanner.scan()
        scanner.print_results()
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")
    
    asyncio.run(main())

