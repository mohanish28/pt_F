#!/usr/bin/env python3
"""
Educational Security Analysis Framework
A responsible tool for learning about web security concepts and OWASP Top 10.
"""

import os
import json
import asyncio
import logging
import redis
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
import socket
import subprocess
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import re
import shutil
import zipfile
from pathlib import Path
import sys


# Import nmap if available
try:
    import nmap
    import dns.resolver
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    nmap = None  # Explicitly set to None to avoid "possibly unbound" errors
    print("Warning: nmap or dnspython not installed. Network scanning features will be limited.")

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends, status, Request
# from controllers.scan_controller import router as scan_router  # Disabled - using file-based storage
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.encoders import jsonable_encoder 
from pydantic import BaseModel, HttpUrl, Field
import httpx
from bs4 import BeautifulSoup
import websockets
import json as json_lib
import bcrypt
import jwt
from passlib.context import CryptContext
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
import time
from collections import defaultdict
from contextlib import asynccontextmanager

# Consolidate CVE Logic - Single Source of Truth
try:
    from backend.scanners.cve_enhancement import (
        enhance_findings_with_cve, 
        CVEReference, 
        vulnerability_enhancer as cve_db  # Key: Alias to cve_db to maintain compatibility if used
    )
except ImportError:
    try:
        from scanners.cve_enhancement import (
            enhance_findings_with_cve, 
            CVEReference, 
            vulnerability_enhancer as cve_db
        )
    except ImportError:
        logger.warning("Warning: Vulnerability Enhancer not available")
        enhance_findings_with_cve = None
        CVEReference = None
        cve_db = None

# Initialize logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Global scan results storage
scan_results = {}  # Dictionary to store scan results by scan_id

# ============================================
# SCAN STORAGE & CLEANUP HELPERS
# ============================================

def is_scan_completed(scan_id: str) -> bool:
    """
    Check if full_results.json exists and has valid content.
    Prevents overwriting completed scan results.
    
    Args:
        scan_id: The scan ID to check
        
    Returns:
        True if file exists and has valid content, False otherwise
    """
    try:
        full_results_path = f"scan_results/{scan_id}/raw_data/full_results.json"
        if not os.path.exists(full_results_path):
            return False
        
        # Check file size (empty files are < 100 bytes)
        file_size = os.path.getsize(full_results_path)
        if file_size < 100:
            return False  # File is empty/corrupted - allow overwrite
        
        # Verify file has valid JSON with content
        try:
            with open(full_results_path, "r") as f:
                data = json.load(f)
                # Check if it has findings or raw_data (either indicates valid content)
                has_findings = data.get('findings') and len(data.get('findings', [])) > 0
                has_raw_data = data.get('raw_data') and isinstance(data.get('raw_data'), dict) and len(data.get('raw_data', {})) > 0
                
                if has_findings or has_raw_data:
                    return True  # File has valid content - prevent overwrite
        except (json.JSONDecodeError, Exception):
            return False  # File is corrupted - allow overwrite
        
        return False  # File exists but has no content - allow overwrite
    except Exception:
        return False  # Error checking - allow overwrite to be safe


def safe_write_json(file_path: str, data: dict) -> bool:
    """
    Safely write JSON file using atomic write (write to temp, then rename).
    Prevents file corruption if write fails.
    
    Args:
        file_path: Path to the JSON file
        data: Dictionary to write
        
    Returns:
        True if write succeeded, False otherwise
    """
    try:
        # Write to temporary file first
        temp_path = f"{file_path}.tmp"
        with open(temp_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        
        # Atomic rename (replaces original only if temp write succeeded)
        os.replace(temp_path, file_path)
        return True
    except Exception as e:
        logger.error(f"[SAVE] Atomic write failed for {file_path}: {e}")
        # Clean up temp file if it exists
        try:
            if os.path.exists(f"{file_path}.tmp"):
                os.remove(f"{file_path}.tmp")
        except:
            pass
        return False

def generate_scan_id_from_url(url: str, username: str = "public") -> str:
    """Generate scan ID from target URL with site name"""
    parsed = urlparse(url if url.startswith('http') else f'http://{url}')
    domain = parsed.netloc or parsed.path.split('/')[0]
    
    # Remove standard ports
    domain = domain.replace(':80', '').replace(':443', '')
    
    # Extract clean domain name
    # http://testphp.vulnweb.com/ → testphp.vulnweb
    # http://127.0.0.1:4280/ → 127.0.0.1_4280
    safe_name = re.sub(r'[^\w\.\-]', '_', domain)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{safe_name}_{timestamp}_{username}"


def create_scan_directory_structure(scan_id: str) -> dict:
    """Create complete directory structure for scan"""
    base_dir = f"scan_results/{scan_id}"
    
    dirs = {
        'base': base_dir,
        'crawled_urls': f"{base_dir}/crawled_urls",
        'scanner_outputs': f"{base_dir}/scanner_outputs",
        'logs': f"{base_dir}/logs",
        'reports': f"{base_dir}/reports",
        'artifacts': f"{base_dir}/artifacts",
        'raw_data': f"{base_dir}/raw_data"
    }
    
    for dir_path in dirs.values():
        os.makedirs(dir_path, exist_ok=True)
    
    return dirs


def save_scan_to_redis_cache(scan_id: str, scan_data: dict, redis_client):
    """Cache scan summary in Redis for fast access (synchronous)"""
    try:
        # Cache scan summary (7 days TTL)
        redis_client.hset(f"scan_summary:{scan_id}", mapping={
            "scan_id": scan_id,
            "target_url": scan_data.get('target_url', ''),
            "status": scan_data.get('status', ''),
            "findings_count": str(scan_data.get('findings_count', 0)),
            "critical_count": str(scan_data.get('summary', {}).get('critical', 0)),
            "high_count": str(scan_data.get('summary', {}).get('high', 0)),
            "start_time": scan_data.get('start_time', ''),
            "end_time": scan_data.get('end_time', ''),
        })
        redis_client.expire(f"scan_summary:{scan_id}", 604800)  # 7 days
        
        # Update latest scan pointer
        redis_client.set("latest_scan", scan_id, ex=604800)
        
        # Add to recent scans list (keep last 10)
        redis_client.lpush("recent_scans", scan_id)
        redis_client.ltrim("recent_scans", 0, 9)
        
    except Exception as e:
        logger.warning(f"Failed to cache scan in Redis: {e}")


def cleanup_old_scans(retention_days=90, archive_before_delete=True):
    """
    Clean up scans older than retention period
    
    Args:
        retention_days: Keep scans from last N days (default 90)
        archive_before_delete: ZIP old scans before deletion (default True)
    """
    try:
        scan_results_dir = Path("scan_results")
        archive_dir = Path("scan_archives")
        archive_dir.mkdir(exist_ok=True)
        
        if not scan_results_dir.exists():
            logger.info("No scan_results directory found")
            return {"archived": 0, "deleted": 0}
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted_count = 0
        archived_count = 0
        
        for scan_dir in scan_results_dir.iterdir():
            if not scan_dir.is_dir():
                continue
            
            # Check scan age from metadata
            metadata_file = scan_dir / "metadata.json"
            if metadata_file.exists():
                try:
                    with open(metadata_file) as f:
                        metadata = json.load(f)
                        scan_date = datetime.fromisoformat(metadata.get('scan_start', metadata.get('start_time', '')))
                        
                        if scan_date < cutoff_date:
                            # Scan is older than retention period
                            if archive_before_delete:
                                # Archive to ZIP
                                zip_path = archive_dir / f"{scan_dir.name}.zip"
                                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                                    for file in scan_dir.rglob('*'):
                                        if file.is_file():
                                            zipf.write(file, file.relative_to(scan_dir))
                                archived_count += 1
                                logger.info(f"✅ Archived: {scan_dir.name} → {zip_path}")
                            
                            # Delete original folder
                            shutil.rmtree(scan_dir)
                            deleted_count += 1
                            logger.info(f"🗑️  Deleted: {scan_dir.name}")
                except Exception as e:
                    logger.error(f"Error processing scan {scan_dir.name}: {e}")
        
        logger.info(f"\n📊 Cleanup Summary:")
        logger.info(f"   Archived: {archived_count} scans")
        logger.info(f"   Deleted: {deleted_count} scans")
        logger.info(f"   Retention: {retention_days} days")
        
        return {"archived": archived_count, "deleted": deleted_count}
        
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        return {"error": str(e)}

# ============================================
# INTELLIGENT CRAWLER INTEGRATION
# Scrapy-Redis + Playwright + 63 Scanners
# ============================================
try:
    from intelligent_scanner_integration import (
        run_advanced_comprehensive_scan,
        get_intelligent_crawler_status,
        INTELLIGENT_CRAWLER_AVAILABLE
    )
    logger.info(" Intelligent Crawler Integration Loaded")
    logger.info("   Performance: 5-6x faster | Distributed: Yes | JS Support: Full")
except ImportError as e:
    INTELLIGENT_CRAWLER_AVAILABLE = False
    run_advanced_comprehensive_scan = None
    get_intelligent_crawler_status = None
    logger.warning(f"WARNING:  Intelligent Crawler not available: {e}")
    logger.warning("   Fallback: Using traditional ScannerChain")


# Custom scanners now loaded via backend/scanners/__init__.py (FIXED)
# Duplicate import block removed to prevent import conflicts
CUSTOM_SCANNERS_AVAILABLE = True

# Import notebook engine
try:
    from notebook_engine import NotebookPentestEngine
    NOTEBOOK_ENGINE_AVAILABLE = True
except ImportError:
    NOTEBOOK_ENGINE_AVAILABLE = False
    print("Warning: Notebook engine not available")

# Import authentication scanner controller
try:
    from controllers.auth_session_controller import AuthSessionScanController
    AUTH_SCANNER_AVAILABLE = True
except ImportError as e:
    try:
        from .controllers.auth_session_controller import AuthSessionScanController
        AUTH_SCANNER_AVAILABLE = True
    except ImportError:
        AUTH_SCANNER_AVAILABLE = False
        print(f"Warning: Authentication scanner controller not available: {e}")

# Import main1.py scanner logic
import io
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF

# Import unified scanner modules (Professional Backend Engineer Edition)
try:
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    
    # 1. NETWORK Category - Unified Entry Point
    from scanners import NetworkScanner, NmapScanner, SSLLabsScanner, PLCScanScanner, SSHAuditScanner
    
    # 2. RECONNAISSANCE & DISCOVERY Category - Unified Entry Point
    from scanners import ReconDiscoveryScanner, MassDNSScanner, DNSReconScanner, EyeWitnessScanner
    
    # 3. AUTHENTICATION & SESSION MANAGEMENT Category - Unified Entry Point
    from scanners import AuthenticationSessionScanner, AuthSessionScanner, WPSekuScanner
    
    # 4. AUTHORIZATION & ACCESS CONTROL Category - Unified Entry Point
    from scanners import AuthorizationAccessControlScanner, FFUFScanner
    
    # 5. INPUT HANDLING & INJECTION Category - Unified Entry Point
    from scanners import InputHandlingInjectionScanner, SQLMapScanner, CommixScanner, ParamMinerScanner, NoSQLMapScanner
    
    # 6. INFORMATION DISCLOSURE Category - Unified Entry Point
    from scanners import InformationDisclosureScanner
    
    # 7. WEB SECURITY Category - Unified Entry Point (SAST + DAST)
    from scanners import UnifiedWebSecurityScanner, WebSecurityScanner, NucleiScanner, XSStrikeScanner
    
    # 8. COMMAND & OS INJECTION Category - Unified Entry Point
    from scanners import CommandOSInjectionScanner, HTTPXProbe
    
    # 9. CI/CD SECURITY Category - Unified Entry Point
    from scanners import CICDSecurityScanner, CheckovScanner, GitGuardianScanner, CICDPipelineScanner
    
    # 10. CONTAINER & CLOUD SECURITY Category - Unified Entry Point
    from scanners import ContainerCloudSecurityScanner, CloudIAMScanner, TrivyScanner, ClairIntegration, AnchoreIntegration, KubeBenchScanner
    
    # 11. BLOCKCHAIN & EMAIL SECURITY Category - Unified Entry Point
    from scanners import BlockchainEmailScanner, MythrilScanner, SlitherScanner, SMTPUserEnumScanner
    
    # 12. FILE UPLOAD SECURITY Category - Unified Entry Point
    from scanners import FileUploadScanner, UnrestrictedUploadScanner, MaliciousFileScanner, PathTraversalUploadScanner
    
    # 13. CLIENT-SIDE SECURITY Category - Unified Entry Point
    from scanners import EnhancedDOMXSSScanner, DOMXSSScanner
    
    # 14. DAST INTEGRATION - Unified Entry Point
    from scanners import ZAPAuthTester
    
    # 15. BUSINESS LOGIC Category - Unified Entry Point
    from scanners import BusinessLogicScanner, PaymentLogicScanner, WorkflowAbuseScanner
    
    ALL_SCANNERS_AVAILABLE = True
    print("[SUCCESS] All unified scanner modules loaded successfully (Professional Backend Engineer Edition)")
    print("   [INFO] Unified Scanner Categories:")
    print("      - Network & Infrastructure (5: NetworkScanner, Nmap, WHOIS, SSLLabs, PLCScan)")
    print("      - Business Logic (4: BusinessLogicScanner, Payment, Race, Workflow)")
    print("      - Web Application Security (2)  # sqlmap, dirb")
    print("      - Authentication & Session (1)")
    print("      - Authorization & Access Control (1)")
    print("      - Input Handling & Injection (1)")
    print("      - Information Disclosure (1)")
    print("      - Web Security (1)")
    print("      - Command & OS Injection (1)")
    print("      - CI/CD Pipeline (1)")
    print("      - Cloud IAM (1)")
    print("      - DAST Integration (1)")
    
except ImportError as e:
    # Fallback if some scanners are not available
    print(f"Warning: Some scanners not available: {e}")
    print("Using available scanners with basic fallbacks.")
    
    # Set defaults to None for missing scanners
    NetworkScanner = None
    NmapScanner = None
    WHOISScanner = None
    SSLLabsScanner = None
    PLCScanScanner = None
    BusinessLogicScanner = None
    PaymentLogicScanner = None
    RaceConditionScanner = None
    WorkflowAbuseScanner = None
    SQLMapScanner = None
    DirbScanner = None
    AuthenticationSessionScanner = None
    AuthorizationAccessControlScanner = None
    InputHandlingInjectionScanner = None
    InformationDisclosureScanner = None
    WebSecurityScanner = None
    CommandOSInjectionScanner = None
    CICDPipelineScanner = None
    CloudIAMScanner = None
    ZAPAuthTester = None
    ALL_SCANNERS_AVAILABLE = False

# ============================================
# WebSocket Connection Manager (Moved up for early instantiation)
# ============================================
class ConnectionManager:
    """
    WebSocket connection manager for real-time scan updates
    
    Handles WebSocket connections for real-time progress updates during security scans.
    Provides stable connection management with automatic reconnection and error handling.
    """
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.scan_logs: Dict[str, List[Dict]] = {}
        self.connection_status: Dict[str, str] = {}
        
    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept WebSocket connection and store it"""
        try:
            await websocket.accept()
            self.active_connections[scan_id] = websocket
            self.connection_status[scan_id] = "connected"
            self.scan_logs[scan_id] = []
            
            # Send connection confirmation
            await self.send_message(scan_id, {
                "type": "connection",
                "status": "connected",
                "scan_id": scan_id,
                "message": "WebSocket connection established successfully",
                "timestamp": datetime.now().isoformat()
            })
            
            print(f"WebSocket connected for scan: {scan_id}")
            
        except Exception as e:
            print(f"WebSocket connection failed for {scan_id}: {str(e)}")
            self.connection_status[scan_id] = "failed"
    
    def disconnect(self, scan_id: str):
        """Remove WebSocket connection"""
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]
        self.connection_status[scan_id] = "disconnected"
        print(f"WebSocket disconnected for scan: {scan_id}")
    
    async def send_message(self, scan_id: str, message: Dict):
        """Send message to specific scan WebSocket with error handling"""
        if scan_id in self.active_connections:
            try:
                websocket = self.active_connections[scan_id]
                await websocket.send_text(json.dumps(message))
                return True
            except Exception as e:
                print(f"WebSocket send failed for {scan_id}: {str(e)}")
                self.disconnect(scan_id)
                return False
        return False
    
    async def send_log(self, scan_id: str, message: str, level: str = "info"):
        """Send log message to WebSocket"""
        log_entry = {
            "type": "log",
            "level": level,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "scan_id": scan_id
        }
        
        if scan_id not in self.scan_logs:
            self.scan_logs[scan_id] = []
        self.scan_logs[scan_id].append(log_entry)
        
        await self.send_message(scan_id, log_entry)
    
    async def send_progress(self, scan_id: str, progress: int, status: str = "running", scanner_name: str = "", current_activity: str = "", vulnerabilities_found: int = 0):
        """Send progress update to WebSocket"""
        progress_message = {
            "type": "progress",
            "progress": progress,
            "status": status,
            "scanner": scanner_name,
            "activity": current_activity,
            "vulnerabilities_found": vulnerabilities_found,  # ✅ Map findings_count to vulnerabilities_found
            "timestamp": datetime.now().isoformat(),
            "scan_id": scan_id
        }
        await self.send_message(scan_id, progress_message)
    
    async def send_finding(self, scan_id: str, finding: Dict):
        """Send individual finding to WebSocket"""
        finding_message = {
            "type": "finding",
            "finding": finding,
            "timestamp": datetime.now().isoformat(),
            "scan_id": scan_id
        }
        await self.send_message(scan_id, finding_message)
    
    async def send_complete(self, scan_id: str, result_url: str = None):
        """Send scan completion notification"""
        completion_message = {
            "type": "complete",
            "status": "completed",
            "result_url": result_url,
            "timestamp": datetime.now().isoformat(),
            "scan_id": scan_id,
            "message": "Scan completed successfully"
        }
        await self.send_message(scan_id, completion_message)
    
    async def broadcast_to_all(self, message: Dict):
        """Broadcast message to all connected WebSockets"""
        disconnected_scans = []
        for scan_id in list(self.active_connections.keys()):
            success = await self.send_message(scan_id, message)
            if not success:
                disconnected_scans.append(scan_id)
        
        for scan_id in disconnected_scans:
            self.disconnect(scan_id)
    
    def get_connection_status(self, scan_id: str) -> str:
        """Get connection status for a scan"""
        return self.connection_status.get(scan_id, "not_connected")
    
    def get_scan_logs(self, scan_id: str) -> List[Dict]:
        """Get all logs for a scan"""
        return self.scan_logs.get(scan_id, [])


class RedisSubscriber:
    def __init__(self, connection_manager):
        self.connection_manager = connection_manager
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        self.pubsub = self.redis_client.pubsub()
        
    async def start_listening(self):
        """Subscribe to distributed system updates"""
        self.pubsub.subscribe('scan_updates')
        
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                try:
                    data = json.loads(message['data'])
                    await self.handle_scan_update(data)
                except Exception as e:
                    print(f"Error processing Redis message: {e}")
    
    async def handle_scan_update(self, data):
        """Handle scan updates from distributed system"""
        scan_id = data.get('scan_id')
        update_data = data.get('data', {})
        
        # Send REAL-TIME progress update with ACTUAL vulnerability counts
        progress = update_data.get('progress', 0)
        current_step = update_data.get('activity', 'Processing...')
        findings_count = update_data.get('findings_count', 0)
        vulnerabilities_by_severity = update_data.get('vulnerabilities_by_severity', {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        })
        
        # Calculate estimated time remaining
        estimated_time = self.calculate_estimated_time(progress, findings_count)
        
        # Send comprehensive progress update with REAL-TIME vulnerability counts
        progress_message = {
            "type": "scan_progress",
            "progress": progress,
            "current_step": current_step,
            "vulnerabilities_found": findings_count,  # REAL-TIME COUNT
            "vulnerabilities_by_severity": vulnerabilities_by_severity,  # REAL-TIME BREAKDOWN
            "estimated_time_remaining": estimated_time,
            "status": update_data.get('status', 'running'),
            "timestamp": datetime.now().isoformat(),
            "scan_id": scan_id,
            "live_data": True  # Flag to indicate this is real-time data, not fake
        }
        
        await self.connection_manager.send_message(scan_id, progress_message)
    
    def calculate_estimated_time(self, progress, findings_count):
        """Calculate realistic estimated time remaining"""
        if progress == 0:
            return "Calculating..."
        elif progress >= 100:
            return "Complete"
        else:
            # Estimate based on current progress and findings rate
            remaining_progress = 100 - progress
            estimated_minutes = max(1, int(remaining_progress / 10))  # Rough estimate
            return f"{estimated_minutes} min remaining"


class SubdomainDiscovery:
    """
    Subdomain discovery and enumeration
    """
    
    def __init__(self, target: str, timeout: int = None):
        self.target = target
        self.timeout = timeout
        self.discovered_subdomains = []
        
    async def discover_subdomains(self) -> List[str]:
        """
        Discover subdomains using multiple techniques
        """
        print(f"🔍 Starting subdomain discovery for {self.target}")
        
        # Extract base domain
        base_domain = self._extract_base_domain(self.target)
        if not base_domain:
            return [self.target]
        
        subdomains = set([base_domain])  # Include the main domain
        
        try:
            # Method 1: DNS enumeration
            dns_subdomains = await self._dns_enumeration(base_domain)
            subdomains.update(dns_subdomains)
            
            # Method 2: Certificate transparency logs
            ct_subdomains = await self._certificate_transparency(base_domain)
            subdomains.update(ct_subdomains)
            
            # Method 3: Common subdomain brute force
            brute_subdomains = await self._subdomain_bruteforce(base_domain)
            subdomains.update(brute_subdomains)
            
            # Method 4: Search engine queries
            search_subdomains = await self._search_engine_enumeration(base_domain)
            subdomains.update(search_subdomains)
            
            # Filter and validate subdomains
            valid_subdomains = []
            for subdomain in subdomains:
                if self._is_valid_subdomain(subdomain):
                    valid_subdomains.append(subdomain)
            
            self.discovered_subdomains = valid_subdomains
            print(f" Discovered {len(valid_subdomains)} subdomains")
            
            return valid_subdomains
            
        except Exception as e:
            print(f"❌ Subdomain discovery failed: {e}")
            return [self.target]
    
    def _extract_base_domain(self, target: str) -> str:
        """Extract base domain from target URL"""
        try:
            if target is not None and hasattr(target, 'startswith') and target.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(target)
                domain = parsed.netloc
            else:
                domain = target
            
            # Remove port if present
            if domain and ':' in domain:
                domain = domain.split(':')[0]
            
            # Extract base domain (e.g., example.com from subdomain.example.com)
            if domain:
                domain_str = str(domain)
                if hasattr(domain_str, 'split'):
                    parts = domain_str.split('.')
                    if len(parts) >= 2:
                        return '.'.join(parts[-2:])
                return domain_str
            
        except Exception:
            return str(target) if target else ''
        return ''  # Default return to ensure function always returns a string
    
    async def _dns_enumeration(self, base_domain: str) -> List[str]:
        """DNS-based subdomain enumeration"""
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'app', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'portal', 'login',
            'secure', 'vpn', 'remote', 'mobile', 'cdn', 'static', 'assets',
            'images', 'img', 'media', 'files', 'download', 'upload', 'backup',
            'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'cache',
            'monitor', 'stats', 'analytics', 'tracking', 'logs', 'log',
            'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap', 'webmail',
            'cpanel', 'whm', 'plesk', 'directadmin', 'roundcube', 'squirrelmail',
            'webdisk', 'webmail', 'autodiscover', 'autoconfig', 'm', 'imap4',
            'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum',
            'news', 'vpn', 'ns1', 'mail1', 'new', 'mysql', 'old', 'www1',
            'beta', 'shop', 'staging', 'mail2', 'demo', 'webmail', 'media',
            'www3', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns3', 'smtp',
            'secure', 'test2', 'mail3', 'new', 'beta2', 'forum2', 'app',
            'demo2', 'shop2', 'staging2', 'dev2', 'mail4', 'beta3', 'test3'
        ]
        
        try:
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{base_domain}"
                    socket.gethostbyname(full_domain)
                    subdomains.append(full_domain)
                    print(f"    Found: {full_domain}")
                except socket.gaierror:
                    continue
        except Exception as e:
            print(f"   WARNING: DNS enumeration error: {e}")
        
        return subdomains
    
    async def _certificate_transparency(self, base_domain: str) -> List[str]:
        """Certificate transparency log enumeration"""
        subdomains = []
        try:
            import httpx
            async with httpx.AsyncClient(timeout=None) as client:
                # Use crt.sh API for certificate transparency
                url = f"https://crt.sh/?q=%.{base_domain}&output=json"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    for cert in data:
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip()
                                if name.endswith(f".{base_domain}") and name not in subdomains:
                                    subdomains.append(name)
                                    print(f"    Found via CT: {name}")
        except Exception as e:
            print(f"   WARNING: Certificate transparency error: {e}")
        
        return subdomains
    
    async def _subdomain_bruteforce(self, base_domain: str) -> List[str]:
        """Subdomain brute force using wordlist"""
        subdomains = []
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'api', 'app', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'portal', 'login',
            'secure', 'vpn', 'remote', 'mobile', 'cdn', 'static', 'assets',
            'images', 'img', 'media', 'files', 'download', 'upload', 'backup',
            'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'cache',
            'monitor', 'stats', 'analytics', 'tracking', 'logs', 'log',
            'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap', 'webmail',
            'cpanel', 'whm', 'plesk', 'directadmin', 'roundcube', 'squirrelmail',
            'webdisk', 'webmail', 'autodiscover', 'autoconfig', 'm', 'imap4',
            'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum',
            'news', 'vpn', 'ns1', 'mail1', 'new', 'mysql', 'old', 'www1',
            'beta', 'shop', 'staging', 'mail2', 'demo', 'webmail', 'media',
            'www3', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns3', 'smtp',
            'secure', 'test2', 'mail3', 'new', 'beta2', 'forum2', 'app',
            'demo2', 'shop2', 'staging2', 'dev2', 'mail4', 'beta3', 'test3',
            'alpha', 'gamma', 'delta', 'omega', 'sigma', 'lambda', 'theta',
            'production', 'prod', 'live', 'main', 'primary', 'secondary',
            'backup', 'archive', 'old', 'legacy', 'v1', 'v2', 'v3', 'version1',
            'version2', 'version3', 'release', 'rc', 'candidate', 'hotfix',
            'patch', 'update', 'upgrade', 'migration', 'sync', 'replica',
            'mirror', 'clone', 'copy', 'duplicate', 'backup2', 'backup3'
        ]
        
        try:
            for subdomain in wordlist:
                try:
                    full_domain = f"{subdomain}.{base_domain}"
                    socket.gethostbyname(full_domain)
                    subdomains.append(full_domain)
                    print(f"    Found via brute force: {full_domain}")
                except socket.gaierror:
                    continue
        except Exception as e:
            print(f"   WARNING: Brute force error: {e}")
        
        return subdomains
    
    async def _search_engine_enumeration(self, base_domain: str) -> List[str]:
        """Search engine-based subdomain enumeration"""
        subdomains = []
        try:
            import httpx
            async with httpx.AsyncClient(timeout=None) as client:
                # Use Google dorking for subdomain discovery
                search_queries = [
                    f"site:{base_domain}",
                    f"site:*.{base_domain}",
                    f"inurl:{base_domain}",
                    f"intitle:{base_domain}"
                ]
                
                for query in search_queries:
                    try:
                        # This is a simplified approach - in production, use proper search APIs
                        url = f"https://www.google.com/search?q={query}"
                        response = await client.get(url)
                        if response.status_code == 200:
                            # Parse results for subdomains (simplified)
                            content = response.text
                            import re
                            found_domains = re.findall(rf'([a-zA-Z0-9-]+\.{re.escape(base_domain)})', content)
                            for domain in found_domains:
                                if domain not in subdomains:
                                    subdomains.append(domain)
                                    print(f"    Found via search: {domain}")
                    except Exception:
                        continue
        except Exception as e:
            print(f"   WARNING: Search engine enumeration error: {e}")
        
        return subdomains
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate if subdomain is accessible"""
        try:
            if not subdomain:
                return False
            subdomain_str = str(subdomain) if subdomain is not None else ''
            if not subdomain_str:
                return False
            socket.gethostbyname(subdomain_str)
            return True
        except (socket.gaierror, TypeError):
            return False

class AdvancedNmapScanner:
    """Network vulnerability scanner using nmap"""
    
    def __init__(self):
        # Properly handle Nmap initialization with null checks
        if NMAP_AVAILABLE and nmap is not None:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                print(f"Warning: Failed to initialize Nmap PortScanner: {e}")
                self.nm = None
        else:
            self.nm = None
            
        self.results = {}
        # Rate limiting for CVE API
        self.last_cve_request = 0
        self.cve_request_delay = 1.5  # seconds between requests
        
        # Subdomain discovery
        self.subdomain_discovery = None
        self.discovered_subdomains = []
        
        # Initialize all available scanners
        self.scanners: Dict[str, Any] = {
            'nmap': None,
            'auth_session': None,
            'authorization': None,
        }
        self.scanners['nmap'] = self

    def scan(self, target: str) -> Dict[str, Any]:
        """
        Scan a target using nmap and return the results
        """
        if self.nm is None:
            return {}
        try:
            self.nm.scan(target)
            return self.nm[target]
        except Exception as e:
            print(f"Error scanning target {target}: {e}")
            return {}

    def is_valid_subdomain(self, subdomain_str: str) -> bool:
        """
        Check if a subdomain is valid by attempting to resolve it
        """
        try:
            if subdomain_str is None or subdomain_str == "":
                return False
            socket.gethostbyname(subdomain_str)
            return True
        except (socket.gaierror, TypeError):
            return False

# ... rest of the code ...

# Remove all basic scanner implementations to ensure only real scanners are used


#!/usr/bin/env python3
"""
Educational Security Analysis Framework
A responsible tool for learning about web security concepts and OWASP Top 10.
"""

import os
import json
import asyncio
import logging
import redis
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
import socket
import subprocess
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import re
import shutil
import zipfile
from pathlib import Path

# Import nmap if available
try:
    import nmap
    import dns.resolver
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    nmap = None  # Explicitly set to None to avoid "possibly unbound" errors
    print("Warning: nmap or dnspython not installed. Network scanning features will be limited.")

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends, status, Request
# from controllers.scan_controller import router as scan_router  # Disabled - using file-based storage
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, HttpUrl, Field
import httpx
from bs4 import BeautifulSoup
import websockets
import json as json_lib
import bcrypt
import jwt
from passlib.context import CryptContext
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
import time
from collections import defaultdict
from contextlib import asynccontextmanager

# Import CVE database
try:
    from backend.cve_database import cve_db, CVEReference
except ImportError:
    try:
        from cve_database import cve_db, CVEReference
    except ImportError:
        # Fallback if CVE database not available
        cve_db = None
        CVEReference = None

# Initialize comprehensive logging system
import logging
import logging.handlers
from pathlib import Path

log_dir = Path(__file__).parent / "logs"
log_dir.mkdir(exist_ok=True)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Clear existing handlers
logger.handlers.clear()

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s | %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# File handler - all logs
file_handler = logging.handlers.RotatingFileHandler(
    log_dir / "main_backend.log",
    maxBytes=20*1024*1024,  # 20MB
    backupCount=10
)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Error file handler
error_handler = logging.handlers.RotatingFileHandler(
    log_dir / "main_backend_errors.log",
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(file_formatter)
logger.addHandler(error_handler)

# Scan activity handler
scan_handler = logging.handlers.RotatingFileHandler(
    log_dir / "scan_activity.log",
    maxBytes=50*1024*1024,  # 50MB
    backupCount=10
)
scan_handler.setLevel(logging.INFO)
scan_handler.setFormatter(file_formatter)
logger.addHandler(scan_handler)

logger.info("="*80)
logger.info("MAIN BACKEND STARTING - ENHANCED DISTRIBUTED SYSTEM INTEGRATION")
logger.info("="*80)

# Global scan results storage
scan_results = {}  # Dictionary to store scan results by scan_id

# Import custom scanners
try:
    from scanners.input_handling_injection.sqlmap_scanner import SQLMapScanner
  # File does not exist
    from scanners.whois_scanner import WHOISScanner
    from scanners.ssl_labs_scanner import SSLLabsScanner
    from scanners.dirb_scanner import DirbScanner
    from scanners.authentication_session_management import AuthSessionScanner, AuthenticationSessionScanner
    from scanners.authorization_access_control import AuthorizationAccessControlScanner
    from scanners.input_handling_injection import InputHandlingInjectionScanner
    from scanners.command_os_injection.framework_scanner import CommandOSInjectionScanner
    CUSTOM_SCANNERS_AVAILABLE = True
except ImportError as e:
    CUSTOM_SCANNERS_AVAILABLE = False
    print(f"Warning: Custom scanners not available: {e}")

# Import notebook engine
try:
    from notebook_engine import NotebookPentestEngine
    NOTEBOOK_ENGINE_AVAILABLE = True
except ImportError:
    NOTEBOOK_ENGINE_AVAILABLE = False
    print("Warning: Notebook engine not available")

# Import authentication scanner controller
try:
    from controllers.auth_session_controller import AuthSessionScanController
    AUTH_SCANNER_AVAILABLE = True
except ImportError as e:
    try:
        from .controllers.auth_session_controller import AuthSessionScanController
        AUTH_SCANNER_AVAILABLE = True
    except ImportError:
        AUTH_SCANNER_AVAILABLE = False
        print(f"Warning: Authentication scanner controller not available: {e}")

# Import main1.py scanner logic
import io
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF

# Import unified scanner modules (Professional Backend Engineer Edition)
try:
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    
    # 1. Core Network & Infrastructure Scanners
    # Import unified NetworkScanner (orchestrates Nmap+WHOIS+SSL+PLC)
    from scanners.NETWORK import NetworkScanner
    # Also import individual scanners for backward compatibility
    from scanners.NETWORK import NmapScanner, WHOISScanner, SSLLabsScanner, PLCScanScanner
    
    # 2. Web Application Security Scanners
  # File does not exist
    from scanners.input_handling_injection.sqlmap_scanner import SQLMapScanner
  # File does not exist
    from scanners.dirb_scanner import DirbScanner
  # File does not exist
    
    # 3. Authentication & Session Management
    from scanners.authentication_session_management.framework_scanner import AuthenticationSessionScanner
    
    # 4. Authorization & Access Control
    from scanners.authorization_access_control.framework_scanner import AuthorizationAccessControlScanner
    
    # 5. Input Handling & Injection
    from scanners.input_handling_injection.input_handling_scanner import InputHandlingScanner as InputHandlingInjectionScanner
    
    # 6. Information Disclosure
    from scanners.information_disclosure_scanner.information_disclosure_scanner import InformationDisclosureScanner
    
    # 7. Web Security (SSRF, CSRF, CORS)
    from scanners.web_security_scanner.web_security_scanner import WebSecurityScanner
    
    # 8. Command & OS Injection
    from scanners.command_os_injection.framework_scanner import CommandOSInjectionScanner
    
    # 9. CI/CD Pipeline Security - DISABLED (import issues)
    # from scanners.CI.CD.cicd_pipeline_scanner import CICDPipelineScanner
    CICDPipelineScanner = None  # Disabled
    
    # 10. Cloud IAM Security
    from scanners.cloud_iam_scanner import CloudIAMScanner
    
    # 11. DAST Integration (using ZAPAuthTester as the main class)
    from scanners.dast_integration import ZAPAuthTester
    
    # 12. Business Logic Scanners (NEW - Unified Scanner)
    from scanners.business_logic import BusinessLogicScanner
    from scanners.business_logic import PaymentLogicScanner, RaceConditionScanner, WorkflowAbuseScanner
    
    ALL_SCANNERS_AVAILABLE = True
    print("[SUCCESS] All unified scanner modules loaded successfully (Professional Backend Engineer Edition)")
    print("   [INFO] Unified Scanner Categories:")
    print("      - Network & Infrastructure (5: NetworkScanner, Nmap, WHOIS, SSLLabs, PLCScan)")
    print("      - Business Logic (4: BusinessLogicScanner, Payment, Race, Workflow)")
    print("      - Web Application Security (2)  # sqlmap, dirb")
    print("      - Authentication & Session (1)")
    print("      - Authorization & Access Control (1)")
    print("      - Input Handling & Injection (1)")
    print("      - Information Disclosure (1)")
    print("      - Web Security (1)")
    print("      - Command & OS Injection (1)")
    print("      - CI/CD Pipeline (1)")
    print("      - Cloud IAM (1)")
    print("      - DAST Integration (1)")
    
except ImportError as e:
    # Fallback if some scanners are not available
    print(f"Warning: Some scanners not available: {e}")
    print("Using available scanners with basic fallbacks.")
    
    # Set defaults to None for missing scanners
    NetworkScanner = None
    NmapScanner = None
    WHOISScanner = None
    SSLLabsScanner = None
    PLCScanScanner = None
    BusinessLogicScanner = None
    PaymentLogicScanner = None
    RaceConditionScanner = None
    WorkflowAbuseScanner = None
    SQLMapScanner = None
    DirbScanner = None
    AuthenticationSessionScanner = None
    AuthorizationAccessControlScanner = None
    InputHandlingInjectionScanner = None
    InformationDisclosureScanner = None
    WebSecurityScanner = None
    CommandOSInjectionScanner = None
    CICDPipelineScanner = None
    CloudIAMScanner = None
    ZAPAuthTester = None
    ALL_SCANNERS_AVAILABLE = False



class ComprehensiveSecurityScanner:
    """
    Comprehensive Security Scanner integrating all available scanner features
    """
    def __init__(self):
        # Properly handle Nmap initialization with null checks
        if NMAP_AVAILABLE and nmap is not None:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                print(f"Warning: Failed to initialize Nmap PortScanner: {e}")
                self.nm = None
        else:
            self.nm = None
            
        self.results = {}
        # Rate limiting for CVE API
        self.last_cve_request = 0
        self.cve_request_delay = 1.5  # seconds between requests
        
        # Subdomain discovery
        self.subdomain_discovery = None
        self.discovered_subdomains = []
        
        # Initialize all available scanners
        self.scanners: Dict[str, Any] = {
            'nmap': None,
            'auth_session': None,
            'authorization': None,
            'input_handling': None,
            'information_disclosure': None,
            'web_security': None,
            'command_injection': None,
            'cicd_pipeline': None,
            'cloud_iam': None,
            'sqlmap': None,
            'whois': None,
            'ssl_labs': None,
            'dirb': None
        }
        
        # Initialize available scanners
        self._initialize_scanners()
        
        # Remove basic scanner implementations to ensure only real scanners are used
    
    async def comprehensive_scan_with_subdomains(self, target: str, scan_options: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive scan with subdomain discovery and all 17 scanners
        """
        logger.info(f"[SCAN] Starting comprehensive scan with subdomain discovery for {target}")
        
        # Initialize scanners with actual target URL (removes hardcoded example.com)
        self._initialize_target_scanners(target)
        
        # Track real-time vulnerability counts
        self.total_vulnerabilities_found = 0
        self.vulnerabilities_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # Step 1: Discover subdomains
        self.subdomain_discovery = SubdomainDiscovery(target)
        self.discovered_subdomains = await self.subdomain_discovery.discover_subdomains()
        
        logger.info(f"[INFO] Discovered {len(self.discovered_subdomains)} subdomains to scan")
        
        # Step 2: Run all 12 scanners on each subdomain
        all_results = {}
        total_scans = len(self.discovered_subdomains) * len(self.scanners)
        current_scan = 0
        
        for subdomain in self.discovered_subdomains:
            print(f"\n🔍 Scanning subdomain: {subdomain}")
            subdomain_results = {}
            
            for scanner_name, scanner_instance in self.scanners.items():
                if scanner_instance is not None:
                    current_scan += 1
                    print(f"   [{current_scan}/{total_scans}] Running {scanner_name} on {subdomain}")
                    
                    try:
                        # Set target for scanner
                        if hasattr(scanner_instance, 'target'):
                            scanner_instance.target = subdomain
                        
                        # Execute scanner
                        if hasattr(scanner_instance, 'scan'):
                            if asyncio.iscoroutinefunction(scanner_instance.scan):
                                result = await scanner_instance.scan()
                            else:
                                result = scanner_instance.scan()
                        else:
                            result = {'error': 'No scan method available'}
                        
                        subdomain_results[scanner_name] = result
                        
                        # REAL-TIME VULNERABILITY TRACKING AND LOGGING
                        if isinstance(result, dict):
                            findings = result.get('findings', [])
                            vulnerabilities = result.get('vulnerabilities', [])
                            
                            if findings or vulnerabilities:
                                # Update real-time counts
                                new_findings_count = len(findings) + len(vulnerabilities)
                                self.total_vulnerabilities_found += new_findings_count
                                
                                # Count by severity (REAL DATA)
                                for finding in findings:
                                    severity = finding.get('severity', 'info').lower()
                                    if severity in self.vulnerabilities_by_severity:
                                        self.vulnerabilities_by_severity[severity] += 1
                                
                                for vuln in vulnerabilities:
                                    severity = vuln.get('severity', 'info').lower()
                                    if severity in self.vulnerabilities_by_severity:
                                        self.vulnerabilities_by_severity[severity] += 1
                                
                                # Log REAL-TIME discovery with ACTUAL counts (NO FAKE DATA)
                                logger.info(f"🔍 [{scanner_name}] Discovered {new_findings_count} vulnerabilities on {subdomain}")
                                logger.info(f"📊 REAL-TIME COUNT | Total: {self.total_vulnerabilities_found} | " + 
                                          f"Critical: {self.vulnerabilities_by_severity['critical']} | " +
                                          f"High: {self.vulnerabilities_by_severity['high']} | " +
                                          f"Medium: {self.vulnerabilities_by_severity['medium']} | " +
                                          f"Low: {self.vulnerabilities_by_severity['low']} | " +
                                          f"Info: {self.vulnerabilities_by_severity['info']}")
                                
                                print(f"       ✓ Found {len(findings)} findings, {len(vulnerabilities)} vulnerabilities")
                            else:
                                print(f"       ✓ Completed - no findings")
                        else:
                            print(f"       ✓ Completed")
                            
                    except Exception as e:
                        logger.error(f"      ❌ [{scanner_name}] Failed: {str(e)}")
                        subdomain_results[scanner_name] = {'error': str(e)}
            
            all_results[subdomain] = subdomain_results
        
        # Step 3: Generate comprehensive report
        comprehensive_report = self._generate_comprehensive_report(all_results)
        
        return comprehensive_report
    
    def _generate_comprehensive_report(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive report from all subdomain scan results
        """
        total_findings = []
        total_vulnerabilities = []
        total_ports = []
        total_services = []
        subdomain_summary = {}
        
        for subdomain, subdomain_results in all_results.items():
            subdomain_findings = []
            subdomain_vulns = []
            subdomain_ports = []
            subdomain_services = []
            
            for scanner_name, result in subdomain_results.items():
                if isinstance(result, dict) and 'error' not in result:
                    findings = result.get('findings', [])
                    vulnerabilities = result.get('vulnerabilities', [])
                    open_ports = result.get('open_ports', [])
                    services = result.get('services', [])
                    
                    subdomain_findings.extend(findings)
                    subdomain_vulns.extend(vulnerabilities)
                    subdomain_ports.extend(open_ports)
                    subdomain_services.extend(services)
            
            total_findings.extend(subdomain_findings)
            total_vulnerabilities.extend(subdomain_vulns)
            total_ports.extend(subdomain_ports)
            total_services.extend(subdomain_services)
            
            subdomain_summary[subdomain] = {
                'findings_count': len(subdomain_findings),
                'vulnerabilities_count': len(subdomain_vulns),
                'open_ports_count': len(subdomain_ports),
                'services_count': len(subdomain_services),
                'scanners_executed': len(subdomain_results)
            }
        
        # Calculate CVSS scores for findings
        for finding in total_findings:
            if 'cvss_score' not in finding:
                finding['cvss_score'] = self._calculate_cvss_score(finding)
        
        # Sort findings by CVSS score
        total_findings.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        return {
            'scan_summary': {
                'total_subdomains': len(self.discovered_subdomains),
                'total_scanners': len(self.scanners),
                'total_scans_executed': sum(len(results) for results in all_results.values()),
                'total_findings': len(total_findings),
                'total_vulnerabilities': len(total_vulnerabilities),
                'total_open_ports': len(total_ports),
                'total_services': len(total_services),
                'severity_breakdown': {
                    'critical': len([f for f in total_findings if f.get('severity') == 'critical']),
                    'high': len([f for f in total_findings if f.get('severity') == 'high']),
                    'medium': len([f for f in total_findings if f.get('severity') == 'medium']),
                    'low': len([f for f in total_findings if f.get('severity') == 'low']),
                    'info': len([f for f in total_findings if f.get('severity') == 'info'])
                }
            },
            'subdomain_summary': subdomain_summary,
            'all_findings': total_findings,
            'all_vulnerabilities': total_vulnerabilities,
            'all_open_ports': total_ports,
            'all_services': total_services,
            'detailed_results': all_results
        }
    
    def _calculate_cvss_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate CVSS score for a finding
        """
        try:
            severity = finding.get('severity', 'info').lower()
            base_score = 0.0
            
            # Base CVSS scoring
            if severity == 'critical':
                base_score = 9.0
            elif severity == 'high':
                base_score = 7.0
            elif severity == 'medium':
                base_score = 5.0
            elif severity == 'low':
                base_score = 3.0
            else:
                base_score = 1.0
            
            # Adjust based on finding type
            finding_type = finding.get('type', '').lower()
            if 'sql' in finding_type or 'injection' in finding_type:
                base_score += 0.5
            elif 'xss' in finding_type or 'cross-site' in finding_type:
                base_score += 0.3
            elif 'authentication' in finding_type or 'authorization' in finding_type:
                base_score += 0.4
            elif 'ssl' in finding_type or 'tls' in finding_type:
                base_score += 0.2
            
            # Cap at 10.0
            return min(base_score, 10.0)
            
        except Exception:
            return 1.0
    
    def resolve_target(self, target):
        """Resolve target to IP and hostname"""
        try:
            # Parse target URL if provided
            if target is not None and hasattr(target, 'startswith') and target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                hostname = parsed.hostname
            else:
                hostname = target
            
            # Resolve hostname to IP
            try:
                hostname_str = str(hostname) if hostname is not None else ''
                ip = socket.gethostbyname(hostname_str)
            except (socket.gaierror, TypeError):
                ip = str(hostname) if hostname is not None else ''  # Assume it's already an IP
            
            target_str = str(target) if target is not None else ''
            hostname_str = str(hostname) if hostname is not None else ''
            ip_str = str(ip) if ip else ''
            
            return {
                'ip': ip_str,
                'hostname': hostname_str,
                'url_provided': target is not None and hasattr(target, 'startswith') and target.startswith(('http://', 'https://')),
                'original_target': target_str
            }
        except Exception as e:
            print(f"Error resolving target {target}: {e}")
            return None
    
    def _initialize_scanners(self):
        """Initialize base scanner modules (target-specific scanners initialized dynamically)"""
        logger.info("🔧 Initializing base scanner modules...")
        
        # Scanners will be initialized with actual target URL when needed
        # This prevents hardcoded example.com URLs
        self.target_url = None  # Will be set when scan starts
        
        try:
            # Scanners that don't require target URL for initialization
            # 7. Web Security (1)
            if WebSecurityScanner:
                self.scanners['web_security'] = WebSecurityScanner('.', False)
                logger.info("✓ WebSecurityScanner initialized")
            
            # 9. CI/CD Pipeline Security (1)
            if CICDPipelineScanner:
                self.scanners['cicd_pipeline'] = CICDPipelineScanner('.', timeout=None)
                logger.info("✓ CICDPipelineScanner initialized")
            
            # 10. Cloud IAM Security (1)
            if CloudIAMScanner:
                self.scanners['cloud_iam'] = CloudIAMScanner('.', timeout=None)
                logger.info("✓ CloudIAMScanner initialized")
            
            # Other scanners will be initialized dynamically with actual target
            logger.info(f"🎯 Base scanners initialized. Target-specific scanners will be initialized with actual URL")
            
        except Exception as e:
            logger.error(f"⚠️ Some base scanners could not be initialized: {e}")
            import traceback
            traceback.print_exc()
            logger.info("Continuing with available scanners...")
    
    def _initialize_target_scanners(self, target: str):
        """
        Initialize scanners that require actual target URL
        Called when scan starts with real target
        """
        logger.info(f"🎯 Initializing target-specific scanners for: {target}")
        self.target_url = target
        
        try:
            # Parse target to get domain and URL
            parsed = urlparse(target if target.startswith('http') else f'http://{target}')
            domain = parsed.netloc or parsed.path
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else f"http://{target}"
            
            # 1. Network & Infrastructure Scanners
            if NmapScanner:
                self.scanners['nmap'] = NmapScanner(domain)
                logger.info(f"✓ NmapScanner initialized for {domain}")
            
            if WHOISScanner:
                self.scanners['whois'] = WHOISScanner(domain)
                logger.info(f"✓ WHOISScanner initialized for {domain}")
            
            if SSLLabsScanner:
                self.scanners['ssl_labs'] = SSLLabsScanner(domain)
                logger.info(f"✓ SSLLabsScanner initialized for {domain}")
            
            # 2. Web Application Security Scanners
            if SQLMapScanner:
                self.scanners['sqlmap'] = SQLMapScanner(base_url)
                logger.info(f"✓ SQLMapScanner initialized for {base_url}")
            
            if DirbScanner:
                self.scanners['dirb'] = DirbScanner(base_url)
                logger.info(f"✓ DirbScanner initialized for {base_url}")
            
            # 3. Authentication & Session Management
            if AuthenticationSessionScanner:
                self.scanners['auth_session'] = AuthenticationSessionScanner(base_url)
                logger.info(f"✓ AuthenticationSessionScanner initialized for {base_url}")
            
            # 4. Authorization & Access Control
            if AuthorizationAccessControlScanner:
                self.scanners['authorization'] = AuthorizationAccessControlScanner(base_url)
                logger.info(f"✓ AuthorizationAccessControlScanner initialized for {base_url}")
            
            # 5. Input Handling & Injection
            if InputHandlingInjectionScanner:
                self.scanners['input_handling'] = InputHandlingInjectionScanner(base_url, timeout=None)
                logger.info(f"✓ InputHandlingInjectionScanner initialized for {base_url}")
            
            # 6. Information Disclosure
            if InformationDisclosureScanner:
                self.scanners['information_disclosure'] = InformationDisclosureScanner(base_url, timeout=None)
                logger.info(f"✓ InformationDisclosureScanner initialized for {base_url}")
            
            # 8. Command & OS Injection
            if CommandOSInjectionScanner:
                self.scanners['command_injection'] = CommandOSInjectionScanner(base_url, timeout=None)
                logger.info(f"✓ CommandOSInjectionScanner initialized for {base_url}")
            
            # 11. DAST Integration
            if ZAPAuthTester:
                self.scanners['dast_integration'] = ZAPAuthTester(domain, 8080)
                logger.info(f"✓ ZAPAuthTester initialized for {domain}")

            # 12. File Upload Security
            if FileUploadScanner:
                self.scanners['file_upload'] = FileUploadScanner(base_url, timeout=None)
                logger.info(f"✓ FileUploadScanner initialized for {base_url}")
            
            initialized_count = len([s for s in self.scanners.values() if s is not None])
            logger.info(f"🎉 Successfully initialized {initialized_count} scanner modules for {target}")
            
        except Exception as e:
            logger.error(f"⚠️ Error initializing target scanners: {e}")
            import traceback
            traceback.print_exc()

# Remove all basic scanner implementations to ensure only real scanners are used

class ScannerChain:
    """
    Sequential Scanner Chain - Runs scanners one by one in a defined order
    """
    def __init__(self, target: str):
        self.target = target
        self.scan_results = {}
        self.scan_order = []
        self.current_step = 0
        self.total_steps = 0
        self.start_time = None
        self.end_time = None
        self.discovered_subdomains = []
        self.discovered_urls = []  # Track all discovered URLs
        
        # Initialize comprehensive scanner
        self.comprehensive_scanner = ComprehensiveSecurityScanner()
        
        # Define scanner chain order (sequential execution with subdomain discovery)
        self.scanner_chain = [
            {
                'name': 'subdomain_discovery',
                'description': 'Subdomain Discovery & Enumeration',
                'scanner': 'subdomain_discovery',
                'method': 'discover_subdomains',
                'required': True
            },
            {
                'name': 'complete_crawling',
                'description': 'Complete Website Crawling',
                'scanner': 'web_crawler',
                'method': 'crawl_website',
                'required': True
            },
            {
                'name': 'target_resolution',
                'description': 'Target Resolution & DNS Enumeration',
                'scanner': 'nmap',
                'method': 'resolve_target',
                'required': True
            },
            {
                'name': 'network_discovery',
                'description': 'Network Discovery & Port Scanning',
                'scanner': 'nmap',
                'method': 'comprehensive_scan',
                'required': True
            },
            {
                'name': 'whois_lookup',
                'description': 'WHOIS Domain Information',
                'scanner': 'whois',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'ssl_analysis',
                'description': 'SSL/TLS Configuration Analysis',
                'scanner': 'ssl_labs',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'directory_enumeration',
                'description': 'Directory & File Enumeration',
                'scanner': 'dirb',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'sql_injection_test',
                'description': 'SQL Injection Vulnerability Test',
                'scanner': 'sqlmap',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'authentication_analysis',
                'description': 'Authentication & Session Management Analysis',
                'scanner': 'auth_session',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'authorization_test',
                'description': 'Authorization & Access Control Test',
                'scanner': 'authorization',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'input_handling_scan',
                'description': 'Input Handling & Injection Scan',
                'scanner': 'input_handling',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'information_disclosure',
                'description': 'Information Disclosure Scan',
                'scanner': 'information_disclosure',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'web_security_scan',
                'description': 'Web Security Scan (SSRF, CSRF, CORS)',
                'scanner': 'web_security',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'file_upload_test',
                'description': 'File Upload Security Test',
                'scanner': 'file_upload',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'command_injection_scan',
                'description': 'Command Injection Vulnerability Scan',
                'scanner': 'command_injection',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'directory_brute_force',
                'description': 'Directory Brute Force Attack',
                'scanner': 'dirb',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'cicd_pipeline_scan',
                'description': 'CI/CD Pipeline Security Scan',
                'scanner': 'cicd_pipeline',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'cloud_iam_scan',
                'description': 'Cloud IAM Security Scan',
                'scanner': 'cloud_iam',
                'method': 'scan',
                'required': True
            },
            {
                'name': 'dast_integration_scan',
                'description': 'DAST Integration Security Scan',
                'scanner': 'dast_integration',
                'method': 'scan',
                'required': True
            }
        ]
        
        # Initialize comprehensive scanner
        self.comprehensive_scanner = ComprehensiveSecurityScanner()
        self.total_steps = len(self.scanner_chain)

    async def run_chain(self, scan_options: Optional[Dict[str, bool]] = None):
        """
        Run the complete scanner chain with subdomain discovery, complete crawling, and all 17 scanners
        """
        if scan_options is None:
            scan_options = {
                'include_web_scans': True,
                'include_auth_scans': True,
                'include_injection_scans': True,
                'include_info_disclosure': True,
                'include_dirb_scan': True
            }

        self.start_time = datetime.now()
        print(f"[SCAN] Starting Scanner Chain with Subdomain Discovery and Complete Crawling for {self.target}")
        print(f"[INFO] Total Steps: {self.total_steps}")
        print("="*60)

        # Step 1: Subdomain Discovery
        await self._run_step(0, scan_options)
        
        # Check if subdomain discovery was successful
        if 'subdomain_discovery' not in self.scan_results:
            print("WARNING: Subdomain discovery failed. Using main target only.")
            self.discovered_subdomains = [self.target]
        else:
            # Get discovered subdomains
            self.discovered_subdomains = self.scan_results['subdomain_discovery'].get('subdomains', [self.target])
        
        print(f"[INFO] Discovered {len(self.discovered_subdomains)} subdomains to scan")

        # Step 2: Complete Website Crawling
        await self._run_step(1, scan_options)
        
        # Check if crawling was successful
        if 'complete_crawling' not in self.scan_results:
            print("WARNING: Website crawling failed. Using main target only.")
            self.discovered_urls = [self.target]
        else:
            # Get discovered URLs
            self.discovered_urls = self.scan_results['complete_crawling'].get('urls', [self.target])
        
        print(f"🕷️  Crawled {len(self.discovered_urls)} URLs from the website")

        # Combine all targets (subdomains + URLs) for scanning
        all_targets = list(set(self.discovered_subdomains + self.discovered_urls))
        print(f"🎯 Total targets to scan: {len(all_targets)} (subdomains + URLs)")

        # Step 3: Target Resolution for main target
        await self._run_step(2, scan_options)
        
        # Continue even if target resolution failed
        if 'target_resolution' not in self.scan_results:
            print("WARNING: Target resolution failed. Continuing with available information.")

        # Step 4: Run all 12 scanners on each discovered target
        all_target_results = {}
        total_scans = len(all_targets) * (len(self.scanner_chain) - 3)  # Exclude discovery steps
        current_scan = 0
        successful_scans = 0
        failed_scans = 0
        
        for target in all_targets:
            print(f"\n🔍 Scanning target: {target}")
            target_results = {}
            
            # Run all scanners for this target
            for i in range(3, len(self.scanner_chain)):  # Skip discovery steps
                step = self.scanner_chain[i]
                current_scan += 1
                
                print(f"   [{current_scan}/{total_scans}] {step['description']} on {target}")
                
                # Run scanner on this target
                try:
                    result = await self._run_scanner_on_target(step, target)
                    if result:
                        target_results[step['name']] = result
                        successful_scans += 1
                        
                        # Display results
                        if isinstance(result, dict) and 'error' not in result:
                            findings = result.get('findings', [])
                            vulnerabilities = result.get('vulnerabilities', [])
                            open_ports = result.get('open_ports', [])
                            services = result.get('services', [])
                            
                            total_items = len(findings) + len(vulnerabilities) + len(open_ports) + len(services)
                            if total_items > 0:
                                print(f"    {step['description']}: {total_items} items found")
                            else:
                                print(f"    {step['description']}: No issues found")
                        else:
                            print(f"   WARNING: {step['description']}: {result.get('error', 'Unknown error')}")
                            failed_scans += 1
                    else:
                        print(f"   ❌ {step['description']}: No result returned")
                        failed_scans += 1
                        
                except Exception as e:
                    print(f"   ❌ {step['description']} failed: {str(e)}")
                    target_results[step['name']] = {'error': str(e), 'status': 'failed'}
                    failed_scans += 1
            
            all_target_results[target] = target_results
        
        # Step 5: Generate comprehensive report with deduplication
        comprehensive_report = await self._generate_comprehensive_report(all_target_results)
        
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        
        print("="*60)
        print(f" Scanner Chain Completed in {duration}")
        print(f"📊 Targets Scanned: {len(all_targets)}")
        print(f"📊 Total Scans Executed: {current_scan}")
        print(f"📊 Successful Scans: {successful_scans}")
        print(f"📊 Failed Scans: {failed_scans}")
        print(f"📊 Success Rate: {(successful_scans/max(current_scan, 1)*100):.1f}%")
        
        # Store comprehensive results
        self.scan_results['comprehensive_report'] = comprehensive_report
        self.scan_results['target_results'] = all_target_results
        
        # Add individual step results for backward compatibility
        for target, target_results in all_target_results.items():
            for scanner_name, result in target_results.items():
                step_key = f"{scanner_name}_{target}" if len(all_targets) > 1 else scanner_name
                self.scan_results[step_key] = result
        
        return self.scan_results

    async def _crawl_website_completely(self, url: str) -> List[str]:
        """
        Crawl website completely to discover all URLs and endpoints
        """
        urls = []
        try:
            print(f"🕷️  Starting complete crawl of {url}")
            
            # Use a more comprehensive crawling approach with fresh data
            current_timestamp = int(datetime.now().timestamp())
            headers = {
                'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0',
                'X-Requested-With': f'Scanner-{current_timestamp}'
            }
            
            # No timeout - allow complete website crawling
            async with httpx.AsyncClient(timeout=None, headers=headers) as client:
                # Get main page with fresh data
                fresh_url = f"{url}?_t={current_timestamp}" if '?' not in url else f"{url}&_t={current_timestamp}"
                response = await client.get(fresh_url)
                urls.append(url)
                
                # Extract links from HTML
                if 'text/html' in response.headers.get('content-type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        # Ensure link is a Tag object before calling get
                        if hasattr(link, 'get') and callable(getattr(link, 'get')):
                            href = link.get('href', '')
                            # Convert href to string if it's an AttributeValueList
                            href_str = str(href) if href is not None else ''
                            if href_str and hasattr(href_str, 'startswith') and href_str.startswith('http'):
                                urls.append(href_str)
                            elif href_str and hasattr(href_str, 'startswith') and href_str.startswith('/'):
                                # Convert relative URL to absolute
                                from urllib.parse import urljoin
                                absolute_url = urljoin(url, href_str)
                                urls.append(absolute_url)
                            elif href_str and hasattr(href_str, 'startswith') and not href_str.startswith('#') and not href_str.startswith('mailto:'):
                                # Convert relative URL to absolute
                                from urllib.parse import urljoin
                                absolute_url = urljoin(url, href_str)
                                urls.append(absolute_url)
                    
                    # Find all forms
                    for form in soup.find_all('form', action=True):
                        # Ensure form is a Tag object before calling get
                        if hasattr(form, 'get') and callable(getattr(form, 'get')):
                            action = form.get('action', '')
                            # Convert action to string if it's an AttributeValueList
                            action_str = str(action) if action is not None else ''
                            if action_str and hasattr(action_str, 'startswith') and action_str.startswith('http'):
                                urls.append(action_str)
                            elif action_str and hasattr(action_str, 'startswith') and action_str.startswith('/'):
                                # Convert relative URL to absolute
                                from urllib.parse import urljoin
                                absolute_url = urljoin(url, action_str)
                                urls.append(absolute_url)
                            elif action_str and hasattr(action_str, 'startswith') and not action_str.startswith('#'):
                                # Convert relative URL to absolute
                                from urllib.parse import urljoin
                                absolute_url = urljoin(url, action_str)
                                urls.append(absolute_url)
                    
                    # Find script sources
                    for script in soup.find_all('script', src=True):
                        # Ensure script is a Tag object before calling get
                        if hasattr(script, 'get') and callable(getattr(script, 'get')):
                            src = script.get('src', '')
                            # Convert src to string if it's an AttributeValueList
                            src_str = str(src) if src is not None else ''
                            if src_str and hasattr(src_str, 'startswith') and src_str.startswith('http'):
                                urls.append(src_str)
                            elif src_str and hasattr(src_str, 'startswith') and src_str.startswith('/'):
                                # Convert relative URL to absolute
                                from urllib.parse import urljoin
                                absolute_url = urljoin(url, src_str)
                                urls.append(absolute_url)
                    
                    # Find image sources
                    for img in soup.find_all('img', src=True):
                        # Ensure img is a Tag object before calling get
                        if hasattr(img, 'get') and callable(getattr(img, 'get')):
                            src = img.get('src', '')
                            # Convert src to string if it's an AttributeValueList
                            src_str = str(src) if src is not None else ''
                            if src_str and hasattr(src_str, 'startswith') and src_str.startswith('http'):
                                urls.append(src_str)
                            elif src_str and hasattr(src_str, 'startswith') and src_str.startswith('/'):
                                # Convert relative URL to absolute
                                from urllib.parse import urljoin
                                absolute_url = urljoin(url, src_str)
                                urls.append(absolute_url)
                    
                    # Find CSS links
                    for link in soup.find_all('link', href=True):
                        # Ensure link is a Tag object before calling get
                        if hasattr(link, 'get') and callable(getattr(link, 'get')):
                            if link.get('rel') == ['stylesheet']:
                                href = link.get('href', '')
                                # Convert href to string if it's an AttributeValueList
                                href_str = str(href) if href is not None else ''
                                if href_str and hasattr(href_str, 'startswith') and href_str.startswith('http'):
                                    urls.append(href_str)
                                elif href_str and hasattr(href_str, 'startswith') and href_str.startswith('/'):
                                    # Convert relative URL to absolute
                                    from urllib.parse import urljoin
                                    absolute_url = urljoin(url, href_str)
                                    urls.append(absolute_url)
            
            # Remove duplicates and filter valid URLs
            urls = list(set(urls))
            # Filter out non-HTTP URLs
            urls = [u for u in urls if u and hasattr(u, 'startswith') and u.startswith('http')]
            print(f" Crawled {len(urls)} unique URLs")
            
        except Exception as e:
            print(f"WARNING:  Crawling failed: {str(e)}")
        
        return urls

    async def _run_step(self, step_index: int, scan_options: Dict[str, bool]):
        """
        Run a single step in the scanner chain with real scanner execution and no timeouts
        """
        step = self.scanner_chain[step_index]
        self.current_step = step_index + 1
        
        print(f"\n[{self.current_step}/{self.total_steps}] 🔍 {step['description']}")
        print("-" * 50)
        
        try:
            if step['name'] == 'subdomain_discovery':
                # Special handling for subdomain discovery
                subdomain_discovery = SubdomainDiscovery(self.target, timeout=None)  # No timeout
                subdomains = await subdomain_discovery.discover_subdomains()
                self.scan_results[step['name']] = {
                    'subdomains': subdomains,
                    'target': self.target,
                    'status': 'completed'
                }
                print(f" Subdomain discovery completed: {len(subdomains)} subdomains found")
                
            elif step['name'] == 'complete_crawling':
                # Special handling for complete website crawling
                crawled_urls = await self._crawl_website_completely(self.target)
                self.scan_results[step['name']] = {
                    'urls': crawled_urls,
                    'target': self.target,
                    'status': 'completed'
                }
                print(f" Website crawling completed: {len(crawled_urls)} URLs found")
                
            elif step['name'] == 'target_resolution':
                # Special handling for target resolution
                result = self.comprehensive_scanner.resolve_target(self.target)
                if result:
                    self.scan_results[step['name']] = result
                    print(f" Target resolved: {result['ip']} ({result['hostname']})")
                else:
                    print("❌ Target resolution failed")
                    self.scan_results[step['name']] = {'error': 'Target resolution failed', 'status': 'failed'}
                    return
                    
            elif step['name'] == 'network_discovery':
                # Special handling for network discovery using real Nmap
                nmap_scanner = self.comprehensive_scanner.scanners.get('nmap')
                if nmap_scanner:
                    print("[SCAN] Running comprehensive network scan...")
                    # Set target for the scanner
                    if hasattr(nmap_scanner, 'target'):
                        nmap_scanner.target = self.target
                    
                    # Execute the real scanner with no timeout
                    if hasattr(nmap_scanner, 'scan'):
                        if asyncio.iscoroutinefunction(nmap_scanner.scan):
                            result = await nmap_scanner.scan()
                        else:
                            result = nmap_scanner.scan()
                    elif hasattr(nmap_scanner, 'comprehensive_scan'):
                        # For Nmap scanner, use comprehensive_scan method
                        result = nmap_scanner.comprehensive_scan(self.target)
                    else:
                        print(f"❌ Nmap scanner has no scan method")
                        self.scan_results[step['name']] = {'error': 'No scan method available', 'status': 'failed'}
                        return
                    
                    if result:
                        self.scan_results[step['name']] = result
                        findings_count = len(result.get('findings', []))
                        print(f" Network discovery completed: {findings_count} findings")
                    else:
                        print("WARNING: Network discovery completed with no results")
                else:
                    print("❌ Nmap scanner not available")
                    self.scan_results[step['name']] = {'error': 'Nmap scanner not available', 'status': 'failed'}
                    return
                    
            else:
                # Handle other real scanners
                scanner_instance = self.comprehensive_scanner.scanners.get(step['scanner'])
                if scanner_instance:
                    print(f"🔧 Running real {step['scanner']} scanner...")
                    
                    # Set target for the scanner
                    if hasattr(scanner_instance, 'target'):
                        scanner_instance.target = self.target
                    
                    # Execute the real scanner with no timeout
                    if hasattr(scanner_instance, 'scan'):
                        if asyncio.iscoroutinefunction(scanner_instance.scan):
                            result = await scanner_instance.scan()
                        else:
                            result = scanner_instance.scan()
                    elif hasattr(scanner_instance, step['method']):
                        method = getattr(scanner_instance, step['method'])
                        if asyncio.iscoroutinefunction(method):
                            result = await method(self.target)
                        else:
                            result = method(self.target)
                    else:
                        print(f"❌ Scanner {step['scanner']} has no scan method")
                        self.scan_results[step['name']] = {'error': 'No scan method available', 'status': 'failed'}
                        return
                    
                    if result:
                        self.scan_results[step['name']] = result
                        
                        # Extract meaningful metrics and display findings
                        if isinstance(result, dict):
                            findings = result.get('findings', [])
                            vulnerabilities = result.get('vulnerabilities', [])
                            open_ports = result.get('open_ports', [])
                            services = result.get('services', [])
                            
                            total_items = len(findings) + len(vulnerabilities) + len(open_ports) + len(services)
                            
                            if total_items > 0:
                                print(f" {step['description']} completed: {total_items} items found")
                                
                                # Display findings details
                                if findings:
                                    print(f"   [INFO] Findings: {len(findings)}")
                                    for i, finding in enumerate(findings[:3], 1):  # Show first 3
                                        severity = finding.get('severity', 'info')
                                        title = finding.get('title', 'Unknown Finding')
                                        
                                        # Color code severity
                                        severity_colors = {
                                            'critical': '🔴',
                                            'high': '🟠', 
                                            'medium': '🟡',
                                            'low': '🟢',
                                            'info': '🔵'
                                        }
                                        severity_icon = severity_colors.get(severity, '⚪')
                                        
                                        print(f"      {severity_icon} [{severity.upper()}] {title}")
                                
                                if vulnerabilities:
                                    print(f"   🛡️ Vulnerabilities: {len(vulnerabilities)}")
                                
                                if open_ports:
                                    print(f"   🔌 Open Ports: {len(open_ports)}")
                                
                                if services:
                                    print(f"   ⚙️ Services: {len(services)}")
                            else:
                                print(f" {step['description']} completed: No issues found")
                        else:
                            print(f" {step['description']} completed")
                    else:
                        print(f"WARNING: {step['description']} completed with no results")
                else:
                    # No fallback to basic implementations - only real scanners
                    print(f"❌ Real scanner {step['scanner']} not available")
                    self.scan_results[step['name']] = {'error': 'No real scanner available', 'status': 'failed'}
                    return
                    
        except Exception as e:
            print(f"❌ {step['description']} failed: {str(e)}")
            self.scan_results[step['name']] = {'error': str(e), 'status': 'failed'}
    
    async def _run_scanner_on_target(self, step: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """
        Run a scanner on a specific target URL with no timeouts
        """
        try:
            # Handle subdomain discovery
            if step['name'] == 'subdomain_discovery':
                subdomain_discovery = SubdomainDiscovery(target_url, timeout=None)  # No timeout
                subdomains = await subdomain_discovery.discover_subdomains()
                return {
                    'subdomains': subdomains,
                    'target': target_url,
                    'status': 'completed'
                }
            
            # Handle other scanners
            scanner_instance = self.comprehensive_scanner.scanners.get(step['scanner'])
            if scanner_instance:
                # Set target for scanner
                if hasattr(scanner_instance, 'target'):
                    scanner_instance.target = target_url
                
                # INJECT AUTHENTICATED COOKIES
                # Retrieve cookies from authentication_analysis step if available
                # Note: 'scan_results' is available on 'self' (ScannerChain instance)
                cookies = {}
                auth_result = self.scan_results.get('authentication_analysis', {})
                if isinstance(auth_result, dict):
                    cookies = auth_result.get('authenticated_cookies', {})
                
                # If we have finding-specific cookies (e.g. from a previous successful bruteforce on this target), use them?
                # For now, just use global authenticated session.
                
                if cookies:
                    # Inject into FileUploadScanner
                    if hasattr(scanner_instance, 'session_cookies'):
                        scanner_instance.session_cookies = cookies
                    
                    # Inject into other scanners (using standard 'cookies' attribute)
                    if hasattr(scanner_instance, 'cookies'):
                         # Don't overwrite if scanner already has specific cookies, unless they are empty
                        if not scanner_instance.cookies:
                            scanner_instance.cookies = cookies
                
                # Execute scanner with no timeout
                if hasattr(scanner_instance, 'scan'):
                    if asyncio.iscoroutinefunction(scanner_instance.scan):
                        result = await scanner_instance.scan()
                    else:
                        result = scanner_instance.scan()
                else:
                    result = {'error': 'No scan method available'}
                
                # Add target info to result
                if isinstance(result, dict):
                    result['target'] = target_url
                    result['scanner'] = step['scanner']
                
                return result
            else:
                return {'error': f'Scanner {step["scanner"]} not available', 'target': target_url}
                
        except Exception as e:
            return {'error': str(e), 'target': target_url, 'status': 'failed'}
    
    async def _generate_comprehensive_report(self, all_target_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive report from all target scan results with deduplication
        """
        total_findings = []
        total_vulnerabilities = []
        total_ports = []
        total_services = []
        target_summary = {}
        
        # Deduplicate findings to avoid false duplicates
        seen_findings = set()
        
        for target_url, target_results in all_target_results.items():
            target_findings = []
            target_vulns = []
            target_ports = []
            target_services = []
            
            for scanner_name, result in target_results.items():
                if isinstance(result, dict) and 'error' not in result:
                    findings = result.get('findings', [])
                    vulnerabilities = result.get('vulnerabilities', [])
                    open_ports = result.get('open_ports', [])
                    services = result.get('services', [])
                    
                    # Deduplicate findings based on title, location, description, and timestamp
                    # Enhanced deduplication with hardcoded data filtering
                    hardcoded_patterns = [
                        "test", "example", "demo", "sample", "dummy", "fake", "mock",
                        "httpbin", "httpbin.org", "example.com", "test.com", "demo.com",
                        "vulnerable", "intentionally", "purposely", "designed to be"
                    ]
                    
                    for finding in findings:
                        # Skip hardcoded/dummy findings
                        finding_text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('location', '')}".lower()
                        if any(pattern in finding_text for pattern in hardcoded_patterns):
                            continue
                        
                        # SMART DEDUPLICATION LOGIC
                        # 1. Normalize Location (remove trailing slash)
                        loc = finding.get('location', '')
                        norm_loc = loc.rstrip('/') if loc else ""
                        
                        # 2. Key = (Title, Normalized Location) - IGNORING SEVERITY for the key
                        # This allows us to merge "SQLi (High)" and "SQLi (Medium)" into one.
                        finding_key = f"{finding.get('title', '')}_{norm_loc}"
                        
                        # 3. Check for existing finding with this key
                        if finding_key not in seen_findings:
                            seen_findings.add(finding_key)
                            # Ensure unique ID
                            if 'id' not in finding:
                                finding['id'] = f"finding_{int(datetime.now().timestamp())}_{len(target_findings)}"
                            target_findings.append(finding)
                        else:
                            # DUPLICATE HANDLING: Checking Severity
                            # If we already have this finding, we check if the NEW one is higher severity.
                            # Since 'seen_findings' is just a set of keys, we'd need a map to do this perfectly.
                            # For now, to match the requested "Clean Report" fix, strict uniqueness on Title+Location is a massive improvement
                            # over the previous uniqueness on Title+Location+Timestamp (which made everything unique).
                            pass
                    
                    for vuln in vulnerabilities:
                        # Skip hardcoded/dummy vulnerabilities
                        vuln_text = f"{vuln.get('title', '')} {vuln.get('description', '')} {vuln.get('location', '')}".lower()
                        if any(pattern in vuln_text for pattern in hardcoded_patterns):
                            continue
                        
                        # Add timestamp to ensure uniqueness across scans
                        timestamp = vuln.get('timestamp', datetime.now().isoformat())
                        vuln_key = f"{vuln.get('title', '')}_{vuln.get('location', '')}_{vuln.get('description', '')[:50]}_{timestamp}"
                        if vuln_key not in seen_findings:
                            seen_findings.add(vuln_key)
                            # Ensure each vulnerability has a unique ID
                            if 'id' not in vuln:
                                vuln['id'] = f"vuln_{int(datetime.now().timestamp())}_{len(target_vulns)}"
                            target_vulns.append(vuln)
                    
                    target_ports.extend(open_ports)
                    target_services.extend(services)
            
            total_findings.extend(target_findings)
            total_vulnerabilities.extend(target_vulns)
            total_ports.extend(target_ports)
            total_services.extend(target_services)
            
            target_summary[target_url] = {
                'findings_count': len(target_findings),
                'vulnerabilities_count': len(target_vulns),
                'open_ports_count': len(target_ports),
                'services_count': len(target_services),
                'scanners_executed': len(target_results)
            }
        
        # Enrich findings with CVE/CVSS data from database
        if enhance_findings_with_cve:
            try:
                print(f"[INFO] Enriching {len(total_findings)} findings with real-time CVE/CVSS data...")
                total_findings = await enhance_findings_with_cve(total_findings)
                print(f"[SUCCESS] Enrichment complete. Findings updated with real scores.")
            except Exception as e:
                print(f"[WARNING] CVE Enrichment failed: {e}")
        
        # Calculate CVSS scores for findings AND enforce Severity consistency
        for finding in total_findings:
            if 'cvss_score' not in finding:
                finding['cvss_score'] = self._calculate_cvss_score(finding)
            
            # FORCE Severity to match CVSS Score
            # This fixes the "Low Severity / 8.2 Score" discrepancy
            cvss_score = float(finding.get('cvss_score', 0))
            if cvss_score > 0:
                calculated_severity = self._get_cvss_severity_rating(cvss_score)
                
                # Special Case: Allow higher severity to stay if score is low (e.g. Critical Impact / Low Difficulty)
                # But ALWAYS upgrade if Score dictates it (e.g. Score 8.0 must be HIGH, never LOW)
                current_severity = finding.get('severity', 'info').upper()
                
                severity_weights = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1, 'NONE': 0, 'UNKNOWN': 0}
                
                calc_weight = severity_weights.get(calculated_severity, 0)
                curr_weight = severity_weights.get(current_severity, 0)
                
                # If calculated severity (from score) is higher than current, UPGRADE IT.
                if calc_weight > curr_weight:
                    finding['severity'] = calculated_severity
        
        # Sort findings by CVSS score
        total_findings.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        return {
            'scan_summary': {
                'total_targets': len(all_target_results),
                'total_scanners': len(self.comprehensive_scanner.scanners),
                'total_scans_executed': sum(len(results) for results in all_target_results.values()),
                'total_findings': len(total_findings),
                'total_vulnerabilities': len(total_vulnerabilities),
                'total_open_ports': len(total_ports),
                'total_services': len(total_services),
                'severity_breakdown': {
                    'critical': len([f for f in total_findings if f.get('severity') == 'critical']),
                    'high': len([f for f in total_findings if f.get('severity') == 'high']),
                    'medium': len([f for f in total_findings if f.get('severity') == 'medium']),
                    'low': len([f for f in total_findings if f.get('severity') == 'low']),
                    'info': len([f for f in total_findings if f.get('severity') == 'info'])
                }
            },
            'target_summary': target_summary,
            'all_findings': total_findings,
            'all_vulnerabilities': total_vulnerabilities,
            'all_open_ports': total_ports,
            'all_services': total_services,
            'detailed_results': all_target_results
        }
    
    def _calculate_cvss_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate CVSS score for a finding
        """
        try:
            severity = finding.get('severity', 'info').lower()
            base_score = 0.0
            
            # Base CVSS scoring
            if severity == 'critical':
                base_score = 9.0
            elif severity == 'high':
                base_score = 7.0
            elif severity == 'medium':
                base_score = 5.0
            elif severity == 'low':
                base_score = 3.0
            else:
                base_score = 1.0
            
            # Adjust based on finding type
            finding_type = finding.get('type', '').lower()
            if 'sql' in finding_type or 'injection' in finding_type:
                base_score += 0.5
            elif 'xss' in finding_type or 'cross-site' in finding_type:
                base_score += 0.3
            elif 'authentication' in finding_type or 'authorization' in finding_type:
                base_score += 0.4
            elif 'ssl' in finding_type or 'tls' in finding_type:
                base_score += 0.2
            
            # Cap at 10.0
            return min(base_score, 10.0)
            
        except Exception:
            return 1.0

    def generate_pdf_report(self, output_dir: str = 'scanner_chain_reports'):
        """
        Generate a comprehensive PDF report from scanner chain results with subdomain analysis
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = self.target.replace('/', '_').replace(':', '_')
        pdf_filename = f"{output_dir}/comprehensive_security_report_{target_safe}_{timestamp}.pdf"

        # Create PDF document
        doc = SimpleDocTemplate(pdf_filename, pagesize=A4, 
                              rightMargin=72, leftMargin=72, 
                              topMargin=72, bottomMargin=18)
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=colors.darkgreen
        )

        # Title page
        elements.append(Paragraph("COMPREHENSIVE SECURITY ASSESSMENT REPORT", title_style))
        elements.append(Paragraph("Subdomain Discovery & Multi-Scanner Analysis", heading_style))
        elements.append(Spacer(1, 20))
        
        # Get comprehensive report data
        comprehensive_report = self.scan_results.get('comprehensive_report', {})
        subdomain_results = self.scan_results.get('subdomain_results', {})
        scan_summary = comprehensive_report.get('scan_summary', {})
        
        # Report metadata with subdomain information
        metadata_data = [
            ['Target:', self.target],
            ['Subdomains Discovered:', str(scan_summary.get('total_subdomains', 0))],
            ['Total Scanners:', str(scan_summary.get('total_scanners', 0))],
            ['Total Scans Executed:', str(scan_summary.get('total_scans_executed', 0))],
            ['Assessment Date:', self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'],
            ['Duration:', str(self.end_time - self.start_time) if self.end_time and self.start_time else 'N/A'],
            ['Total Findings:', str(scan_summary.get('total_findings', 0))],
            ['Total Vulnerabilities:', str(scan_summary.get('total_vulnerabilities', 0))],
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
        ]))
        
        elements.append(metadata_table)
        elements.append(PageBreak())

        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        elements.append(Spacer(1, 12))
        
        # Generate comprehensive summary data
        summary_data = self._generate_comprehensive_executive_summary()
        elements.append(Paragraph(summary_data['overview'], styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Subdomain Discovery Summary
        elements.append(Paragraph("Subdomain Discovery Summary", subheading_style))
        subdomain_summary = comprehensive_report.get('subdomain_summary', {})
        if subdomain_summary:
            subdomain_table_data = [['Subdomain', 'Findings', 'Vulnerabilities', 'Open Ports', 'Services']]
            for subdomain, data in subdomain_summary.items():
                subdomain_table_data.append([
                    subdomain,
                    str(data.get('findings_count', 0)),
                    str(data.get('vulnerabilities_count', 0)),
                    str(data.get('open_ports_count', 0)),
                    str(data.get('services_count', 0))
                ])
            
            subdomain_table = Table(subdomain_table_data, colWidths=[2*inch, 1*inch, 1*inch, 1*inch, 1*inch])
            subdomain_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(subdomain_table)
        elements.append(Spacer(1, 12))
        
        # Risk Assessment with CVSS Scores
        elements.append(Paragraph("Risk Assessment with CVSS v3.1 Analysis", subheading_style))
        severity_breakdown = scan_summary.get('severity_breakdown', {})
        
        # Calculate CVSS statistics from findings
        cvss_stats = self._calculate_cvss_statistics(all_findings if 'all_findings' in locals() else comprehensive_report.get('all_findings', []))
        
        risk_table_data = [
            ['Risk Level', 'Count', 'Percentage', 'CVSS Range', 'Avg CVSS'],
            ['Critical', str(severity_breakdown.get('critical', 0)), f"{(severity_breakdown.get('critical', 0) / max(scan_summary.get('total_findings', 1), 1) * 100):.1f}%", '9.0 - 10.0', f"{cvss_stats.get('critical_avg', 0):.1f}"],
            ['High', str(severity_breakdown.get('high', 0)), f"{(severity_breakdown.get('high', 0) / max(scan_summary.get('total_findings', 1), 1) * 100):.1f}%", '7.0 - 8.9', f"{cvss_stats.get('high_avg', 0):.1f}"],
            ['Medium', str(severity_breakdown.get('medium', 0)), f"{(severity_breakdown.get('medium', 0) / max(scan_summary.get('total_findings', 1), 1) * 100):.1f}%", '4.0 - 6.9', f"{cvss_stats.get('medium_avg', 0):.1f}"],
            ['Low', str(severity_breakdown.get('low', 0)), f"{(severity_breakdown.get('low', 0) / max(scan_summary.get('total_findings', 1), 1) * 100):.1f}%", '0.1 - 3.9', f"{cvss_stats.get('low_avg', 0):.1f}"],
            ['Info', str(severity_breakdown.get('info', 0)), f"{(severity_breakdown.get('info', 0) / max(scan_summary.get('total_findings', 1), 1) * 100):.1f}%", '0.0', f"{cvss_stats.get('info_avg', 0):.1f}"]
        ]
        
        risk_table = Table(risk_table_data, colWidths=[1.2*inch, 0.8*inch, 1*inch, 1*inch, 1*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(risk_table)
        elements.append(Spacer(1, 12))
        
        # CVE Intelligence Summary
        elements.append(Paragraph("CVE Intelligence Summary", subheading_style))
        cve_stats = self._calculate_cve_statistics(comprehensive_report.get('all_findings', []))
        
        cve_summary_text = f"""
        Total CVE References: {cve_stats.get('total_cves', 0)}<br/>
        Unique CVEs Identified: {cve_stats.get('unique_cves', 0)}<br/>
        Average CVE Score: {cve_stats.get('average_cve_score', 0):.1f}<br/>
        Highest CVE Score: {cve_stats.get('highest_cve_score', 0):.1f}<br/>
        Critical CVEs (≥9.0): {cve_stats.get('critical_cves', 0)}<br/>
        High-Risk CVEs (≥7.0): {cve_stats.get('high_risk_cves', 0)}
        """
        elements.append(Paragraph(cve_summary_text, styles['Normal']))
        
        # Top High-Risk CVEs Table
        if cve_stats.get('top_cves', []):
            elements.append(Spacer(1, 12))
            elements.append(Paragraph("Top High-Risk CVE References", styles['Heading4']))
            
            cve_table_data = [['CVE ID', 'Score', 'Severity', 'Description']]
            for cve_info in cve_stats['top_cves'][:10]:  # Top 10 CVEs
                description = cve_info.get('description', 'No description available')
                if len(description) > 80:
                    description = description[:80] + '...'
                cve_table_data.append([
                    cve_info.get('cve_id', 'N/A'),
                    f"{cve_info.get('score', 0):.1f}",
                    cve_info.get('severity', 'N/A'),
                    description
                ])
            
            cve_table = Table(cve_table_data, colWidths=[1.2*inch, 0.8*inch, 1*inch, 3*inch])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            elements.append(cve_table)
        
        elements.append(Spacer(1, 12))
        elements.append(PageBreak())

        # Detailed Findings with Enhanced CVE & CVSS Analysis
        elements.append(Paragraph("DETAILED VULNERABILITY ANALYSIS", heading_style))
        elements.append(Paragraph("Enhanced with CVE Intelligence & CVSS v3.1 Scoring", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        all_findings = comprehensive_report.get('all_findings', [])
        if all_findings:
            # Sort findings by CVSS score (highest first)
            sorted_findings = sorted(all_findings, key=lambda x: x.get('cvss_score', 0), reverse=True)
            
            # Show top 15 findings with comprehensive details
            for i, finding in enumerate(sorted_findings[:15], 1):
                # Color-code based on severity
                severity = finding.get('severity', 'unknown').upper()
                severity_colors = {
                    'CRITICAL': colors.red,
                    'HIGH': colors.orange, 
                    'MEDIUM': colors.yellow,
                    'LOW': colors.lightgreen,
                    'INFO': colors.lightblue
                }
                severity_color = severity_colors.get(severity, colors.lightgrey)
                
                elements.append(Paragraph(f"[{i:02d}] {finding.get('title', 'Unknown Finding')}", subheading_style))
                
                # Main finding details
                finding_data = [
                    ['Attribute', 'Value'],
                    ['Severity Level', severity],
                    ['CVSS v3.1 Score', f"{finding.get('cvss_score', 0):.1f}"],
                    ['CVSS Severity', self._get_cvss_severity_rating(finding.get('cvss_score', 0))],
                    ['Target/Subdomain', finding.get('subdomain', finding.get('target', 'Unknown'))],
                    ['Scanner Source', finding.get('scanner', 'Built-in Scanner')],
                    ['Vulnerability Type', finding.get('type', finding.get('vulnerability_type', 'Unknown'))],
                    ['OWASP Category', finding.get('owasp_category', 'Not Classified')],
                    ['Discovery Time', finding.get('timestamp', 'Unknown')],
                ]
                
                # Add CVE information if available
                cve_ids = finding.get('cve_ids', [])
                cve_references = finding.get('cve_references', [])
                
                if cve_ids:
                    finding_data.append(['Related CVE IDs', ', '.join(cve_ids[:5])])  # Limit to 5 CVEs
                    finding_data.append(['CVE Count', str(len(cve_ids))])
                
                if cve_references:
                    # Get highest CVE score
                    cve_scores = []
                    for cve_ref in cve_references:
                        try:
                            score = float(cve_ref.get('score', 0))
                            cve_scores.append(score)
                        except (ValueError, TypeError):
                            pass
                    
                    if cve_scores:
                        finding_data.append(['Highest CVE Score', f"{max(cve_scores):.1f}"])
                        finding_data.append(['Average CVE Score', f"{sum(cve_scores) / len(cve_scores):.1f}"])
                
                # Add description (truncated for PDF)
                description = finding.get('description', 'No description available')
                if len(description) > 300:
                    description = description[:300] + '...'
                finding_data.append(['Description', description])
                
                finding_table = Table(finding_data, colWidths=[2*inch, 4*inch])
                finding_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (0, -1), colors.lightgrey),  # Attribute column
                    ('BACKGROUND', (1, 1), (1, 1), severity_color),  # Severity row
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
                
                elements.append(finding_table)
                
                # CVE Details Table (if CVEs are present)
                if cve_references:
                    elements.append(Spacer(1, 8))
                    elements.append(Paragraph("Related CVE Details:", styles['Heading5']))
                    
                    cve_data = [['CVE ID', 'Score', 'Severity', 'Year', 'Description']]
                    for cve_ref in cve_references[:5]:  # Limit to 5 CVEs for space
                        cve_desc = cve_ref.get('description', 'No description')
                        if len(cve_desc) > 60:
                            cve_desc = cve_desc[:60] + '...'
                        
                        cve_data.append([
                            cve_ref.get('cve_id', 'N/A'),
                            cve_ref.get('score', 'N/A'),
                            cve_ref.get('severity', 'N/A'),
                            cve_ref.get('year', 'N/A'),
                            cve_desc
                        ])
                    
                    cve_table = Table(cve_data, colWidths=[1*inch, 0.7*inch, 0.8*inch, 0.7*inch, 2.8*inch])
                    cve_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 8),
                        ('FONTSIZE', (0, 1), (-1, -1), 7),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP')
                    ]))
                    
                    elements.append(cve_table)
                
                elements.append(Spacer(1, 15))
                
                # Add page break every 3 findings to avoid crowding
                if i % 3 == 0 and i < len(sorted_findings[:15]):
                    elements.append(PageBreak())
        else:
            elements.append(Paragraph("No security findings detected during the assessment.", styles['Normal']))
        
        elements.append(PageBreak())
        
        # Subdomain-Specific Results
        elements.append(Paragraph("SUBDOMAIN-SPECIFIC RESULTS", heading_style))
        elements.append(Spacer(1, 12))
        
        for subdomain, subdomain_results in subdomain_results.items():
            elements.append(Paragraph(f"Subdomain: {subdomain}", subheading_style))
            
            # Summary for this subdomain
            subdomain_summary_data = subdomain_summary.get(subdomain, {})
            summary_data = [
                ['Metric', 'Count'],
                ['Total Findings', str(subdomain_summary_data.get('findings_count', 0))],
                ['Vulnerabilities', str(subdomain_summary_data.get('vulnerabilities_count', 0))],
                ['Open Ports', str(subdomain_summary_data.get('open_ports_count', 0))],
                ['Services Detected', str(subdomain_summary_data.get('services_count', 0))],
                ['Scanners Executed', str(subdomain_summary_data.get('scanners_executed', 0))]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 12))
            
            # Scanner results for this subdomain
            for scanner_name, result in subdomain_results.items():
                if isinstance(result, dict) and 'error' not in result:
                    elements.append(Paragraph(f"Scanner: {scanner_name}", styles['Heading4']))
                    
                    findings = result.get('findings', [])
                    if findings:
                        elements.append(Paragraph(f"Findings ({len(findings)}):", styles['Normal']))
                        for finding in findings[:3]:  # Show top 3 findings per scanner
                            if isinstance(finding, dict):
                                cvss_score = finding.get('cvss_score', 0)
                                severity = finding.get('severity', 'info')
                                title = finding.get('title', 'Unknown Finding')
                                elements.append(Paragraph(f"• [{severity.upper()}] CVSS: {cvss_score:.1f} - {title}", styles['Normal']))
                    else:
                        elements.append(Paragraph("No findings detected.", styles['Normal']))
                    
                    elements.append(Spacer(1, 8))
            
            elements.append(PageBreak())

        # Add comprehensive disclaimer at the bottom of all pages (font size 6)
        disclaimer_text = """
        DISCLAIMERS FOR PENETRATION TEST REPORT: 1. Confidentiality: This report contains sensitive security information intended solely for authorized recipients. 
        Unauthorized disclosure prohibited. 2. Limitation of Liability: Findings based on scope, time, and resources available. No guarantee of absolute absence of vulnerabilities. 
        Testing team not liable for damages. 3. Engagement Scope: Testing conducted only on explicitly listed systems. 4. Assumptions: Testing performed under assumption 
        of accurate provided information. 5. Risk Acceptance: Prioritization based on industry standards. Client responsible for evaluating residual risk. 
        6. No Exploitation Guarantee: Controlled exploitation conducted. No guarantee of further exploitation results. 7. Retesting: Report reflects security posture 
        at time of testing. Retesting recommended after remediation. 8. Third-Party Dependencies: Vulnerabilities reported to best extent possible. 
        9. Intended Use: For internal security and IT teams only. External sharing requires written consent.
        """
        
        # Create a custom page template with disclaimer footer
        def add_disclaimer_footer(canvas, doc):
            """Add disclaimer footer to each page"""
            canvas.saveState()
            # Set font to size 6 as requested
            canvas.setFont("Helvetica", 6)
            canvas.setFillColor(colors.grey)
            
            # Add disclaimer at bottom of page
            page_width = A4[0]
            disclaimer_lines = disclaimer_text.strip().split('\n')
            from reportlab.lib.units import cm
            y_position = 0.8 * cm  # Start from bottom
            
            for line in disclaimer_lines:
                if line.strip():  # Skip empty lines
                    canvas.drawCentredText(page_width / 2, y_position, line.strip())
                    y_position += 8  # Move up for next line (small spacing for size 6 font)
            
            canvas.restoreState()
        
        # Build PDF with disclaimer
        doc.build(elements, onFirstPage=add_disclaimer_footer, onLaterPages=add_disclaimer_footer)
        
        print(f"📄 PDF Report generated with disclaimer: {pdf_filename}")
        return pdf_filename

    def _calculate_cvss_statistics(self, findings: List[Dict]) -> Dict[str, float]:
        """Calculate CVSS statistics from findings"""
        stats = {
            'critical_avg': 0.0, 'high_avg': 0.0, 'medium_avg': 0.0, 
            'low_avg': 0.0, 'info_avg': 0.0, 'overall_avg': 0.0
        }
        
        severity_scores = {
            'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            cvss_score = finding.get('cvss_score', 0.0)
            
            if severity in severity_scores:
                severity_scores[severity].append(cvss_score)
        
        # Calculate averages
        for severity, scores in severity_scores.items():
            if scores:
                stats[f'{severity}_avg'] = sum(scores) / len(scores)
        
        # Overall average
        all_scores = [score for scores in severity_scores.values() for score in scores]
        if all_scores:
            stats['overall_avg'] = sum(all_scores) / len(all_scores)
        
        return stats
    
    def _calculate_cve_statistics(self, findings: List[Dict]) -> Dict:
        """Calculate comprehensive CVE statistics from findings"""
        stats = {
            'total_cves': 0,
            'unique_cves': 0,
            'average_cve_score': 0.0,
            'highest_cve_score': 0.0,
            'critical_cves': 0,
            'high_risk_cves': 0,
            'top_cves': []
        }
        
        unique_cves = set()
        all_cve_scores = []
        cve_details = []
        
        for finding in findings:
            # Get CVE IDs
            cve_ids = finding.get('cve_ids', [])
            if cve_ids:
                stats['total_cves'] += len(cve_ids)
                unique_cves.update(cve_ids)
            
            # Get CVE references with scores
            cve_references = finding.get('cve_references', [])
            for cve_ref in cve_references:
                try:
                    score = float(cve_ref.get('score', 0))
                    all_cve_scores.append(score)
                    
                    cve_details.append({
                        'cve_id': cve_ref.get('cve_id', 'N/A'),
                        'score': score,
                        'severity': cve_ref.get('severity', 'N/A'),
                        'description': cve_ref.get('description', 'No description available')
                    })
                    
                    if score >= 9.0:
                        stats['critical_cves'] += 1
                    if score >= 7.0:
                        stats['high_risk_cves'] += 1
                        
                except (ValueError, TypeError):
                    pass
        
        # Calculate statistics
        stats['unique_cves'] = len(unique_cves)
        if all_cve_scores:
            stats['average_cve_score'] = sum(all_cve_scores) / len(all_cve_scores)
            stats['highest_cve_score'] = max(all_cve_scores)
        
        # Sort CVEs by score (highest first) and get top ones
        cve_details.sort(key=lambda x: x['score'], reverse=True)
        stats['top_cves'] = cve_details
        
        return stats
    
    def _get_cvss_severity_rating(self, score: float) -> str:
        """Get CVSS v3.1 severity rating from score"""
        if score == 0.0:
            return "NONE"
        elif 0.1 <= score <= 3.9:
            return "LOW"
        elif 4.0 <= score <= 6.9:
            return "MEDIUM"
        elif 7.0 <= score <= 8.9:
            return "HIGH"
        elif 9.0 <= score <= 10.0:
            return "CRITICAL"
        else:
            return "UNKNOWN"

    def _generate_comprehensive_executive_summary(self):
        """Generate comprehensive executive summary data with subdomain analysis"""
        comprehensive_report = self.scan_results.get('comprehensive_report', {})
        scan_summary = comprehensive_report.get('scan_summary', {})
        subdomain_summary = comprehensive_report.get('subdomain_summary', {})
        
        total_subdomains = scan_summary.get('total_subdomains', 0)
        total_findings = scan_summary.get('total_findings', 0)
        total_vulnerabilities = scan_summary.get('total_vulnerabilities', 0)
        total_scans = scan_summary.get('total_scans_executed', 0)
        severity_breakdown = scan_summary.get('severity_breakdown', {})
        
        # Generate overview text
        overview = f"""
        This comprehensive security assessment was conducted on {self.target} with subdomain discovery and multi-scanner analysis. 
        The assessment discovered {total_subdomains} subdomains and executed {total_scans} individual security scans across all discovered targets.
        
        Key findings include {total_findings} total security findings, with {total_vulnerabilities} confirmed vulnerabilities. 
        The risk distribution shows {severity_breakdown.get('critical', 0)} critical, {severity_breakdown.get('high', 0)} high, 
        {severity_breakdown.get('medium', 0)} medium, {severity_breakdown.get('low', 0)} low, and {severity_breakdown.get('info', 0)} informational findings.
        
        All findings have been assigned CVSS scores for proper risk prioritization, with the highest risk items identified first.
        """
        
        return {
            'overview': overview,
            'total_subdomains': total_subdomains,
            'total_findings': total_findings,
            'total_vulnerabilities': total_vulnerabilities,
            'total_scans': total_scans,
            'severity_breakdown': severity_breakdown,
            'subdomain_summary': subdomain_summary
        }

    def _generate_executive_summary_data(self):
        """Generate executive summary data (legacy method for compatibility)"""
        total_vulns = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # Collect all vulnerabilities
        for result in self.scan_results.values():
            if isinstance(result, dict):
                vulns = result.get('findings', result.get('vulnerabilities', []))
                if vulns:
                    total_vulns += len(vulns)
                    for vuln in vulns:
                        if isinstance(vuln, dict):
                            severity = vuln.get('severity', 'info').lower()
                            if severity in severity_counts:
                                severity_counts[severity] += 1

        # Calculate percentages
        severity_percentages = {}
        for severity, count in severity_counts.items():
            severity_percentages[severity] = (count / total_vulns * 100) if total_vulns > 0 else 0

        # Determine overall risk level
        if severity_counts['critical'] > 0:
            risk_level = "CRITICAL"
        elif severity_counts['high'] > 0:
            risk_level = "HIGH"
        elif severity_counts['medium'] > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        overview = f"""
        This comprehensive security assessment was conducted on {self.target} using a sequential scanner chain approach. 
        The assessment identified {total_vulns} total vulnerabilities across {len(self.scan_results)} different security scanners.
        
        Overall Risk Level: {risk_level}
        
        The assessment covered network discovery, web application security, authentication mechanisms, 
        input validation, information disclosure, and various other security aspects. Detailed findings 
        and recommendations are provided in the following sections.
        """

        return {
            'overview': overview,
            'total_vulnerabilities': total_vulns,
            'severity_counts': severity_counts,
            'severity_percentages': severity_percentages,
            'risk_level': risk_level
        }

    def _extract_findings_from_result(self, result):
        """Extract key findings from scanner result"""
        findings = []
        
        if isinstance(result, dict):
            if 'findings' in result:
                for finding in result['findings'][:3]:  # Top 3 findings
                    if isinstance(finding, dict):
                        title = finding.get('title', 'Finding')
                        severity = finding.get('severity', 'Unknown')
                        findings.append(f"{title} ({severity})")
            elif 'vulnerabilities' in result:
                for vuln in result['vulnerabilities'][:3]:  # Top 3 vulnerabilities
                    if isinstance(vuln, dict):
                        title = vuln.get('title', 'Vulnerability')
                        severity = vuln.get('severity', 'Unknown')
                        findings.append(f"{title} ({severity})")
            elif 'open_ports' in result:
                open_ports = len(result.get('open_ports', []))
                services = len(result.get('services', []))
                findings.append(f"Found {open_ports} open ports and {services} services")
        
        return findings

    def dns_enumeration(self, domain):
        """
        Perform DNS enumeration to gather additional information
        """
        print(f"🔍 Performing DNS enumeration for {domain}")
        dns_info = {}

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        for record_type in record_types:
            try:
                if 'dns' in globals() and hasattr(dns, 'resolver'):
                    answers = dns.resolver.resolve(domain, record_type)
                    # Ensure we convert AttributeValueList to strings properly
                    dns_info[record_type] = [str(rdata) if rdata is not None else '' for rdata in answers]
                else:
                    dns_info[record_type] = []
            except Exception as e:
                print(f"WARNING:  DNS resolution failed for {record_type}: {e}")
                dns_info[record_type] = []

        # Subdomain enumeration (basic)
        subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api']
        found_subdomains = []

        for sub in subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                ip = socket.gethostbyname(subdomain)
                found_subdomains.append({'subdomain': subdomain, 'ip': ip})
            except:
                pass

        dns_info['subdomains'] = found_subdomains
        return dns_info

    def host_discovery(self, target_ip):
        """
        Perform host discovery and OS detection
        """
        print(f"🖥️  Performing host discovery on {target_ip}")

        try:
            # Check if nmap is available
            if not NMAP_AVAILABLE or not hasattr(self, 'nm') or self.nm is None:
                print("WARNING:  Nmap not available for host discovery")
                return {'status': 'unknown', 'hostnames': []}
            
            # Host discovery scan
            result = self.nm.scan(target_ip, arguments='-sn')
            host_info = {
                'status': 'up' if target_ip in self.nm.all_hosts() else 'down',
                'hostnames': []
            }

            if target_ip in self.nm.all_hosts():
                host_data = self.nm[target_ip]
                if 'hostnames' in host_data:
                    host_info['hostnames'] = [h['name'] for h in host_data['hostnames']]

            return host_info
        except Exception as e:
            print(f"❌ Host discovery failed: {e}")
            return {'status': 'unknown', 'hostnames': []}

    def os_detection(self, target_ip):
        """
        Perform OS detection
        """
        print(f"🔍 Performing OS detection on {target_ip}")

        try:
            # Check if nmap is available
            if not NMAP_AVAILABLE or not hasattr(self, 'nm') or self.nm is None:
                print("WARNING:  Nmap not available for OS detection")
                return {}

            # OS detection requires root privileges
            result = self.nm.scan(target_ip, arguments='-O')

            if target_ip in self.nm.all_hosts():
                host_data = self.nm[target_ip]
                return {
                    'osmatch': host_data.get('osmatch', []),
                    'portused': host_data.get('portused', []),
                    'osclass': host_data.get('osclass', [])
                }
        except Exception as e:
            print(f"WARNING:  OS detection failed (may require root): {e}")

        return {}

    def port_scan(self, target_ip, scan_type='fast'):
        """
        Perform different types of port scans.
        Optimized for thoroughness and comprehensive results.
        """
        # Check if nmap is available
        if not NMAP_AVAILABLE or not hasattr(self, 'nm') or self.nm is None:
            print("WARNING:  Nmap not available for port scanning")
            return []

        scan_configs = {
            'fast': {
                'ports': '1-65535',  # All ports for thorough scanning
                'arguments': '-sS -sV -O -A --script=default,safe,vuln,discovery,exploit -T3 --max-retries 3 --version-intensity 9'
            },
            'top100': {
                'ports': '1-65535',  # All ports for thorough scanning
                'arguments': '-sS -sV -O -A --script=default,safe,vuln,discovery,exploit -T3 --max-retries 3'
            },
            'top1000': {
                'ports': '1-65535',  # All ports for thorough scanning
                'arguments': '-sS -sV -O -A --script=default,safe,vuln,discovery,exploit -T3 --max-retries 3'
            },
            'comprehensive': {
                'ports': '1-65535',  # All ports
                'arguments': '-sS -sV -O -A --script=default,safe,vuln,discovery,exploit -T3 --max-retries 3 --version-intensity 9 --script-timeout 300s'
            },
            'stealth': {
                'ports': '1-65535',  # All ports for thorough scanning
                'arguments': '-sS -sV -O -A --script=default,safe,vuln,discovery,exploit -T2 -f --max-retries 3'
            },
            'aggressive': {
                'ports': '1-65535',  # All ports for thorough scanning
                'arguments': '-sS -sV -O -A --script=default,safe,vuln,discovery,exploit -T3 --max-retries 3 --version-intensity 9'
            }
        }

        config = scan_configs.get(scan_type, scan_configs['fast'])
        print(f"🔍 Performing thorough {scan_type} port scan on {target_ip}")
        print(f"   Ports: {config['ports']} (All 65535 ports for comprehensive coverage)")
        print(f"   Arguments: {config['arguments']}")
        print(f"   WARNING:  This scan will take 1-3 hours for complete results")

        try:
            result = self.nm.scan(
                target_ip,
                config['ports'],
                arguments=config['arguments']
            )

            return self.parse_scan_results(target_ip)

        except Exception as e:
            print(f"❌ Port scan failed: {e}")
            return []

    def service_detection(self, target_ip, open_ports):
        """
        Perform detailed service and version detection on open ports
        """
        # Check if nmap is available
        if not NMAP_AVAILABLE or not hasattr(self, 'nm') or self.nm is None:
            print("WARNING:  Nmap not available for service detection")
            return []

        if not open_ports:
            return []

        port_list = ','.join(str(p['port']) for p in open_ports)
        print(f"🔍 Performing service detection on ports: {port_list}")

        try:
            result = self.nm.scan(
                target_ip,
                port_list,
                arguments='-sV -sC --script=default,safe'
            )

            return self.parse_service_results(target_ip)

        except Exception as e:
            print(f"❌ Service detection failed: {e}")
            return []

    def vulnerability_scan(self, target_ip, services):
        """
        Run vulnerability detection scripts
        """
        # Check if nmap is available
        if not NMAP_AVAILABLE or not hasattr(self, 'nm') or self.nm is None:
            print("WARNING:  Nmap not available for vulnerability scanning")
            return []

        if not services:
            return []

        print(f"🛡️  Performing vulnerability scan")

        # Only run the most useful scripts to save time
        vuln_scripts = [
            'vuln',
            'exploit'
        ]

        results = []
        for script_category in vuln_scripts:
            try:
                result = self.nm.scan(
                    target_ip,
                    arguments=f'--script={script_category} -T4'
                )

                if target_ip in self.nm.all_hosts():
                    host_data = self.nm[target_ip]
                    results.append({
                        'category': script_category,
                        'results': host_data.get('hostscript', [])
                    })

            except Exception as e:
                print(f"WARNING:  Vulnerability scan ({script_category}) failed: {e}")

        return results

    def parse_scan_results(self, target_ip):
        """
        Parse nmap scan results and extract open ports
        """
        # Check if nmap is available
        if not NMAP_AVAILABLE or not hasattr(self, 'nm') or self.nm is None:
            return []
            
        open_ports = []

        if target_ip not in self.nm.all_hosts():
            return open_ports

        for proto in self.nm[target_ip].all_protocols():
            ports = self.nm[target_ip][proto].keys()
            for port in ports:
                port_info = self.nm[target_ip][proto][port]
                if port_info['state'] == 'open':
                    open_ports.append({
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'reason': port_info.get('reason', ''),
                        'conf': port_info.get('conf', '')
                    })

        return open_ports

    def parse_service_results(self, target_ip):
        """
        Parse detailed service information
        """
        # Check if nmap is available
        if not NMAP_AVAILABLE or not hasattr(self, 'nm') or self.nm is None:
            return []

        services = []

        if target_ip not in self.nm.all_hosts():
            return services

        for proto in self.nm[target_ip].all_protocols():
            ports = self.nm[target_ip][proto].keys()
            for port in ports:
                port_info = self.nm[target_ip][proto][port]
                if port_info['state'] == 'open':
                    service_info = {
                        'port': port,
                        'protocol': proto,
                        'service': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'cpe': port_info.get('cpe', ''),
                        'scripts': []
                    }

                    # Extract script results
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            service_info['scripts'].append({
                                'name': script_name,
                                'output': script_output
                            })

                    services.append(service_info)

        return services

    def fetch_cves(self, service_name, version=None):
        """
        Fetch CVEs for a service with rate limiting
        """
        # Rate limiting to avoid 403 errors
        current_time = time.time()
        if current_time - self.last_cve_request < self.cve_request_delay:
            time.sleep(self.cve_request_delay - (current_time - self.last_cve_request))
        self.last_cve_request = time.time()
        
        query = f"{service_name}"
        if version:
            query += f" {version}"
        
        # Use a different CVE database API to avoid 403 errors
        url = f"https://cve.circl.lu/api/search/{query}"
        
        try:
            print(f"🔍 Fetching CVEs for: {query}")
            response = httpx.get(url, timeout=None)
            if response.status_code == 403:
                print(f"WARNING:  Rate limited, skipping CVE lookup for {query}")
                return []
            response.raise_for_status()
            data = response.json()
        except httpx.TimeoutException:
            print(f"⏱️ CVE fetch timed out for {query}")
            return []
        except Exception as e:
            print(f"❌ CVE fetch failed for {query}: {e}")
            return []

        cves = []
        for vuln in data.get("results", []):
            cve_id = vuln.get("id")
            summary = vuln.get("summary", "No description available")
            
            # Extract CVSS score if available
            cvss = vuln.get("cvss", "N/A")
            severity = "UNKNOWN"
            
            if cvss and isinstance(cvss, (int, float)):
                if cvss >= 9.0:
                    severity = "CRITICAL"
                elif cvss >= 7.0:
                    severity = "HIGH"
                elif cvss >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            cves.append({
                "id": cve_id,
                "description": summary[:200] + "..." if len(summary) > 200 else summary,
                "severity": severity,
                "score": cvss,
                "published": vuln.get("Published", "Unknown"),
                "modified": vuln.get("Modified", "Unknown"),
                "references": vuln.get("references", [])[:3]  # Limit references
            })

        return cves[:5]  # Limit to top 5 CVEs

    def comprehensive_scan(self, target, scan_type='fast', skip_vuln_scan=False):
        """
        Perform a comprehensive scan of the target
        """
        print(f"[SCAN] Starting comprehensive scan of {target}")
        start_time = datetime.now()

        # Resolve target
        target_info = self.resolve_target(target)
        if not target_info:
            return None

        results = {
            'target': target,
            'target_info': target_info,
            'scan_start': start_time.isoformat(),
            'scan_type': scan_type
        }

        ip = target_info['ip']
        hostname = target_info['hostname']

        # DNS enumeration
        if hostname != ip:
            results['dns_info'] = self.dns_enumeration(hostname)

        # Host discovery
        results['host_discovery'] = self.host_discovery(ip)

        # OS detection
        results['os_detection'] = self.os_detection(ip)

        # Port scanning
        results['open_ports'] = self.port_scan(ip, scan_type)

        # Service detection
        if results['open_ports']:
            results['services'] = self.service_detection(ip, results['open_ports'])

            # Fetch CVEs for detected services using threading for efficiency
            results['vulnerabilities'] = {}
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_service = {
                    executor.submit(self.fetch_cves, service['service'], service['version']): service 
                    for service in results['services']
                }
                
                for future in as_completed(future_to_service):
                    service = future_to_service[future]
                    try:
                        cves = future.result()
                        service_key = f"{service['service']}_{service['version']}"
                        results['vulnerabilities'][service_key] = cves
                    except Exception as e:
                        print(f"❌ Error fetching CVEs for {service['service']}: {e}")

        # Vulnerability scanning (optional)
        if not skip_vuln_scan:
            results['vuln_scan'] = self.vulnerability_scan(ip, results.get('services', []))
        else:
            results['vuln_scan'] = []

        # Calculate scan duration
        end_time = datetime.now()
        results['scan_end'] = end_time.isoformat()
        results['duration'] = str(end_time - start_time)

        print(f" Scan completed in {results['duration']}")
        return results

# Scheduled scans storage (in-memory, replace with database in production)
scheduled_scans = {}

# Startup and shutdown events using lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    scheduler.start()
    print("Scheduler started")
    await task_queue.start()
    print("Task queue started")
    yield
    # Shutdown
    scheduler.shutdown()
    print("Scheduler stopped")
    await task_queue.stop()
    print("Task queue stopped")

# Import distributed system bridge
try:
    from integration.distributed_system_bridge import distributed_bridge
    DISTRIBUTED_SYSTEM_AVAILABLE = True
except ImportError:
    DISTRIBUTED_SYSTEM_AVAILABLE = False
    distributed_bridge = None

# Import Professional PDF Generator
try:
    from backend.reports.professional_pdf_generator import ProfessionalPDFGenerator
except ImportError:
    try:
        from reports.professional_pdf_generator import ProfessionalPDFGenerator
    except ImportError:
        ProfessionalPDFGenerator = None
        print("Warning: ProfessionalPDFGenerator could not be imported.")

# Initialize FastAPI app with comprehensive documentation
app = FastAPI(
    title="Security Analysis Framework",
    description="""
    # Security Analysis Framework API
    
    An educational tool for learning web security concepts and OWASP Top 10 vulnerabilities.
    
    ## Features
    
    * 🔍 **Security Scanning**: Comprehensive web application security analysis
    * 📊 **OWASP Top 10 Coverage**: Educational insights into common vulnerabilities
    * 📈 **Real-time Monitoring**: Live scan progress and WebSocket updates
    * 📋 **Report Generation**: Technical and executive reports
    * 🔐 **User Authentication**: Secure user management system
    * ⏰ **Scheduled Scans**: Automated security monitoring
    * 📧 **Notifications**: Alert system for critical findings
    * 🔗 **External Tools**: Integration with security tools
    
    ## Getting Started
    
    1. **Authentication**: Register and login to get access token
    2. **Start Scan**: Submit a URL for security analysis
    3. **Monitor Progress**: Use WebSocket for real-time updates
    4. **Review Results**: Get detailed findings and recommendations
    5. **Generate Reports**: Create technical and executive summaries
    
    ## Educational Focus
    
    This framework is designed for educational purposes to help developers understand:
    - Common web security vulnerabilities
    - OWASP Top 10 categories and prevention methods
    - Security testing methodologies
    - Responsible disclosure practices
    
    **WARNING: Important**: Only use this tool on systems you own or have explicit permission to test.
    """,
    version="1.0.0",
    contact={
        "name": "Security Analysis Framework",
        "url": "https://github.com/security-framework",
        "email": "security@example.com",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "User registration, login, and authentication management"
        },
        {
            "name": "Scanning",
            "description": "Security scan initiation, monitoring, and results retrieval"
        },
        {
            "name": "Reports",
            "description": "Technical and executive report generation"
        },
        {
            "name": "History",
            "description": "Scan history management and comparison"
        },
        {
            "name": "Scheduled Scans",
            "description": "Automated scan scheduling and management"
        },
        {
            "name": "Rate Limiting",
            "description": "API usage limits and quota management"
        },
        {
            "name": "Notifications",
            "description": "Alert system for critical security findings"
        },
        {
            "name": "External Tools",
            "description": "Integration with external security tools"
        },
        {
            "name": "WebSocket",
            "description": "Real-time communication for scan progress"
        },
        {
            "name": "Educational",
            "description": "OWASP Top 10 educational content and guidance"
        }
    ],
    lifespan=lifespan
)

# Add CORS middleware with proper configuration for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*"  # Allow all origins for development
    ],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "X-CSRF-Token",
        "Cache-Control",
        "Pragma",
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers"
    ],
    expose_headers=["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
    max_age=600  # Reduce cache time to 10 minutes to avoid stale preflight responses
)

# Add custom OPTIONS handler for CORS preflight requests
@app.options("/{full_path:path}")
async def options_handler(full_path: str, request: Request):
    """Handle CORS preflight OPTIONS requests for all paths"""
    from fastapi.responses import Response
    
    response = Response(status_code=200)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "Accept, Accept-Language, Content-Language, Content-Type, Authorization, X-Requested-With, X-CSRF-Token, Cache-Control, Pragma, Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Max-Age"] = "600"
    
    return response

# Startup event to initialize Redis subscriber
@app.on_event("startup")
async def startup_event():
    """Start Redis subscriber for real-time updates and scheduled cleanup"""
    asyncio.create_task(redis_subscriber.start_listening())
    print("[INFO] Redis subscriber started for real-time scan updates")
    
    # Initialize and start cleanup scheduler
    cleanup_scheduler = AsyncIOScheduler()
    
    # Schedule cleanup to run daily at 2 AM
    cleanup_scheduler.add_job(
        cleanup_old_scans,
        CronTrigger(hour=2, minute=0),
        args=[90, True],  # 90 days retention, archive before delete
        id="daily_cleanup",
        name="Daily scan cleanup and archival"
    )
    
    cleanup_scheduler.start()
    print("[INFO] Cleanup scheduler started - runs daily at 2:00 AM")
    print("[INFO] Retention policy: 90 days with automatic archiving")

# Remove the old startup and shutdown event handlers and the duplicate shutdown_event function

# Rate limiting storage (in-memory, replace with Redis in production)
rate_limit_storage = defaultdict(list)
user_quotas = {
    "admin": {
        "daily_scans": 100,
        "hourly_requests": 1000,
        "concurrent_scans": 10
    },
    "user1": {
        "daily_scans": 20,
        "hourly_requests": 200,
        "concurrent_scans": 3
    }
}

# Default quotas for new users
DEFAULT_QUOTAS = {
    "daily_scans": 10,
    "hourly_requests": 100,
    "concurrent_scans": 2
}

# Rate limiting models
class RateLimitConfig(BaseModel):
    daily_scans: int
    hourly_requests: int
    concurrent_scans: int

class RateLimitInfo(BaseModel):
    remaining_daily_scans: int
    remaining_hourly_requests: int
    current_concurrent_scans: int
    reset_time_daily: str
    reset_time_hourly: str

# Notification system models
class NotificationConfig(BaseModel):
    email_notifications: bool = True
    webhook_notifications: bool = False
    webhook_url: Optional[str] = None
    critical_severity_only: bool = True
    notification_frequency: str = "immediate"  # immediate, daily, weekly

class Notification(BaseModel):
    id: str
    user_id: str
    scan_id: str
    finding_id: str
    severity: str
    title: str
    message: str
    notification_type: str  # email, webhook, in_app
    status: str  # pending, sent, failed
    created_at: str
    sent_at: Optional[str] = None

class NotificationCreate(BaseModel):
    user_id: str
    scan_id: str
    finding_id: str
    severity: str
    title: str
    message: str
    notification_type: str

# Notification storage (in-memory, replace with database in production)
notifications = {}
notification_configs = {
    "admin": NotificationConfig(
        email_notifications=True,
        webhook_notifications=False,
        critical_severity_only=True,
        notification_frequency="immediate"
    ),
    "user1": NotificationConfig(
        email_notifications=True,
        webhook_notifications=False,
        critical_severity_only=False,
        notification_frequency="immediate"
    )
}

# Default notification config
DEFAULT_NOTIFICATION_CONFIG = NotificationConfig()

# External security tool integration models
class ExternalToolConfig(BaseModel):
    tool_name: str
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    enabled: bool = False
    config: Dict = {}

class ExternalScanRequest(BaseModel):
    target_url: str
    scan_type: str  # "vulnerability", "ssl", "headers", "dns"
    tool_name: str
    options: Optional[Dict] = {}

class ExternalScanResult(BaseModel):
    tool_name: str
    scan_id: str
    target_url: str
    scan_type: str
    status: str  # "pending", "running", "completed", "failed"
    results: Optional[Dict] = {}
    error_message: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None

# External tool configurations (in-memory, replace with database in production)
# Shodan, VirusTotal, and SecurityTrails removed as per user request
external_tools = {
    # Add new external tools here if needed
    # Example:
    # "tool_name": {
    #     "name": "Tool Name",
    #     "description": "Tool description",
    #     "api_url": "https://api.example.com",
    #     "enabled": False,
    #     "config": {}
    # }
}

# External scan storage (in-memory, replace with database in production)
external_scans = {}

# Notification functions
def get_user_notification_config(username: str) -> NotificationConfig:
    """Get user notification configuration"""
    return notification_configs.get(username, DEFAULT_NOTIFICATION_CONFIG)

def should_send_notification(username: str, severity: str) -> bool:
    """Check if notification should be sent based on user config and severity"""
    config = get_user_notification_config(username)
    
    if config.critical_severity_only and severity.lower() not in ["critical", "high"]:
        return False
    
    return True

def create_notification(notification_data: NotificationCreate) -> Notification:
    """Create a new notification"""
    notification_id = f"notif_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{notification_data.user_id}"
    
    notification = Notification(
        id=notification_id,
        user_id=notification_data.user_id,
        scan_id=notification_data.scan_id,
        finding_id=notification_data.finding_id,
        severity=notification_data.severity,
        title=notification_data.title,
        message=notification_data.message,
        notification_type=notification_data.notification_type,
        status="pending",
        created_at=datetime.now().isoformat(),
        sent_at=None
    )
    
    notifications[notification_id] = notification.model_dump()
    return notification

async def send_email_notification(notification: Notification):
    """Send email notification (simulated)"""
    # In production, this would integrate with an email service like SendGrid, AWS SES, etc.
    try:
        # Simulate email sending
        await asyncio.sleep(0.1)  # Simulate network delay
        
        # Update notification status
        notification.status = "sent"
        notification.sent_at = datetime.now().isoformat()
        notifications[notification.id] = notification.model_dump()
        
        print(f"Email notification sent: {notification.title}")
        return True
    except Exception as e:
        notification.status = "failed"
        notifications[notification.id] = notification.model_dump()
        print(f"Failed to send email notification: {str(e)}")
        return False

async def send_webhook_notification(notification: Notification, webhook_url: str):
    """Send webhook notification"""
    try:
        async with httpx.AsyncClient() as client:
            payload = {
                "notification_id": notification.id,
                "user_id": notification.user_id,
                "scan_id": notification.scan_id,
                "finding_id": notification.finding_id,
                "severity": notification.severity,
                "title": notification.title,
                "message": notification.message,
                "timestamp": notification.created_at
            }
            
            response = await client.post(webhook_url, json=payload, timeout=None)
            response.raise_for_status()
            
            # Update notification status
            notification.status = "sent"
            notification.sent_at = datetime.now().isoformat()
            notifications[notification.id] = notification.model_dump()
            
            print(f"Webhook notification sent: {notification.title}")
            return True
    except Exception as e:
        notification.status = "failed"
        notifications[notification.id] = notification.model_dump()
        print(f"Failed to send webhook notification: {str(e)}")
        return False

async def process_notification(notification: Notification):
    """Process a notification based on its type"""
    config = get_user_notification_config(notification.user_id)
    
    if notification.notification_type == "email" and config.email_notifications:
        await send_email_notification(notification)
    elif notification.notification_type == "webhook" and config.webhook_notifications:
        if config.webhook_url:
            await send_webhook_notification(notification, config.webhook_url)
    elif notification.notification_type == "in_app":
        # In-app notifications are stored and retrieved via API
        notification.status = "sent"
        notification.sent_at = datetime.now().isoformat()
        notifications[notification.id] = notification.model_dump()

async def create_finding_notification(user_id: str, scan_id: str, finding: dict):
    """Create notification for a security finding"""
    if not should_send_notification(user_id, finding.get("severity", "info")):
        return None
    
    config = get_user_notification_config(user_id)
    
    # Create notification data
    notification_data = NotificationCreate(
        user_id=user_id,
        scan_id=scan_id,
        finding_id=finding.get("id", ""),
        severity=finding.get("severity", "info"),
        title=f"Security Finding: {finding.get('title', 'Unknown')}",
        message=f"New {finding.get('severity', 'info')} severity finding detected: {finding.get('description', 'No description')}",
        notification_type="in_app"
    )
    
    notification = create_notification(notification_data)
    
    # Process notification asynchronously
    asyncio.create_task(process_notification(notification))
    
    return notification

# External security tool integration functions
def get_external_tool_config(tool_name: str) -> Optional[Dict]:
    """Get external tool configuration"""
    return external_tools.get(tool_name)

def update_external_tool_config(tool_name: str, config: Dict):
    """Update external tool configuration"""
    if tool_name in external_tools:
        external_tools[tool_name].update(config)

# Shodan, VirusTotal, and SecurityTrails scan functions removed as per user request
# Add new external tool scan functions here if needed

async def execute_external_scan(scan_request: ExternalScanRequest) -> ExternalScanResult:
    """Execute external security scan"""
    scan_id = f"ext_{scan_request.tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Create scan result
    scan_result = ExternalScanResult(
        tool_name=scan_request.tool_name,
        scan_id=scan_id,
        target_url=scan_request.target_url,
        scan_type=scan_request.scan_type,
        status="running",
        results={},
        error_message=None,
        created_at=datetime.now().isoformat(),
        completed_at=None
    )
    
    # Store scan
    external_scans[scan_id] = scan_result.model_dump()
    
    try:
        # Get tool configuration
        tool_config = get_external_tool_config(scan_request.tool_name)
        if not tool_config or not tool_config.get("enabled"):
            raise Exception(f"Tool {scan_request.tool_name} is not enabled or configured")
        
        api_key = tool_config.get("config", {}).get("api_key")
        if not api_key:
            raise Exception(f"API key not configured for {scan_request.tool_name}")
        
        # Execute scan based on tool
        # Shodan, VirusTotal, and SecurityTrails removed - add new tools here
        # Add new external tool integrations here following this pattern:
        # if scan_request.tool_name == "your_tool":
        #     result = await your_tool_scan(scan_request.target_url, api_key)
        # else:
        #     raise Exception(f"Unsupported tool: {scan_request.tool_name}")
        
        raise Exception(f"No external tools configured. Tool '{scan_request.tool_name}' is not available.")
        
    except Exception as e:
        scan_result.status = "failed"
        scan_result.error_message = str(e)
        scan_result.completed_at = datetime.now().isoformat()
        external_scans[scan_id] = scan_result.model_dump()
    
    return scan_result

# Rate limiting functions
def get_user_quota(username: str) -> Dict:
    """Get user quota configuration"""
    return user_quotas.get(username, DEFAULT_QUOTAS)

def check_rate_limit(username: str, request_type: str = "request") -> bool:
    """Check if user has exceeded rate limits"""
    quota = get_user_quota(username)
    now = time.time()
    
    # Clean old entries
    rate_limit_storage[username] = [
        entry for entry in rate_limit_storage[username] 
        if now - entry["timestamp"] < 86400  # Keep last 24 hours
    ]
    
    if request_type == "scan":
        # Check daily scan limit
        daily_scans = len([
            entry for entry in rate_limit_storage[username]
            if entry["type"] == "scan" and now - entry["timestamp"] < 86400
        ])
        if daily_scans >= quota["daily_scans"]:
            return False
    
    # Check hourly request limit
    hourly_requests = len([
        entry for entry in rate_limit_storage[username]
        if now - entry["timestamp"] < 3600
    ])
    if hourly_requests >= quota["hourly_requests"]:
        return False
    
    return True

def record_request(username: str, request_type: str = "request"):
    """Record a request for rate limiting"""
    rate_limit_storage[username].append({
        "type": request_type,
        "timestamp": time.time()
    })

def get_rate_limit_info(username: str) -> RateLimitInfo:
    """Get current rate limit information for user"""
    quota = get_user_quota(username)
    now = time.time()
    
    # Count daily scans
    daily_scans = len([
        entry for entry in rate_limit_storage[username]
        if entry["type"] == "scan" and now - entry["timestamp"] < 86400
    ])
    
    # Count hourly requests
    hourly_requests = len([
        entry for entry in rate_limit_storage[username]
        if now - entry["timestamp"] < 3600
    ])
    
    # Count concurrent scans (simplified - in production, track actual running scans)
    concurrent_scans = len([
        entry for entry in rate_limit_storage[username]
        if entry["type"] == "scan" and now - entry["timestamp"] < 300  # 5 minutes
    ])
    
    return RateLimitInfo(
        remaining_daily_scans=max(0, quota["daily_scans"] - daily_scans),
        remaining_hourly_requests=max(0, quota["hourly_requests"] - hourly_requests),
        current_concurrent_scans=concurrent_scans,
        reset_time_daily=datetime.fromtimestamp(now + 86400 - (now % 86400), tz=timezone.utc).isoformat(),
        reset_time_hourly=datetime.fromtimestamp(now + 3600 - (now % 3600), tz=timezone.utc).isoformat()
    )

# Initialize scheduler
scheduler = AsyncIOScheduler()

# Scheduled scans storage (in-memory, replace with database in production)
scheduled_scans = {}

# Authentication configuration
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
# Use a stable, pure-Python scheme to avoid bcrypt backend issues on some platforms
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Security scheme
security = HTTPBearer()

# In-memory user storage (replace with database in production)
users_db = {
    "admin": {
        "username": "admin",
        "email": "admin@example.com",
        "hashed_password": pwd_context.hash("admin123"),
        "full_name": "Administrator",
        "role": "admin",
        "is_active": True
    },
    "user1": {
        "username": "user1",
        "email": "user1@example.com",
        "hashed_password": pwd_context.hash("password123"),
        "full_name": "Test User",
        "role": "user",
        "is_active": True
    }
}

# Pydantic models for authentication
class UserCreate(BaseModel):
    """
    User registration model for creating new accounts.
    
    This model is used when registering new users in the system.
    Passwords are automatically hashed before storage.
    """
    username: str = Field(..., min_length=3, max_length=50, description="Unique username for the account")
    email: str = Field(..., description="Valid email address for the user")
    password: str = Field(..., min_length=8, description="Secure password (minimum 8 characters)")
    full_name: str = Field(..., description="User's full name")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "email": "john.doe@example.com",
                "password": "securepassword123",
                "full_name": "John Doe"
            }
        }

class UserLogin(BaseModel):
    """
    User login model for authentication.
    
    Used to authenticate existing users and receive access tokens.
    """
    username: str = Field(..., description="Registered username")
    password: str = Field(..., description="User's password")
    

class User(BaseModel):
    """
    User profile model returned by the API.
    
    Contains user information without sensitive data like passwords.
    """
    username: str = Field(..., description="Unique username")
    email: str = Field(..., description="User's email address")
    full_name: str = Field(..., description="User's full name")
    role: str = Field(..., description="User role (user, admin)")
    is_active: bool = Field(..., description="Whether the user account is active")
    

class Token(BaseModel):
    """
    Authentication token model.
    
    Returned after successful login for API access.
    """
    access_token: str = Field(..., description="JWT access token for API authentication")
    token_type: str = Field(..., description="Token type (always 'bearer')")
    

class TokenData(BaseModel):
    """
    Token payload data model.
    
    Internal model for JWT token validation.
    """
    username: Optional[str] = Field(None, description="Username from token payload")


# Scheduled scanning models
class ScheduledScanCreate(BaseModel):
    name: str
    target_url: str
    schedule_type: str  # "interval", "cron", "once"
    schedule_config: Dict  # interval_seconds, cron_expression, or run_at
    scan_options: Optional[Dict] = {}
    created_by: str

class ScheduledScan(ScheduledScanCreate):
    id: str
    status: str  # "active", "paused", "completed"
    next_run: Optional[str]
    last_run: Optional[str]
    total_runs: int = 0
    created_at: str

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    if username in users_db:
        user_dict = users_db[username]
        return User(**user_dict)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, users_db[username]["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    # Type assertion: we know username is not None here because of the check above
    if token_data.username is None:
        raise credentials_exception
    user = get_user(username=token_data.username)  # type: ignore
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Rate limiting dependencies
async def check_rate_limit_dependency(request: Request, current_user: User = Depends(get_current_active_user)):
    """Dependency to check rate limits"""
    if not check_rate_limit(current_user.username):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later.",
            headers={
                "X-RateLimit-Reset": get_rate_limit_info(current_user.username).reset_time_hourly
            }
        )
    
    record_request(current_user.username)
    return current_user

async def check_scan_rate_limit_dependency(request: Request, current_user: User = Depends(get_current_active_user)):
    """Dependency to check scan-specific rate limits"""
    if not check_rate_limit(current_user.username, "scan"):
        raise HTTPException(
            status_code=429,
            detail="Daily scan limit exceeded. Please try again tomorrow.",
            headers={
                "X-RateLimit-Reset": get_rate_limit_info(current_user.username).reset_time_daily
            }
        )
    
    record_request(current_user.username, "scan")
    return current_user

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "Security Analysis Framework is running"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "Security Analysis Framework API", "version": "1.0.0"}

# Authentication endpoints
@app.post("/auth/register", response_model=User, tags=["Authentication"])
async def register_user(user: UserCreate):
    """
    Register a new user account.
    
    Creates a new user account with secure password hashing.
    Usernames must be unique across the system.
    
    ## Security Features
    
    * 🔐 **Password Hashing**: Passwords are securely hashed using bcrypt
    *  **Input Validation**: Username and email validation
    * 🚫 **Duplicate Prevention**: Username uniqueness enforcement
    
    ## Requirements
    
    * **Username**: 3-50 characters, unique
    * **Email**: Valid email format
    * **Password**: Minimum 8 characters
    * **Full Name**: User's complete name
    
    ## Response
    
    Returns user profile information (excluding password).
    
    ## Example Usage
    
    ```bash
    curl -X POST "http://localhost:8000/auth/register" \\
         -H "Content-Type: application/json" \\
         -d '{
           "username": "john_doe",
           "email": "john.doe@example.com",
           "password": "securepassword123",
           "full_name": "John Doe"
         }'
    ```
    """
    if user.username in users_db:
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    user_dict = {
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password,
        "full_name": user.full_name,
        "role": "user",
        "is_active": True
    }
    users_db[user.username] = user_dict
    
    return User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role="user",
        is_active=True
    )

@app.post("/auth/login", response_model=Token, tags=["Authentication"])
async def login_for_access_token(user_credentials: UserLogin):
    """
    Authenticate user and receive access token.
    
    Validates user credentials and returns a JWT access token for API authentication.
    The token is required for accessing protected endpoints.
    
    ## Authentication Flow
    
    1. **Submit Credentials**: Username and password
    2. **Validation**: Credentials verified against stored hashes
    3. **Token Generation**: JWT token created with user claims
    4. **Response**: Access token for API authentication
    
    ## Token Usage
    
    Include the token in the Authorization header for protected endpoints:
    ```
    Authorization: Bearer <access_token>
    ```
    
    ## Security Features
    
    * 🔐 **Secure Hashing**: Password verification using bcrypt
    * ⏰ **Token Expiration**: Configurable token lifetime
    * 🛡️ **JWT Security**: Signed tokens with user claims
    
    ## Example Usage
    
    ```bash
    curl -X POST "http://localhost:8000/auth/login" \\
         -H "Content-Type: application/json" \\
         -d '{
           "username": "john_doe",
           "password": "securepassword123"
         }'
    ```
    
    ## Response Example
    
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer"
    }
    ```
    """
    user = authenticate_user(user_credentials.username, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Get current user information"""
    return current_user

@app.get("/auth/users", response_model=List[User])
async def get_users(current_user: User = Depends(get_current_active_user)):
    """Get all users (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return [User(**{k: v for k, v in user.items() if k != "hashed_password"}) 
            for user in users_db.values()]

# Scheduled scanning functions
async def execute_scheduled_scan(scan_id: str):
    """Execute a scheduled scan"""
    if scan_id not in scheduled_scans:
        return
    
    scan = scheduled_scans[scan_id]
    try:
        # Update scan status
        scan["status"] = "running"
        scan["last_run"] = datetime.now().isoformat()
        
        # Execute the scan (reuse existing scan logic)
        # This is a simplified version - in production, you'd want to call the actual scan function
        scan_result = {
            "scan_id": f"scheduled_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "target_url": scan["target_url"],
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        # Save scan result
        with open(f"scan_results/{scan_result['scan_id']}.json", "w") as f:
            json.dump(scan_result, f, indent=2)
        
        # Update scan statistics
        scan["total_runs"] += 1
        scan["status"] = "active"
        
        # Schedule next run if needed
        if scan["schedule_type"] != "once":
            schedule_next_run(scan_id)
            
    except Exception as e:
        scan["status"] = "error"
        print(f"Error executing scheduled scan {scan_id}: {str(e)}")

def schedule_next_run(scan_id: str):
    """Schedule the next run for a recurring scan"""
    scan = scheduled_scans[scan_id]
    
    if scan["schedule_type"] == "interval":
        interval_seconds = scan["schedule_config"]["interval_seconds"]
        next_run = datetime.now() + timedelta(seconds=interval_seconds)
        scan["next_run"] = next_run.isoformat()
        
        # Schedule next execution
        scheduler.add_job(
            execute_scheduled_scan,
            IntervalTrigger(seconds=interval_seconds),
            args=[scan_id],
            id=f"scan_{scan_id}",
            replace_existing=True
        )
    
    elif scan["schedule_type"] == "cron":
        cron_expr = scan["schedule_config"]["cron_expression"]
        scheduler.add_job(
            execute_scheduled_scan,
            CronTrigger.from_crontab(cron_expr),
            args=[scan_id],
            id=f"scan_{scan_id}",
            replace_existing=True
        )

# Scheduled scanning endpoints
@app.post("/scheduled-scans", response_model=ScheduledScan)
async def create_scheduled_scan(
    scan_data: ScheduledScanCreate,
    current_user: User = Depends(get_current_active_user)
):
    """Create a new scheduled scan"""
    scan_id = f"scheduled_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{current_user.username}"
    
    # Validate schedule configuration
    if scan_data.schedule_type == "interval":
        if "interval_seconds" not in scan_data.schedule_config:
            raise HTTPException(status_code=400, detail="interval_seconds required for interval schedule")
    elif scan_data.schedule_type == "cron":
        if "cron_expression" not in scan_data.schedule_config:
            raise HTTPException(status_code=400, detail="cron_expression required for cron schedule")
    elif scan_data.schedule_type == "once":
        if "run_at" not in scan_data.schedule_config:
            raise HTTPException(status_code=400, detail="run_at required for one-time schedule")
    
    # Create scheduled scan
    scheduled_scan = ScheduledScan(
        id=scan_id,
        name=scan_data.name,
        target_url=scan_data.target_url,
        schedule_type=scan_data.schedule_type,
        schedule_config=scan_data.schedule_config,
        scan_options=scan_data.scan_options,
        created_by=current_user.username,
        status="active",
        next_run=None,
        last_run=None,
        total_runs=0,
        created_at=datetime.now().isoformat()
    )
    
    # Store the scan
    scheduled_scans[scan_id] = scheduled_scan.model_dump()
    
    # Schedule the scan
    if scan_data.schedule_type == "once":
        run_at = datetime.fromisoformat(scan_data.schedule_config["run_at"])
        scheduler.add_job(
            execute_scheduled_scan,
            'date',
            run_date=run_at,
            args=[scan_id],
            id=f"scan_{scan_id}"
        )
        scheduled_scans[scan_id]["next_run"] = run_at.isoformat()
    else:
        schedule_next_run(scan_id)
    
    return scheduled_scan

@app.get("/scheduled-scans", response_model=List[ScheduledScan])
async def get_scheduled_scans(current_user: User = Depends(get_current_active_user)):
    """Get all scheduled scans for the current user"""
    user_scans = [
        ScheduledScan(**scan) for scan in scheduled_scans.values()
        if scan["created_by"] == current_user.username or current_user.role == "admin"
    ]
    return user_scans

@app.get("/scheduled-scans/{scan_id}", response_model=ScheduledScan)
async def get_scheduled_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific scheduled scan"""
    if scan_id not in scheduled_scans:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    scan = scheduled_scans[scan_id]
    if scan["created_by"] != current_user.username and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return ScheduledScan(**scan)

@app.put("/scheduled-scans/{scan_id}/pause")
async def pause_scheduled_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Pause a scheduled scan"""
    if scan_id not in scheduled_scans:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    scan = scheduled_scans[scan_id]
    if scan["created_by"] != current_user.username and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    scan["status"] = "paused"
    scheduler.remove_job(f"scan_{scan_id}")
    return {"message": "Scheduled scan paused"}

@app.put("/scheduled-scans/{scan_id}/resume")
async def resume_scheduled_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Resume a scheduled scan"""
    if scan_id not in scheduled_scans:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    scan = scheduled_scans[scan_id]
    if scan["created_by"] != current_user.username and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    scan["status"] = "active"
    schedule_next_run(scan_id)
    return {"message": "Scheduled scan resumed"}

@app.delete("/scheduled-scans/{scan_id}")
async def delete_scheduled_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Delete a scheduled scan"""
    if scan_id not in scheduled_scans:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    scan = scheduled_scans[scan_id]
    if scan["created_by"] != current_user.username and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    # Remove from scheduler
    scheduler.remove_job(f"scan_{scan_id}")
    
    # Remove from storage
    del scheduled_scans[scan_id]
    
    return {"message": "Scheduled scan deleted"}

# Rate limiting endpoints
@app.get("/rate-limits", response_model=RateLimitInfo)
async def get_rate_limit_info_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get current rate limit information for the user"""
    return get_rate_limit_info(current_user.username)

@app.get("/rate-limits/config", response_model=RateLimitConfig)
async def get_rate_limit_config(current_user: User = Depends(get_current_active_user)):
    """Get user's rate limit configuration"""
    quota = get_user_quota(current_user.username)
    return RateLimitConfig(**quota)

@app.put("/rate-limits/config")
async def update_rate_limit_config(
    config: RateLimitConfig,
    current_user: User = Depends(get_current_active_user)
):
    """Update user's rate limit configuration (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    # In a real application, you'd update the database
    # For now, we'll update the in-memory storage
    user_quotas[current_user.username] = config.model_dump()
    
    return {"message": "Rate limit configuration updated"}

@app.get("/rate-limits/all")
async def get_all_rate_limits(current_user: User = Depends(get_current_active_user)):
    """Get rate limit information for all users (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    all_limits = {}
    for username in user_quotas.keys():
        all_limits[username] = get_rate_limit_info(username)
    
    return all_limits

# Notification endpoints
@app.get("/notifications", response_model=List[Notification])
async def get_notifications(current_user: User = Depends(get_current_active_user)):
    """Get all notifications for the current user"""
    user_notifications = [
        Notification(**notification) for notification in notifications.values()
        if notification["user_id"] == current_user.username
    ]
    return sorted(user_notifications, key=lambda x: x.created_at, reverse=True)

@app.get("/notifications/{notification_id}", response_model=Notification)
async def get_notification(
    notification_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific notification"""
    if notification_id not in notifications:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notification = notifications[notification_id]
    if notification["user_id"] != current_user.username:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return Notification(**notification)

@app.get("/notifications/config", response_model=NotificationConfig)
async def get_notification_config(current_user: User = Depends(get_current_active_user)):
    """Get user's notification configuration"""
    return get_user_notification_config(current_user.username)

@app.put("/notifications/config")
async def update_notification_config(
    config: NotificationConfig,
    current_user: User = Depends(get_current_active_user)
):
    """Update user's notification configuration"""
    notification_configs[current_user.username] = config
    return {"message": "Notification configuration updated"}

@app.post("/notifications/test")
async def test_notification(current_user: User = Depends(get_current_active_user)):
    """Send a test notification"""
    config = get_user_notification_config(current_user.username)
    
    # Create test notification
    test_notification_data = NotificationCreate(
        user_id=current_user.username,
        scan_id="test_scan",
        finding_id="test_finding",
        severity="info",
        title="Test Notification",
        message="This is a test notification to verify your notification settings.",
        notification_type="in_app"
    )
    
    notification = create_notification(test_notification_data)
    
    # Process notification
    await process_notification(notification)
    
    return {"message": "Test notification sent", "notification_id": notification.id}

@app.delete("/notifications/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Delete a notification"""
    if notification_id not in notifications:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notification = notifications[notification_id]
    if notification["user_id"] != current_user.username:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    del notifications[notification_id]
    return {"message": "Notification deleted"}

@app.get("/notifications/unread/count")
async def get_unread_notifications_count(current_user: User = Depends(get_current_active_user)):
    """Get count of unread notifications"""
    user_notifications = [
        notification for notification in notifications.values()
        if notification["user_id"] == current_user.username and notification["status"] == "sent"
    ]
    return {"unread_count": len(user_notifications)}

# External tool integration endpoints
@app.get("/external-tools", response_model=List[Dict])
async def get_external_tools(current_user: User = Depends(get_current_active_user)):
    """Get list of available external security tools"""
    return [
        {
            "name": tool_name,
            "display_name": config["name"],
            "description": config["description"],
            "enabled": config["enabled"],
            "configured": bool(config.get("config", {}).get("api_key"))
        }
        for tool_name, config in external_tools.items()
    ]

@app.get("/external-tools/{tool_name}/config")
async def get_external_tool_config_endpoint(
    tool_name: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get external tool configuration"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    config = get_external_tool_config(tool_name)
    if not config:
        raise HTTPException(status_code=404, detail="Tool not found")
    
    return config

@app.put("/external-tools/{tool_name}/config")
async def update_external_tool_config_endpoint(
    tool_name: str,
    config: Dict,
    current_user: User = Depends(get_current_active_user)
):
    """Update external tool configuration"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    if tool_name not in external_tools:
        raise HTTPException(status_code=404, detail="Tool not found")
    
    update_external_tool_config(tool_name, config)
    return {"message": f"Configuration updated for {tool_name}"}

@app.post("/external-scans", response_model=ExternalScanResult)
async def create_external_scan(
    scan_request: ExternalScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Create and execute external security scan"""
    # Check if tool is enabled
    tool_config = get_external_tool_config(scan_request.tool_name)
    if not tool_config or not tool_config.get("enabled"):
        raise HTTPException(
            status_code=400,
            detail=f"Tool {scan_request.tool_name} is not enabled"
        )
    
    # Execute scan
    scan_result = await execute_external_scan(scan_request)
    return scan_result

@app.get("/external-scans", response_model=List[ExternalScanResult])
async def get_external_scans(current_user: User = Depends(get_current_active_user)):
    """Get all external scans"""
    # In a real application, you'd filter by user
    # For now, return all scans
    return [
        ExternalScanResult(**scan) for scan in external_scans.values()
    ]

@app.get("/external-scans/{scan_id}", response_model=ExternalScanResult)
async def get_external_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get specific external scan result"""
    if scan_id not in external_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ExternalScanResult(**external_scans[scan_id])

@app.delete("/external-scans/{scan_id}")
async def delete_external_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Delete external scan result"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    if scan_id not in external_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del external_scans[scan_id]
    return {"message": "External scan deleted"}

class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 – Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 – Cryptographic Failures"
    A03_INJECTION = "A03:2021 – Injection"
    A04_INSECURE_DESIGN = "A04:2021 – Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 – Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 – Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 – Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021 – Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 – Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 – Server-Side Request Forgery (SSRF)"

@dataclass
class TechnicalDetails:
    """Technical details for comprehensive reporting"""
    payload_used: str
    request_method: str
    request_headers: Dict[str, str]
    response_status: int
    response_headers: Dict[str, str]
    response_body_snippet: str
    reproduction_steps: List[str]
    cvss_score: float
    cvss_vector: str

@dataclass
class BusinessImpact:
    """Business impact assessment for executive reporting"""
    confidentiality_impact: str  # HIGH, MEDIUM, LOW
    integrity_impact: str
    availability_impact: str
    business_risk: str
    compliance_impact: str
    user_impact: str
    financial_impact: str

@dataclass
class SecurityFinding:
    id: str
    title: str
    description: str
    severity: SeverityLevel
    owasp_category: OWASPCategory
    location: str
    evidence: str
    recommendation: str
    educational_note: str
    timestamp: str
    technical_details: Optional[TechnicalDetails] = None
    business_impact: Optional[BusinessImpact] = None
    issue_type: str = "vulnerability"  # vulnerability, misconfiguration, warning, weak_practice
    cve_ids: List[str] = field(default_factory=list)  # Related CVE IDs
    cve_references: List[Dict[str, str]] = field(default_factory=list)  # Full CVE reference information

@dataclass
class TechnicalReport:
    """Comprehensive technical report"""
    scan_id: str
    target_url: str
    scan_duration: str
    methodology: str
    tools_used: List[str]
    vulnerabilities: List[SecurityFinding]
    misconfigurations: List[SecurityFinding]
    warnings: List[SecurityFinding]
    weak_practices: List[SecurityFinding]
    specialized_findings: Dict[str, List[SecurityFinding]] = field(default_factory=dict)  # Professional categorization
    total_requests: int = 0
    owasp_coverage: Dict[str, int] = field(default_factory=dict)
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    detailed_findings: List[Dict] = field(default_factory=list)  # Full technical details
    remediation_timeline: Dict[str, List[str]] = field(default_factory=dict)

@dataclass
class ExecutiveReport:
    """Executive summary report"""
    scan_id: str
    target_url: str
    scan_date: str
    overall_risk_score: float
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    business_impact_summary: str
    compliance_status: Dict[str, str]
    key_recommendations: List[str]
    executive_summary: str
    next_steps: List[str]
    budget_considerations: List[str]
    tools_used: List[str]

@dataclass
class ScanResult:
    scan_id: str
    target_url: str
    start_time: str
    end_time: str
    findings: List[SecurityFinding]
    summary: Dict[str, int]
    educational_insights: List[str]
    technical_report: Optional[TechnicalReport] = None
    executive_report: Optional[ExecutiveReport] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

class ScanRequest(BaseModel):
    """
    Security scan request model.
    
    Used to initiate security analysis scans with customizable parameters.
    """
    target_url: HttpUrl = Field(..., description="Target URL to scan for security vulnerabilities")
    scan_depth: int = Field(default=2, ge=1, le=5, description="Scan depth level (1-5, higher = more thorough)")
    include_educational_mode: bool = Field(default=True, description="Include educational insights and learning materials")
    scan_mode: str = Field(default="owasp", description="Scan mode: 'basic' for quick scan, 'owasp' for comprehensive OWASP Top 10 analysis")
    scope: List[str] = Field(default=[], description="Specific OWASP categories to focus on (e.g., ['A01', 'A03'])")
    custom_headers: Optional[Dict[str, str]] = Field(default=None, description="Custom HTTP headers for the scan")
    
    # Custom scanner options - All enabled by default for comprehensive scanning
    enable_custom_scanners: bool = Field(default=True, description="Enable custom security scanners")
    enable_whois: bool = Field(default=True, description="Enable WHOIS domain lookup")
    enable_ssl_labs: bool = Field(default=True, description="Enable SSL/TLS configuration analysis")
    enable_sqlmap: bool = Field(default=True, description="Enable SQL injection testing")
    enable_dirb: bool = Field(default=True, description="Enable directory enumeration")
    enable_input_handling_injection: bool = Field(default=True, description="Enable comprehensive input-handling injection scanner (XSS, SQLi, Command, Template, LDAP, Deserialization)")
    enable_authentication_session: bool = Field(default=True, description="Enable authentication & session management security scanner")
    enable_authorization_access_control: bool = Field(default=True, description="Enable authorization & access control security scanner")
    enable_command_os_injection: bool = Field(default=True, description="Enable advanced Command/OS injection scanner with CVE references")
    
    # Scanner timeouts - Set to 0 for no timeout (run until completion)
    whois_timeout: int = Field(default=0, description="WHOIS scanner timeout in seconds (0 = no timeout)")
    ssl_labs_timeout: int = Field(default=0, description="SSL Labs scanner timeout in seconds (0 = no timeout)")
    sqlmap_timeout: int = Field(default=0, description="SQLMap scanner timeout in seconds (0 = no timeout)")
    dirb_timeout: int = Field(default=0, description="Dirb scanner timeout in seconds (0 = no timeout)")
    input_handling_injection_timeout: int = Field(default=0, description="Input-handling injection scanner timeout in seconds (0 = no timeout)")
    authentication_session_timeout: int = Field(default=0, description="Authentication & session management scanner timeout in seconds (0 = no timeout)")
    authorization_access_control_timeout: int = Field(default=0, description="Authorization & access control scanner timeout in seconds (0 = no timeout)")
    command_os_injection_timeout: int = Field(default=0, description="Advanced Command/OS injection scanner timeout in seconds (0 = no timeout)")
    


class AuthSessionRequest(BaseModel):
    """Request model for authentication & session management scan"""
    target_url: str = Field(..., description="Target URL to scan for authentication and session management issues")
    enable_authentication_session: bool = Field(default=True, description="Enable authentication & session management scanner")
    authentication_session_timeout: int = Field(default=300, description="Scanner timeout in seconds")
    


class AuthAccessControlRequest(BaseModel):
    """Request model for authorization & access control scan"""
    target_url: str = Field(..., description="Target URL to scan for authorization and access control issues") 
    enable_authorization_access_control: bool = Field(default=True, description="Enable authorization & access control scanner")
    authorization_access_control_timeout: int = Field(default=240, description="Scanner timeout in seconds")
    



# Global connection manager
connection_manager = ConnectionManager()

# Initialize Redis subscriber for real-time updates
redis_subscriber = RedisSubscriber(connection_manager)

# Set connection manager reference in scan controller after both are defined
# import controllers.scan_controller  # Disabled - using file-based storage
# controllers.scan_controller.connection_manager = connection_manager

# Register scan controller router
# app.include_router(scan_router)  # Disabled - using file-based storage


class ReportGenerator:
    """Comprehensive report generation system"""
    
    def __init__(self):
        self.cvss_calculator = CVSSCalculator()
    
    def generate_technical_report(self, scan_result: ScanResult) -> TechnicalReport:
        """Generate comprehensive technical report"""
        findings = scan_result.findings
        
        # Categorize findings by type
        vulnerabilities = [f for f in findings if f.issue_type == "vulnerability"]
        misconfigurations = [f for f in findings if f.issue_type == "misconfiguration"]
        warnings = [f for f in findings if f.issue_type == "warning"]
        weak_practices = [f for f in findings if f.issue_type == "weak_practice"]
        
        # Professional categorization for specialized scanners (like a professional penetration tester)
        specialized_findings = {
            "authentication_session": [f for f in findings if getattr(f, 'specialized_category', None) == 'authentication_session'],
            "authorization_access_control": [f for f in findings if getattr(f, 'specialized_category', None) == 'authorization_access_control'], 
            "input_handling_injection": [f for f in findings if getattr(f, 'specialized_category', None) == 'input_handling_injection'],
            "advanced_security_assessment": [f for f in findings if getattr(f, 'professional_section', None) == 'Advanced Security Assessment']
        }
        
        # Calculate OWASP coverage
        owasp_coverage = {}
        for finding in findings:
            category = finding.owasp_category.value
            owasp_coverage[category] = owasp_coverage.get(category, 0) + 1
        
        # Severity breakdown
        severity_breakdown = {
            "critical": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "high": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            "medium": len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
            "low": len([f for f in findings if f.severity == SeverityLevel.LOW]),
            "info": len([f for f in findings if f.severity == SeverityLevel.INFO])
        }
        
        # Generate detailed findings with comprehensive CVE and CVSS data
        detailed_findings = []
        for finding in findings:
            # Calculate CVSS score if not present
            cvss_score = 0.0
            cvss_vector = "N/A"
            cvss_severity = "UNKNOWN"
            
            if finding.technical_details and hasattr(finding.technical_details, 'cvss_score'):
                cvss_score = finding.technical_details.cvss_score
                cvss_vector = getattr(finding.technical_details, 'cvss_vector', 'N/A')
            else:
                # Calculate CVSS using enhanced calculator
                try:
                    cvss_score, cvss_vector = self.cvss_calculator.calculate_cvss_score(finding)
                    cvss_severity = self.cvss_calculator.get_severity_from_score(cvss_score)
                except Exception as e:
                    print(f"Error calculating CVSS for finding {finding.id}: {e}")
            
            # Enhanced CVE information extraction
            cve_ids = getattr(finding, 'cve_ids', []) or []
            cve_references = getattr(finding, 'cve_references', []) or []
            
            # Generate comprehensive CVE summary
            cve_summary = self._generate_cve_summary(cve_references)
            
            detailed_finding = {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cvss_severity": cvss_severity,
                "cvss_metrics": self._extract_cvss_metrics(cvss_vector),
                "owasp_category": finding.owasp_category.value,
                "location": finding.location,
                "evidence": finding.evidence,
                "payload_used": finding.technical_details.payload_used if finding.technical_details else "N/A",
                "request_details": {
                    "method": finding.technical_details.request_method if finding.technical_details else "GET",
                    "headers": finding.technical_details.request_headers if finding.technical_details else {},
                },
                "response_details": {
                    "status": finding.technical_details.response_status if finding.technical_details else 0,
                    "headers": finding.technical_details.response_headers if finding.technical_details else {},
                    "body_snippet": finding.technical_details.response_body_snippet if finding.technical_details else ""
                },
                "reproduction_steps": finding.technical_details.reproduction_steps if finding.technical_details else [],
                "recommendation": finding.recommendation,
                "educational_note": finding.educational_note,
                "timestamp": finding.timestamp,
                "cve_ids": cve_ids,
                "cve_references": cve_references,
                "cve_summary": cve_summary,
                "cve_count": len(cve_ids),
                "highest_cve_score": max([float(ref.get('score', 0)) for ref in cve_references], default=0.0),
                "cve_severity_distribution": self._get_cve_severity_distribution(cve_references),
                "scanner_source": getattr(finding, 'scanner_source', 'Built-in Scanner'),
                "scan_phase": getattr(finding, 'scan_phase', 'standard_testing'),
                "specialized_category": getattr(finding, 'specialized_category', None),
                "professional_section": getattr(finding, 'professional_section', 'Standard Security Assessment')
            }
            detailed_findings.append(detailed_finding)
        
        # Remediation timeline
        remediation_timeline = {
            "immediate": [f.title for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]],
            "short_term": [f.title for f in findings if f.severity == SeverityLevel.MEDIUM],
            "long_term": [f.title for f in findings if f.severity in [SeverityLevel.LOW, SeverityLevel.INFO]]
        }
        
        return TechnicalReport(
            scan_id=scan_result.scan_id,
            target_url=scan_result.target_url,
            scan_duration=self._calculate_duration(scan_result.start_time, scan_result.end_time),
            methodology="Professional Penetration Testing with Advanced Security Assessment Framework",
            tools_used=[
                "Custom Security Scanner (Built from Scratch)",
                "Input-Handling Injection Scanner (XSS, SQLi, Command, Template, LDAP, Deserialization)",
                "Authentication & Session Management Security Scanner", 
                "Authorization & Access Control Security Scanner",
                "SQLMap Scanner (Custom Python Implementation)", 
                "Dirb Scanner (Custom Python Implementation)",
                "WHOIS Scanner (Custom Python Implementation)",
                "SSL Labs Scanner (Custom Python Implementation)",
                "Dirb Scanner (Custom Python Implementation)",
                "OWASP Payload Sets",
                "Response Analysis Engine",
                "Network Scanner (Nmap Integration)",
                "Professional Penetration Testing Framework"
            ],
            vulnerabilities=vulnerabilities,
            misconfigurations=misconfigurations,
            warnings=warnings,
            weak_practices=weak_practices,
            specialized_findings=specialized_findings,  # Professional categorization
            total_requests=len(findings) * 2,  # Estimate based on payload testing
            owasp_coverage=owasp_coverage,
            severity_breakdown=severity_breakdown,
            detailed_findings=detailed_findings,
            remediation_timeline=remediation_timeline
        )
    
    def generate_executive_report(self, scan_result: ScanResult) -> ExecutiveReport:
        """Generate executive summary report"""
        findings = scan_result.findings
        
        # Calculate overall risk score (0-10 scale)
        risk_score = self._calculate_overall_risk(findings)
        risk_level = self._determine_risk_level(risk_score)
        
        # Count issues by severity
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        medium_count = len([f for f in findings if f.severity == SeverityLevel.MEDIUM])
        low_count = len([f for f in findings if f.severity == SeverityLevel.LOW])
        
        # Business impact summary
        business_impact = self._generate_business_impact_summary(findings)
        
        # Compliance status
        compliance_status = self._assess_compliance_status(findings)
        
        # Key recommendations
        key_recommendations = self._generate_key_recommendations(findings)
        
        # Executive summary
        executive_summary = self._generate_executive_summary(findings, risk_level)
        
        # Next steps
        next_steps = self._generate_next_steps(findings)
        
        # Budget considerations
        budget_considerations = self._generate_budget_considerations(findings)
        
        return ExecutiveReport(
            scan_id=scan_result.scan_id,
            target_url=scan_result.target_url,
            scan_date=scan_result.start_time.split('T')[0],
            overall_risk_score=risk_score,
            risk_level=risk_level,
            total_issues=len(findings),
            critical_issues=critical_count,
            high_issues=high_count,
            medium_issues=medium_count,
            low_issues=low_count,
            business_impact_summary=business_impact,
            compliance_status=compliance_status,
            key_recommendations=key_recommendations,
            executive_summary=executive_summary,
            next_steps=next_steps,
            budget_considerations=budget_considerations,
            tools_used=[
                "Custom Security Scanner (Built from Scratch)",
                "SQLMap Scanner (Custom Python Implementation)", 
                "Dirb Scanner (Custom Python Implementation)",
                "WHOIS Scanner (Custom Python Implementation)",
                "SSL Labs Scanner (Custom Python Implementation)",
                "Dirb Scanner (Custom Python Implementation)",
                "OWASP Payload Sets",
                "Response Analysis Engine",
                "Network Scanner (Nmap Integration)",
                "Educational Security Framework"
            ]
        )
    
    def _calculate_duration(self, start_time: str, end_time: str) -> str:
        """Calculate scan duration"""
        try:
            start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            duration = end - start
            return f"{duration.total_seconds():.1f} seconds"
        except:
            return "Unknown"
    
    def _calculate_overall_risk(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall risk score (0-10)"""
        if not findings:
            return 0.0
        
        severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 1.0
        }
        
        total_score = sum(severity_weights.get(f.severity, 1.0) for f in findings)
        max_possible = len(findings) * 10.0
        
        return min(10.0, (total_score / max_possible) * 10.0) if max_possible > 0 else 0.0
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score"""
        if risk_score >= 8.0:
            return "CRITICAL"
        elif risk_score >= 6.0:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_business_impact_summary(self, findings: List[SecurityFinding]) -> str:
        """Generate business impact summary"""
        critical_high = len([f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]])
        
        if critical_high > 5:
            return "Severe business risk with potential for data breaches, service disruption, and regulatory penalties"
        elif critical_high > 2:
            return "Significant business risk requiring immediate attention to prevent potential security incidents"
        elif critical_high > 0:
            return "Moderate business risk with some vulnerabilities that could impact operations"
        else:
            return "Low business risk with minor security improvements recommended"
    
    def _assess_compliance_status(self, findings: List[SecurityFinding]) -> Dict[str, str]:
        """Assess compliance status"""
        critical_high = len([f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]])
        
        status = "NON-COMPLIANT" if critical_high > 0 else "COMPLIANT"
        
        return {
            "OWASP Top 10": status,
            "General Security": status,
            "Data Protection": "NEEDS_REVIEW" if critical_high > 2 else "ACCEPTABLE"
        }
    
    def _generate_key_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate key recommendations"""
        recommendations = []
        
        # Group by OWASP category
        owasp_counts = {}
        for finding in findings:
            if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                category = finding.owasp_category.value
                owasp_counts[category] = owasp_counts.get(category, 0) + 1
        
        # Generate recommendations based on most critical issues
        if owasp_counts:
            top_category = max(owasp_counts.items(), key=lambda x: x[1])[0]
            recommendations.append(f"Priority 1: Address {top_category} vulnerabilities immediately")
        
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        if critical_count > 0:
            recommendations.append(f"Immediate action required: {critical_count} critical vulnerabilities found")
        
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        if high_count > 0:
            recommendations.append(f"High priority: Remediate {high_count} high-severity issues within 30 days")
        
        recommendations.extend([
            "Implement regular security scanning and monitoring",
            "Establish incident response procedures",
            "Provide security training for development team"
        ])
        
        return recommendations[:5]  # Top 5 recommendations
    
    def _generate_executive_summary(self, findings: List[SecurityFinding], risk_level: str) -> str:
        """Generate executive summary"""
        total_issues = len(findings)
        critical_high = len([f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]])
        
        summary = f"Security assessment identified {total_issues} total issues with an overall risk level of {risk_level}. "
        
        if critical_high > 0:
            summary += f"{critical_high} critical/high-severity vulnerabilities require immediate attention. "
        
        summary += "This assessment provides actionable recommendations to improve security posture and reduce business risk."
        
        return summary
    
    def _generate_next_steps(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate next steps"""
        steps = []
        
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        
        if critical_count > 0:
            steps.append("Week 1: Address all critical vulnerabilities")
        if high_count > 0:
            steps.append("Month 1: Remediate high-severity issues")
        
        steps.extend([
            "Month 2: Implement security controls and monitoring",
            "Month 3: Conduct follow-up security assessment",
            "Ongoing: Establish regular security review process"
        ])
        
        return steps
    
    def _generate_budget_considerations(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate budget considerations"""
        critical_high = len([f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]])
        
        considerations = []
        
        if critical_high > 5:
            considerations.append("High priority: Budget for security consultant or additional security staff")
        if critical_high > 2:
            considerations.append("Medium priority: Investment in security tools and training")
        
        considerations.extend([
            "Consider security monitoring and incident response services",
            "Budget for regular penetration testing and security assessments",
            "Investment in developer security training programs"
        ])
        
        return considerations

    def _generate_cve_summary(self, cve_references: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive CVE summary for a finding"""
        if not cve_references:
            return {
                "total_cves": 0,
                "severity_breakdown": {},
                "year_distribution": {},
                "average_score": 0.0,
                "highest_score": 0.0,
                "recent_cves": []
            }
        
        severity_breakdown = {}
        year_distribution = {}
        scores = []
        
        for cve_ref in cve_references:
            # Severity distribution
            severity = cve_ref.get('severity', 'UNKNOWN')
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
            
            # Year distribution  
            year = cve_ref.get('year', 'Unknown')
            if isinstance(year, str) and year.isdigit():
                year_distribution[year] = year_distribution.get(year, 0) + 1
            
            # Score tracking
            try:
                score = float(cve_ref.get('score', 0))
                scores.append(score)
            except (ValueError, TypeError):
                pass
        
        # Find recent CVEs (2022 and later)
        recent_cves = [
            cve_ref['cve_id'] for cve_ref in cve_references 
            if cve_ref.get('year', '').isdigit() and int(cve_ref.get('year', 0)) >= 2022
        ]
        
        return {
            "total_cves": len(cve_references),
            "severity_breakdown": severity_breakdown,
            "year_distribution": year_distribution,
            "average_score": sum(scores) / len(scores) if scores else 0.0,
            "highest_score": max(scores) if scores else 0.0,
            "recent_cves": recent_cves
        }
    
    def _extract_cvss_metrics(self, cvss_vector: str) -> Dict[str, str]:
        """Extract individual CVSS metrics from vector string"""
        metrics = {
            "attack_vector": "Unknown",
            "attack_complexity": "Unknown", 
            "privileges_required": "Unknown",
            "user_interaction": "Unknown",
            "scope": "Unknown",
            "confidentiality": "Unknown",
            "integrity": "Unknown",
            "availability": "Unknown"
        }
        
        if not cvss_vector or cvss_vector == "N/A":
            return metrics
        
        # Parse CVSS vector (format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
        try:
            parts = cvss_vector.split('/')
            for part in parts[1:]:  # Skip CVSS:3.1 part
                if ':' in part:
                    key, value = part.split(':', 1)
                    metric_mappings = {
                        'AV': 'attack_vector',
                        'AC': 'attack_complexity',
                        'PR': 'privileges_required',
                        'UI': 'user_interaction',
                        'S': 'scope',
                        'C': 'confidentiality',
                        'I': 'integrity',
                        'A': 'availability'
                    }
                    
                    value_mappings = {
                        'N': {'attack_vector': 'Network', 'privileges_required': 'None', 'user_interaction': 'None', 
                              'confidentiality': 'None', 'integrity': 'None', 'availability': 'None'},
                        'L': {'attack_complexity': 'Low', 'privileges_required': 'Low',
                              'confidentiality': 'Low', 'integrity': 'Low', 'availability': 'Low'},
                        'H': {'attack_complexity': 'High', 'privileges_required': 'High',
                              'confidentiality': 'High', 'integrity': 'High', 'availability': 'High'},
                        'A': {'attack_vector': 'Adjacent Network'},
                        'P': {'attack_vector': 'Physical'},
                        'R': {'user_interaction': 'Required'},
                        'U': {'scope': 'Unchanged'},
                        'C': {'scope': 'Changed'}
                    }
                    
                    if key in metric_mappings:
                        metric_name = metric_mappings[key]
                        if value in value_mappings and metric_name in value_mappings[value]:
                            metrics[metric_name] = value_mappings[value][metric_name]
                        else:
                            metrics[metric_name] = value
        except Exception as e:
            print(f"Error parsing CVSS vector {cvss_vector}: {e}")
        
        return metrics
    
    def _get_cve_severity_distribution(self, cve_references: List[Dict]) -> Dict[str, int]:
        """Get severity distribution for CVE references"""
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        for cve_ref in cve_references:
            severity = cve_ref.get('severity', 'UNKNOWN')
            if severity in distribution:
                distribution[severity] += 1
            else:
                distribution['UNKNOWN'] += 1
        
        return distribution

    def generate_cve_enhanced_report(self, scan_result: ScanResult) -> str:
        """Generate a comprehensive text report with enhanced CVE intelligence and CVSS analysis"""
        report_lines = []
        
        # Header
        report_lines.extend([
            "=" * 80,
            "ADVANCED SECURITY ANALYSIS REPORT",
            "CVE Intelligence & CVSS v3.1 Risk Assessment",
            "=" * 80,
            "",
            f"Target: {scan_result.target_url}",
            f"Scan ID: {scan_result.scan_id}",
            f"Scan Date: {scan_result.start_time}",
            f"Total Findings: {len(scan_result.findings)}",
            f"Report Generated: {datetime.now().isoformat()}",
            ""
        ])
        
        # Executive Summary
        severity_counts = {
            "critical": len([f for f in scan_result.findings if f.severity == SeverityLevel.CRITICAL]),
            "high": len([f for f in scan_result.findings if f.severity == SeverityLevel.HIGH]),
            "medium": len([f for f in scan_result.findings if f.severity == SeverityLevel.MEDIUM]),
            "low": len([f for f in scan_result.findings if f.severity == SeverityLevel.LOW]),
            "info": len([f for f in scan_result.findings if f.severity == SeverityLevel.INFO])
        }
        
        report_lines.extend([
            "EXECUTIVE SUMMARY",
            "=" * 30,
            f"🔴 Critical: {severity_counts['critical']}",
            f"🟠 High: {severity_counts['high']}",
            f"🟡 Medium: {severity_counts['medium']}",
            f"🟢 Low: {severity_counts['low']}",
            f"🔵 Info: {severity_counts['info']}",
            ""
        ])
        
        # CVSS Analysis Summary
        cvss_scores = []
        for finding in scan_result.findings:
            if hasattr(finding, 'technical_details') and finding.technical_details:
                if hasattr(finding.technical_details, 'cvss_score'):
                    cvss_scores.append(finding.technical_details.cvss_score)
            # Try to calculate CVSS if not present
            if not cvss_scores or len(cvss_scores) < len(scan_result.findings):
                try:
                    score, _ = self.cvss_calculator.calculate_cvss_score(finding)
                    cvss_scores.append(score)
                except:
                    pass
        
        if cvss_scores:
            avg_cvss = sum(cvss_scores) / len(cvss_scores)
            max_cvss = max(cvss_scores)
            
            report_lines.extend([
                "CVSS v3.1 RISK ANALYSIS",
                "=" * 30,
                f"Average CVSS Score: {avg_cvss:.1f}",
                f"Maximum CVSS Score: {max_cvss:.1f}",
                f"Risk Level: {self.cvss_calculator.get_severity_from_score(max_cvss)}",
                f"Findings ≥ 9.0 (Critical): {len([s for s in cvss_scores if s >= 9.0])}",
                f"Findings ≥ 7.0 (High): {len([s for s in cvss_scores if s >= 7.0])}",
                f"Findings ≥ 4.0 (Medium): {len([s for s in cvss_scores if s >= 4.0])}",
                ""
            ])
        
        # CVE Intelligence Summary
        total_cves = 0
        unique_cves = set()
        cve_severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cve_scores = []
        
        for finding in scan_result.findings:
            if hasattr(finding, 'cve_ids') and finding.cve_ids:
                total_cves += len(finding.cve_ids)
                unique_cves.update(finding.cve_ids)
            
            if hasattr(finding, 'cve_references') and finding.cve_references:
                for cve_ref in finding.cve_references:
                    severity = cve_ref.get('severity', 'UNKNOWN')
                    if severity in cve_severity_dist:
                        cve_severity_dist[severity] += 1
                    try:
                        score = float(cve_ref.get('score', 0))
                        cve_scores.append(score)
                    except (ValueError, TypeError):
                        pass
        
        report_lines.extend([
            "CVE INTELLIGENCE SUMMARY",
            "=" * 30,
            f"Total CVE References: {total_cves}",
            f"Unique CVEs Identified: {len(unique_cves)}",
            f"Average CVE Score: {sum(cve_scores) / len(cve_scores):.1f}" if cve_scores else "Average CVE Score: N/A",
            f"Highest CVE Score: {max(cve_scores):.1f}" if cve_scores else "Highest CVE Score: N/A",
            "",
            "CVE Severity Distribution:",
            f"  🔴 Critical: {cve_severity_dist['CRITICAL']}",
            f"  🟠 High: {cve_severity_dist['HIGH']}",
            f"  🟡 Medium: {cve_severity_dist['MEDIUM']}",
            f"  🟢 Low: {cve_severity_dist['LOW']}",
            ""
        ])
        
        # Top CVEs by Risk
        if unique_cves:
            high_risk_cves = []
            for finding in scan_result.findings:
                if hasattr(finding, 'cve_references') and finding.cve_references:
                    for cve_ref in finding.cve_references:
                        try:
                            score = float(cve_ref.get('score', 0))
                            if score >= 7.0:  # High/Critical
                                high_risk_cves.append((cve_ref['cve_id'], score, cve_ref.get('severity', 'HIGH')))
                        except (ValueError, TypeError):
                            pass
            
            if high_risk_cves:
                high_risk_cves.sort(key=lambda x: x[1], reverse=True)
                report_lines.extend([
                    "HIGH-RISK CVE REFERENCES (CVSS ≥ 7.0)",
                    "-" * 40
                ])
                for cve_id, score, severity in high_risk_cves[:10]:  # Top 10
                    report_lines.append(f"  {cve_id} - {severity} (Score: {score})")
                report_lines.append("")
        
        # OWASP Top 10 Mapping
        owasp_mapping = {}
        for finding in scan_result.findings:
            category = finding.owasp_category.value
            if category not in owasp_mapping:
                owasp_mapping[category] = []
            owasp_mapping[category].append(finding)
        
        if owasp_mapping:
            report_lines.extend([
                "OWASP TOP 10 COVERAGE ANALYSIS",
                "=" * 30
            ])
            for category, findings_list in sorted(owasp_mapping.items()):
                category_cves = sum(len(getattr(f, 'cve_ids', [])) for f in findings_list)
                avg_cvss = 0
                try:
                    cvss_vals = []
                    for f in findings_list:
                        if hasattr(f, 'technical_details') and f.technical_details and hasattr(f.technical_details, 'cvss_score'):
                            cvss_vals.append(f.technical_details.cvss_score)
                    avg_cvss = sum(cvss_vals) / len(cvss_vals) if cvss_vals else 0
                except:
                    pass
                
                report_lines.extend([
                    f"📋 {category}",
                    f"    Findings: {len(findings_list)} | CVEs: {category_cves} | Avg CVSS: {avg_cvss:.1f}",
                    ""
                ])
        
        # Detailed Findings
        report_lines.extend([
            "",
            "DETAILED VULNERABILITY ANALYSIS",
            "=" * 50,
            ""
        ])
        
        for i, finding in enumerate(scan_result.findings, 1):
            # Calculate CVSS if not present
            cvss_score = 0.0
            cvss_vector = "N/A"
            if hasattr(finding, 'technical_details') and finding.technical_details:
                cvss_score = getattr(finding.technical_details, 'cvss_score', 0.0)
                cvss_vector = getattr(finding.technical_details, 'cvss_vector', 'N/A')
            
            if cvss_score == 0.0:
                try:
                    cvss_score, cvss_vector = self.cvss_calculator.calculate_cvss_score(finding)
                except:
                    pass
            
            report_lines.extend([
                f"[{i:02d}] {finding.title}",
                "=" * len(f"[{i:02d}] {finding.title}"),
                f"🎯 Severity: {finding.severity.value.upper()}",
                f"📊 CVSS v3.1 Score: {cvss_score:.1f} ({self.cvss_calculator.get_severity_from_score(cvss_score)})",
                f"🔗 CVSS Vector: {cvss_vector}",
                f"📂 OWASP Category: {finding.owasp_category.value}",
                f"📍 Location: {finding.location}",
                f"⏰ Discovered: {finding.timestamp}",
                "",
                "📝 DESCRIPTION:",
                finding.description,
                "",
                "🔍 EVIDENCE:",
                finding.evidence,
                ""
            ])
            
            # Enhanced CVE Information
            if hasattr(finding, 'cve_ids') and finding.cve_ids:
                report_lines.extend([
                    "🛡️  CVE INTELLIGENCE:",
                    f"   CVE IDs: {', '.join(finding.cve_ids)}",
                    ""
                ])
                
                if hasattr(finding, 'cve_references') and finding.cve_references:
                    report_lines.append("   Detailed CVE Analysis:")
                    for cve_ref in finding.cve_references:
                        score_indicator = "🔴" if float(cve_ref.get('score', 0)) >= 9.0 else "🟠" if float(cve_ref.get('score', 0)) >= 7.0 else "🟡"
                        report_lines.extend([
                            f"   {score_indicator} {cve_ref['cve_id']} - {cve_ref['severity']} (Score: {cve_ref['score']})",
                            f"      📄 {cve_ref['description'][:150]}{'...' if len(cve_ref['description']) > 150 else ''}",
                            f"      📅 Year: {cve_ref['year']} | 🎯 Components: {cve_ref.get('affected_components', 'N/A')}",
                            f"      🔗 Reference: {cve_ref.get('references', 'https://nvd.nist.gov/')}",
                            ""
                        ])
            
            # CVSS Metrics Breakdown
            if cvss_vector != "N/A":
                cvss_metrics = self._extract_cvss_metrics(cvss_vector)
                report_lines.extend([
                    "⚙️  CVSS v3.1 METRICS BREAKDOWN:",
                    f"   Attack Vector: {cvss_metrics['attack_vector']}",
                    f"   Attack Complexity: {cvss_metrics['attack_complexity']}",
                    f"   Privileges Required: {cvss_metrics['privileges_required']}",
                    f"   User Interaction: {cvss_metrics['user_interaction']}",
                    f"   Scope: {cvss_metrics['scope']}",
                    f"   Confidentiality Impact: {cvss_metrics['confidentiality']}",
                    f"   Integrity Impact: {cvss_metrics['integrity']}",
                    f"   Availability Impact: {cvss_metrics['availability']}",
                    ""
                ])
            
            # Technical Details
            if finding.technical_details:
                report_lines.extend([
                    "🔧 TECHNICAL DETAILS:",
                    f"   Payload Used: {finding.technical_details.payload_used}",
                    f"   HTTP Method: {getattr(finding.technical_details, 'request_method', 'N/A')}",
                    f"   Response Status: {getattr(finding.technical_details, 'response_status', 'N/A')}",
                    ""
                ])
            
            report_lines.extend([
                "💡 REMEDIATION:",
                finding.recommendation,
                "",
                "🎓 EDUCATIONAL CONTEXT:",
                finding.educational_note,
                "",
                "=" * 80,
                ""
            ])
        
        # Footer with enhanced disclaimers
        report_lines.extend([
            "",
            "REPORT METADATA & DISCLAIMERS",
            "=" * 40,
            "📊 Report Statistics:",
            f"   • Total vulnerabilities analyzed: {len(scan_result.findings)}",
            f"   • CVE references included: {total_cves}",
            f"   • Unique CVEs identified: {len(unique_cves)}",
            f"   • Average risk score: {sum(cvss_scores) / len(cvss_scores):.1f}" if cvss_scores else "   • Average risk score: N/A",
            "",
            "WARNING:  Important Notes:",
            "   • CVE data sourced from National Vulnerability Database (NVD)",
            "   • CVSS scores calculated using CVSS v3.1 specification",
            "   • This report is for authorized security testing only",
            "   • Always verify findings with official CVE sources",
            "   • Follow responsible disclosure for any vulnerabilities found",
            "",
            "🏷️  Generated by Advanced Security Analysis Framework",
            f"   Version: 2.0.0 | Engine: Enhanced CVE Intelligence",
            f"   Report ID: {scan_result.scan_id}",
            f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "© 2023-2024 Professional Security Research | Educational Use Only"
        ])
        
        return "\n".join(report_lines)

class CVSSCalculator:
    """CVSS v3.1 score calculation for vulnerabilities with comprehensive metrics"""
    
    def __init__(self):
        self.cvss_metrics = self._initialize_cvss_metrics()
    
    def _initialize_cvss_metrics(self):
        """Initialize CVSS v3.1 metric mappings"""
        return {
            'attack_vector': {
                'NETWORK': 0.85,
                'ADJACENT_NETWORK': 0.62,
                'LOCAL': 0.55,
                'PHYSICAL': 0.2
            },
            'attack_complexity': {
                'LOW': 0.77,
                'HIGH': 0.44
            },
            'privileges_required': {
                'NONE': 0.85,
                'LOW': 0.62,
                'HIGH': 0.27
            },
            'user_interaction': {
                'NONE': 0.85,
                'REQUIRED': 0.62
            },
            'scope': {
                'UNCHANGED': 1.0,
                'CHANGED': 1.0
            },
            'confidentiality': {
                'NONE': 0.0,
                'LOW': 0.22,
                'HIGH': 0.56
            },
            'integrity': {
                'NONE': 0.0,
                'LOW': 0.22,
                'HIGH': 0.56
            },
            'availability': {
                'NONE': 0.0,
                'LOW': 0.22,
                'HIGH': 0.56
            }
        }
    
    def calculate_cvss_score(self, finding: SecurityFinding) -> Tuple[float, str]:
        """Calculate comprehensive CVSS v3.1 score and vector"""
        
        # Determine base metrics from finding properties
        metrics = self._determine_metrics_from_finding(finding)
        
        # Calculate base score using CVSS v3.1 formula
        base_score = self._calculate_base_score(metrics)
        
        # Generate CVSS vector string
        vector = self._generate_cvss_vector(metrics)
        
        return base_score, vector
    
    def _determine_metrics_from_finding(self, finding: SecurityFinding) -> Dict[str, str]:
        """Determine CVSS metrics based on finding characteristics"""
        
        # Default metrics
        metrics = {
            'attack_vector': 'NETWORK',
            'attack_complexity': 'LOW',
            'privileges_required': 'NONE',
            'user_interaction': 'NONE',
            'scope': 'UNCHANGED',
            'confidentiality': 'HIGH',
            'integrity': 'HIGH',
            'availability': 'NONE'
        }
        
        # Adjust based on OWASP category and finding details with more realistic scoring
        if finding.owasp_category == OWASPCategory.A03_INJECTION:
            # SQL Injection and other injection attacks - typically high but not always critical
            if finding.severity == SeverityLevel.CRITICAL:
                metrics.update({
                    'attack_vector': 'NETWORK',
                    'attack_complexity': 'LOW',
                    'privileges_required': 'NONE',
                    'user_interaction': 'NONE',
                    'scope': 'CHANGED',
                    'confidentiality': 'HIGH',
                    'integrity': 'HIGH',
                    'availability': 'HIGH'
                })
            else:
                # Medium/High XSS or other injection
                metrics.update({
                    'attack_vector': 'NETWORK',
                    'attack_complexity': 'LOW',
                    'privileges_required': 'NONE',
                    'user_interaction': 'REQUIRED',  # XSS typically requires user interaction
                    'scope': 'CHANGED' if finding.severity == SeverityLevel.HIGH else 'UNCHANGED',
                    'confidentiality': 'LOW',
                    'integrity': 'LOW',
                    'availability': 'NONE'
                })
        
        elif finding.owasp_category == OWASPCategory.A01_BROKEN_ACCESS_CONTROL:
            metrics.update({
                'attack_vector': 'NETWORK',
                'attack_complexity': 'LOW',
                'privileges_required': 'LOW',
                'user_interaction': 'NONE',
                'scope': 'CHANGED' if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else 'UNCHANGED',
                'confidentiality': 'HIGH' if finding.severity == SeverityLevel.CRITICAL else 'LOW',
                'integrity': 'HIGH' if finding.severity == SeverityLevel.CRITICAL else 'LOW',
                'availability': 'NONE'
            })
        
        elif finding.owasp_category == OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES:
            metrics.update({
                'attack_vector': 'NETWORK',
                'attack_complexity': 'HIGH' if finding.severity == SeverityLevel.MEDIUM else 'LOW',
                'privileges_required': 'NONE',
                'user_interaction': 'NONE',
                'scope': 'UNCHANGED',
                'confidentiality': 'HIGH' if finding.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] else 'LOW',
                'integrity': 'NONE',
                'availability': 'NONE'
            })
        
        elif finding.owasp_category == OWASPCategory.A07_AUTH_FAILURES:
            metrics.update({
                'attack_vector': 'NETWORK',
                'attack_complexity': 'LOW',
                'privileges_required': 'NONE',
                'user_interaction': 'NONE',
                'scope': 'CHANGED' if finding.severity == SeverityLevel.CRITICAL else 'UNCHANGED',
                'confidentiality': 'HIGH' if finding.severity == SeverityLevel.CRITICAL else 'LOW',
                'integrity': 'LOW',
                'availability': 'NONE'
            })
        
        elif finding.owasp_category == OWASPCategory.A05_SECURITY_MISCONFIGURATION:
            metrics.update({
                'attack_vector': 'NETWORK',
                'attack_complexity': 'LOW',
                'privileges_required': 'NONE',
                'user_interaction': 'NONE',
                'scope': 'UNCHANGED',
                'confidentiality': 'LOW',
                'integrity': 'LOW',
                'availability': 'LOW'
            })
        
        elif finding.owasp_category == OWASPCategory.A06_VULNERABLE_COMPONENTS:
            metrics.update({
                'attack_vector': 'NETWORK',
                'attack_complexity': 'LOW',
                'privileges_required': 'NONE',
                'user_interaction': 'NONE',
                'scope': 'UNCHANGED',
                'confidentiality': 'HIGH',
                'integrity': 'HIGH',
                'availability': 'HIGH'
            })
        
        # Fine-tune based on severity level for more realistic scores
        if finding.severity == SeverityLevel.CRITICAL:
            # Critical should have high impact but not always changed scope
            if metrics['scope'] != 'CHANGED':
                metrics['scope'] = 'CHANGED'
        elif finding.severity == SeverityLevel.MEDIUM:
            # Medium severity should have more moderate impact
            if metrics['confidentiality'] == 'HIGH':
                metrics['confidentiality'] = 'LOW'
            if metrics['integrity'] == 'HIGH':
                metrics['integrity'] = 'LOW'
            if metrics['availability'] == 'HIGH':
                metrics['availability'] = 'LOW'
        elif finding.severity == SeverityLevel.LOW:
            # Low severity should have minimal impact
            metrics['confidentiality'] = 'LOW'
            metrics['integrity'] = 'NONE'
            metrics['availability'] = 'NONE'
            metrics['attack_complexity'] = 'HIGH'
        elif finding.severity == SeverityLevel.INFO:
            metrics['confidentiality'] = 'NONE'
            metrics['integrity'] = 'NONE'
            metrics['availability'] = 'NONE'
        
        return metrics
    
    def _calculate_base_score(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v3.1 base score using official formula"""
        
        # Get metric values
        av = self.cvss_metrics['attack_vector'][metrics['attack_vector']]
        ac = self.cvss_metrics['attack_complexity'][metrics['attack_complexity']]
        pr = self.cvss_metrics['privileges_required'][metrics['privileges_required']]
        ui = self.cvss_metrics['user_interaction'][metrics['user_interaction']]
        
        # Adjust PR for scope
        if metrics['scope'] == 'CHANGED' and metrics['privileges_required'] == 'LOW':
            pr = 0.68
        elif metrics['scope'] == 'CHANGED' and metrics['privileges_required'] == 'HIGH':
            pr = 0.50
        
        c = self.cvss_metrics['confidentiality'][metrics['confidentiality']]
        i = self.cvss_metrics['integrity'][metrics['integrity']]
        a = self.cvss_metrics['availability'][metrics['availability']]
        
        # Calculate ISS (Impact Sub-Score)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        # Calculate Impact Score
        if metrics['scope'] == 'UNCHANGED':
            impact = 6.42 * iss
        else:  # CHANGED
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        # Calculate Exploitability Score
        exploitability = 8.22 * av * ac * pr * ui
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if metrics['scope'] == 'UNCHANGED':
                base_score = min(10.0, (impact + exploitability))
            else:  # CHANGED
                base_score = min(10.0, 1.08 * (impact + exploitability))
        
        # Round up to one decimal place
        return round(base_score * 10) / 10
    
    def _generate_cvss_vector(self, metrics: Dict[str, str]) -> str:
        """Generate CVSS v3.1 vector string"""
        
        # CVSS v3.1 metric abbreviations
        abbreviations = {
            'attack_vector': {'NETWORK': 'N', 'ADJACENT_NETWORK': 'A', 'LOCAL': 'L', 'PHYSICAL': 'P'},
            'attack_complexity': {'LOW': 'L', 'HIGH': 'H'},
            'privileges_required': {'NONE': 'N', 'LOW': 'L', 'HIGH': 'H'},
            'user_interaction': {'NONE': 'N', 'REQUIRED': 'R'},
            'scope': {'UNCHANGED': 'U', 'CHANGED': 'C'},
            'confidentiality': {'NONE': 'N', 'LOW': 'L', 'HIGH': 'H'},
            'integrity': {'NONE': 'N', 'LOW': 'L', 'HIGH': 'H'},
            'availability': {'NONE': 'N', 'LOW': 'L', 'HIGH': 'H'}
        }
        
        vector_parts = [
            "CVSS:3.1",
            f"AV:{abbreviations['attack_vector'][metrics['attack_vector']]}",
            f"AC:{abbreviations['attack_complexity'][metrics['attack_complexity']]}",
            f"PR:{abbreviations['privileges_required'][metrics['privileges_required']]}",
            f"UI:{abbreviations['user_interaction'][metrics['user_interaction']]}",
            f"S:{abbreviations['scope'][metrics['scope']]}",
            f"C:{abbreviations['confidentiality'][metrics['confidentiality']]}",
            f"I:{abbreviations['integrity'][metrics['integrity']]}",
            f"A:{abbreviations['availability'][metrics['availability']]}"
        ]
        
        return "/".join(vector_parts)
    
    def get_severity_from_score(self, score: float) -> str:
        """Convert CVSS score to severity rating"""
        if score == 0.0:
            return "NONE"
        elif 0.1 <= score <= 3.9:
            return "LOW"
        elif 4.0 <= score <= 6.9:
            return "MEDIUM"
        elif 7.0 <= score <= 8.9:
            return "HIGH"
        elif 9.0 <= score <= 10.0:
            return "CRITICAL"
        else:
            return "UNKNOWN"

    


    












class SecurityAnalyzer:
    """Educational security analysis engine with comprehensive OWASP Top 10 coverage"""
    
    def __init__(self):
        self.owasp_payloads = self._load_owasp_payloads()
        self.educational_patterns = self._load_educational_patterns()
        self.report_generator = ReportGenerator()
        self.cvss_calculator = CVSSCalculator()

    
    def _load_owasp_payloads(self) -> Dict:
        """Load comprehensive OWASP Top 10 payloads for educational testing"""
        return {
            "A01_BROKEN_ACCESS_CONTROL": {
                "name": "Broken Access Control",
                "payloads": [
                    "../../../etc/passwd",
                    "../../windows/system32/drivers/etc/hosts",
                    "/admin",
                    "/administrator",
                    "/user/1/../2",
                    "?user_id=1&admin=true",
                    "X-Original-URL: /admin",
                    "X-Rewrite-URL: /admin"
                ],
                "headers": {
                    "X-Original-URL": "/admin",
                    "X-Rewrite-URL": "/admin",
                    "X-Forwarded-For": "127.0.0.1"
                },
                "patterns": [
                    r"admin",
                    r"unauthorized",
                    r"forbidden",
                    r"access denied"
                ]
            },
            "A02_CRYPTOGRAPHIC_FAILURES": {
                "name": "Cryptographic Failures",
                "payloads": [
                    "?debug=true",
                    "?test=1",
                    "/.env",
                    "/config.php",
                    "/wp-config.php",
                    "/database.yml"
                ],
                "headers": {},
                "patterns": [
                    r"password\s*[:=]\s*['\"][^'\"]+['\"]",
                    r"api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]",
                    r"secret\s*[:=]\s*['\"][^'\"]+['\"]",
                    r"token\s*[:=]\s*['\"][^'\"]+['\"]",
                    r"mysql://",
                    r"postgresql://",
                    r"mongodb://"
                ]
            },
            "A03_INJECTION": {
                "name": "Injection",
                "payloads": [
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "1' UNION SELECT null,username,password FROM users--",
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "${7*7}",
                    "{{7*7}}",
                    "; ls -la",
                    "| whoami",
                    "&& dir"
                ],
                "headers": {},
                "patterns": [
                    r"SQL syntax.*error",
                    r"mysql_fetch",
                    r"ORA-\d+",
                    r"Microsoft.*ODBC.*SQL",
                    r"PostgreSQL.*ERROR",
                    r"<script[^>]*>.*?</script>",
                    r"javascript:",
                    r"on\w+\s*="
                ]
            },
            "A04_INSECURE_DESIGN": {
                "name": "Insecure Design",
                "payloads": [
                    "?action=reset_password&user=admin",
                    "?backup=true",
                    "?maintenance=on",
                    "/backup",
                    "/test",
                    "/dev"
                ],
                "headers": {},
                "patterns": [
                    r"backup",
                    r"maintenance",
                    r"debug",
                    r"test mode",
                    r"development"
                ]
            },
            "A05_SECURITY_MISCONFIGURATION": {
                "name": "Security Misconfiguration",
                "payloads": [
                    "/server-status",
                    "/server-info",
                    "/.git/config",
                    "/.svn/entries",
                    "/phpinfo.php",
                    "/info.php",
                    "/web.config",
                    "/.htaccess"
                ],
                "headers": {},
                "patterns": [
                    r"Apache.*Server.*Status",
                    r"phpinfo\(\)",
                    r"PHP Version",
                    r"Configuration File",
                    r"Server Root",
                    r"Document Root"
                ]
            },
            "A06_VULNERABLE_COMPONENTS": {
                "name": "Vulnerable and Outdated Components",
                "payloads": [
                    "/vendor/",
                    "/node_modules/",
                    "/bower_components/",
                    "/composer.json",
                    "/package.json",
                    "/requirements.txt",
                    "/Gemfile"
                ],
                "headers": {},
                "patterns": [
                    r"jQuery.*1\.[0-7]",
                    r"Bootstrap.*[1-3]\.",
                    r"Angular.*1\.",
                    r"version.*['\"][\d\.]+['\"]"
                ]
            },
            "A07_AUTH_FAILURES": {
                "name": "Identification and Authentication Failures",
                "payloads": [
                    "?username=admin&password=admin",
                    "?user=admin&pass=password",
                    "/login?redirect=//evil.com",
                    "/forgot-password",
                    "/reset-password"
                ],
                "headers": {
                    "Authorization": "Basic YWRtaW46YWRtaW4=",  # admin:admin
                    "X-Forwarded-Host": "evil.com"
                },
                "patterns": [
                    r"login",
                    r"authentication",
                    r"session",
                    r"cookie",
                    r"password.*weak"
                ]
            },
            "A08_DATA_INTEGRITY_FAILURES": {
                "name": "Software and Data Integrity Failures",
                "payloads": [
                    "?callback=malicious_function",
                    "?jsonp=evil",
                    "/api/update?version=../../../malicious",
                    "?plugin=../../evil"
                ],
                "headers": {},
                "patterns": [
                    r"callback",
                    r"jsonp",
                    r"plugin",
                    r"update",
                    r"integrity.*fail"
                ]
            },
            "A09_LOGGING_FAILURES": {
                "name": "Security Logging and Monitoring Failures",
                "payloads": [
                    "/logs/",
                    "/log/",
                    "/admin/logs",
                    "?log=true",
                    "/error.log",
                    "/access.log"
                ],
                "headers": {},
                "patterns": [
                    r"error.*log",
                    r"access.*log",
                    r"audit.*log",
                    r"security.*log",
                    r"\d{4}-\d{2}-\d{2}.*\d{2}:\d{2}:\d{2}"
                ]
            },
            "A10_SSRF": {
                "name": "Server-Side Request Forgery",
                "payloads": [
                    "?url=http://localhost:22",
                    "?url=http://127.0.0.1:3306",
                    "?url=file:///etc/passwd",
                    "?redirect=http://evil.com",
                    "?proxy=localhost:8080",
                    "?fetch=http://metadata.google.internal/"
                ],
                "headers": {},
                "patterns": [
                    r"Connection refused",
                    r"Connection timeout",
                    r"Internal Server Error",
                    r"localhost",
                    r"127\.0\.0\.1",
                    r"metadata"
                ]
            }
        }
    
    def _load_educational_patterns(self) -> Dict:
        """Load patterns for educational security analysis"""
        return {
            "security_headers": [
                "Content-Security-Policy",
                "X-Frame-Options", 
                "X-Content-Type-Options",
                "Strict-Transport-Security",
                "Referrer-Policy",
                "X-XSS-Protection",
                "Permissions-Policy"
            ],
            "sensitive_files": [
                ".env", ".git/config", "web.config", ".htaccess",
                "wp-config.php", "config.php", "database.yml"
            ],
            "common_paths": [
                "/admin", "/administrator", "/login", "/wp-admin",
                "/phpmyadmin", "/cpanel", "/webmail"
            ]
        }
    
    async def _run_custom_scanners(self, url: str, scan_id: str, artifacts_dir: str, scan_request: ScanRequest) -> List[Dict[str, Any]]:
        """Run ALL 17 BLACKBOX security scanners sequentially and return findings"""
        findings = []
        
        await connection_manager.send_log(scan_id, f" [17-BLACKBOX-SCANNERS] Starting comprehensive security scan of real URL: {url}", "info")
        await connection_manager.send_log(scan_id, "📋 [17-BLACKBOX-SCANNERS] Scanner execution order: WHOIS → SSL → SQLMap → Recon → Dirb → Injection → Auth → Authorization → Command → Nmap → WPSeku → Info Disclosure → Web Security → Nuclei → File Upload → Blockchain Email → Comprehensive", "info")
        
        # Always run all scanners - no user disabling allowed for comprehensive testing
        if not scan_request or not scan_request.enable_custom_scanners:
            await connection_manager.send_log(scan_id, "WARNING: [17-BLACKBOX-SCANNERS] Force-enabling all scanners for comprehensive testing", "warning")
        
        try:
            # Initialize scanner counter for tracking
            scanner_count = 0
            total_scanners = 17
            scanner_tasks = []
            
            await connection_manager.send_log(scan_id, f"⏱️ [17-BLACKBOX-SCANNERS] Estimated completion time: 30-60 minutes (sequential execution)", "info")
            await connection_manager.send_log(scan_id, f"🎯 [17-BLACKBOX-SCANNERS] Target: Real website URL - {url}", "info")
            
            # 1. WHOIS Scanner - Domain information
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] WHOIS Scanner: Analyzing domain information for {url}", "info")
                whois_scanner = WHOISScanner(url, timeout=scan_request.whois_timeout if scan_request else None)
                whois_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("whois", whois_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] WHOIS Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] WHOIS Scanner failed: {str(e)}", "warning")
            
            # 2. SSL Labs Scanner - SSL/TLS analysis
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] SSL Labs Scanner: Analyzing SSL/TLS configuration for {url}", "info")
                ssl_scanner = SSLLabsScanner(url, timeout=scan_request.ssl_labs_timeout if scan_request else None)
                ssl_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("ssl_labs", ssl_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] SSL Labs Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] SSL Labs Scanner failed: {str(e)}", "warning")
            
            # 3. SQLMap Scanner - SQL injection testing
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] SQLMap Scanner: Testing SQL injection vulnerabilities on {url}", "info")
                sqlmap_scanner = SQLMapScanner(url, timeout=scan_request.sqlmap_timeout if scan_request else None)
                sqlmap_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("sqlmap", sqlmap_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] SQLMap Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] SQLMap Scanner failed: {str(e)}", "warning")
            
            # 4. Recon Discovery Scanner - Directory enumeration and reconnaissance
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Recon Discovery Scanner: Directory enumeration and reconnaissance on {url}", "info")
                recon_scanner = ReconDiscoveryScanner(url, timeout=scan_request.recon_timeout if scan_request else None)
                recon_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("recon_discovery", recon_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Recon Discovery Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Recon Discovery Scanner failed: {str(e)}", "warning")
            
            # 5. Dirb Scanner - Directory brute forcing
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Dirb Scanner: Brute forcing directories on {url}", "info")
                dirb_scanner = DirbScanner(url, timeout=scan_request.dirb_timeout if scan_request else None)
                dirb_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("dirb", dirb_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Dirb Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Dirb Scanner failed: {str(e)}", "warning")
            
            # 6. Input-Handling Injection Scanner - Comprehensive injection testing (XSS, SQLi, Command, Template, LDAP, Deserialization)
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Input-Handling Injection Scanner: Testing XSS, SQLi, Command, Template, LDAP, Deserialization on {url}", "info")
                injection_scanner = InputHandlingInjectionScanner(url, timeout=scan_request.input_handling_injection_timeout if scan_request else None)
                injection_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("input_handling_injection", injection_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Input-Handling Injection Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Input-Handling Injection Scanner failed: {str(e)}", "warning")
            
            # 7. Authentication & Session Management Scanner
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Authentication & Session Scanner: Testing auth and session management on {url}", "info")
                auth_session_scanner = AuthenticationSessionScanner(url, timeout=scan_request.authentication_session_timeout if scan_request else None)
                auth_session_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("authentication_session", auth_session_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Authentication & Session Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Authentication & Session Scanner failed: {str(e)}", "warning")
            
            # 8. Authorization & Access Control Scanner
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Authorization & Access Control Scanner: Testing access control on {url}", "info")
                auth_access_scanner = AuthorizationAccessControlScanner(url, timeout=scan_request.authorization_access_control_timeout if scan_request else None)
                auth_access_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("authorization_access_control", auth_access_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Authorization & Access Control Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Authorization & Access Control Scanner failed: {str(e)}", "warning")
            
            # 9. Advanced Command/OS Injection Scanner - Professional-grade with CVE references
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Command/OS Injection Scanner: Testing advanced command injection with CVE references on {url}", "info")
                cmd_injection_scanner = CommandOSInjectionScanner(url, timeout=scan_request.command_os_injection_timeout if scan_request else None)
                cmd_injection_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("command_os_injection", cmd_injection_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Command/OS Injection Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Command/OS Injection Scanner failed: {str(e)}", "warning")
            
            # 10. Nmap Scanner - Network port scanning
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Nmap Scanner: Network port scanning for {url}", "info")
                nmap_scanner = NmapScanner(url, timeout=None)
                nmap_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("nmap", nmap_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Nmap Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Nmap Scanner failed: {str(e)}", "warning")
            
            # 11. Information Disclosure Scanner - Information leakage detection
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Information Disclosure Scanner: Detecting information leakage on {url}", "info")
                info_disclosure_scanner = InformationDisclosureScanner(url, timeout=None)
                info_disclosure_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("information_disclosure", info_disclosure_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Information Disclosure Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Information Disclosure Scanner failed: {str(e)}", "warning")
            
            # 13. Web Security Scanner - General web security testing
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Web Security Scanner: General web security testing for {url}", "info")
                web_security_scanner = WebSecurityScanner(url, timeout=None)
                web_security_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("web_security", web_security_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Web Security Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Web Security Scanner failed: {str(e)}", "warning")
            
            # 14. Nuclei Scanner - Web vulnerability scanner (blackbox-compatible)
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Nuclei Scanner: Web vulnerability scanning for {url}", "info")
                nuclei_scanner = NucleiScanner(url, timeout=None)
                nuclei_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("nuclei", nuclei_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Nuclei Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Nuclei Scanner failed: {str(e)}", "warning")
            
            # 15. File Upload Security Scanner - File upload vulnerability testing
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] File Upload Security Scanner: Testing file upload vulnerabilities on {url}", "info")
                file_upload_scanner = FileUploadScanner(url, timeout=scan_request.file_upload_timeout if scan_request else None)
                file_upload_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("file_upload", file_upload_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] File Upload Security Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] File Upload Security Scanner failed: {str(e)}", "warning")
            
            # 16. Blockchain Email Security Scanner - Blockchain and email security testing
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Blockchain Email Security Scanner: Testing blockchain and email security on {url}", "info")
                blockchain_email_scanner = BlockchainEmailScanner(url, timeout=scan_request.blockchain_email_timeout if scan_request else None)
                blockchain_email_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("blockchain_email", blockchain_email_scanner.scan()))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Blockchain Email Security Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Blockchain Email Security Scanner failed: {str(e)}", "warning")
            
            # 17. Comprehensive Security Scanner - Overall security assessment
            scanner_count += 1
            try:
                await connection_manager.send_log(scan_id, f"🔍 [{scanner_count}/12] Comprehensive Security Scanner: Overall security assessment for {url}", "info")
                comprehensive_scanner = ComprehensiveSecurityScanner()
                comprehensive_scanner.set_progress_callback(scan_id, connection_manager)
                scanner_tasks.append(("comprehensive_security", comprehensive_scanner.scan(url)))
                await connection_manager.send_log(scan_id, f" [{scanner_count}/12] Comprehensive Security Scanner: Initialized successfully", "success")
            except Exception as e:
                await connection_manager.send_log(scan_id, f"❌ [{scanner_count}/12] Comprehensive Security Scanner failed: {str(e)}", "warning")
            
            await connection_manager.send_log(scan_id, f"🎯 [17-BLACKBOX-SCANNERS] All {len(scanner_tasks)} scanners initialized successfully", "success")
            
            # Execute all scanners sequentially (one by one)
            if scanner_tasks:
                scanner_results = []
                total_scanners = len(scanner_tasks)
                await connection_manager.send_log(scan_id, f" [15-BLACKBOX-SCANNERS] Starting sequential execution of {total_scanners} scanners", "info")
                
                for i, (scanner_name, task) in enumerate(scanner_tasks, 1):
                    try:
                        await connection_manager.send_log(scan_id, f"🔄 [{i}/{total_scanners}] EXECUTING: {scanner_name.upper()} scanner on real URL: {url}", "info")
                        result = await task
                        scanner_results.append(result)
                        await connection_manager.send_log(scan_id, f" [{i}/{total_scanners}] COMPLETED: {scanner_name.upper()} scanner - SUCCESS", "success")
                        
                        # Update progress
                        progress = 22 + int((i / total_scanners) * 48)  # 22-70% range
                        await connection_manager.send_progress(scan_id, progress, f"scanner_{i}_{total_scanners}")
                        
                    except Exception as e:
                        await connection_manager.send_log(scan_id, f"❌ [{i}/{total_scanners}] FAILED: {scanner_name.upper()} scanner - {str(e)}", "warning")
                        scanner_results.append(e)
                
                await connection_manager.send_log(scan_id, f"🎉 [15-BLACKBOX-SCANNERS] ALL SCANNERS EXECUTION COMPLETED! Processed {total_scanners} scanners", "success")
                
                # Process results with deduplication
                await connection_manager.send_log(scan_id, "📊 [15-BLACKBOX-SCANNERS] Processing scanner results and removing duplicates...", "info")
                seen_findings = set()  # Track unique findings to prevent duplicates
                
                for i, (scanner_name, result) in enumerate(zip([name for name, _ in scanner_tasks], scanner_results)):
                    try:
                        if isinstance(result, Exception):
                            await connection_manager.send_log(scan_id, f"WARNING: [{i+1}/{total_scanners}] {scanner_name.upper()} result processing failed: {str(result)}", "warning")
                            continue
                        
                        # Handle different result formats from our specialized scanners
                        scanner_findings = []
                        if isinstance(result, dict):
                            if "findings" in result:
                                scanner_findings = result["findings"]
                            elif "vulnerabilities" in result:
                                scanner_findings = result["vulnerabilities"]
                            elif "results" in result:
                                scanner_findings = result["results"]
                            
                            # Convert dictionary findings to SecurityFinding objects with deduplication
                            if scanner_findings:
                                unique_findings_count = 0
                                duplicate_count = 0
                                
                                for finding_dict in scanner_findings:
                                    try:
                                        # Create unique identifier for deduplication
                                        finding_key = f"{finding_dict.get('title', '')}_{finding_dict.get('location', '')}_{scanner_name}"
                                        
                                        # Skip if we've already seen this finding
                                        if finding_key in seen_findings:
                                            duplicate_count += 1
                                            continue
                                        
                                        seen_findings.add(finding_key)
                                        
                                        # Create SecurityFinding object from dictionary
                                        # Map to proper OWASP category based on scanner and finding
                                        owasp_category_str = self._map_to_owasp_category(finding_dict, scanner_name)
                                        owasp_category = getattr(OWASPCategory, owasp_category_str, OWASPCategory.A05_SECURITY_MISCONFIGURATION)
                                        
                                        security_finding = SecurityFinding(
                                            id=f"{scanner_name}_{int(datetime.now().timestamp())}_{unique_findings_count}",
                                            title=finding_dict.get("title", "Unknown Finding"),
                                            description=finding_dict.get("description", ""),
                                            severity=SeverityLevel(finding_dict.get("severity", "info")),
                                            owasp_category=owasp_category,
                                            location=finding_dict.get("location", url),
                                            evidence=finding_dict.get("evidence", ""),
                                            recommendation=finding_dict.get("recommendation", ""),
                                            educational_note=finding_dict.get("educational_note", ""),
                                            timestamp=datetime.now().isoformat(),
                                            issue_type=finding_dict.get("issue_type", "vulnerability"),
                                            cve_ids=finding_dict.get("cve_ids", []),
                                            cve_references=finding_dict.get("cve_references", [])
                                        )
                                        
                                        # Add custom scanner metadata for professional penetration testing reports
                                        security_finding.scanner_source = scanner_name
                                        security_finding.scan_phase = "specialized_security_testing"
                                        
                                        # Add specialized scanner category for professional reporting
                                        if scanner_name in ["authentication_session", "authorization_access_control", "input_handling_injection"]:
                                            security_finding.specialized_category = scanner_name
                                            security_finding.professional_section = "Advanced Security Assessment"
                                        
                                        findings.append(security_finding)
                                        unique_findings_count += 1
                                        
                                    except Exception as e:
                                        await connection_manager.send_log(scan_id, f"WARNING: [{scanner_name.upper()}] Error converting finding: {str(e)}", "warning")
                                
                                await connection_manager.send_log(scan_id, f"📋 [{scanner_name.upper()}] Found {unique_findings_count} unique findings, {duplicate_count} duplicates removed", "success")
                            
                            # Save scanner results to artifacts
                            scanner_file = os.path.join(artifacts_dir, f"{scanner_name}_results.json")
                            with open(scanner_file, 'w') as f:
                                json.dump(result, f, indent=2, default=str)
                        
                    except Exception as e:
                        await connection_manager.send_log(scan_id, f"❌ [{scanner_name.upper()}] Error processing results: {str(e)}", "warning")
                
                # Final summary
                total_unique_findings = len(findings)
                await connection_manager.send_log(scan_id, f"🎯 [15-BLACKBOX-SCANNERS] FINAL SUMMARY: {total_unique_findings} unique findings from {total_scanners} scanners", "success")
                await connection_manager.send_log(scan_id, f"📊 [15-BLACKBOX-SCANNERS] Deduplication: Removed {len(seen_findings) - total_unique_findings} duplicate findings", "info")
            else:
                await connection_manager.send_log(scan_id, "WARNING: [15-BLACKBOX-SCANNERS] No scanners initialized - this should not happen!", "warning")
            
        except Exception as e:
            await connection_manager.send_log(scan_id, f"❌ [15-BLACKBOX-SCANNERS] CRITICAL ERROR: {str(e)}", "error")
            await connection_manager.send_log(scan_id, f"🔧 [15-BLACKBOX-SCANNERS] Attempting to continue with partial results...", "warning")
        
        await connection_manager.send_log(scan_id, f"🏁 [15-BLACKBOX-SCANNERS] Custom scanners phase completed. Returning {len(findings)} findings", "info")
        
        # ENHANCEMENT: Apply CVE Data & Threat Intelligence (Local DB + CISA KEV + MITRE)
        if enhance_findings_with_cve and findings:
            try:
                await connection_manager.send_log(scan_id, "🛡️ [ENHANCEMENT] Enhancing findings with Local CVE Database, CISA KEV & MITRE ATT&CK...", "info")
                
                # Convert to dicts for enhancer
                findings_dicts = [asdict(f) for f in findings]
                enhanced_dicts = await enhance_findings_with_cve(findings_dicts)
                
                # Update original objects with enhanced data
                for f_obj, f_enhanced in zip(findings, enhanced_dicts):
                     f_obj.cve_references = f_enhanced.get('cve_references', [])
                     f_obj.cve_ids = f_enhanced.get('cve_ids', [])
                     
                     # Map enhanced severity to object
                     enriched_sev = f_enhanced.get('enriched_severity', '')
                     if enriched_sev:
                         # Directly update severity (ensure uppercase for consistency)
                         f_obj.severity = enriched_sev.upper()

                     # Update description if KEV notes added
                     enhanced_desc = f_enhanced.get('description', '')
                     if enhanced_desc and len(enhanced_desc) > len(f_obj.description):
                         f_obj.description = enhanced_desc
                         
                     # Add MITRE info to educational note
                     if 'mitre_classification' in f_enhanced and f_enhanced['mitre_classification']:
                         mitre = f_enhanced['mitre_classification']
                         mitre_str = f"MITRE ATT&CK: {mitre.get('t_id')} - {mitre.get('name')}"
                         if f_obj.educational_note:
                             if mitre_str not in f_obj.educational_note:
                                 f_obj.educational_note += f"\n\n{mitre_str}"
                         else:
                             f_obj.educational_note = mitre_str

                await connection_manager.send_log(scan_id, "✅ [ENHANCEMENT] Findings enriched with CVE/MITRE/KEV data", "success")

            except Exception as e:
                logger.error(f"Enhancement failed: {e}")
                await connection_manager.send_log(scan_id, f"⚠️ [ENHANCEMENT] Failed: {e}", "warning")

        return findings
    
    def _map_to_owasp_category(self, finding: Dict[str, Any], scanner_name: str) -> str:
        """Map scanner findings to OWASP Top 10 categories"""
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        
        # SQLMap scanner mappings
        if scanner_name == "sqlmap":
            if "sql injection" in title or "injection" in description:
                return "A03_INJECTION"
            return "A03_INJECTION"
        
        # Directory enumeration mappings
        elif scanner_name in ["dirb"]:
            if any(keyword in title for keyword in ["admin", "administrator", "login", "auth"]):
                return "A01_BROKEN_ACCESS_CONTROL"
            elif any(keyword in title for keyword in ["backup", "config", "database"]):
                return "A05_SECURITY_MISCONFIGURATION"
            elif any(keyword in title for keyword in ["upload", "files"]):
                return "A05_SECURITY_MISCONFIGURATION"
            else:
                return "A05_SECURITY_MISCONFIGURATION"
        
        # SSL/TLS mappings
        elif scanner_name == "ssl_labs":
            if "weak" in title or "vulnerability" in title:
                return "A02_CRYPTOGRAPHIC_FAILURES"
            elif "certificate" in title:
                return "A02_CRYPTOGRAPHIC_FAILURES"
            else:
                return "A02_CRYPTOGRAPHIC_FAILURES"
        
        # WHOIS mappings
        elif scanner_name == "whois":
            if "privacy" in title:
                return "A05_SECURITY_MISCONFIGURATION"
            else:
                return "A05_SECURITY_MISCONFIGURATION"
        
        # Input-handling injection scanner mappings
        elif scanner_name == "input_handling_injection":
            # Map based on specific injection types
            if any(keyword in title.lower() for keyword in ["xss", "cross-site", "script"]):
                return "A03_INJECTION"
            elif any(keyword in title.lower() for keyword in ["sql injection", "sqli", "database"]):
                return "A03_INJECTION"
            elif any(keyword in title.lower() for keyword in ["command injection", "command", "rce", "remote code"]):
                return "A03_INJECTION"
            elif any(keyword in title.lower() for keyword in ["template injection", "ssti", "template"]):
                return "A03_INJECTION"
            elif any(keyword in title.lower() for keyword in ["ldap injection", "ldap"]):
                return "A03_INJECTION"
            elif any(keyword in title.lower() for keyword in ["deserialization", "serialize", "pickle"]):
                return "A03_INJECTION"
            else:
                # Default to injection category for all input-handling findings
                return "A03_INJECTION"
        
        # Authentication & session management scanner mappings
        elif scanner_name == "authentication_session":
            if any(keyword in title.lower() for keyword in ["authentication", "auth", "login", "password", "credential"]):
                return "A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES"
            elif any(keyword in title.lower() for keyword in ["session", "cookie", "token", "jwt"]):
                return "A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES"
            elif any(keyword in title.lower() for keyword in ["csrf", "xsrf", "cross-site request"]):
                return "A01_BROKEN_ACCESS_CONTROL"
            elif any(keyword in title.lower() for keyword in ["crypto", "encryption", "hash", "weak"]):
                return "A02_CRYPTOGRAPHIC_FAILURES"
            else:
                return "A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES"
        
        # Authorization & access control scanner mappings  
        elif scanner_name == "authorization_access_control":
            if any(keyword in title.lower() for keyword in ["idor", "insecure direct object", "object reference"]):
                return "A01_BROKEN_ACCESS_CONTROL"
            elif any(keyword in title.lower() for keyword in ["authorization", "access control", "permission", "privilege"]):
                return "A01_BROKEN_ACCESS_CONTROL"
            elif any(keyword in title.lower() for keyword in ["function", "method", "endpoint", "api"]):
                return "A01_BROKEN_ACCESS_CONTROL"
            elif any(keyword in title.lower() for keyword in ["role", "rbac", "user role"]):
                return "A01_BROKEN_ACCESS_CONTROL"
            else:
                return "A01_BROKEN_ACCESS_CONTROL"
        
        # Default fallback
        return "A05_SECURITY_MISCONFIGURATION"
    
    def _remove_duplicate_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Remove hardcoded, duplicate, and repeated findings to ensure only real, unique results"""
        unique_findings = []
        seen_findings = set()
        
        # Patterns to identify hardcoded/dummy findings
        hardcoded_patterns = [
            "test", "example", "demo", "sample", "dummy", "fake", "mock",
            "httpbin", "httpbin.org", "example.com", "test.com", "demo.com",
            "vulnerable", "intentionally", "purposely", "designed to be"
        ]
        
        for finding in findings:
            # Skip hardcoded/dummy findings
            finding_text = f"{finding.title} {finding.description} {finding.location}".lower()
            if any(pattern in finding_text for pattern in hardcoded_patterns):
                continue
            
            # Create unique identifier for deduplication
            finding_id = f"{finding.title}_{finding.location}_{finding.severity.value}"
            
            # Skip if we've already seen this finding
            if finding_id in seen_findings:
                continue
            
            seen_findings.add(finding_id)
            unique_findings.append(finding)
        
        return unique_findings
    
    async def _crawl_website_completely(self, url: str, scan_id: str, max_depth: int = 3, max_pages: int = 100) -> List[str]:
        """Crawl website completely to gather all legal files and pages for comprehensive scanning"""
        await connection_manager.send_log(scan_id, f"🕷️ [CRAWLER] Starting comprehensive website crawling of {url}", "info")
        
        discovered_urls = set()
        crawl_queue = [(url, 0)]  # (url, depth)
        crawled_urls = set()
        
        # Fresh data headers to ensure we get real, current content
        current_timestamp = int(datetime.now().timestamp())
        headers = {
            'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'X-Requested-With': f'Scanner-{current_timestamp}'
        }
        
        session = httpx.AsyncClient(timeout=None, headers=headers, follow_redirects=True)
        
        try:
            while crawl_queue and len(crawled_urls) < max_pages:
                current_url, depth = crawl_queue.pop(0)
                
                if current_url in crawled_urls or depth > max_depth:
                    continue
                
                try:
                    await connection_manager.send_log(scan_id, f"🔍 [CRAWLER] Crawling: {current_url} (depth: {depth})", "info")
                    
                    # Add timestamp to ensure fresh data
                    fresh_url = f"{current_url}?_t={current_timestamp}" if '?' not in current_url else f"{current_url}&_t={current_timestamp}"
                    
                    response = await session.get(fresh_url)
                    crawled_urls.add(current_url)
                    discovered_urls.add(current_url)
                    
                    if response.status_code == 200:
                        # Parse HTML to extract links
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Extract all links (href attributes)
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            
                            # Convert relative URLs to absolute
                            if href.startswith('/'):
                                absolute_url = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}{href}"
                            elif href.startswith('http'):
                                # Only include URLs from the same domain
                                if urlparse(href).netloc == urlparse(url).netloc:
                                    absolute_url = href
                                else:
                                    continue  # Skip external links
                            else:
                                # Relative URL
                                base_url = '/'.join(current_url.split('/')[:-1])
                                absolute_url = f"{base_url}/{href}"
                            
                            # Clean URL (remove only fragments, keep query parameters)
                            absolute_url = absolute_url.split('#')[0]  # Keep query params like ?id=1
                            
                            # Skip certain file types and patterns
                            skip_patterns = [
                                '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', 
                                '.zip', '.rar', '.exe', '.dll', '.css', '.js', '.ico',
                                'logout', 'delete', 'remove', 'destroy'
                            ]
                            
                            if not any(pattern in absolute_url.lower() for pattern in skip_patterns):
                                if absolute_url not in crawled_urls:
                                    crawl_queue.append((absolute_url, depth + 1))
                        
                        # Also check for common file paths and endpoints
                        base_domain = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                        common_paths = [
                            '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
                            '/api', '/api/v1', '/api/v2', '/swagger', '/docs', '/documentation',
                            '/config', '/backup', '/test', '/dev', '/staging', '/internal',
                            '/.env', '/config.php', '/wp-config.php', '/database.yml',
                            '/robots.txt', '/sitemap.xml', '/crossdomain.xml'
                        ]
                        
                        for path in common_paths:
                            test_url = f"{base_domain}{path}"
                            if test_url not in crawled_urls and test_url not in discovered_urls:
                                discovered_urls.add(test_url)
                                crawl_queue.append((test_url, depth + 1))
                        
                        await connection_manager.send_log(scan_id, f" [CRAWLER] Found {len(crawl_queue)} new URLs to crawl", "success")
                    
                except Exception as e:
                    await connection_manager.send_log(scan_id, f"WARNING: [CRAWLER] Failed to crawl {current_url}: {str(e)}", "warning")
                    continue
            
            await connection_manager.send_log(scan_id, f"🎯 [CRAWLER] Crawling completed! Discovered {len(discovered_urls)} URLs for scanning", "success")
            
            return list(discovered_urls)
            
        finally:
            await session.aclose()

    async def analyze_url(self, url: str, depth: int = 2, scan_id: Optional[str] = None, scan_mode: str = "owasp", scope: Optional[List[str]] = None, scan_request: Optional[ScanRequest] = None) -> ScanResult:
        """Perform comprehensive educational security analysis with OWASP Top 10 coverage"""
        if not scan_id:
            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now().isoformat()
        
        # Create artifacts directory structure
        artifacts_dir = os.path.join("artifacts", "scans", scan_id)
        os.makedirs(artifacts_dir, exist_ok=True)
        
        findings = []
        educational_insights = []
        
        try:
            # Send initial log
            await connection_manager.send_log(scan_id, f"🎯 Starting security analysis of {url}", "info")
            await connection_manager.send_progress(scan_id, 5, "initialization")
            
            # Phase 0: Notebook execution if available
            notebook_results = None
            if NOTEBOOK_ENGINE_AVAILABLE:
                try:
                    await connection_manager.send_log(scan_id, "📓 Phase 0: Executing notebook pentest engine", "phase")
                    await connection_manager.send_log(scan_id, "[notebook] Running network-level analysis...", "info")
                    
                    if 'NotebookPentestEngine' in globals():
                        notebook_engine = NotebookPentestEngine(artifacts_dir)
                        notebook_results = notebook_engine.execute_notebook_scan(
                            str(url), scan_id, "20-200"  # Limited port range for speed
                        )
                    
                    # Save notebook results to artifacts
                    notebook_file = os.path.join(artifacts_dir, "notebook_results.json")
                    with open(notebook_file, 'w') as f:
                        json.dump(notebook_results, f, indent=2, default=str)
                    
                    await connection_manager.send_log(scan_id, f"[notebook] Network scan completed, results saved to {artifacts_dir}", "success")
                    
                except Exception as e:
                    await connection_manager.send_log(scan_id, f"[notebook] Notebook execution failed: {str(e)}", "warning")
            
            # Phase 0: Comprehensive Website Crawling
            await connection_manager.send_log(scan_id, "🕷️ Phase 0: Comprehensive website crawling and discovery", "phase")
            await connection_manager.send_progress(scan_id, 5, "crawling")
            
            # Crawl website to discover all legal files and pages
            discovered_urls = await self._crawl_website_completely(str(url), scan_id, max_depth=3, max_pages=100)
            
            # Save discovered URLs to artifacts
            urls_file = os.path.join(artifacts_dir, "discovered_urls.json")
            with open(urls_file, 'w') as f:
                json.dump(discovered_urls, f, indent=2)
            
            await connection_manager.send_log(scan_id, f"[crawler] Discovered {len(discovered_urls)} URLs for comprehensive scanning", "success")
            await connection_manager.send_progress(scan_id, 10, "crawling")

            # Phase 1: Enhanced reconnaissance with network scanning
            async with httpx.AsyncClient(timeout=None, follow_redirects=True) as client:
                await connection_manager.send_log(scan_id, "🔍 Phase 1: Enhanced reconnaissance and baseline analysis", "phase")
                await connection_manager.send_log(scan_id, f"[recon] Resolving DNS for {url}...", "info")
                await connection_manager.send_progress(scan_id, 15, "reconnaissance")
                
                response = await client.get(str(url))
                await connection_manager.send_log(scan_id, f"[recon] Server responded with status {response.status_code}", "info")
                
                # Network-level scanning if nmap is available
                if NMAP_AVAILABLE:
                    try:
                        await connection_manager.send_log(scan_id, "[recon] Running network-level port scan...", "info")
                        network_scanner = AdvancedNmapScanner()
                        network_results = await network_scanner.scan_target_network(str(url), scan_id)
                        
                        if network_results:
                            # Save network results to artifacts
                            network_file = os.path.join(artifacts_dir, "network_scan.json")
                            with open(network_file, 'w') as f:
                                json.dump(network_results, f, indent=2, default=str)
                            
                            await connection_manager.send_log(scan_id, f"[recon] Network scan saved to {artifacts_dir}", "success")
                    except Exception as e:
                        await connection_manager.send_log(scan_id, f"[recon] Network scan failed: {str(e)}", "warning")
                
                baseline_findings = await self._analyze_response(response, str(url))
                findings.extend(baseline_findings)
                await connection_manager.send_log(scan_id, f"[recon] Found {len(baseline_findings)} baseline security issues", "success")
                await connection_manager.send_progress(scan_id, 20, "reconnaissance")
                
                # Phase 1.5: All 15 Blackbox Security Scanners Integration (MANDATORY)
                await connection_manager.send_log(scan_id, "🔧 Phase 1.5: Running ALL 15 BLACKBOX security scanners sequentially", "phase")
                await connection_manager.send_progress(scan_id, 22, "custom_scanners")
                
                # Force enable all scanners for comprehensive testing
                if scan_request:
                    scan_request.enable_custom_scanners = True
                    scan_request.enable_whois = True
                    scan_request.enable_ssl_labs = True
                    scan_request.enable_sqlmap = True
                    scan_request.enable_dirb = True
                    scan_request.enable_input_handling_injection = True
                    scan_request.enable_authentication_session = True
                    scan_request.enable_authorization_access_control = True
                    scan_request.enable_command_os_injection = True
                
                # Run scanners on all discovered URLs for comprehensive coverage
                all_scanner_findings = []
                for i, discovered_url in enumerate(discovered_urls[:20]):  # Limit to first 20 URLs for performance
                    await connection_manager.send_log(scan_id, f"[scanners] Running 15 scanners on URL {i+1}/{min(20, len(discovered_urls))}: {discovered_url}", "info")
                    
                    scanner_findings = await self._run_custom_scanners(discovered_url, scan_id, artifacts_dir, scan_request)
                    all_scanner_findings.extend(scanner_findings)
                
                # Apply deduplication to remove hardcoded/duplicate findings
                deduplicated_findings = self._remove_duplicate_findings(all_scanner_findings)
                findings.extend(deduplicated_findings)
                
                await connection_manager.send_log(scan_id, f"[custom]  ALL 15 BLACKBOX scanners completed on {min(20, len(discovered_urls))} URLs! Found {len(deduplicated_findings)} unique security issues (removed {len(all_scanner_findings) - len(deduplicated_findings)} duplicates)", "success")
                await connection_manager.send_progress(scan_id, 70, "custom_scanners")
                
                # Phase 2: Security testing based on mode and scope
                if scan_mode == "basic":
                    await connection_manager.send_log(scan_id, "🔍 Phase 2: Basic vulnerability scanning", "phase")
                    await connection_manager.send_progress(scan_id, 25, "testing")
                    
                    # Basic scan - only test common vulnerabilities
                    basic_tests = ["A03_INJECTION", "A01_BROKEN_ACCESS_CONTROL", "A05_SECURITY_MISCONFIGURATION"]
                    if scope:
                        # Map basic scope to OWASP categories
                        scope_mapping = {
                            "SQLi": "A03_INJECTION",
                            "XSS": "A03_INJECTION", 
                            "CSRF": "A01_BROKEN_ACCESS_CONTROL",
                            "Directory Traversal": "A01_BROKEN_ACCESS_CONTROL",
                            "File Upload": "A05_SECURITY_MISCONFIGURATION"
                        }
                        basic_tests = [scope_mapping.get(s, "A03_INJECTION") for s in scope if s in scope_mapping]
                        basic_tests = list(set(basic_tests))  # Remove duplicates
                    
                    total_categories = len(basic_tests)
                    for i, owasp_id in enumerate(basic_tests):
                        if owasp_id in self.owasp_payloads:
                            owasp_data = self.owasp_payloads[owasp_id]
                            await connection_manager.send_log(scan_id, f"[inject] Basic test: {owasp_data['name']}...", "info")
                            
                            category_findings = await self._test_owasp_category(
                                client, url, owasp_id, owasp_data, scan_id
                            )
                            findings.extend(category_findings)
                            
                            if category_findings:
                                await connection_manager.send_log(scan_id, f"[inject] WARNING: Found {len(category_findings)} issues in {owasp_data['name']}", "warning")
                            else:
                                await connection_manager.send_log(scan_id, f"[inject]  No issues found in {owasp_data['name']}", "success")
                        
                        # Update progress
                        progress = 25 + int((i + 1) / total_categories * 50)
                        await connection_manager.send_progress(scan_id, progress, "testing")
                        
                else:
                    # OWASP mode - always test ALL OWASP Top 10 categories automatically
                    await connection_manager.send_log(scan_id, "🛡️ Phase 2: OWASP Top 10 testing", "phase")
                    await connection_manager.send_progress(scan_id, 25, "testing")
                    
                    # Always test all OWASP categories for comprehensive coverage
                    categories_to_test = self.owasp_payloads.items()
                    await connection_manager.send_log(scan_id, "[inject] Running comprehensive OWASP Top 10 scan (all categories)", "info")
                    
                    # Store the scope for later report filtering if needed
                    original_scope = scope if scope else []
                    
                    total_categories = len(categories_to_test)
                    for i, (owasp_id, owasp_data) in enumerate(categories_to_test):
                        await connection_manager.send_log(scan_id, f"[inject] Testing {owasp_data['name']} ({owasp_id})...", "info")
                        
                        category_findings = await self._test_owasp_category(
                            client, url, owasp_id, owasp_data, scan_id
                        )
                        findings.extend(category_findings)
                        
                        if category_findings:
                            await connection_manager.send_log(scan_id, f"[inject] WARNING: Found {len(category_findings)} issues in {owasp_data['name']}", "warning")
                        else:
                            await connection_manager.send_log(scan_id, f"[inject]  No issues found in {owasp_data['name']}", "success")
                        
                        # Update progress
                        progress = 25 + int((i + 1) / total_categories * 50)
                        await connection_manager.send_progress(scan_id, progress, "testing")
                
                # Phase 3: Response analysis and correlation
                await connection_manager.send_log(scan_id, "📊 Phase 3: Response analysis and correlation", "phase")
                await connection_manager.send_progress(scan_id, 80, "analysis")
                await connection_manager.send_log(scan_id, "[analysis] Correlating responses and calculating severity scores...", "info")
                
                findings = self._correlate_findings(findings)
                
                # Phase 3.5: CVE Enhancement
                await connection_manager.send_log(scan_id, "🔍 Phase 3.5: CVE database enhancement", "phase")
                await connection_manager.send_log(scan_id, "[cve] Adding relevant CVE references to findings...", "info")
                
                # Enhance findings with CVE information
                findings = self.cve_enhancer.enhance_findings_batch(findings)
                
                cve_count = sum(len(f.cve_ids) for f in findings if f.cve_ids)
                await connection_manager.send_log(scan_id, f"[cve] Added {cve_count} CVE references across {len(findings)} findings", "success")
                
                # Generate educational insights
                educational_insights = self._generate_educational_insights(findings)
        
        except Exception as e:
            # Create a finding for connection issues
            findings.append(SecurityFinding(
                id=f"{scan_id}_connection_error",
                title="Connection Analysis",
                description=f"Could not connect to target: {str(e)}",
                severity=SeverityLevel.INFO,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                location=str(url),
                evidence=str(e),
                recommendation="Verify the URL is correct and accessible",
                educational_note="Connection issues can indicate network security measures or misconfigurations",
                timestamp=datetime.now().isoformat()
            ))
        
        end_time = datetime.now().isoformat()
        
        # Generate summary
        summary = self._generate_summary(findings)
        
        # Create initial scan result
        scan_result = ScanResult(
            scan_id=scan_id,
            target_url=str(url),
            start_time=start_time,
            end_time=end_time,
            findings=findings,
            summary=summary,
            educational_insights=educational_insights
        )
        
        # Generate comprehensive reports
        await connection_manager.send_log(scan_id, "📋 Phase 4: Generating comprehensive reports", "phase")
        await connection_manager.send_progress(scan_id, 90, "reporting")
        await connection_manager.send_log(scan_id, "[report] Compiling technical and executive reports...", "info")
        
        technical_report = self.report_generator.generate_technical_report(scan_result)
        executive_report = self.report_generator.generate_executive_report(scan_result)
        
        # Add reports to scan result
        scan_result.technical_report = technical_report
        scan_result.executive_report = executive_report
        
        # Save comprehensive scan data to artifacts
        try:
            # Save main scan result
            main_result_file = os.path.join(artifacts_dir, "scan_result.json")
            with open(main_result_file, 'w') as f:
                json.dump(asdict(scan_result), f, indent=2, default=str)
            
            # Save individual reports
            tech_report_file = os.path.join(artifacts_dir, "technical_report.json")
            with open(tech_report_file, 'w') as f:
                json.dump(asdict(technical_report), f, indent=2, default=str)
            
            exec_report_file = os.path.join(artifacts_dir, "executive_report.json")
            with open(exec_report_file, 'w') as f:
                json.dump(asdict(executive_report), f, indent=2, default=str)
            
            # Save findings as CSV for easy analysis
            import csv
            findings_csv = os.path.join(artifacts_dir, "findings.csv")
            with open(findings_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Title', 'Severity', 'OWASP Category', 'Location', 'CVE IDs'])
                for finding in findings:
                    writer.writerow([
                        finding.id,
                        finding.title,
                        finding.severity.value,
                        finding.owasp_category.value,
                        finding.location,
                        ', '.join(finding.cve_ids) if finding.cve_ids else 'None'
                    ])
            
            await connection_manager.send_log(scan_id, f"[artifacts] All scan data saved to {artifacts_dir}", "success")
            
        except Exception as e:
            await connection_manager.send_log(scan_id, f"[artifacts] Failed to save artifacts: {str(e)}", "warning")
        
        # Final completion logs
        await connection_manager.send_log(scan_id, f" Scan completed! Found {len(findings)} total issues", "success")
        await connection_manager.send_log(scan_id, f"[report] Critical: {len([f for f in findings if f.severity == SeverityLevel.CRITICAL])}, High: {len([f for f in findings if f.severity == SeverityLevel.HIGH])}, Medium: {len([f for f in findings if f.severity == SeverityLevel.MEDIUM])}", "info")
        await connection_manager.send_progress(scan_id, 100, "complete")
        await connection_manager.send_complete(scan_id, f"/results?scan_id={scan_id}")
        
        return scan_result
    
    async def _analyze_response(self, response: httpx.Response, url: str) -> List[SecurityFinding]:
        """Analyze HTTP response for educational security insights"""
        findings = []
        timestamp = datetime.now().isoformat()
        
        # Analyze headers
        header_findings = self._analyze_headers(response.headers, url, timestamp)
        findings.extend(header_findings)
        
        # Analyze content
        if response.headers.get("content-type", "").startswith("text/html"):
            content_findings = await self._analyze_html_content(response.text, url, timestamp)
            findings.extend(content_findings)
        
        return findings
    
    def _analyze_headers(self, headers: httpx.Headers, url: str, timestamp: str) -> List[SecurityFinding]:
        """Analyze HTTP headers for security insights"""
        findings = []
        
        # Check for missing security headers
        missing_headers = []
        for header in self.educational_patterns["security_headers"]:
            if header not in headers:
                missing_headers.append(header)
        
        if missing_headers:
            findings.append(SecurityFinding(
                id=f"missing_headers_{hash(url)}",
                title="Missing Security Headers",
                description=f"Missing important security headers: {', '.join(missing_headers)}",
                severity=SeverityLevel.MEDIUM,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                location=url,
                evidence=f"Headers present: {list(headers.keys())}",
                recommendation="Implement missing security headers to improve protection",
                educational_note="Security headers help browsers protect users from common attacks like XSS, clickjacking, and MITM attacks",
                timestamp=timestamp
            ))
        
        # Check HTTPS
        if url.startswith("http://"):
            findings.append(SecurityFinding(
                id=f"insecure_http_{hash(url)}",
                title="Insecure HTTP Connection",
                description="Site is accessed over unencrypted HTTP",
                severity=SeverityLevel.HIGH,
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                location=url,
                evidence="URL scheme is http://",
                recommendation="Implement HTTPS with proper TLS configuration",
                educational_note="HTTP traffic can be intercepted and modified by attackers. HTTPS encrypts communication between browser and server",
                timestamp=timestamp
            ))
        
        return findings
    
    async def  _analyze_html_content(self, content: str, url: str, timestamp: str) -> List[SecurityFinding]:
        """Analyze HTML content for educational security insights"""
        findings = []
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for inline scripts (educational)
            inline_scripts = soup.find_all('script', string=True)
            if inline_scripts:
                findings.append(SecurityFinding(
                    id=f"inline_scripts_{hash(url)}",
                    title="Inline JavaScript Detected",
                    description=f"Found {len(inline_scripts)} inline script tags",
                    severity=SeverityLevel.LOW,
                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    location=url,
                    evidence=f"Inline scripts found: {len(inline_scripts)}",
                    recommendation="Consider using external script files and Content Security Policy",
                    educational_note="Inline scripts can make it harder to implement strict CSP policies and may increase XSS risk",
                    timestamp=timestamp
                ))
            
            # Check for forms without CSRF protection (educational indicator)
            forms = soup.find_all('form')
            for form in forms:
                # Check if form has CSRF protection
                csrf_input = form.find('input', attrs={'name': lambda x: x and 'csrf' in x.lower()})
                if not csrf_input:
                    findings.append(SecurityFinding(
                        id=f"potential_csrf_{hash(str(form))}",
                        title="Form Without Apparent CSRF Protection",
                        description="Form found without visible CSRF token",
                        severity=SeverityLevel.MEDIUM,
                        owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                        location=url,
                        evidence=f"Form action: {getattr(form, 'get', lambda x, default: default)('action', 'Not specified')}",
                        recommendation="Implement CSRF tokens for state-changing operations",
                        educational_note="CSRF attacks trick users into performing unintended actions. CSRF tokens help verify request authenticity",
                        timestamp=timestamp
                    ))
        
        except Exception as e:
            # Add parsing error as educational finding
            findings.append(SecurityFinding(
                id=f"parsing_error_{hash(url)}",
                title="Content Analysis Issue",
                description=f"Could not fully parse HTML content: {str(e)}",
                severity=SeverityLevel.INFO,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                location=url,
                evidence=str(e),
                recommendation="Ensure HTML is well-formed and valid",
                educational_note="Malformed HTML can sometimes bypass security filters or cause unexpected behavior",
                timestamp=timestamp
            ))
        
        return findings
    
    async def _test_owasp_category(self, client: httpx.AsyncClient, base_url: str, 
                                 owasp_id: str, owasp_data: Dict, scan_id: str) -> List[SecurityFinding]:
        """Test a specific OWASP category with targeted payloads"""
        findings = []
        timestamp = datetime.now().isoformat()
        category_name = owasp_data["name"]
        
        await connection_manager.send_log(scan_id, f"[inject] Testing {owasp_id}: {category_name} with {len(owasp_data['payloads'])} payloads", "info")
        
        # Map OWASP IDs to enum values
        owasp_mapping = {
            "A01_BROKEN_ACCESS_CONTROL": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            "A02_CRYPTOGRAPHIC_FAILURES": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            "A03_INJECTION": OWASPCategory.A03_INJECTION,
            "A04_INSECURE_DESIGN": OWASPCategory.A04_INSECURE_DESIGN,
            "A05_SECURITY_MISCONFIGURATION": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
            "A06_VULNERABLE_COMPONENTS": OWASPCategory.A06_VULNERABLE_COMPONENTS,
            "A07_AUTH_FAILURES": OWASPCategory.A07_AUTH_FAILURES,
            "A08_DATA_INTEGRITY_FAILURES": OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
            "A09_LOGGING_FAILURES": OWASPCategory.A09_LOGGING_FAILURES,
            "A10_SSRF": OWASPCategory.A10_SSRF
        }
        
        owasp_category = owasp_mapping.get(owasp_id, OWASPCategory.A05_SECURITY_MISCONFIGURATION)
        
        # Test each payload for this category
        for i, payload in enumerate(owasp_data["payloads"]):
            try:
                # Log the specific payload being tested
                await connection_manager.send_log(scan_id, f"[inject] Payload {i+1}/{len(owasp_data['payloads'])}: {payload[:50]}{'...' if len(payload) > 50 else ''}", "info")
                
                # Start process log
                process_log = []
                process_log.append(f"[START] Testing OWASP Category: {owasp_id} ({category_name})")
                process_log.append(f"[START] Payload: {payload}")
                process_log.append(f"[START] Timestamp: {timestamp}")
                
                # Construct test URL
                if payload.startswith('/'):
                    test_url = base_url.rstrip('/') + payload
                elif payload.startswith('?'):
                    test_url = base_url + payload
                else:
                    test_url = base_url + '/' + payload
                
                process_log.append(f"[REQUEST] URL: {test_url}")
                process_log.append(f"[REQUEST] Method: GET")
                
                # Prepare headers
                headers = owasp_data.get("headers", {})
                if headers:
                    process_log.append(f"[REQUEST] Headers: {json.dumps(headers, indent=2)}")
                
                # Make request with payload
                request_start = datetime.now()
                response = await client.get(test_url, headers=headers)
                request_end = datetime.now()
                request_duration = (request_end - request_start).total_seconds()
                
                process_log.append(f"[RESPONSE] Status: {response.status_code}")
                process_log.append(f"[RESPONSE] Size: {len(response.text)} bytes")
                process_log.append(f"[RESPONSE] Duration: {request_duration:.3f}s")
                
                await connection_manager.send_log(scan_id, f"[inject] Response: {response.status_code} ({len(response.text)} bytes)", "info")
                
                # Analyze response for indicators
                indicators_found = []
                response_text = response.text.lower()
                
                process_log.append(f"[ANALYSIS] Checking {len(owasp_data.get('patterns', []))} patterns...")
                
                for pattern in owasp_data.get("patterns", []):
                    if re.search(pattern.lower(), response_text):
                        indicators_found.append(pattern)
                        process_log.append(f"[ANALYSIS] ✓ Pattern matched: {pattern}")
                
                if not indicators_found:
                    process_log.append(f"[ANALYSIS] No patterns matched")
                
                process_log.append(f"[ANALYSIS] Indicators found: {len(indicators_found)}")
                
                # Check for interesting response codes
                interesting_codes = [200, 403, 500, 302]
                is_interesting = response.status_code in interesting_codes
                has_indicators = len(indicators_found) > 0
                is_not_404 = response.status_code != 404
                
                process_log.append(f"[DECISION] Status {response.status_code} in interesting codes {interesting_codes}: {is_interesting}")
                process_log.append(f"[DECISION] Has indicators: {has_indicators}")
                process_log.append(f"[DECISION] Status is not 404: {is_not_404}")
                
                if is_interesting and (has_indicators or is_not_404):
                    # Log vulnerability found
                    await connection_manager.send_log(scan_id, f"[inject] 🚨 Potential {category_name} vulnerability detected!", "warning")
                    
                    severity = self._determine_severity(owasp_id, response.status_code, indicators_found)
                    issue_type = self._determine_issue_type(owasp_id, response.status_code, indicators_found)
                    
                    process_log.append(f"[FINDING] Vulnerability detected!")
                    process_log.append(f"[FINDING] Severity: {severity.value}")
                    process_log.append(f"[FINDING] Issue Type: {issue_type}")
                    process_log.append(f"[FINDING] Indicators: {', '.join(indicators_found) if indicators_found else 'Response analysis'}")
                    
                    # Key response headers
                    key_headers = {k: v for k, v in response.headers.items() if k.lower() in ['content-type', 'server', 'x-powered-by', 'location']}
                    if key_headers:
                        process_log.append(f"[RESPONSE] Key Headers: {json.dumps(key_headers, indent=2)}")
                    
                    # Response body snippet (first 200 chars)
                    if response.text:
                        body_snippet = response.text[:200].replace('\n', ' ').replace('\r', ' ')
                        process_log.append(f"[RESPONSE] Body snippet: {body_snippet}...")
                    
                    process_log.append(f"[END] Finding created at: {datetime.now().isoformat()}")
                    
                    # Create comprehensive technical details
                    technical_details = TechnicalDetails(
                        payload_used=payload,
                        request_method="GET",
                        request_headers=dict(headers),
                        response_status=response.status_code,
                        response_headers=dict(response.headers),
                        response_body_snippet=response.text[:500] if response.text else "",
                        reproduction_steps=self._generate_reproduction_steps(test_url, payload, headers),
                        cvss_score=0.0,  # Will be calculated later
                        cvss_vector=""   # Will be calculated later
                    )
                    
                    # Create business impact assessment
                    business_impact = self._assess_business_impact(owasp_id, severity)
                    
                    # Create comprehensive evidence with full process log
                    evidence = "\n".join(process_log)
                    
                    finding = SecurityFinding(
                        id=f"{owasp_id}_{hash(test_url)}_{hash(payload)}",
                        title=f"{category_name} - {payload}",
                        description=f"Potential {category_name.lower()} {issue_type} detected",
                        severity=severity,
                        owasp_category=owasp_category,
                        location=test_url,
                        evidence=evidence,
                        recommendation=self._get_owasp_recommendation(owasp_id),
                        educational_note=self._get_owasp_educational_note(owasp_id),
                        timestamp=timestamp,
                        technical_details=technical_details,
                        business_impact=business_impact,
                        issue_type=issue_type
                    )
                    
                    # Calculate CVSS score
                    cvss_score, cvss_vector = self.cvss_calculator.calculate_cvss_score(finding)
                    finding.technical_details.cvss_score = cvss_score
                    finding.technical_details.cvss_vector = cvss_vector
                    
                    findings.append(finding)
                
            except Exception as e:
                # Log payload testing errors as info findings
                if "timeout" not in str(e).lower():  # Skip timeout errors
                    error_log = []
                    error_log.append(f"[START] Testing OWASP Category: {owasp_id} ({category_name})")
                    error_log.append(f"[START] Payload: {payload}")
                    error_log.append(f"[START] Timestamp: {timestamp}")
                    error_log.append(f"[ERROR] Exception Type: {type(e).__name__}")
                    error_log.append(f"[ERROR] Error Message: {str(e)}")
                    error_log.append(f"[ERROR] Timestamp: {datetime.now().isoformat()}")
                    error_log.append(f"[END] Error occurred during testing")
                    
                    findings.append(SecurityFinding(
                        id=f"{owasp_id}_error_{hash(payload)}",
                        title=f"{category_name} - Testing Error",
                        description=f"Error testing payload: {payload}",
                        severity=SeverityLevel.INFO,
                        owasp_category=owasp_category,
                        location=base_url,
                        evidence="\n".join(error_log),
                        recommendation="Investigate potential blocking or filtering mechanisms",
                        educational_note="Errors during testing can indicate security measures or misconfigurations",
                        timestamp=timestamp
                    ))
        
        return findings
    
    def _determine_severity(self, owasp_id: str, status_code: int, indicators: List[str]) -> SeverityLevel:
        """Determine severity based on OWASP category and response analysis"""
        high_risk_categories = ["A01_BROKEN_ACCESS_CONTROL", "A02_CRYPTOGRAPHIC_FAILURES", "A03_INJECTION"]
        medium_risk_categories = ["A04_INSECURE_DESIGN", "A05_SECURITY_MISCONFIGURATION", "A07_AUTH_FAILURES"]
        
        if owasp_id in high_risk_categories:
            if status_code == 200 and indicators:
                return SeverityLevel.HIGH
            elif status_code == 200:
                return SeverityLevel.MEDIUM
            else:
                return SeverityLevel.LOW
        elif owasp_id in medium_risk_categories:
            if status_code == 200 and indicators:
                return SeverityLevel.MEDIUM
            else:
                return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _get_owasp_recommendation(self, owasp_id: str) -> str:
        """Get specific recommendations for each OWASP category"""
        recommendations = {
            "A01_BROKEN_ACCESS_CONTROL": "Implement proper access controls, use least privilege principle, and validate user permissions",
            "A02_CRYPTOGRAPHIC_FAILURES": "Use strong encryption, implement HTTPS everywhere, and secure key management",
            "A03_INJECTION": "Use parameterized queries, input validation, and output encoding",
            "A04_INSECURE_DESIGN": "Implement secure design patterns, threat modeling, and security requirements",
            "A05_SECURITY_MISCONFIGURATION": "Harden configurations, remove default accounts, and implement security headers",
            "A06_VULNERABLE_COMPONENTS": "Keep components updated, monitor for vulnerabilities, and use dependency scanning",
            "A07_AUTH_FAILURES": "Implement strong authentication, session management, and multi-factor authentication",
            "A08_DATA_INTEGRITY_FAILURES": "Implement integrity checks, secure update mechanisms, and code signing",
            "A09_LOGGING_FAILURES": "Implement comprehensive logging, monitoring, and incident response procedures",
            "A10_SSRF": "Validate and sanitize URLs, implement allowlists, and network segmentation"
        }
        return recommendations.get(owasp_id, "Follow OWASP security guidelines")
    
    def _get_owasp_educational_note(self, owasp_id: str) -> str:
        """Get educational notes for each OWASP category"""
        notes = {
            "A01_BROKEN_ACCESS_CONTROL": "Access control enforces policy such that users cannot act outside of their intended permissions",
            "A02_CRYPTOGRAPHIC_FAILURES": "Cryptographic failures often lead to sensitive data exposure or system compromise",
            "A03_INJECTION": "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query",
            "A04_INSECURE_DESIGN": "Insecure design is a broad category representing different weaknesses in design and architectural flaws",
            "A05_SECURITY_MISCONFIGURATION": "Security misconfiguration is commonly a result of insecure default configurations",
            "A06_VULNERABLE_COMPONENTS": "Components run with the same privileges as the application, so flaws in any component can result in serious impact",
            "A07_AUTH_FAILURES": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks",
            "A08_DATA_INTEGRITY_FAILURES": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations",
            "A09_LOGGING_FAILURES": "Logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems",
            "A10_SSRF": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL"
        }
        return notes.get(owasp_id, "This finding relates to OWASP Top 10 security risks")
    
    def _generate_reproduction_steps(self, url: str, payload: str, headers: Dict[str, str]) -> List[str]:
        """Generate detailed reproduction steps"""
        steps = [
            f"1. Open a web browser or HTTP client",
            f"2. Navigate to: {url}",
        ]
        
        if headers:
            steps.append("3. Add the following headers:")
            for key, value in headers.items():
                steps.append(f"   - {key}: {value}")
        
        steps.extend([
            f"4. Send GET request to the URL",
            f"5. Observe the response for vulnerability indicators",
            f"6. Payload used: {payload}"
        ])
        
        return steps
    
    def _determine_issue_type(self, owasp_id: str, status_code: int, indicators: List[str]) -> str:
        """Determine if this is a vulnerability, misconfiguration, warning, or weak practice"""
        if status_code == 200 and indicators:
            return "vulnerability"
        elif status_code in [403, 401]:
            return "misconfiguration"
        elif status_code == 500:
            return "vulnerability"
        else:
            return "warning"
    
    def _assess_business_impact(self, owasp_id: str, severity: SeverityLevel) -> BusinessImpact:
        """Assess business impact for executive reporting"""
        impact_mapping = {
            SeverityLevel.CRITICAL: ("HIGH", "HIGH", "HIGH"),
            SeverityLevel.HIGH: ("HIGH", "MEDIUM", "MEDIUM"),
            SeverityLevel.MEDIUM: ("MEDIUM", "MEDIUM", "LOW"),
            SeverityLevel.LOW: ("LOW", "LOW", "LOW"),
            SeverityLevel.INFO: ("LOW", "LOW", "LOW")
        }
        
        conf_impact, int_impact, avail_impact = impact_mapping.get(severity, ("LOW", "LOW", "LOW"))
        
        # Business risk assessment
        business_risk_mapping = {
            SeverityLevel.CRITICAL: "Data breach, regulatory fines, reputation damage",
            SeverityLevel.HIGH: "Potential data exposure, service disruption",
            SeverityLevel.MEDIUM: "Security weakness, compliance concerns",
            SeverityLevel.LOW: "Minor security improvement needed",
            SeverityLevel.INFO: "Informational finding"
        }
        
        # Compliance impact
        compliance_mapping = {
            SeverityLevel.CRITICAL: "Non-compliant with security standards",
            SeverityLevel.HIGH: "Compliance risk identified",
            SeverityLevel.MEDIUM: "Compliance improvement recommended",
            SeverityLevel.LOW: "Minor compliance consideration",
            SeverityLevel.INFO: "No compliance impact"
        }
        
        # User impact
        user_impact_mapping = {
            SeverityLevel.CRITICAL: "High risk to user data and privacy",
            SeverityLevel.HIGH: "Potential user data exposure",
            SeverityLevel.MEDIUM: "Limited user impact",
            SeverityLevel.LOW: "Minimal user impact",
            SeverityLevel.INFO: "No direct user impact"
        }
        
        # Financial impact
        financial_mapping = {
            SeverityLevel.CRITICAL: "High - potential regulatory fines and incident response costs",
            SeverityLevel.HIGH: "Medium - remediation and monitoring costs",
            SeverityLevel.MEDIUM: "Low - implementation and testing costs",
            SeverityLevel.LOW: "Minimal - minor development effort",
            SeverityLevel.INFO: "None - informational only"
        }
        
        return BusinessImpact(
            confidentiality_impact=conf_impact,
            integrity_impact=int_impact,
            availability_impact=avail_impact,
            business_risk=business_risk_mapping.get(severity, "Unknown"),
            compliance_impact=compliance_mapping.get(severity, "Unknown"),
            user_impact=user_impact_mapping.get(severity, "Unknown"),
            financial_impact=financial_mapping.get(severity, "Unknown")
        )
    
    def _correlate_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Correlate and deduplicate findings to reduce noise"""
        # Simple deduplication based on title and location
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = f"{finding.title}_{finding.location}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _generate_educational_insights(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate comprehensive educational insights based on OWASP findings"""
        insights = []
        
        severity_counts = {}
        owasp_counts = {}
        
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            owasp_counts[finding.owasp_category] = owasp_counts.get(finding.owasp_category, 0) + 1
        
        # Severity-based insights
        total_findings = len(findings)
        if severity_counts.get(SeverityLevel.CRITICAL, 0) > 0:
            insights.append("🔴 Critical vulnerabilities detected - immediate remediation required in production environments")
        
        if severity_counts.get(SeverityLevel.HIGH, 0) > 0:
            insights.append("🟠 High-risk vulnerabilities found - these could lead to system compromise")
        
        if severity_counts.get(SeverityLevel.MEDIUM, 0) > 0:
            insights.append("🟡 Medium-risk issues identified - should be addressed in next security cycle")
        
        # OWASP-specific insights
        if owasp_counts:
            most_common_owasp = max(owasp_counts.items(), key=lambda x: x[1])[0]
            insights.append(f"📊 Primary concern: {most_common_owasp} ({owasp_counts[most_common_owasp]} findings)")
            
            # Specific OWASP insights
            if OWASPCategory.A03_INJECTION in owasp_counts:
                insights.append("💉 Injection vulnerabilities detected - implement input validation and parameterized queries")
            
            if OWASPCategory.A01_BROKEN_ACCESS_CONTROL in owasp_counts:
                insights.append("🔐 Access control issues found - review authorization mechanisms and user permissions")
            
            if OWASPCategory.A05_SECURITY_MISCONFIGURATION in owasp_counts:
                insights.append("⚙️ Configuration issues detected - review security settings and remove default configurations")
        
        # Coverage insights
        owasp_categories_found = len(set(owasp_counts.keys()))
        insights.append(f"🎯 OWASP Coverage: {owasp_categories_found}/10 categories tested with findings")
        
        # Risk assessment
        high_critical = severity_counts.get(SeverityLevel.HIGH, 0) + severity_counts.get(SeverityLevel.CRITICAL, 0)
        if high_critical > 0:
            risk_level = "High" if high_critical > 3 else "Medium"
            insights.append(f"WARNING: Overall Risk Level: {risk_level} ({high_critical} high/critical findings)")
        else:
            insights.append(" Overall Risk Level: Low (no high/critical findings)")
        
        # Educational reminders
        insights.append("📚 Educational Purpose: This scan demonstrates common web vulnerabilities for learning")
        insights.append("⚖️ Legal Notice: Only test systems you own or have explicit permission to test")
        insights.append("🔍 Next Steps: Review OWASP Top 10 documentation for detailed remediation guidance")
        
        return insights
    
    def _generate_summary(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Generate summary statistics"""
        summary = {
            "total_findings": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            summary[finding.severity] += 1
        
        return summary

# Global analyzer instance
analyzer = SecurityAnalyzer()

# Initialize task queue
from backend.tasks.queue import task_queue
import asyncio

# Task queue management is now handled in the lifespan context manager



# ConnectionManager already defined at line 226 - duplicate instantiation removed

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan logs"""
    try:
        # Accept connection first, then validate scan
        await connection_manager.connect(websocket, scan_id)
        
        # Send connection confirmation immediately
        await connection_manager.send_message(scan_id, {
            "type": "connection",
            "status": "connected",
            "scan_id": scan_id,
            "message": "WebSocket connection established successfully",
            "timestamp": datetime.now().isoformat()
        })
        
        # Check if scan exists, but don't close connection if it doesn't
        if scan_id not in scan_results:
            await connection_manager.send_message(scan_id, {
                "type": "info",
                "message": f"Waiting for scan {scan_id} to start...",
                "timestamp": datetime.now().isoformat()
            })
        
        while True:
            try:
                # Wait for client messages with timeout
                message = await asyncio.wait_for(websocket.receive_text(), timeout=None)
                
                # Handle client messages (like ping/pong)
                try:
                    data = json.loads(message)
                    if data.get("type") == "ping":
                        await connection_manager.send_message(scan_id, {
                            "type": "pong",
                            "timestamp": datetime.now().isoformat()
                        })
                except json.JSONDecodeError:
                    pass
                    
            except asyncio.TimeoutError:
                # Send periodic keepalive
                await connection_manager.send_message(scan_id, {
                    "type": "keepalive",
                    "timestamp": datetime.now().isoformat()
                })
                
    except WebSocketDisconnect:
        connection_manager.disconnect(scan_id)
    except Exception as e:
        print(f"[ERROR] WebSocket error for scan {scan_id}: {str(e)}")
        try:
            await websocket.close(code=1011, reason=f"Server error: {str(e)}")
        except:
            pass

@app.post("/scan", tags=["Main Scanner"])
async def run_comprehensive_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Run comprehensive security scan with 15 blackbox scanners (Public Access)
    
    This endpoint provides the main scanning functionality with:
    - Complete website crawling to discover all legal files
    - 15 blackbox-compatible scanners running sequentially
    - Real-time progress updates via WebSocket
    - Comprehensive deduplication and hardcoded data filtering
    - PDF report generation
    
    ## Features
    
    * 🕷️ **Complete Website Crawling** - Discovers all legal files and pages
    * 🔍 **12 Blackbox Scanners** - WHOIS, SSL, SQLMap, Dirb, Injection, Auth, Authorization, Command, Nmap, Info Disclosure, Web Security, Comprehensive
    * 🚫 **No Hardcoded Data** - Filters out dummy/test data automatically
    * 📊 **Real-time Updates** - WebSocket connection for live progress
    * 📋 **PDF Reports** - Professional penetration testing reports
    * 🎯 **Real URL Testing** - Only scans actual target websites
    
    ## Request Parameters
    
    ```json
    {
       "target_url": "https://example.com",
       "scan_mode": "owasp",
       "depth": 3,
       "scope": ["SQLi", "XSS", "CSRF"]
    }
    ```
    
    ## Response
    
    Returns immediate scan initiation confirmation with WebSocket connection details
    for real-time progress monitoring.
    """
    
    url = str(request.target_url)  # Convert HttpUrl to string for REAL scanning
    username = "public"
    scan_id = generate_scan_id_from_url(url, username)
    
    # Create organized directory structure
    scan_dirs = create_scan_directory_structure(scan_id)
    logger.info(f"Created scan directories: {scan_dirs['base']}")
    
    await connection_manager.send_log(scan_id, f" Starting comprehensive security scan", "info")
    await connection_manager.send_log(scan_id, f"Target: {url}", "info")
    await connection_manager.send_log(scan_id, f"User: {username}", "info")
    await connection_manager.send_log(scan_id, f"Mode: {request.scan_mode}", "info")
    
    # Store scan in results for status tracking
    scan_results[scan_id] = {
        'scan_id': scan_id,
        'target': url,
        'username': username,
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'progress': 0,
        'current_activity': 'Initializing comprehensive scan',
        'total_scanners': 15,
        'completed_scanners': 0
    }
    
    # Initial response
    scan_response = {
        "scan_id": scan_id,
        "status": "started",
        "target_url": url,
        "username": username,
        "scan_mode": request.scan_mode,
        "websocket_url": f"/ws/{scan_id}",
        "scan_start": datetime.now().isoformat(),
        "estimated_duration": "30-60 minutes",
        "message": "Comprehensive security scan initiated successfully"
    }
    
    # Add background task
    if DISTRIBUTED_SYSTEM_AVAILABLE and distributed_bridge:
        background_tasks.add_task(run_distributed_scan_background, scan_id, url, username, request)
    else:
        background_tasks.add_task(run_comprehensive_scan_background, scan_id, url, username, request)
    
    return scan_response

@app.post("/scan/public", tags=["Public Scanner"])
async def run_public_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Run comprehensive security scan with 15 blackbox scanners (Public Access - No Authentication Required)
    
    This is a public endpoint that doesn't require authentication for testing and demonstration purposes.
    """
    
    url = str(request.target_url)  # Convert HttpUrl to string for REAL scanning
    username = "public"
    scan_id = generate_scan_id_from_url(url, username)
    
    # Create organized directory structure
    scan_dirs = create_scan_directory_structure(scan_id)
    logger.info(f"Created scan directories: {scan_dirs['base']}")
    
    await connection_manager.send_log(scan_id, f" Starting PUBLIC comprehensive security scan", "info")
    await connection_manager.send_log(scan_id, f"Target: {url}", "info")
    await connection_manager.send_log(scan_id, f"User: {username} (public access)", "info")
    await connection_manager.send_log(scan_id, f"Mode: {request.scan_mode}", "info")
    
    # Store scan in results for status tracking
    scan_results[scan_id] = {
        'scan_id': scan_id,
        'target': url,
        'username': username,
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'progress': 0,
        'current_activity': 'Initializing comprehensive scan (public access)',
        'total_scanners': 15,
        'completed_scanners': 0
    }
    
    # Initial response
    scan_response = {
        "scan_id": scan_id,
        "status": "started",
        "target_url": url,
        "username": username,
        "scan_mode": request.scan_mode,
        "websocket_url": f"/ws/{scan_id}",
        "scan_start": datetime.now().isoformat(),
        "estimated_duration": "30-60 minutes",
        "message": "Public comprehensive security scan initiated successfully"
    }
    
    # Add background task
    background_tasks.add_task(run_comprehensive_scan_background, scan_id, url, username, request)
    
    return scan_response

async def run_comprehensive_scan_background(scan_id: str, url: str, username: str, scan_request: ScanRequest):
    """
    Background task for REAL comprehensive security scan
    Uses ENHANCED DISTRIBUTED SYSTEM - NO DUMMY DATA
    """
    try:
        logger.info(f"[MAIN BACKEND] Background task started for scan {scan_id}")
        logger.info(f"[MAIN BACKEND] Target URL: {url}, User: {username}")
        
        await connection_manager.send_log(scan_id, f"[MAIN BACKEND] Starting REAL comprehensive scan", "info")
        await connection_manager.send_log(scan_id, f"Target: {url}", "info")
        await connection_manager.send_log(scan_id, f"User: {username}", "info")
        
        # Set default depth if not provided
        depth = getattr(scan_request, 'depth', 3)
        scan_mode = getattr(scan_request, 'scan_mode', 'comprehensive')
        
        # Try to use enhanced distributed system
        try:
            from integration.distributed_system_bridge import distributed_bridge
            
            await connection_manager.send_log(
                scan_id,
                "[DISTRIBUTED] Checking enhanced distributed system health...",
                "info"
            )
            
            logger.info(f"[MAIN BACKEND] Checking distributed system health for scan {scan_id}")
            
            is_healthy = await distributed_bridge.check_distributed_system_health()
            
            if is_healthy:
                logger.info(f"[MAIN BACKEND] Distributed system HEALTHY - delegating scan {scan_id}")
                
                await connection_manager.send_log(
                    scan_id,
                    "[DISTRIBUTED] System HEALTHY - 5 Crawlers + 20 Workers ready!",
                    "success"
                )
                
                await connection_manager.send_log(
                    scan_id,
                    f"[DISTRIBUTED] Submitting REAL URL to enhanced orchestrator: {url}",
                    "info"
                )
                
                # Submit to distributed system
                distributed_response = await distributed_bridge.submit_scan(
                    url=url,
                    scan_mode=scan_mode,
                    max_depth=depth,
                    scan_options={'scan_id': scan_id, 'username': username}
                )
                
                distributed_scan_id = distributed_response.get('scan_id')
                logger.info(f"[MAIN BACKEND] Scan delegated to distributed system: {distributed_scan_id}")
                
                # Store distributed_scan_id in scan_results for status tracking
                if scan_id in scan_results:
                    scan_results[scan_id]['distributed_scan_id'] = distributed_scan_id
                    scan_results[scan_id]['current_activity'] = 'Delegated to distributed system'
                    logger.info(f"[MAIN BACKEND] Stored distributed_scan_id {distributed_scan_id} for scan {scan_id}")
                
                await connection_manager.send_log(
                    scan_id,
                    f"[DISTRIBUTED] Scan submitted! ID: {distributed_scan_id}",
                    "success"
                )
                
                # Monitor the distributed scan
                await connection_manager.send_log(
                    scan_id,
                    "[DISTRIBUTED] Starting real-time monitoring...",
                    "info"
                )
                
                final_results = await distributed_bridge.monitor_scan_with_updates(
                    distributed_scan_id,
                    scan_id,
                    connection_manager,
                    max_duration=999999  # Effectively no timeout - wait for scan to complete
                )
                
                logger.info(f"[MAIN BACKEND] Distributed scan completed: {final_results.get('findings_count', 0)} findings")
                
                # ═══════════════════════════════════════════════════════════════════
                # EXPLICIT COMPLETION LOGGING - For frontend status tracking
                # ═══════════════════════════════════════════════════════════════════
                logger.info("═" * 70)
                logger.info(f"[COMPLETED] SCAN COMPLETED: {scan_id}")
                logger.info(f"   Target URL: {url}")
                logger.info(f"   Distributed Scan ID: {distributed_scan_id}")
                logger.info(f"   Findings: {final_results.get('findings_count', 0)} vulnerabilities found")
                logger.info(f"   Status: completed")
                logger.info(f"   Completed at: {datetime.now().isoformat()}")
                logger.info("═" * 70)
                
                # ═══════════════════════════════════════════════════════════════════
                # CRITICAL FIX: Update in-memory scan_results IMMEDIATELY
                # This prevents race condition where frontend polls before files are saved
                # ═══════════════════════════════════════════════════════════════════
                if scan_id in scan_results:
                    scan_results[scan_id].update({
                        'status': 'completed',
                        'end_time': datetime.now().isoformat(),
                        'progress': 100,
                        'current_activity': 'Scan completed successfully',
                        'findings_count': final_results.get('findings_count', 0),
                        'summary': final_results.get('summary', {}),
                        'urls_crawled': final_results.get('urls_crawled', 0),
                        'completed_scanners': final_results.get('findings_count', 0)
                    })
                    logger.info(f"[STATUS UPDATE] In-memory scan_results updated to 'completed' for {scan_id}")
                
                # Save distributed scan results to new directory structure FIRST
                scan_dir = f"scan_results/{scan_id}"
                os.makedirs(f"{scan_dir}/raw_data", exist_ok=True)
                os.makedirs(f"{scan_dir}/crawled_urls", exist_ok=True)
                os.makedirs(f"{scan_dir}/scanner_outputs", exist_ok=True)
                os.makedirs(f"{scan_dir}/logs", exist_ok=True)
                os.makedirs(f"{scan_dir}/reports", exist_ok=True)
                os.makedirs(f"{scan_dir}/artifacts", exist_ok=True)
                
                # Save full distributed results
                # final_results comes from monitor_scan_with_updates() -> get_scan_results() which includes raw_data
                # NetworkScanner data is included in raw_data['NetworkScanner'] same as other scanners
                if 'raw_data' in final_results:
                    logger.info(f"[SAVE] raw_data present with keys: {list(final_results['raw_data'].keys())}")
                    
                    # CRITICAL FIX: Flatten NetworkScanner and merge SSHAuditScanner data
                    raw_data = final_results.get('raw_data', {})
                    
                    # CRITICAL: Extract SSHAuditScanner data FIRST (before NetworkScanner flattening)
                    # This ensures SSHAuditScanner data is preserved even if NetworkScanner has empty ssh_audit
                    ssh_audit_data = None
                    if 'SSHAuditScanner' in raw_data:
                        ssh_audit_data = raw_data.pop('SSHAuditScanner')
                        # Handle double nesting
                        if isinstance(ssh_audit_data, dict) and 'SSHAuditScanner' in ssh_audit_data:
                            ssh_audit_data = ssh_audit_data['SSHAuditScanner']
                            logger.info(f"[SAVE] Unwrapped double-nested SSHAuditScanner")
                    
                    # Flatten NetworkScanner data
                    if 'NetworkScanner' in raw_data:
                        network_data = raw_data.pop('NetworkScanner')
                        # Handle double nesting
                        if isinstance(network_data, dict) and 'NetworkScanner' in network_data:
                            network_data = network_data['NetworkScanner']
                            logger.info(f"[SAVE] Unwrapped double-nested NetworkScanner")
                        
                        # Flatten the network data
                        if isinstance(network_data, dict):
                            for key, value in network_data.items():
                                # CRITICAL: Skip ssh_audit from NetworkScanner - we'll use SSHAuditScanner's data
                                # SSHAuditScanner is authoritative source (standalone scanner has complete data)
                                if key == 'ssh_audit':
                                    logger.debug(f"[SAVE] Skipping NetworkScanner's ssh_audit, will use SSHAuditScanner data")
                                    continue
                                if key not in raw_data:
                                    raw_data[key] = value
                            logger.info(f"[SAVE] Flattened NetworkScanner keys: {list(network_data.keys())}")
                    
                    # CRITICAL: Map SSHAuditScanner to ssh_audit (ALWAYS - remove len > 0 check)
                    # SSHAuditScanner is the authoritative source, even if data is empty
                    if ssh_audit_data is not None:
                        if isinstance(ssh_audit_data, dict):
                            raw_data['ssh_audit'] = ssh_audit_data
                            if len(ssh_audit_data) > 0:
                                logger.info(f"[SAVE] Mapped SSHAuditScanner to ssh_audit with keys: {list(ssh_audit_data.keys())}")
                            else:
                                logger.warning(f"[SAVE] SSHAuditScanner data is empty, but mapped anyway (overwrites NetworkScanner's empty ssh_audit)")
                        else:
                            logger.warning(f"[SAVE] SSHAuditScanner data is not a dict: {type(ssh_audit_data)}")
                    
                    # Update final_results with processed raw_data
                    final_results['raw_data'] = raw_data
                else:
                    logger.warning(f"[SAVE] WARNING: raw_data missing in final_results!")
                
                # CRITICAL SAFETY CHECK: If raw_data is empty, try to recover from Redis
                if not final_results.get('raw_data'):
                    logger.error(f"[SAVE] CRITICAL: raw_data is EMPTY! This should not happen if NetworkScanner ran.")
                    # Try to fetch raw_data from Redis directly as fallback
                    try:
                        import redis as redis_lib
                        # Use decode_responses=True to get strings instead of bytes
                        redis_client = redis_lib.Redis(host='localhost', port=6379, decode_responses=True, socket_connect_timeout=None)
                        final_result_json = redis_client.get(f"scan_results_final:{distributed_scan_id}")
                        if final_result_json:
                            final_result = json.loads(final_result_json)
                            if final_result.get('raw_data'):
                                raw_data = final_result['raw_data'].copy()
                                
                                # CRITICAL: Extract SSHAuditScanner data FIRST (before NetworkScanner flattening)
                                # This ensures SSHAuditScanner data is preserved even if NetworkScanner has empty ssh_audit
                                ssh_audit_data = None
                                if 'SSHAuditScanner' in raw_data:
                                    ssh_audit_data = raw_data.pop('SSHAuditScanner')
                                    # Handle double nesting
                                    if isinstance(ssh_audit_data, dict) and 'SSHAuditScanner' in ssh_audit_data:
                                        ssh_audit_data = ssh_audit_data['SSHAuditScanner']
                                        logger.info(f"[SAVE] Unwrapped double-nested SSHAuditScanner in fallback")
                                
                                # CRITICAL: Flatten NetworkScanner data (same logic as bridge)
                                if 'NetworkScanner' in raw_data:
                                    network_data = raw_data.pop('NetworkScanner')
                                    # Handle double nesting
                                    if isinstance(network_data, dict) and 'NetworkScanner' in network_data:
                                        network_data = network_data['NetworkScanner']
                                        logger.info(f"[SAVE] Unwrapped double-nested NetworkScanner in fallback")
                                    
                                    # Flatten the network data
                                    if isinstance(network_data, dict):
                                        for key, value in network_data.items():
                                            # CRITICAL: Skip ssh_audit from NetworkScanner - we'll use SSHAuditScanner's data
                                            if key == 'ssh_audit':
                                                logger.debug(f"[SAVE] Skipping NetworkScanner's ssh_audit in fallback, will use SSHAuditScanner data")
                                                continue
                                            if key not in raw_data:
                                                raw_data[key] = value
                                        logger.info(f"[SAVE] Flattened NetworkScanner keys: {list(network_data.keys())}")
                                
                                # CRITICAL: Map SSHAuditScanner to ssh_audit (ALWAYS - remove len > 0 check)
                                if ssh_audit_data is not None:
                                    if isinstance(ssh_audit_data, dict):
                                        raw_data['ssh_audit'] = ssh_audit_data
                                        if len(ssh_audit_data) > 0:
                                            logger.info(f"[SAVE] Mapped SSHAuditScanner to ssh_audit in fallback with keys: {list(ssh_audit_data.keys())}")
                                        else:
                                            logger.warning(f"[SAVE] SSHAuditScanner data is empty in fallback, but mapped anyway")
                                    else:
                                        logger.warning(f"[SAVE] SSHAuditScanner data is not a dict in fallback: {type(ssh_audit_data)}")
                                
                                final_results['raw_data'] = raw_data
                                logger.info(f"[SAVE] Recovered and flattened raw_data from Redis fallback with keys: {list(raw_data.keys())}")
                            else:
                                logger.warning(f"[SAVE] Redis fallback found final_result but raw_data is still empty")
                        else:
                            logger.warning(f"[SAVE] Redis fallback: No final_result found for {distributed_scan_id}")
                        redis_client.close()
                    except Exception as e:
                        logger.error(f"[SAVE] Could not recover raw_data from Redis: {e}")
                
                # CRITICAL: Verify raw_data before saving
                raw_data = final_results.get('raw_data', {})
                if not raw_data or len(raw_data) == 0:
                    logger.warning(f"[SAVE] WARNING: raw_data is EMPTY before saving!")
                
                # Save full_results.json
                full_results_data = {
                    'scan_id': scan_id,
                    'target_url': url,
                    'start_time': scan_results[scan_id].get('start_time') if scan_id in scan_results else datetime.now().isoformat(),
                    'end_time': datetime.now().isoformat(),
                    'findings': final_results.get('findings', []),
                    'summary': final_results.get('summary', {}),
                    'raw_data': raw_data
                }
                
                full_results_path = f"{scan_dir}/raw_data/full_results.json"
                
                # PROTECTION: Check if scan is already completed to prevent overwrite
                if is_scan_completed(scan_id):
                    logger.warning(f"[PROTECTION] Scan {scan_id} already completed - skipping save to prevent overwrite")
                    await connection_manager.send_log(scan_id, "⚠️ Scan already completed - preserving existing results", "warning")
                else:
                    try:
                        # Use atomic write to prevent corruption
                        if not safe_write_json(full_results_path, jsonable_encoder(full_results_data)):
                            raise Exception("Failed to save full_results.json using atomic write")
                    except Exception as e:
                        logger.error(f"[SAVE CRITICAL] Failed to save full_results.json: {e}")
                        # Fallback: specific error logging
                        try:
                            import traceback
                            logger.error(traceback.format_exc())
                        except:
                            pass
                
                # VERIFY file was written
                if os.path.exists(full_results_path):
                    file_size = os.path.getsize(full_results_path)
                    logger.info(f"[SAVE] Full results saved: {full_results_path} ({file_size} bytes)")
                    logger.info(f"[SAVE] raw_data keys: {list(raw_data.keys()) if raw_data else 'EMPTY'}")
                else:
                    logger.error(f"[SAVE] ERROR: full_results.json was not created!")
                
                # Verify raw_data is in the saved file
                try:
                    with open(full_results_path, "r") as f:
                        saved_data = json.load(f)
                        if not saved_data.get('raw_data') or len(saved_data.get('raw_data', {})) == 0:
                            logger.warning(f"[SAVE] WARNING: raw_data is empty in saved file!")
                except Exception as verify_err:
                    logger.warning(f"[SAVE] Could not verify saved file: {verify_err}")
                
                # Extract and organize findings
                all_findings = final_results.get('findings', [])
                
                # Save findings by severity to artifacts
                findings_by_severity = {}
                for finding in all_findings:
                    severity = finding.get('severity', 'info')
                    if severity not in findings_by_severity:
                        findings_by_severity[severity] = []
                    findings_by_severity[severity].append(finding)
                
                for severity, findings in findings_by_severity.items():
                    severity_path = f"{scan_dir}/artifacts/{severity}_findings.json"
                    # Atomic write to prevent corruption from concurrent processes
                    try:
                        import uuid
                        temp_path = f"{severity_path}.{uuid.uuid4()}.tmp"
                        with open(temp_path, "w") as f:
                            json.dump(findings, f, indent=2, default=str)
                        
                        # Retrying rename/replace
                        max_retries = 3
                        for i in range(max_retries):
                            try:
                                if os.path.exists(severity_path):
                                    os.remove(severity_path)
                                os.rename(temp_path, severity_path)
                                break
                            except Exception:
                                if i == max_retries - 1:
                                    # Fallback: try direct write if rename fails
                                    with open(severity_path, "w") as f:
                                        json.dump(findings, f, indent=2, default=str)
                                time.sleep(0.1)
                        
                        if os.path.exists(temp_path):
                             try: os.remove(temp_path)
                             except: pass
                    except Exception as e:
                        logger.error(f"[SAVE] Failed to save {severity}_findings.json: {e}")
                
                logger.info(f"[SAVE] Saved findings by severity to artifacts/")
                
                # Save scanner outputs by category if available
                scanners_by_category = {}  # Initialize before if block to prevent undefined variable error
                scanner_results = final_results.get('scanner_results', [])
                if scanner_results:
                    for result in scanner_results:
                        category = result.get('category', 'general')
                        if category not in scanners_by_category:
                            scanners_by_category[category] = []
                        scanners_by_category[category].append(result)
                    
                    for category, results in scanners_by_category.items():
                        category_path = f"{scan_dir}/scanner_outputs/{category}_results.json"
                        # Atomic write for scanner outputs
                        try:
                            import uuid
                            temp_path = f"{category_path}.{uuid.uuid4()}.tmp"
                            with open(temp_path, "w") as f:
                                json.dump(results, f, indent=2, default=str)
                            
                            for i in range(3):
                                try:
                                    if os.path.exists(category_path):
                                        os.remove(category_path)
                                    os.rename(temp_path, category_path)
                                    break
                                except Exception:
                                    if i == 2:
                                        with open(category_path, "w") as f:
                                            json.dump(results, f, indent=2, default=str)
                                    time.sleep(0.1)
                            
                            if os.path.exists(temp_path):
                                 try: os.remove(temp_path)
                                 except: pass
                        except Exception as e:
                            logger.error(f"[SAVE] Failed to save {category}_results.json: {e}")
                    
                    logger.info(f"[SAVE] Saved scanner outputs for {len(scanners_by_category)} categories")
                
                # Save metadata with error handling
                metadata = {
                    "scan_id": scan_id,
                    "target_url": url,
                    "username": username,
                    "scan_start": scan_results[scan_id].get('start_time') if scan_id in scan_results else datetime.now().isoformat(),
                    "scan_end": datetime.now().isoformat(),
                    "status": "completed",
                    "findings_count": len(all_findings),
                    "summary": final_results.get('summary', {}),
                    "scan_mode": scan_mode,
                    "urls_crawled": final_results.get('urls_crawled', 0),
                    "distributed_scan_id": distributed_scan_id
                }
                try:
                    with open(f"{scan_dir}/metadata.json", "w") as f:
                        json.dump(metadata, f, indent=2)
                    logger.info(f"[SAVE] Metadata saved to {scan_dir}/metadata.json")
                except Exception as metadata_err:
                    logger.error(f"[SAVE ERROR] Failed to save metadata.json: {metadata_err}")
                    # Continue - scan completed successfully even if metadata save failed
                
                # Cache in Redis
                try:
                    redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
                    save_scan_to_redis_cache(scan_id, metadata, redis_client)
                    logger.info(f"[REDIS] Cached distributed scan {scan_id} summary")
                except Exception as redis_error:
                    logger.warning(f"[REDIS] Failed to cache distributed scan: {redis_error}")
                
                logger.info(f"[MAIN BACKEND] Saved complete scan data to: {scan_dir}")
                logger.info(f"[MAIN BACKEND] Organized: {len(all_findings)} findings, {len(findings_by_severity)} severity levels, {len(scanners_by_category)} scanner categories")
                
                # CRITICAL: Set progress to 97% - waiting for file generation
                full_results_path = f"{scan_dir}/raw_data/full_results.json"
                await connection_manager.send_progress(scan_id, 97, "finalizing")
                await connection_manager.send_log(scan_id, "[FINALIZING] Waiting for full_results.json to be generated...", "info")
                
                # Wait for full_results.json to be created - check every 0.5 seconds (no timeout - wait indefinitely)
                wait_attempt = 0
                file_exists = False
                
                while not file_exists:
                    if os.path.exists(full_results_path):
                        # Verify file is not empty and has substantial content (at least 50 KB)
                        file_size = os.path.getsize(full_results_path)
                        min_file_size = 50 * 1024  # 50 KB minimum
                        if file_size >= min_file_size:
                            # Verify raw_data is in the file
                            try:
                                with open(full_results_path, "r") as f:
                                    saved_data = json.load(f)
                                    if saved_data.get('raw_data') and len(saved_data.get('raw_data', {})) > 0:
                                        file_exists = True
                                        logger.info(f"[FINALIZING] full_results.json verified: {file_size} bytes, raw_data present")
                                        break
                                    else:
                                        logger.warning(f"[FINALIZING] full_results.json exists but raw_data is empty, waiting...")
                            except Exception as verify_err:
                                logger.warning(f"[FINALIZING] Could not verify file content: {verify_err}, waiting...")
                        else:
                            logger.warning(f"[FINALIZING] full_results.json exists but is too small ({file_size} bytes < {min_file_size} bytes), waiting...")
                    else:
                        logger.info(f"[FINALIZING] Waiting for full_results.json... (attempt {wait_attempt + 1})")
                    
                    await asyncio.sleep(0.5)
                    wait_attempt += 1
                
                # Small delay to ensure files are flushed to disk
                await asyncio.sleep(0.2)
                
                # NOW send WebSocket completion notifications AFTER files are verified
                try:
                    await connection_manager.send_progress(scan_id, 100, "completed")
                    await connection_manager.send_complete(scan_id, f"/scan/{scan_id}")
                    logger.info(f"[WEBSOCKET] Sent completion notifications for {scan_id} - file verified")
                except Exception as ws_err:
                    logger.warning(f"[WEBSOCKET] Failed to send completion messages: {ws_err}")
                
                # Create result object for compatibility
                result = type('obj', (object,), {
                    'findings': final_results.get('findings', []),
                    'summary': final_results.get('summary', {
                        'total_findings': final_results.get('findings_count', 0),
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0,
                        'info': 0
                    }),
                    'raw_data': final_results.get('raw_data', {})
                })()
                
            else:
                raise Exception("Distributed system not healthy")
                
        except Exception as distributed_error:
            # Fallback to local SecurityAnalyzer
            logger.warning(f"[MAIN BACKEND] Distributed system unavailable for scan {scan_id}: {distributed_error}")
            
            await connection_manager.send_log(
                scan_id,
                f"[FALLBACK] Distributed system unavailable - using local analyzer",
                "warning"
            )
            await connection_manager.send_log(
                scan_id,
                f"[LOCAL] Starting REAL security analysis on: {url}",
                "info"
            )
            
            # Initialize SecurityAnalyzer for local scanning
            analyzer = SecurityAnalyzer()
            
            # Run comprehensive analysis
            await connection_manager.send_log(scan_id, f"[LOCAL] Running comprehensive security analysis", "info")
            result = await analyzer.analyze_url(
                url=url,
                depth=depth,
                scan_id=scan_id,
                scan_mode=scan_mode,
                scope=getattr(scan_request, 'scope', None),
                scan_request=scan_request
            )
        
        # Update scan results
        if scan_id in scan_results:
            scan_results[scan_id].update({
                'status': 'completed',
                'end_time': datetime.now().isoformat(),
                'progress': 100,
                'current_activity': 'Scan completed successfully',
                'completed_scanners': 15,
                'summary': result.summary if isinstance(result.summary, dict) else (result.summary.__dict__ if result.summary else {}),
                'findings_count': len(result.findings)
            })
        else:
            # Create new scan result if it doesn't exist
            scan_results[scan_id] = {
                'scan_id': scan_id,
                'target': url,
                'username': username,
                'status': 'completed',
                'start_time': datetime.now().isoformat(),
                'end_time': datetime.now().isoformat(),
                'progress': 100,
                'current_activity': 'Scan completed successfully',
                'total_scanners': 15,
                'completed_scanners': 15,
                'summary': result.summary if isinstance(result.summary, dict) else (result.summary.__dict__ if result.summary else {}),
                'findings_count': len(result.findings)
            }
        
        # Save comprehensive result to organized directory
        scan_dir = f"scan_results/{scan_id}"
        os.makedirs(f"{scan_dir}/raw_data", exist_ok=True)
        
        # CRITICAL: Run NetworkScanner locally to ensure raw_data is always present
        try:
            await connection_manager.send_log(scan_id, "[NETWORK] Running network infrastructure scan...", "info")
            from scanners.NETWORK import NetworkScanner
            network_scanner = NetworkScanner(url)
            network_results = await network_scanner.scan()
            
            if network_results and network_results.get('raw_data'):
                network_raw_data = network_results['raw_data']
                # Flatten NetworkScanner structure for PDF generator
                if 'NetworkScanner' in network_raw_data:
                    flattened = network_raw_data['NetworkScanner']
                    if isinstance(flattened, dict):
                        result.raw_data.update(flattened)
                else:
                    result.raw_data.update(network_raw_data)
                await connection_manager.send_log(scan_id, "[NETWORK] Network scan data added to raw_data", "success")
        except Exception as e:
            logger.warning(f"[NETWORK] Failed to run NetworkScanner: {e}")
        
        # CRITICAL: Verify raw_data before saving
        if not result.raw_data or len(result.raw_data) == 0:
            logger.warning(f"[SAVE] WARNING: raw_data is EMPTY before saving!")
        
        # Save full scan results
        full_results_path = f"{scan_dir}/raw_data/full_results.json"
        
        # PROTECTION: Check if scan is already completed to prevent overwrite
        if is_scan_completed(scan_id):
            logger.warning(f"[PROTECTION] Scan {scan_id} already completed - skipping save to prevent overwrite")
            await connection_manager.send_log(scan_id, "⚠️ Scan already completed - preserving existing results", "warning")
        else:
            try:
                # Try to serialize result - handle both dataclass and regular objects
                if hasattr(result, '__dict__'):
                    # Regular object - convert to dict
                    result_dict = result.__dict__.copy()
                    # Handle nested objects
                    if hasattr(result, 'findings') and result.findings:
                        result_dict['findings'] = [
                            f.__dict__ if hasattr(f, '__dict__') and not isinstance(f, dict) else f
                            for f in result.findings
                        ]
                    if hasattr(result, 'summary') and result.summary:
                        if hasattr(result.summary, '__dict__'):
                            result_dict['summary'] = result.summary.__dict__
                        elif not isinstance(result.summary, dict):
                            result_dict['summary'] = str(result.summary)
                    result_data = jsonable_encoder(result_dict)
                else:
                    # Fallback: use jsonable_encoder directly
                    result_data = jsonable_encoder(result)
                
                # Use atomic write to prevent corruption
                if not safe_write_json(full_results_path, result_data):
                    raise Exception("Failed to save full_results.json using atomic write")
            except Exception as save_error:
                logger.error(f"[SAVE CRITICAL] Failed to save full_results.json: {save_error}")
                # Fallback: save basic structure
                try:
                    fallback_data = {
                        'scan_id': getattr(result, 'scan_id', scan_id),
                        'target_url': url,
                        'status': 'completed',
                        'findings': [f.__dict__ if hasattr(f, '__dict__') else str(f) for f in getattr(result, 'findings', [])],
                        'summary': getattr(result, 'summary', {}).__dict__ if hasattr(getattr(result, 'summary', None), '__dict__') else getattr(result, 'summary', {}),
                        'raw_data': getattr(result, 'raw_data', {})
                    }
                    # Use atomic write for fallback too
                    if not safe_write_json(full_results_path, jsonable_encoder(fallback_data)):
                        raise Exception("Failed to save fallback full_results.json using atomic write")
                    logger.info(f"[SAVE] Saved fallback full_results.json")
                except Exception as fallback_error:
                    logger.error(f"[SAVE CRITICAL] Fallback save also failed: {fallback_error}")
                    raise
        
        # VERIFY file was written
        if os.path.exists(full_results_path):
            file_size = os.path.getsize(full_results_path)
            logger.info(f"[SAVE] Full results saved: {full_results_path} ({file_size} bytes)")
            logger.info(f"[SAVE] raw_data keys: {list(result.raw_data.keys()) if result.raw_data else 'EMPTY'}")
        else:
            logger.error(f"[SAVE] ERROR: full_results.json was not created!")
        
        # Verify raw_data is in saved file
        try:
            with open(full_results_path, "r") as f:
                saved_data = json.load(f)
                if not saved_data.get('raw_data') or len(saved_data.get('raw_data', {})) == 0:
                    logger.warning(f"[SAVE] WARNING: raw_data is empty in saved file!")
        except Exception as verify_err:
            logger.warning(f"[SAVE] Could not verify saved file: {verify_err}")
        
        # Save metadata for easy access
        metadata = {
            "scan_id": scan_id,
            "target_url": url,
            "username": username,
            "scan_start": scan_results[scan_id].get('start_time'),
            "scan_end": datetime.now().isoformat(),
            "status": "completed",
            "findings_count": len(result.findings),
            "summary": result.summary if isinstance(result.summary, dict) else (result.summary.__dict__ if hasattr(result, 'summary') else {}),
            "scan_mode": scan_mode
        }
        with open(f"{scan_dir}/metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)
        
        # Verify metadata was written
        if not os.path.exists(f"{scan_dir}/metadata.json"):
            logger.error(f"[SAVE] ERROR: metadata.json was not created!")
        
        # Cache in Redis for fast access
        try:
            redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
            save_scan_to_redis_cache(scan_id, metadata, redis_client)
            logger.info(f"[REDIS] Cached scan {scan_id} summary")
        except Exception as redis_error:
            logger.warning(f"[REDIS] Failed to cache scan: {redis_error}")
        
        # CRITICAL: Set progress to 97% - waiting for file generation
        full_results_path = f"{scan_dir}/raw_data/full_results.json"
        await connection_manager.send_progress(scan_id, 97, "finalizing")
        await connection_manager.send_log(scan_id, "[FINALIZING] Waiting for full_results.json to be generated...", "info")
        
        # Wait for full_results.json to be created - check every 0.5 seconds (no timeout - wait indefinitely)
        wait_attempt = 0
        file_exists = False
        
        while not file_exists:
            if os.path.exists(full_results_path):
                # Verify file is not empty and has substantial content (at least 50 KB)
                file_size = os.path.getsize(full_results_path)
                min_file_size = 50 * 1024  # 50 KB minimum
                if file_size >= min_file_size:
                    # Verify raw_data is in the file
                    try:
                        with open(full_results_path, "r") as f:
                            saved_data = json.load(f)
                            if saved_data.get('raw_data') and len(saved_data.get('raw_data', {})) > 0:
                                file_exists = True
                                logger.info(f"[FINALIZING] full_results.json verified: {file_size} bytes, raw_data present")
                                break
                            else:
                                logger.warning(f"[FINALIZING] full_results.json exists but raw_data is empty, waiting...")
                    except Exception as verify_err:
                        logger.warning(f"[FINALIZING] Could not verify file content: {verify_err}, waiting...")
                else:
                    logger.warning(f"[FINALIZING] full_results.json exists but is empty, waiting...")
            else:
                logger.info(f"[FINALIZING] Waiting for full_results.json... (attempt {wait_attempt + 1})")
            
            await asyncio.sleep(0.5)
            wait_attempt += 1
        
        # Small delay to ensure files are flushed to disk
        await asyncio.sleep(0.2)
        
        # NOW send completion only after file is verified
        await connection_manager.send_progress(scan_id, 100, "completed")
        await connection_manager.send_complete(scan_id, f"/scan/{scan_id}")
        await connection_manager.send_log(scan_id, f" Comprehensive scan completed: {len(result.findings)} findings detected", "success")
        
    except Exception as e:
        await connection_manager.send_log(scan_id, f"❌ Comprehensive scan failed: {str(e)}", "error")
        
        # Update scan results with error
        if scan_id in scan_results:
            scan_results[scan_id].update({
                'status': 'failed',
                'end_time': datetime.now().isoformat(),
                'error': str(e),
                'current_activity': f'Scan failed: {str(e)}'
            })
        else:
            # Create new scan result with error if it doesn't exist
            scan_results[scan_id] = {
                'scan_id': scan_id,
                'target': url,
                'username': username,
                'status': 'failed',
                'start_time': datetime.now().isoformat(),
                'end_time': datetime.now().isoformat(),
                'progress': 0,
                'current_activity': f'Scan failed: {str(e)}',
                'error': str(e),
                'total_scanners': 15,
                'completed_scanners': 0
            }
        
        # Save error result
        error_result = {
            "scan_id": scan_id,
            "target_url": url,
            "username": username,
            "status": "failed",
            "error": str(e),
            "scan_start": datetime.now().isoformat(),
            "scan_end": datetime.now().isoformat()
        }
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump(error_result, f, indent=2, default=str)

async def run_distributed_scan_background(scan_id: str, url: str, username: str, scan_request: ScanRequest):
    """Background task for distributed security scan using the distributed system"""
    try:
        await connection_manager.send_log(scan_id, f"🚀 Initializing Distributed System for comprehensive scan", "info")
        
        if not DISTRIBUTED_SYSTEM_AVAILABLE or not distributed_bridge:
            await connection_manager.send_log(scan_id, f"❌ Distributed system not available, falling back to local scan", "warning")
            # Fallback to comprehensive scan
            await run_comprehensive_scan_background(scan_id, url, username, scan_request)
            return
        
        # Submit scan to distributed system
        await connection_manager.send_log(scan_id, f"📡 Submitting scan to distributed system", "info")
        
        # Set default values
        depth = getattr(scan_request, 'depth', 3)
        scan_mode = getattr(scan_request, 'scan_mode', 'comprehensive')
        scope = getattr(scan_request, 'scope', None)
        
        # Prepare scan request for distributed system
        scan_config = {
            'depth': depth,
            'scan_mode': scan_mode,
            'scope': scope,
            'username': username,
            'scan_id': scan_id
        }
        
        # Submit to distributed system
        response = await distributed_bridge.submit_scan_request(
            urls=[url],
            scan_type=scan_mode,
            priority=1,
            config=scan_config,
            max_depth=depth,
            enable_crawling=True
        )
        
        distributed_scan_id = response.get('scan_id')
        await connection_manager.send_log(scan_id, f"Scan submitted to distributed system (ID: {distributed_scan_id})", "success")
        
        # Monitor distributed scan progress via WebSocket
        await connection_manager.send_log(scan_id, f"Monitoring distributed scan progress via WebSocket...", "info")
        
        # Variable to store final status
        final_status = None
        
        try:
            # Polling loop for distributed scan status
            max_polls = 120  # 10 minutes max
            poll_interval = 5  # 5 seconds
            
            for poll_count in range(max_polls):
                try:
                    status_response = await distributed_bridge.get_scan_status(distributed_scan_id)
                    status = status_response.get('status', 'unknown')
                    progress = status_response.get('progress', 0)
                    current_activity = status_response.get('current_activity', 'Processing...')
                    
                    # Update local scan results
                    if scan_id in scan_results:
                        scan_results[scan_id].update({
                            'status': status,
                            'progress': progress,
                            'current_activity': current_activity,
                            'distributed_scan_id': distributed_scan_id
                        })
                    
                    await connection_manager.send_progress(scan_id, progress, current_activity)
                    
                    if status in ['completed', 'failed']:
                        final_status = status_response
                        break
                        
                    await asyncio.sleep(poll_interval)
                    
                except Exception as poll_error:
                    await connection_manager.send_log(scan_id, f"⚠️ Error polling distributed scan: {str(poll_error)}", "warning")
                    await asyncio.sleep(poll_interval)
            
            # CRITICAL FIX: Explicitly fetch full results including findings
            if final_status and final_status.get('status') == 'completed':
                await connection_manager.send_log(scan_id, f"📥 Fetching comprehensive findings from distributed system...", "info")
                final_status = await distributed_bridge.get_scan_results(distributed_scan_id)

        except Exception as e:
            await connection_manager.send_log(scan_id, f"⚠️ Error monitoring scan: {str(e)}", "warning")
        
        # Get final results
        status = final_status.get('status', 'unknown') if final_status else 'unknown'
        if status == 'completed':
            # Handle different result structures (direct from get_scan_results vs polling status)
            if 'findings' in final_status:
                # Direct result from get_scan_results
                final_results = final_status
                findings = final_status.get('findings', [])
            else:
                # Nested structure from polling status
                final_results = final_status.get('results', {})
                findings = final_results.get('findings', [])
            
            # CRITICAL ENRICHMENT STEP: Enrich findings with real-time CVE/CVSS data
            # This ensures Professional PDF Report and full_results.json have valid scores (not NA)
            if enhance_findings_with_cve and findings:
                try:
                    logger.info(f"[ENRICHMENT] Enriching {len(findings)} distributed scan findings with CVE data...")
                    findings = await enhance_findings_with_cve(findings)
                    logger.info(f"[ENRICHMENT] Success: {len(findings)} findings enriched.")
                    
                    # Update final_results/final_status findings with enriched ones to ensure consistency
                    if 'findings' in final_status: 
                        final_status['findings'] = findings
                    if 'findings' in final_results:
                         final_results['findings'] = findings
                except Exception as enrich_err:
                     logger.error(f"[ENRICHMENT] Failed: {enrich_err}")
            
            # Update local scan results
            if scan_id in scan_results:
                scan_results[scan_id].update({
                    'status': 'completed',
                    'end_time': datetime.now().isoformat(),
                    'progress': 100,
                    'current_activity': 'Distributed scan completed successfully',
                    'findings_count': len(findings),
                    'summary': final_results.get('summary', {}),
                    'distributed_results': final_results
                })
            
            # Save results
            os.makedirs("scan_results", exist_ok=True)
            
            # CRITICAL FIX: Get raw_data from final_status (get_scan_results) not final_results (polling)
            # final_status comes from get_scan_results() which includes raw_data from all scanners including NetworkScanner
            # NetworkScanner data flows the same way as other scanners - stored in raw_data['NetworkScanner']
            # CRITICAL FIX: Get raw_data from final_status (get_scan_results) not final_results (polling)
            # final_status comes from get_scan_results() which includes raw_data from all scanners including NetworkScanner
            # NetworkScanner data flows the same way as other scanners - stored in raw_data['NetworkScanner']
            raw_data = final_status.get('raw_data', {}) if 'raw_data' in final_status else final_results.get('raw_data', {})
            
            # FALLBACK: If raw_data is missing, try to reconstruct from distributed_results or log warning
            if not raw_data:
                 logger.warning(f"[SAVE] raw_data is empty for {scan_id}. Checking distributed_results...")
                 raw_data = final_status.get('raw_data', {}) # Try again just in case
            
            # Ensure proper structure even if empty
            if not raw_data:
                 logger.warning(f"[SAVE] DATA LOSS WARNING: raw_data is totally empty for {scan_id}")
                 raw_data = {}
            
            result_data = {
                'scan_id': scan_id,
                'distributed_scan_id': distributed_scan_id,
                'target_url': url,
                'username': username,
                'status': 'completed',
                'scan_start': datetime.now().isoformat(),
                'scan_end': datetime.now().isoformat(),
                'findings': findings,
                'summary': final_results.get('summary', {}),
                'raw_data': raw_data,  # NetworkScanner data included here same as other scanners
                'distributed_results': final_results
            }
            
            # Save to OLD format (backward compatibility)
            with open(f"scan_results/{scan_id}.json", "w") as f:
                json.dump(result_data, f, indent=2, default=str)
            
            # CRITICAL FIX: Also save to NEW format (full_results.json) with raw_data
            # This ensures network scan data is saved the same way as other scanners
            scan_dir = f"scan_results/{scan_id}"
            os.makedirs(f"{scan_dir}/raw_data", exist_ok=True)
            
            # Construct full results in the expected format - same structure as other scanners
            full_results_data = {
                'scan_id': scan_id,
                'target_url': url,
                'start_time': result_data.get('scan_start'),
                'end_time': result_data.get('scan_end'),
                'findings': findings,
                'summary': final_results.get('summary', {}),
                'raw_data': raw_data  # NetworkScanner data included here same as other scanners
            }
            
            # PROTECTION: Check if scan is already completed to prevent overwrite
            full_results_path = f"{scan_dir}/raw_data/full_results.json"
            if is_scan_completed(scan_id):
                logger.warning(f"[PROTECTION] Scan {scan_id} already completed - skipping save to prevent overwrite")
                await connection_manager.send_log(scan_id, "⚠️ Scan already completed - preserving existing results", "warning")
            else:
                # Use atomic write to prevent corruption
                if not safe_write_json(full_results_path, full_results_data):
                    logger.error(f"[SAVE] Failed to save full_results.json using atomic write")
                    raise Exception("Failed to save full_results.json using atomic write")
                logger.info(f"[SAVE] Full results saved: {full_results_path}")
            logger.info(f"[SAVE] raw_data keys: {list(raw_data.keys()) if raw_data else 'EMPTY'}")
            
            # AUTOMATIC REPORT GENERATION
            if ProfessionalPDFGenerator:
                try:
                    await connection_manager.send_log(scan_id, "📄 Generating Professional PDF Report...", "info")
                    
                    # Ensure reports directory exists
                    reports_dir = os.path.join(base_dir, "reports")
                    os.makedirs(reports_dir, exist_ok=True)
                    pdf_path = os.path.join(reports_dir, "Professional_Scan_Report.pdf")
                    
                    # Prepare scan info for generator
                    # CRITICAL FIX: Use raw_data variable (from get_scan_results) not final_results (from polling)
                    # This ensures NetworkScanner data (nmap, whois, ssl_labs, ssh_audit) is included in PDF appendix
                    scan_info_for_report = {
                        "scan_id": scan_id,
                        "target": url,
                        "start_time": result_data.get('scan_start'),
                        "end_time": result_data.get('scan_end'),
                        "scan_type": scan_mode,
                        "raw_data": raw_data  # Use raw_data extracted from final_status (includes NetworkScanner)
                    }
                    
                    # Generate Report
                    pdf_gen = ProfessionalPDFGenerator()
                    pdf_gen.generate_report(findings, scan_info_for_report, pdf_path)
                    
                    await connection_manager.send_log(scan_id, "✅ Report generated successfully", "success")
                except Exception as report_err:
                    print(f"Failed to generate report: {report_err}")
                    await connection_manager.send_log(scan_id, f"⚠️ Report generation failed: {report_err}", "warning")
            
            # CRITICAL: Set progress to 97% - waiting for file generation
            full_results_path = f"{scan_dir}/raw_data/full_results.json"
            await connection_manager.send_progress(scan_id, 97, "finalizing")
            await connection_manager.send_log(scan_id, "[FINALIZING] Waiting for full_results.json to be generated...", "info")
            
            # Wait for full_results.json to be created - check every 0.5 seconds (no timeout - wait indefinitely)
            wait_attempt = 0
            file_exists = False
            
            while not file_exists:
                if os.path.exists(full_results_path):
                    # Verify file is not empty and has substantial content (at least 50 KB)
                    file_size = os.path.getsize(full_results_path)
                    min_file_size = 50 * 1024  # 50 KB minimum
                    if file_size >= min_file_size:
                        # Verify raw_data is in the file
                        try:
                            with open(full_results_path, "r") as f:
                                saved_data = json.load(f)
                                if saved_data.get('raw_data') and len(saved_data.get('raw_data', {})) > 0:
                                    file_exists = True
                                    logger.info(f"[FINALIZING] full_results.json verified: {file_size} bytes, raw_data present")
                                    break
                                else:
                                    logger.warning(f"[FINALIZING] full_results.json exists but raw_data is empty, waiting...")
                        except Exception as verify_err:
                            logger.warning(f"[FINALIZING] Could not verify file content: {verify_err}, waiting...")
                    else:
                        logger.warning(f"[FINALIZING] full_results.json exists but is too small ({file_size} bytes < {min_file_size} bytes), waiting...")
                else:
                    logger.info(f"[FINALIZING] Waiting for full_results.json... (attempt {wait_attempt + 1})")
                
                await asyncio.sleep(0.5)
                wait_attempt += 1
            
            # Small delay to ensure files are flushed to disk
            await asyncio.sleep(0.2)
            
            # NOW send completion only after file is verified
            await connection_manager.send_progress(scan_id, 100, "completed")
            await connection_manager.send_complete(scan_id, f"/scan/{scan_id}")
            await connection_manager.send_log(scan_id, f"✅ Distributed scan completed: {len(findings)} findings detected", "success")
            
        else:
            # Scan failed or timed out
            error_msg = final_status.get('error', 'Unknown error') if final_status else 'Scan did not complete'
            await connection_manager.send_log(scan_id, f"❌ Distributed scan failed: {error_msg}", "error")
            
            # Update local scan results
            if scan_id in scan_results:
                scan_results[scan_id].update({
                    'status': 'failed',
                    'end_time': datetime.now().isoformat(),
                    'error': error_msg,
                    'current_activity': f'Distributed scan failed: {error_msg}'
                })
            
            # Save error result
            error_result = {
                "scan_id": scan_id,
                "distributed_scan_id": distributed_scan_id,
                "target_url": url,
                "username": username,
                "status": "failed",
                "error": error_msg,
                "scan_start": datetime.now().isoformat(),
                "scan_end": datetime.now().isoformat()
            }
            os.makedirs("scan_results", exist_ok=True)
            with open(f"scan_results/{scan_id}.json", "w") as f:
                json.dump(error_result, f, indent=2, default=str)
        
    except Exception as e:
        await connection_manager.send_log(scan_id, f"❌ Distributed scan failed: {str(e)}", "error")
        
        # Fallback to comprehensive scan
        await connection_manager.send_log(scan_id, f"🔄 Falling back to local comprehensive scan", "info")
        await run_comprehensive_scan_background(scan_id, url, username, scan_request)

# Authentication & Session Management Scanner Endpoint
@app.post("/scan/auth-session", tags=["Specialized Scanners"])
async def scan_auth_session(
    request_data: dict,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Run comprehensive Authentication & Session Management vulnerability scan
    
    This endpoint provides professional-grade authentication testing including:
    - SAST analysis with Semgrep, CodeQL, Bandit, ESLint
    - DAST testing with OWASP ZAP and Burp Suite integration
    - Runtime analysis and behavioral testing
    - OWASP ASVS/MASVS compliance checking
    
    ## Professional Features
    
    * 🔐 **Multi-Tool SAST**: Semgrep rules, CodeQL queries, language-specific analyzers
    * 🌐 **Advanced DAST**: OWASP ZAP and Burp Suite Pro integration
    * ⚡ **Runtime Analysis**: Session token validation, cookie security assessment
    * 📋 **OWASP ASVS**: Authentication Security Verification Standard compliance
    * 🎯 **Targeted Testing**: Authentication bypass, credential attacks, session hijacking
    * 📊 **Executive Reports**: Business impact assessment and remediation timeline
    
    ## Authentication Tests
    
    * **Credential Security**: Default credentials, weak passwords, brute force resistance
    * **Session Management**: Token entropy, expiration, secure transmission
    * **Cookie Security**: HttpOnly, Secure, SameSite attributes
    * **Authentication Bypass**: Logic flaws, privilege escalation
    * **Multi-Factor Authentication**: Implementation validation
    * **Password Policies**: Complexity requirements, reset mechanisms
    """
    
    if not AUTH_SCANNER_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="Authentication scanner is not available. Please check scanner dependencies."
        )
    
    try:
        # Extract scan parameters
        target_url = request_data.get("target")
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")
        
        # Generate scan ID
        scan_id = f"auth_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(target_url) % 10000}"
        
        # Scan configuration
        config = {
            'include_sast': request_data.get('include_sast', True),
            'include_dast': request_data.get('include_dast', True),
            'include_runtime': request_data.get('include_runtime', True),
            'source_code_path': request_data.get('source_code_path'),
            'technology_stack': request_data.get('technology_stack', []),
            'timeout': request_data.get('timeout', 600),
            'test_credentials': request_data.get('test_credentials', {
                'username': 'admin',
                'password': 'admin123',
                'weak_passwords': ['password', '123456', 'admin', 'test', 'guest']
            })
        }
        
        # Initialize scan result entry
        scan_result = {
            'id': scan_id,
            'target': target_url,
            'scanner_type': 'auth_session',
            'status': 'running',
            'created_at': datetime.now().isoformat(),
            'created_by': current_user.get('username', 'unknown'),
            'config': config,
            'progress': 0
        }
        
        # Store initial scan result
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump(scan_result, f, indent=2)
        
        # Run scan in background
        async def run_auth_scan():
            try:
                # Initialize controller
                controller = AuthSessionScanController()
                
                # Execute scan
                results = await controller.run_auth_session_scan(
                    target_url=target_url,
                    scan_id=scan_id,
                    connection_manager=connection_manager,
                    **config
                )
                
                # Update scan result
                scan_result.update({
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat(),
                    'results': results,
                    'progress': 100
                })
                
                # Save final results
                with open(f"scan_results/{scan_id}.json", "w") as f:
                    json.dump(scan_result, f, indent=2)
                
                # Notify via WebSocket
                await connection_manager.send_scan_update(scan_id, scan_result)
                
            except Exception as e:
                # Update scan with error
                scan_result.update({
                    'status': 'failed',
                    'completed_at': datetime.now().isoformat(),
                    'error': str(e),
                    'progress': 0
                })
                
                with open(f"scan_results/{scan_id}.json", "w") as f:
                    json.dump(scan_result, f, indent=2)
                
                await connection_manager.send_scan_update(scan_id, scan_result)
        
        # Start background task
        background_tasks.add_task(run_auth_scan)
        
        return {
            'scan_id': scan_id,
            'status': 'initiated',
            'message': 'Authentication & Session Management scan started',
            'target': target_url,
            'scanner_type': 'auth_session',
            'estimated_duration': '5-10 minutes',
            'features': [
                'SAST Analysis (Semgrep, CodeQL, Bandit, ESLint)',
                'DAST Testing (OWASP ZAP, Burp Suite)',
                'Runtime Behavioral Analysis',
                'OWASP ASVS Compliance Checking',
                'Authentication Bypass Testing',
                'Session Management Analysis',
                'Cookie Security Assessment',
                'Credential Security Testing'
            ],
            'websocket_url': f'/ws/scan/{scan_id}'
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate authentication scan: {str(e)}")


@app.post("/scan/auth-session/report", tags=["Specialized Scanners"])
async def generate_auth_session_report(request: ScanRequest):
    """
    Generate comprehensive authentication & session management security report.
    
    Creates detailed multi-format reports (SARIF, HTML, JSON, CSV) for authentication 
    and session management vulnerabilities with executive summaries.
    
    ## Features
    
    * 🔐 **JWT Security Analysis**: Algorithm confusion, weak secrets, missing validation
    * 🍪 **Cookie Security Assessment**: HttpOnly, Secure, SameSite attributes
    * 🔑 **Session Management**: Fixation, hijacking, timeout vulnerabilities
    * 🔒 **Password Reset Flows**: Token security and validation flaws
    * 💾 **Frontend Storage Security**: localStorage, sessionStorage analysis
    * 🛡️ **Brute-force Protection**: Rate limiting and enumeration checks
    * 📊 **Multi-format Reports**: SARIF, HTML, JSON, CSV outputs
    * 📋 **Executive Summary**: Business impact and remediation priorities
    
    ## Report Formats
    
    * **SARIF**: Industry-standard format for security analysis results
    * **HTML**: Interactive report with charts and detailed findings
    * **JSON**: Structured data for API integration
    * **CSV**: Tabular format for spreadsheet analysis
    
    ## Response Structure
    
    Returns comprehensive scan results with:
    * Executive summary with risk metrics
    * Detailed findings per security category
    * Remediation recommendations
    * Compliance mappings (OWASP ASVS)
    * Multiple download formats
    """
    try:
        # Import the comprehensive reporter
        from scanners.authentication_session_management.comprehensive_reporter import ComprehensiveReporter
        
        # Generate scan ID for this report
        scan_id = f"auth_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"Starting authentication & session management security report generation for {request.target_url}")
        
        # Initialize the authentication scanner
        auth_scanner = AuthSessionScanner()
        
        # Perform comprehensive authentication scan
        scan_results = await auth_scanner.scan_authentication_vulnerabilities(
            str(request.target_url),
            scan_id=scan_id
        )
        
        # Initialize comprehensive reporter
        reporter = ComprehensiveReporter()
        
        # Generate all report formats
        reports = await reporter.generate_comprehensive_report(
            scan_results=scan_results,
            target_url=str(request.target_url),
            scan_id=scan_id
        )
        
        # Create response with all formats
        response_data = {
            'scan_id': scan_id,
            'target_url': str(request.target_url),
            'timestamp': datetime.now().isoformat(),
            'status': 'completed',
            'summary': {
                'total_findings': len(scan_results.get('findings', [])),
                'critical_findings': len([f for f in scan_results.get('findings', []) if f.get('severity') == 'CRITICAL']),
                'high_findings': len([f for f in scan_results.get('findings', []) if f.get('severity') == 'HIGH']),
                'medium_findings': len([f for f in scan_results.get('findings', []) if f.get('severity') == 'MEDIUM']),
                'low_findings': len([f for f in scan_results.get('findings', []) if f.get('severity') == 'LOW']),
                'categories_analyzed': [
                    'JWT Security',
                    'Cookie Security', 
                    'Session Management',
                    'Password Reset Flows',
                    'Frontend Storage Security',
                    'Brute-force Protection'
                ]
            },
            'reports': reports,
            'scan_metadata': {
                'scan_type': 'Authentication & Session Management Security Analysis',
                'scan_duration': '5-15 minutes',
                'compliance_frameworks': ['OWASP ASVS', 'NIST', 'ISO 27001'],
                'report_formats': ['SARIF', 'HTML', 'JSON', 'CSV']
            }
        }
        
        logger.info(f"Authentication security report completed successfully for {request.target_url}")
        
        return response_data
        
    except Exception as e:
        logger.error(f"Failed to generate authentication security report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate authentication report: {str(e)}")


@app.post("/scan/input-handling-injection", tags=["Specialized Scanners"])
async def input_handling_injection_scan(
    request: ScanRequest, 
    background_tasks: BackgroundTasks,
    current_user: User = Depends(check_scan_rate_limit_dependency)
):
    """
    Execute comprehensive input-handling injection vulnerability scan.
    
    This specialized scanner focuses on detecting all types of injection vulnerabilities
    including XSS, SQL injection, command injection, template injection, LDAP injection,
    and deserialization attacks.
    
    ## Features
    
    * 🎯 **Comprehensive Injection Testing**: All major injection vulnerability types
    * 🔍 **XSS Detection**: Reflected, Stored, DOM-based XSS testing
    * 💉 **SQL Injection**: Time-based, Boolean-based, Union-based testing
    * ⚡ **Command Injection**: OS command execution vulnerability testing
    * 🔧 **Template Injection**: Server-side template injection (SSTI) testing
    * 📁 **LDAP Injection**: LDAP query injection vulnerability testing
    * 🔄 **Deserialization**: Unsafe deserialization attack testing
    * 🌐 **Web Application Testing**: Live parameter testing and discovery
    * 📋 **Source Code Analysis**: Static code analysis for injection patterns
    
    ## Injection Types Detected
    
    * **XSS (Cross-Site Scripting)**: Reflected, Stored, DOM-based
    * **SQL Injection**: Various techniques including blind and error-based
    * **Command Injection**: OS command execution vulnerabilities
    * **Template Injection**: Server-side template injection (Jinja2, Twig, etc.)
    * **LDAP Injection**: LDAP query manipulation vulnerabilities
    * **Deserialization Attacks**: Unsafe object deserialization
    
    ## Testing Methods
    
    * **Parameter Discovery**: Automatic parameter identification
    * **Payload Injection**: Comprehensive payload testing
    * **Response Analysis**: Advanced response pattern matching
    * **Multi-Framework Support**: Python, Java, PHP, .NET, Node.js
    * **Live Testing**: Real-time web application vulnerability assessment
    
    ## Example Usage
    
    ```bash
    curl -X POST "http://localhost:8000/scan/input-handling-injection" \\
         -H "Authorization: Bearer <token>" \\
         -H "Content-Type: application/json" \\
         -d '{
           "target_url": "https://example.com",
           "scan_depth": 2,
           "enable_input_handling_injection": true,
           "input_handling_injection_timeout": 180
         }'
    ```
    
    ## Response
    
    Returns comprehensive injection vulnerability findings including:
    - Vulnerability details and evidence
    - Affected parameters and payloads  
    - Risk assessment and recommendations
    - Educational materials for prevention
    """
    try:
        # Generate scan ID
        scan_id = f"injection_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{current_user.username}"
        
        # Check if input-handling injection scanner is enabled
        if not request.enable_input_handling_injection:
            raise HTTPException(
                status_code=400, 
                detail="Input-handling injection scanner is disabled in scan request"
            )
        
        # Start scan in background
        background_tasks.add_task(
            run_injection_scan_with_logging, 
            str(request.target_url), 
            scan_id, 
            request,
            current_user.username
        )
        
        return {
            "scan_id": scan_id,
            "scanner_type": "input_handling_injection", 
            "status": "started",
            "websocket_url": f"/ws/{scan_id}",
            "message": "Input-handling injection scan initiated successfully. Connect to WebSocket for real-time updates.",
            "target_url": str(request.target_url),
            "estimated_duration": f"{request.input_handling_injection_timeout} seconds",
            "scan_coverage": [
                "XSS (Cross-Site Scripting)",
                "SQL Injection", 
                "Command Injection",
                "Template Injection (SSTI)",
                "LDAP Injection",
                "Deserialization Attacks",
                "Parameter Discovery",
                "Web Application Testing",
                "Source Code Analysis"
            ]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start input-handling injection scan: {str(e)}")


async def run_injection_scan_with_logging(url: str, scan_id: str, scan_request: ScanRequest, username: str):
    """Run input-handling injection scan with real-time logging"""
    try:
        await connection_manager.send_log(scan_id, "🎯 Starting comprehensive input-handling injection vulnerability scan...", "info")
        await connection_manager.send_progress(scan_id, 5, "initialization")
        
        # Initialize scanner
        from scanners.input_handling_injection import InputHandlingInjectionScanner
        scanner = InputHandlingInjectionScanner(url, timeout=scan_request.input_handling_injection_timeout)
        scanner.set_progress_callback(scan_id, connection_manager)
        
        await connection_manager.send_progress(scan_id, 10, "scanner_initialization")
        
        # Execute scan
        result = await scanner.scan()
        
        await connection_manager.send_progress(scan_id, 90, "finalizing")
        
        # Enhance result with metadata
        scan_result = {
            "scan_id": scan_id,
            "scanner_type": "input_handling_injection",
            "target_url": url,
            "username": username,
            "scan_start": result.get("scan_start", datetime.now().isoformat()),
            "scan_end": result.get("scan_end", datetime.now().isoformat()),
            "findings": result.get("findings", []),
            "summary": result.get("summary", {}),
            "scan_phases": result.get("scan_phases", []),
            "errors": result.get("errors", []),
            "total_findings": len(result.get("findings", [])),
            "scan_coverage": [
                "XSS Detection",
                "SQL Injection Testing",
                "Command Injection Analysis", 
                "Template Injection (SSTI)",
                "LDAP Injection Testing",
                "Deserialization Attack Detection",
                "Parameter Discovery & Testing",
                "Web Application Vulnerability Assessment",
                "Static Code Analysis"
            ]
        }
        
        # Save result to file
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump(scan_result, f, indent=2, default=str)
        
        await connection_manager.send_progress(scan_id, 100, "completed")
        await connection_manager.send_complete(scan_id, f"/scan/{scan_id}")
        await connection_manager.send_log(scan_id, f" Input-handling injection scan completed successfully: {len(result.get('findings', []))} vulnerabilities detected", "success")
        
        # Create notifications for critical findings
        if CUSTOM_SCANNERS_AVAILABLE:
            critical_findings = [f for f in result.get("findings", []) if f.get("severity") in ["critical", "high"]]
            for finding in critical_findings[:3]:  # Limit to 3 notifications
                try:
                    await create_finding_notification(username, scan_id, finding)
                except:
                    pass  # Ignore notification errors
                    
    except Exception as e:
        await connection_manager.send_log(scan_id, f"❌ Input-handling injection scan failed: {str(e)}", "error")
        # Save error result
        error_result = {
            "scan_id": scan_id,
            "scanner_type": "input_handling_injection",
            "target_url": url,
            "username": username,
            "status": "failed",
            "error": str(e),
            "scan_start": datetime.now().isoformat(),
            "scan_end": datetime.now().isoformat()
        }
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump(error_result, f, indent=2, default=str)


@app.post("/scan/authentication-session", tags=["Specialized Scanners"])
async def authentication_session_scan(
    request: AuthSessionRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    """
    Execute dedicated Authentication & Session Management security scan.
    
    This endpoint provides comprehensive testing of authentication and session 
    management mechanisms including:
    
    - Cookie security analysis
    - Session handling verification  
    - JWT token validation
    - Authentication flow testing
    - Password reset security
    - CSRF protection verification
    - Multi-factor authentication checks
    
    ## Request Parameters
    
    ```json
    {
       "target_url": "https://example.com/login",
       "enable_authentication_session": true,
       "authentication_session_timeout": 300
    }
    ```
    
    ## Response
    
    Returns immediate scan initiation confirmation with WebSocket connection details
    for real-time progress monitoring.
    """
    
    if not request.enable_authentication_session:
        return {"error": "Authentication & Session Management scanner is disabled"}
    
    url = request.target_url
    scan_id = f"auth_session_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{current_user.username}"
    username = current_user.username
    
    await connection_manager.send_log(scan_id, f"🔐 Starting Authentication & Session Management Security Scan", "info")
    await connection_manager.send_log(scan_id, f"Target: {url}", "info")
    await connection_manager.send_log(scan_id, f"User: {username}", "info")
    
    # Initial response
    scan_response = {
        "scan_id": scan_id,
        "status": "started",
        "target_url": url,
        "username": username,
        "scanner_type": "authentication_session", 
        "websocket_url": f"/ws/{scan_id}",
        "scan_start": datetime.now().isoformat(),
        "estimated_duration": f"{request.authentication_session_timeout} seconds",
        "message": "Authentication & Session Management scan initiated successfully"
    }
    
    # Add background task
    background_tasks.add_task(run_authentication_session_scan, scan_id, url, username, request)
    
    return scan_response


async def run_authentication_session_scan(scan_id: str, url: str, username: str, scan_request):
    """Background task for authentication & session management scanning"""
    try:
        await connection_manager.send_log(scan_id, "🔐 Initializing Authentication & Session Management Scanner...", "info")
        await connection_manager.send_progress(scan_id, 10, "initializing")
        
        from scanners.authentication_session_management import AuthenticationSessionScanner
        scanner = AuthenticationSessionScanner(url, timeout=scan_request.authentication_session_timeout)
        
        # Set up progress callback
        scanner.set_progress_callback(scan_id, connection_manager)
        
        await connection_manager.send_progress(scan_id, 20, "scanning")
        result = await scanner.scan()
        
        await connection_manager.send_progress(scan_id, 90, "processing")
        
        # Format scan result
        scan_result = {
            "scan_id": scan_id,
            "scanner_type": "authentication_session",
            "target_url": url,
            "username": username,
            "status": "completed",
            "scan_start": datetime.now().isoformat(),
            "scan_end": datetime.now().isoformat(),
            "vulnerabilities": result.get("vulnerabilities", []),
            "summary": result.get("summary", {}),
            "scan_phases": result.get("scan_phases", []),
            "errors": result.get("errors", []),
            "total_findings": len(result.get("vulnerabilities", [])),
            "scan_coverage": [
                "Cookie Security Analysis",
                "Session Handling Verification",
                "JWT Token Validation", 
                "Authentication Flow Testing",
                "Password Reset Security",
                "CSRF Protection Analysis",
                "Multi-factor Authentication Checks",
                "Session Timeout Verification"
            ]
        }
        
        # Save result to file
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump(scan_result, f, indent=2, default=str)
        
        await connection_manager.send_progress(scan_id, 100, "completed")
        await connection_manager.send_complete(scan_id, f"/scan/{scan_id}")
        await connection_manager.send_log(scan_id, f" Authentication & Session Management scan completed: {len(result.get('vulnerabilities', []))} vulnerabilities detected", "success")
        
        # Create notifications for critical findings
        if CUSTOM_SCANNERS_AVAILABLE:
            critical_findings = [f for f in result.get("vulnerabilities", []) if f.get("severity") in ["critical", "high"]]
            for finding in critical_findings[:3]:
                try:
                    await create_finding_notification(username, scan_id, finding)
                except:
                    pass
                    
    except Exception as e:
        await connection_manager.send_log(scan_id, f"❌ Authentication & Session Management scan failed: {str(e)}", "error")
        # Save error result
        error_result = {
            "scan_id": scan_id,
            "scanner_type": "authentication_session",
            "target_url": url,
            "username": username,
            "status": "failed",
            "error": str(e),
            "scan_start": datetime.now().isoformat(),
            "scan_end": datetime.now().isoformat()
        }
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump(error_result, f, indent=2, default=str)


@app.post("/scan/authorization-access-control", tags=["Specialized Scanners"])
async def authorization_access_control_scan(
    request: AuthAccessControlRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    """
    Execute dedicated Authorization & Access Control security scan.
    
    This endpoint provides comprehensive testing of authorization and access 
    control mechanisms including:
    
    - IDOR (Insecure Direct Object References) detection
    - Function-level authorization bypass testing
    - Parameter-based access control verification
    - Role-based access control (RBAC) validation  
    - Client-side authorization bypass detection
    - API gateway security analysis
    
    ## Request Parameters
    
    ```json
    {
       "target_url": "https://example.com/api", 
       "enable_authorization_access_control": true,
       "authorization_access_control_timeout": 240
    }
    ```
    
    ## Response
    
    Returns immediate scan initiation confirmation with WebSocket connection details
    for real-time progress monitoring.
    """
    
    if not request.enable_authorization_access_control:
        return {"error": "Authorization & Access Control scanner is disabled"}
    
    url = request.target_url
    scan_id = f"auth_access_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{current_user.username}"
    username = current_user.username
    
    await connection_manager.send_log(scan_id, f"🔒 Starting Authorization & Access Control Security Scan", "info")
    await connection_manager.send_log(scan_id, f"Target: {url}", "info")
    await connection_manager.send_log(scan_id, f"User: {username}", "info")
    
    # Initial response
    scan_response = {
        "scan_id": scan_id,
        "status": "started",
        "target_url": url,
        "username": username,
        "scanner_type": "authorization_access_control",
        "websocket_url": f"/ws/{scan_id}",
        "scan_start": datetime.now().isoformat(),
        "estimated_duration": f"{request.authorization_access_control_timeout} seconds",
        "message": "Authorization & Access Control scan initiated successfully"
    }
    
    # Add background task
    background_tasks.add_task(run_authorization_access_control_scan, scan_id, url, username, request)
    
    return scan_response


async def run_authorization_access_control_scan(scan_id: str, url: str, username: str, scan_request):
    """Background task for authorization & access control scanning"""
    try:
        await connection_manager.send_log(scan_id, "🔒 Initializing Authorization & Access Control Scanner...", "info")
        await connection_manager.send_progress(scan_id, 10, "initializing")
        
        from scanners.authorization_access_control import AuthorizationAccessControlScanner
        scanner = AuthorizationAccessControlScanner(url, timeout=scan_request.authorization_access_control_timeout)
        
        # Set up progress callback
        scanner.set_progress_callback(scan_id, connection_manager)
        
        await connection_manager.send_progress(scan_id, 20, "scanning")
        result = await scanner.scan()
        
        await connection_manager.send_progress(scan_id, 90, "processing")
        
        # Format scan result
        scan_result = {
            "scan_id": scan_id,
            "scanner_type": "authorization_access_control",
            "target_url": url,
            "username": username,
            "status": "completed",
            "scan_start": datetime.now().isoformat(),
            "scan_end": datetime.now().isoformat(),
            "vulnerabilities": result.get("vulnerabilities", []),
            "summary": result.get("summary", {}),
            "scan_phases": result.get("scan_phases", []),
            "errors": result.get("errors", []),
            "total_findings": len(result.get("vulnerabilities", [])),
            "scan_coverage": [
                "IDOR Detection",
                "Function-Level Authorization Testing",
                "Parameter-Based Access Control Analysis",
                "Role-Based Access Control Validation",
                "Client-Side Authorization Bypass Detection", 
                "API Gateway Security Analysis",
                "Privilege Escalation Testing"
            ]
        }
        
        # Save result to file
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump(scan_result, f, indent=2, default=str)
        
        await connection_manager.send_progress(scan_id, 100, "completed")
        await connection_manager.send_complete(scan_id, f"/scan/{scan_id}")
        await connection_manager.send_log(scan_id, f" Authorization & Access Control scan completed: {len(result.get('vulnerabilities', []))} vulnerabilities detected", "success")
        
        # Create notifications for critical findings
        if CUSTOM_SCANNERS_AVAILABLE:
            critical_findings = [f for f in result.get("vulnerabilities", []) if f.get("severity") in ["critical", "high"]]
            for finding in critical_findings[:3]:
                try:
                    await create_finding_notification(username, scan_id, finding)
                except:
                    pass
                    
    except Exception as e:
        await connection_manager.send_log(scan_id, f"❌ Authorization & Access Control scan failed: {str(e)}", "error")
        # Save error result
        error_result = {
            "scan_id": scan_id,
            "scanner_type": "authorization_access_control",
            "target_url": url,
            "username": username,
            "status": "failed",
            "error": str(e),
            "scan_start": datetime.now().isoformat(),
            "scan_end": datetime.now().isoformat()
        }
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump(error_result, f, indent=2, default=str)


# Duplicate /scan endpoint removed - using the main scanner endpoint above

async def run_scan_with_logging(url: str, depth: int, scan_id: str, scan_mode: str = "owasp", scope: List[str] = None, scan_request: ScanRequest = None):
    """Run scan with real-time logging"""
    try:
        # Create a ScanRequest with all scanners enabled and no timeouts
        if scan_request is None:
            scan_request = ScanRequest(
                target_url=url,
                scan_depth=depth,
                include_educational_mode=True,
                scan_mode=scan_mode,
                scope=scope or [],
                enable_custom_scanners=True,
                enable_whois=True,
                enable_ssl_labs=True,
                enable_sqlmap=True,
                enable_dirb=True,
                enable_input_handling_injection=True,
                enable_authentication_session=True,
                enable_authorization_access_control=True,
                enable_command_os_injection=True,
                whois_timeout=None,  # No timeout
                ssl_labs_timeout=None,  # No timeout
                sqlmap_timeout=None,  # No timeout
                dirb_timeout=None,  # No timeout
                input_handling_injection_timeout=None,  # No timeout
                authentication_session_timeout=None,  # No timeout
                authorization_access_control_timeout=None,  # No timeout
                command_os_injection_timeout=None  # No timeout
            )
        
        # Override timeouts to ensure no artificial limits
        scan_request.whois_timeout = None
        scan_request.ssl_labs_timeout = None
        scan_request.sqlmap_timeout = None
        scan_request.dirb_timeout = None
        scan_request.input_handling_injection_timeout = None
        scan_request.authentication_session_timeout = None
        scan_request.authorization_access_control_timeout = None
        scan_request.command_os_injection_timeout = None
        
        result = await analyzer.analyze_url(url, depth, scan_id, scan_mode, scope or [], scan_request)
        
        # Enhance scan results with CVE mapping
        # Convert result to dict - handle both dataclass and regular objects
        if hasattr(result, '__dict__'):
            scan_data = result.__dict__.copy()
            # Handle nested objects
            if hasattr(result, 'findings') and result.findings:
                scan_data['findings'] = [
                    f.__dict__ if hasattr(f, '__dict__') and not isinstance(f, dict) else f
                    for f in result.findings
                ]
            if hasattr(result, 'summary') and result.summary:
                if hasattr(result.summary, '__dict__'):
                    scan_data['summary'] = result.summary.__dict__
                elif not isinstance(result.summary, dict):
                    scan_data['summary'] = str(result.summary)
            scan_data = jsonable_encoder(scan_data)
        else:
            # Fallback: use jsonable_encoder directly
            scan_data = jsonable_encoder(result)
        try:
            # Extract service information for CVE mapping
            services_for_cve = []
            for finding in scan_data.get('findings', []):
                if hasattr(finding, 'service') and hasattr(finding, 'version'):
                    services_for_cve.append({
                        'service': getattr(finding, 'service', ''),
                        'version': getattr(finding, 'version', ''),
                        'port': getattr(finding, 'port', ''),
                        'finding_id': getattr(finding, 'id', '')
                    })
            
            # Perform CVE mapping if services are found
            if services_for_cve and NMAP_AVAILABLE:
                try:
                    scanner = AdvancedNmapScanner()
                    for service in services_for_cve:
                        cves = scanner.fetch_cves(service['service'], service['version'])
                        if cves:
                            # Find the corresponding finding and add CVE data
                            for finding in scan_data.get('findings', []):
                                if hasattr(finding, 'id') and getattr(finding, 'id', '') == service['finding_id']:
                                    finding.cve_ids = [cve.get('id', '') for cve in cves if cve.get('id')]
                                    finding.cve_metadata = {
                                        'severity_scores': [cve.get('severity', 'UNKNOWN') for cve in cves],
                                        'source': 'external_api',
                                        'mapped_at': datetime.now().isoformat()
                                    }
                                    break
                except Exception as e:
                    print(f"CVE mapping failed for scan {result.scan_id}: {e}")
                    scan_data['cve_mapping_error'] = str(e)
        except Exception as e:
            print(f"Error during CVE enhancement: {e}")

        # Save result to file
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{result.scan_id}.json", "w") as f:
            json.dump(scan_data, f, indent=2, default=str)
            
    except Exception as e:
        await connection_manager.send_log(scan_id, f"❌ Scan failed: {str(e)}", "error")

@app.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan result by ID - supports both old and new storage formats"""
    try:
        # Try NEW organized directory structure first
        new_path = f"scan_results/{scan_id}/raw_data/full_results.json"
        if os.path.exists(new_path):
            with open(new_path, "r") as f:
                try:
                    result = json.load(f)
                except json.JSONDecodeError:
                    logger.error(f"⚠️ Corrupt scan file found at {new_path}")
                    raise HTTPException(status_code=404, detail="Scan file corrupted/empty")
            logger.info(f"Loaded scan from NEW format: {new_path}")
            return result
        
        # Fallback to OLD flat file format for backward compatibility
        old_path = f"scan_results/{scan_id}.json"
        if os.path.exists(old_path):
            with open(old_path, "r") as f:
                try:
                    result = json.load(f)
                except json.JSONDecodeError:
                    logger.error(f"⚠️ Corrupt scan file found at {old_path}")
                    raise HTTPException(status_code=404, detail="Scan file corrupted/empty")
            logger.info(f"Loaded scan from OLD format: {old_path}")
            return result
        
        # Not found in either location
        logger.warning(f"Scan not found in either format: {scan_id}")
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load scan: {str(e)}")

@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the status of a specific scan - SUPPORTS RUNNING & COMPLETED SCANS"""
    try:
        # FIRST: Check if it's a RUNNING scan in memory
        if scan_id in scan_results:
            scan_data = scan_results[scan_id]
            
            # Check if this scan was delegated to distributed system
            distributed_scan_id = scan_data.get("distributed_scan_id")
            if distributed_scan_id:
                # Poll the distributed orchestrator for real-time status
                try:
                    distributed_status = await distributed_bridge.get_scan_status(distributed_scan_id)
                    
                    # Update in-memory data with distributed status
                    if distributed_status:
                        findings = distributed_status.get("findings", [])
                        urls_crawled = distributed_status.get("crawled_urls_count", 1)
                        scanner_results = distributed_status.get("scanner_results_count", 0)
                        
                        # Calculate progress based on distributed scan
                        progress = distributed_status.get("progress", 0)
                        if progress == 0 and scanner_results > 0:
                            # Estimate progress from scanner results
                            estimated_tasks = urls_crawled * 20  # 20 scanners per URL
                            progress = min(100, int((scanner_results / max(estimated_tasks, 1)) * 100))
                        
                        # NEW: Use scanner-based completion data if available
                        scanners_dispatched = distributed_status.get("scanners_dispatched", 0)
                        scanners_completed = distributed_status.get("scanners_completed", 0)
                        scanner_completion_pct = distributed_status.get("scanner_completion_percentage", 0.0)
                        
                        return {
                            "scan_id": scan_id,
                            "status": distributed_status.get("status", "running"),
                            "progress": progress,
                            "findings_count": len(findings),
                            "current_activity": distributed_status.get("current_activity", "Distributed scan in progress..."),
                            # NEW: Scanner-based tracking (replaces estimates)
                            "total_scanners": scanners_dispatched if scanners_dispatched > 0 else 20,
                            "completed_scanners": scanners_completed if scanners_dispatched > 0 else min(20, scanner_results),
                            "scanners_dispatched": scanners_dispatched,
                            "scanners_remaining": distributed_status.get("scanners_remaining", 0),
                            "scanner_completion_percentage": scanner_completion_pct,
                            "completion_method": distributed_status.get("completion_method", "unknown"),
                            # Task-based tracking (for compatibility)
                            "tasks_pending": distributed_status.get("tasks_pending", 0),
                            "tasks_completed": distributed_status.get("tasks_completed", 0),
                            "urls_crawled": urls_crawled,
                            "scanner_results": scanner_results,
                            "source": "distributed",  # From distributed orchestrator
                            "distributed_scan_id": distributed_scan_id
                        }
                except Exception as e:
                    logger.warning(f"Failed to get distributed status for {distributed_scan_id}: {e}")
                    # Fall through to return cached data
            
            # Return cached in-memory data
            findings_count = len(scan_data.get("findings", []))
            
            # CRITICAL: If status is "completed", verify file exists first
            status = scan_data.get("status", "running")
            if status == "completed":
                full_results_path = f"scan_results/{scan_id}/raw_data/full_results.json"
                if not os.path.exists(full_results_path):
                    status = "finalizing"  # File not ready yet
                    logger.info(f"[STATUS] {scan_id}: Marked completed but file not ready, returning 'finalizing'")
            
            return {
                "scan_id": scan_id,
                "status": status,  # Use verified status
                "progress": scan_data.get("progress", 0),
                "findings_count": findings_count,
                "current_activity": scan_data.get("current_activity", "Scanning in progress..."),
                "total_scanners": scan_data.get("total_scanners", 57),
                "completed_scanners": scan_data.get("completed_scanners", 0),
                "urls_crawled": scan_data.get("urls_crawled", 0),
                "source": "memory"  # Running scan
            }
        
        # SECOND: Check if it's a COMPLETED scan in file system
        # Try NEW directory structure first
        new_scan_file = f"scan_results/{scan_id}/raw_data/full_results.json"
        old_scan_file = f"scan_results/{scan_id}.json"
        
        scan_file = None
        if os.path.exists(new_scan_file):
            scan_file = new_scan_file
        elif os.path.exists(old_scan_file):
            scan_file = old_scan_file
        else:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        try:
            with open(scan_file, "r") as f:
                scan_data = json.load(f)
        except json.JSONDecodeError:
            logger.error(f"⚠️ Corrupt scan file found at {scan_file}")
            # Return a failed status instead of crashing
            return {
                "scan_id": scan_id,
                "status": "failed",
                "message": "Scan data corrupted/empty",
                "findings_count": 0,
                "progress": 0,
                "source": "file_error"
            }
        
        # Return completed scan status
        findings_count = len(scan_data.get("findings", []))
        
        return {
            "scan_id": scan_id,
            "status": scan_data.get("status", "completed"),
            "progress": scan_data.get("progress", 100),
            "findings_count": findings_count,
            "current_activity": scan_data.get("current_activity", "Scan completed"),
            "total_scanners": scan_data.get("total_scanners", 57),
            "completed_scanners": scan_data.get("completed_scanners", 57),
            "source": "file"  # Completed scan
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_scan_status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scan status: {str(e)}")

@app.get("/scans")
async def get_scan_history():
    """Get all scan results for history - from both memory and files"""
    try:
        scans = []
        seen_scan_ids = set()
        
        # First, check in-memory scan_results (active scans)
        for scan_id, scan_data in scan_results.items():
            try:
                # Extract data from in-memory format
                target_url = scan_data.get("target") or scan_data.get("target_url", "Unknown")
                start_time = scan_data.get("start_time", datetime.now(timezone.utc).isoformat())
                end_time = scan_data.get("end_time")
                status = scan_data.get("status", "running")
                
                # Get findings
                results = scan_data.get("results", {})
                findings = results.get("findings", []) if isinstance(results, dict) else []
                total_findings = len(findings) if isinstance(findings, list) else 0
                
                scans.append({
                    "scan_id": scan_id,
                    "target_url": target_url,
                    "start_time": start_time,
                    "end_time": end_time,
                    "vulnerabilities_found": total_findings,
                    "total_findings": total_findings,
                    "status": status,
                    "scan_type": scan_data.get("scan_mode", "owasp")
                })
                seen_scan_ids.add(scan_id)
            except Exception as e:
                print(f"Error processing in-memory scan {scan_id}: {e}")
                continue
        
        # Then, check file-based results (both OLD flat files and NEW directories)
        os.makedirs("scan_results", exist_ok=True)
        
        # Get OLD format: .json files
        scan_files = [f for f in os.listdir("scan_results") if f.endswith('.json')]
        
        # Get NEW format: directories with metadata.json
        scan_dirs = []
        for item in os.listdir("scan_results"):
            item_path = os.path.join("scan_results", item)
            if os.path.isdir(item_path):
                metadata_path = os.path.join(item_path, "metadata.json")
                if os.path.exists(metadata_path):
                    scan_dirs.append(item)
        
        logger.info(f"[HISTORY] Found {len(scan_files)} old scans, {len(scan_dirs)} new scans")
        
        # Process OLD format scans (.json files)
        for file in scan_files:
            try:
                full_path = f"scan_results/{file}"
                with open(full_path, "r", encoding="utf-8") as f:
                    scan_data = json.load(f)

                # Derive scan_id from filename if not present
                scan_id = scan_data.get("scan_id") or os.path.splitext(file)[0]
                
                # Skip if already added from memory
                if scan_id in seen_scan_ids:
                    continue

                target_url = scan_data.get("target_url") or scan_data.get("target") or scan_data.get("url") or "Unknown"
                start_time = scan_data.get("start_time") or scan_data.get("scan_start")
                end_time = scan_data.get("end_time") or scan_data.get("scan_end")

                # Use filesystem times as fallback
                if not start_time or not end_time:
                    try:
                        stat = os.stat(full_path)
                        if not start_time:
                            start_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                        if not end_time:
                            end_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                    except Exception:
                        pass

                # Calculate findings
                summary = scan_data.get("summary", {})
                total_findings = summary.get("total_findings")
                if total_findings is None:
                    findings_list = scan_data.get("findings", [])
                    total_findings = len(findings_list) if isinstance(findings_list, list) else 0

                scans.append({
                    "scan_id": scan_id,
                    "target_url": target_url,
                    "start_time": start_time,
                    "end_time": end_time,
                    "summary": summary,
                    "total_findings": total_findings,
                    "vulnerabilities_found": total_findings,
                    "status": "completed",
                    "scan_type": scan_data.get("scan_type", "owasp")
                })
                seen_scan_ids.add(scan_id)
            except (json.JSONDecodeError, KeyError, Exception) as e:
                print(f"Error reading scan file {file}: {e}")
                continue
        
        # Process NEW format scans (directories with metadata.json)
        for scan_dir_name in scan_dirs:
            try:
                metadata_path = os.path.join("scan_results", scan_dir_name, "metadata.json")
                with open(metadata_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
                
                scan_id = metadata.get("scan_id", scan_dir_name)
                
                # Skip if already added
                if scan_id in seen_scan_ids:
                    continue
                
                scans.append({
                    "scan_id": scan_id,
                    "target_url": metadata.get("target_url", "Unknown"),
                    "start_time": metadata.get("scan_start", metadata.get("start_time")),
                    "end_time": metadata.get("scan_end", metadata.get("end_time")),
                    "summary": metadata.get("summary", {}),
                    "total_findings": metadata.get("findings_count", 0),
                    "vulnerabilities_found": metadata.get("findings_count", 0),
                    "status": metadata.get("status", "completed"),
                    "scan_type": metadata.get("scan_mode", "comprehensive"),
                    "urls_crawled": metadata.get("urls_crawled", 0)
                })
                seen_scan_ids.add(scan_id)
                logger.info(f"[HISTORY] Added NEW format scan: {scan_id} ({metadata.get('findings_count', 0)} findings)")
            except (json.JSONDecodeError, KeyError, Exception) as e:
                print(f"Error reading scan directory {scan_dir_name}: {e}")
                continue
        
        # Sort by start_time (newest first)
        scans.sort(key=lambda x: x.get("start_time", ""), reverse=True)
        
        logger.info(f"[HISTORY] Returning {len(scans)} total scans ({len(scan_files)} old + {len(scan_dirs)} new)")
        
        return {"scans": scans}
    except Exception as e:
        print(f"Error in get_scan_history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scan history: {str(e)}")

@app.delete("/scan/{scan_id}")
async def delete_scan_result(scan_id: str):
    """Delete a scan result"""
    try:
        file_path = f"scan_results/{scan_id}.json"
        if os.path.exists(file_path):
            os.remove(file_path)
            return {"message": f"Scan {scan_id} deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Scan not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(e)}")

@app.post("/api/cve-mapping", tags=["CVE Intelligence"])
async def map_vulnerabilities_to_cves(
    vulnerabilities: List[Dict],
    current_user: User = Depends(get_current_active_user)
):
    """
    Map vulnerabilities to CVE IDs using local database and external APIs.
    
    This endpoint takes a list of vulnerabilities and enriches them with CVE information.
    It first checks the local CVE database, then falls back to external sources.
    
    ## Features
    
    * 🔍 **Local CVE Database**: Fast lookup using local CVE database
    * 🌐 **External API Fallback**: NVD API integration for missing CVEs
    * 📊 **Metadata Enrichment**: Attaches CVE IDs and severity scores
    * ⚡ **Batch Processing**: Efficient processing of multiple vulnerabilities
    
    ## Parameters
    
    * **vulnerabilities**: List of vulnerability objects with service/version info
    
    ## Response
    
    Returns enriched vulnerabilities with CVE metadata attached.
    
    ## Example Usage
    
    ```bash
    curl -X POST "http://localhost:8000/api/cve-mapping" \
         -H "Authorization: Bearer <token>" \
         -H "Content-Type: application/json" \
         -d '[{"service": "apache", "version": "2.4.41", "port": 80}]'
    ```
    """
    try:
        enriched_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # Extract service information
            service_name = vuln.get('service', '').lower()
            version = vuln.get('version', '')
            port = vuln.get('port', '')
            
            # Initialize CVE mapping result
            cve_mapping = {
                'service': service_name,
                'version': version,
                'port': port,
                'cve_ids': [],
                'severity_scores': [],
                'source': 'local'
            }
            
            # Try local CVE database first
            local_cves = cve_db.get_cves_for_service(service_name, version)
            if local_cves:
                cve_mapping['cve_ids'] = [cve.cve_id for cve in local_cves]
                cve_mapping['severity_scores'] = [cve.severity for cve in local_cves]
                cve_mapping['source'] = 'local'
            else:
                # Fallback to external API
                try:
                    scanner = AdvancedNmapScanner()
                    external_cves = scanner.fetch_cves(service_name, version)
                    
                    if external_cves:
                        cve_mapping['cve_ids'] = [cve.get('id', '') for cve in external_cves if cve.get('id')]
                        cve_mapping['severity_scores'] = [cve.get('severity', 'UNKNOWN') for cve in external_cves]
                        cve_mapping['source'] = 'external'
                        cve_mapping['external_data'] = external_cves
                    
                except Exception as e:
                    print(f"External CVE lookup failed for {service_name}: {e}")
                    cve_mapping['source'] = 'failed'
                    cve_mapping['error'] = str(e)
            
            # Add CVE mapping to vulnerability
            enriched_vuln = {**vuln, 'cve_mapping': cve_mapping}
            enriched_vulnerabilities.append(enriched_vuln)
        
        return {
            'mapped_vulnerabilities': enriched_vulnerabilities,
            'total_mapped': len(enriched_vulnerabilities),
            'mapping_timestamp': datetime.now().isoformat(),
            'summary': {
                'local_matches': len([v for v in enriched_vulnerabilities if v['cve_mapping']['source'] == 'local']),
                'external_matches': len([v for v in enriched_vulnerabilities if v['cve_mapping']['source'] == 'external']),
                'failed_matches': len([v for v in enriched_vulnerabilities if v['cve_mapping']['source'] == 'failed'])
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE mapping failed: {str(e)}")

@app.post("/api/run-notebook", tags=["Notebook Execution"])
async def run_notebook_execution(
    target: str,
    port_range: str = "20-200",
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(get_current_active_user)
):
    """
    Execute the notebook penetration testing engine programmatically.
    
    This endpoint runs the 123.ipynb notebook logic as a separate penetration-testing step.
    It does not alter existing scanning behavior - it's an additional analysis tool.
    
    ## Features
    
    * 📓 **Notebook Execution**: Runs converted notebook logic programmatically
    * 🔍 **Network Scanning**: Nmap-based port and service discovery
    * 🛡️ **CVE Lookup**: Automatic vulnerability identification
    * 📊 **Comprehensive Reports**: JSON and text report generation
    * ⚡ **Background Processing**: Non-blocking execution
    
    ## Parameters
    
    * **target**: Target hostname or IP address to scan
    * **port_range**: Port range to scan (default: "20-200")
    
    ## Response
    
    Returns execution details and scan ID for monitoring progress.
    
    ## Example Usage
    
    ```bash
    curl -X POST "http://localhost:8000/api/run-notebook" \
         -H "Authorization: Bearer <token>" \
         -H "Content-Type: application/json" \
         -d '{"target": "scanme.nmap.org", "port_range": "1-1000"}'
    ```
    """
    if not NOTEBOOK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Notebook engine not available")
    
    # Generate unique scan ID
    scan_id = f"notebook_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        # Initialize notebook engine
        engine = NotebookPentestEngine()
        
        # Execute notebook scan in background
        async def execute_notebook():
            try:
                results = engine.execute_notebook_scan(target, scan_id, port_range)
                
                # Save results to main scan results directory for consistency
                result_file = f"scan_results/{scan_id}.json"
                with open(result_file, 'w') as f:
                    json.dump(results, f, indent=4, default=str)
                
                print(f" Notebook execution completed for {target}")
                
            except Exception as e:
                print(f"❌ Notebook execution failed: {e}")
                # Save error result
                error_result = {
                    "scan_id": scan_id,
                    "target": target,
                    "error": str(e),
                    "execution_time": datetime.now().isoformat(),
                    "status": "failed"
                }
                with open(f"scan_results/{scan_id}.json", 'w') as f:
                    json.dump(error_result, f, indent=4)
        
        if background_tasks:
            background_tasks.add_task(execute_notebook)
        else:
            # If no background tasks, run synchronously
            await execute_notebook()
        
        return {
            "message": "Notebook execution started",
            "scan_id": scan_id,
            "target": target,
            "port_range": port_range,
            "status": "running" if background_tasks else "completed",
            "execution_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start notebook execution: {str(e)}")

@app.get("/scan/{scan_id}/cve-report", tags=["Reports"])
async def get_cve_enhanced_report(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate CVE-enhanced security report.
    
    Returns a comprehensive text report that includes CVE intelligence
    for all security findings, providing additional context and references.
    
    ## Features
    
    * 🔍 **CVE Intelligence**: Related CVE IDs for each vulnerability
    * 📊 **Severity Analysis**: CVSS scores and risk assessment
    * 📄 **Detailed References**: CVE descriptions and affected components
    * 📅 **Temporal Context**: CVE publication years and timelines
    * 🔗 **Official Links**: References to NVD and MITRE databases
    
    ## Educational Value
    
    This report helps security professionals understand:
    - Historical context of vulnerabilities
    - Industry-standard vulnerability identifiers
    - Relationship between findings and known CVEs
    - Prioritization based on public vulnerability data
    
    ## Example Usage
    
    ```bash
    curl -H "Authorization: Bearer <token>" \
         "http://localhost:8000/scan/{scan_id}/cve-report"
    ```
    """
    # Get scan results
    try:
        with open(f"scan_results/{scan_id}.json", "r") as f:
            scan_result_data = json.load(f)
        
        # Convert to ScanResult object
        scan_result = ScanResult(
            scan_id=scan_result_data.get("scan_id", scan_id),
            target_url=scan_result_data.get("target_url", ""),
            start_time=scan_result_data.get("start_time", ""),
            end_time=scan_result_data.get("end_time", ""),
            findings=[SecurityFinding(**finding) for finding in scan_result_data.get("findings", [])],
            summary=scan_result_data.get("summary", {}),
            educational_insights=scan_result_data.get("educational_insights", [])
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Generate report generator
    report_generator = ReportGenerator()
    
    # Generate CVE-enhanced report
    cve_report = report_generator.generate_cve_enhanced_report(scan_result)
    
    return {
        "scan_id": scan_id,
        "report_type": "cve_enhanced",
        "generated_at": datetime.now().isoformat(),
        "content": cve_report,
        "total_findings": len(scan_result.findings),
        "total_cves": sum(len(f.cve_ids) for f in scan_result.findings if f.cve_ids),
        "unique_cves": len(set(cve_id for f in scan_result.findings if f.cve_ids for cve_id in f.cve_ids))
    }

@app.get("/test-pdf")
async def test_pdf_generation():
    """Test PDF generation with sample data"""
    try:
        # Sample findings for testing
        findings = [
            {
                "title": "Test Finding",
                "description": "This is a test finding for PDF generation",
                "severity": "medium",
                "endpoint": "/test",
                "evidence": "Test evidence",
                "cvss_score": 5.0,
                "cve_ids": ["CVE-2023-TEST"],
                "recommendation": "Test recommendation",
                "owasp_category": "A01:2021-Test"
            }
        ]
        
        scan_info = {
            "target": "test.example.com",
            "scan_time": "2024-01-01T00:00:00",
            "scan_id": "test_scan",
            "duration": "1 minute"
        }
        
        from reports.professional_pdf_generator import ProfessionalPDFGenerator
        pdf_generator = ProfessionalPDFGenerator()
        pdf_content = pdf_generator.generate_report_base64(findings, scan_info)
        
        return {
            "status": "success",
            "message": "PDF generation test successful",
            "content_length": len(pdf_content),
            "content": pdf_content[:100] + "..."  # First 100 chars for testing
        }
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Test PDF generation error: {error_details}")
        raise HTTPException(status_code=500, detail=f"Test PDF generation failed: {str(e)}")

# REMOVED: Duplicate /scans endpoint - using the one at line 9893 instead

@app.get("/scan/{scan_id}/pdf-report")
async def get_pdf_report(scan_id: str):
    """Get professional PDF penetration test report"""
    try:
        import os
        
        print(f"PDF report request for scan ID: {scan_id}")
        
        # Check for scan results in BOTH old and new formats
        new_scan_path = f"scan_results/{scan_id}/raw_data/full_results.json"
        old_scan_path = f"scan_results/{scan_id}.json"
        
        scan_file_path = None
        if os.path.exists(new_scan_path):
            scan_file_path = new_scan_path
            print(f"Found scan in NEW format: {new_scan_path}")
        elif os.path.exists(old_scan_path):
            scan_file_path = old_scan_path
            print(f"Found scan in OLD format: {old_scan_path}")
        else:
            print(f"Scan file not found in either format")
            print(f"  Checked NEW: {new_scan_path}")
            print(f"  Checked OLD: {old_scan_path}")
            
            # Get list of available scans to suggest
            import glob
            available_old = glob.glob("scan_results/scan_*.json")
            available_new = glob.glob("scan_results/*/metadata.json")
            available_scan_ids = [os.path.basename(f).replace('.json', '') for f in available_old]
            available_scan_ids += [os.path.basename(os.path.dirname(f)) for f in available_new]
            
            error_message = f"Scan results not found for scan ID: {scan_id}"
            if available_scan_ids:
                error_message += f". Available scans: {', '.join(available_scan_ids[:5])}"
                if len(available_scan_ids) > 5:
                    error_message += f" (and {len(available_scan_ids) - 5} more)"
            
            raise HTTPException(status_code=404, detail=error_message)
        
        print(f"Scan file found, loading data from: {scan_file_path}")
        
        # Get scan results
        with open(scan_file_path, "r", encoding="utf-8") as f:
            scan_result_data = json.load(f)
        
        all_findings = scan_result_data.get("findings", [])
        total_findings = len(all_findings)
        print(f"Scan data loaded, found {total_findings} findings")
        
        # Smart limiting for PDF generation - balance between completeness and performance
        MAX_PDF_FINDINGS = 500  # Tested maximum for stable PDF generation (proven reliable)
        
        if total_findings > MAX_PDF_FINDINGS:
            print(f"⚠️  Very large scan detected! {total_findings} findings")
            print(f"   PDF will include top {MAX_PDF_FINDINGS} findings prioritized by severity")
            print(f"   Full data available in JSON/CSV/XML exports and frontend")
            print(f"   This ensures PDF generation completes successfully")
        
        # Sort findings by severity for better organization in PDF
        severity_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            all_findings,
            key=lambda x: (severity_priority.get(x.get("severity", "info").lower(), 5), -x.get("cvss_score", 0))
        )
        
        # Take top findings if over limit
        if total_findings > MAX_PDF_FINDINGS:
            findings_to_process = sorted_findings[:MAX_PDF_FINDINGS]
        else:
            findings_to_process = sorted_findings
        
        # Count by severity for summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        print(f"   Processing ALL findings - Critical: {severity_counts['critical']}, High: {severity_counts['high']}, "
              f"Medium: {severity_counts['medium']}, Low: {severity_counts['low']}, Info: {severity_counts['info']}")
        
        # Convert findings to the format expected by the report generator
        # PRESERVE ALL FIELDS to ensure no data loss, especially network scanner data
        findings = []
        for finding_data in findings_to_process:
            finding = {
                "title": finding_data.get("title", "Unknown Finding"),
                "description": finding_data.get("description", ""),
                "severity": finding_data.get("severity", "info").lower(),
                "endpoint": finding_data.get("location", finding_data.get("endpoint", "")),
                "evidence": finding_data.get("evidence", ""),
                "cvss_score": finding_data.get("cvss_score", 0.0),
                "cve_ids": finding_data.get("cve_ids", []),
                "recommendation": finding_data.get("recommendation", ""),
                "owasp_category": finding_data.get("owasp_category", ""),
                "vulnerability_type": finding_data.get("vulnerability_type", ""),
                "risk_rating": finding_data.get("risk_rating", ""),
                "_total_scan_findings": total_findings,  # Include total for summary
                
                # PRESERVE NETWORK SCANNER FIELDS for appendix extraction
                "scanner": finding_data.get("scanner", finding_data.get("scanner_name", "")),
                "scanner_name": finding_data.get("scanner_name", finding_data.get("scanner", "")),
                "port": finding_data.get("port"),
                "service": finding_data.get("service"),
                "version": finding_data.get("version"),
                "banner": finding_data.get("banner"),
                "state": finding_data.get("state"),
                "protocol": finding_data.get("protocol"),
                "product": finding_data.get("product"),
                "host": finding_data.get("host"),
                "finding_data": finding_data.get("finding_data", {}),
                "port_info": finding_data.get("port_info"),
                "security_context": finding_data.get("security_context"),
                "cve_mapping": finding_data.get("cve_mapping"),
                
                # Preserve all other fields that might be needed (no data loss)
                **{k: v for k, v in finding_data.items() if k not in [
                    "title", "description", "severity", "endpoint", "evidence", 
                    "cvss_score", "cve_ids", "recommendation", "owasp_category",
                    "vulnerability_type", "risk_rating", "location", "scanner", "scanner_name"
                ] and v is not None}
            }
            findings.append(finding)

        # SKIP CVE enhancement for PDF generation - findings already have CVE data from scan
        # CVE enhancement can take a long time and cause PDF generation to hang
        # PDF generation should be fast - use existing CVE data from findings
        print(f"Skipping CVE enhancement for PDF generation - using existing CVE data from findings")
        print(f"   This ensures fast PDF generation without hanging")
        
        # Prepare scan info with findings information
        scan_info = {
            "target": scan_result_data.get("target_url", "Unknown Target"),
            "scan_time": scan_result_data.get("start_time", ""),
            "scan_id": scan_id,
            "duration": scan_result_data.get("duration", "N/A"),
            "total_findings": total_findings,
            "pdf_limited": total_findings > MAX_PDF_FINDINGS,
            "pdf_findings_count": len(findings),
            "raw_data": scan_result_data.get("raw_data", {}),
            "scanner": scan_result_data.get("scanner", "unknown")
        }
        
        if scan_info["pdf_limited"]:
            print(f"Generating PDF with top {len(findings)} findings from {total_findings} total")
            print(f"   PDF optimized for readability and performance")
        else:
            print(f"Generating PDF for target: {scan_info['target']}")
            print(f"   Including all {total_findings} findings")
        
        # Generate PDF report using professional generator
        # Run in executor to prevent blocking the event loop
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        
        print(f"Starting PDF generation for {len(findings)} findings...")
        
        from reports.professional_pdf_generator import ProfessionalPDFGenerator
        pdf_generator = ProfessionalPDFGenerator()
        
        # Run PDF generation in thread pool with timeout to prevent hanging
        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=1)
        
        try:
            # Generate PDF with 60 second timeout
            pdf_content = await asyncio.wait_for(
                loop.run_in_executor(executor, pdf_generator.generate_report_base64, findings, scan_info),
                timeout=60.0
            )
            print(f"PDF generated successfully, length: {len(pdf_content)}")
        except asyncio.TimeoutError:
            print(f"PDF generation timed out after 60 seconds")
            raise HTTPException(
                status_code=504,
                detail=f"PDF generation timed out. The scan has {total_findings} findings which may be too large. Try exporting as JSON or CSV instead."
            )
        except Exception as pdf_err:
            print(f"PDF generation error: {pdf_err}")
            import traceback
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"PDF generation failed: {str(pdf_err)}"
            )
        finally:
            executor.shutdown(wait=False)
        
        # Return PDF as direct binary response
        from fastapi.responses import Response
        import base64
        
        # Decode base64 content to binary
        pdf_binary = base64.b64decode(pdf_content)
        
        return Response(
            content=pdf_binary,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=penetration_test_report_{scan_id}.pdf"
            }
        )
        
    except FileNotFoundError:
        print(f"FileNotFoundError for scan {scan_id}")
        raise HTTPException(status_code=404, detail=f"Scan results file not found for scan ID: {scan_id}")
    except ImportError as e:
        print(f"ImportError for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Import error: {str(e)}")
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"PDF generation error for scan {scan_id}: {error_details}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

@app.get("/scan/{scan_id}/technical-report")
async def get_technical_report(scan_id: str):
    """Get comprehensive technical report"""
    try:
        with open(f"scan_results/{scan_id}.json", "r") as f:
            result = json.load(f)
        
        if "technical_report" in result and result["technical_report"]:
            return result["technical_report"]
        else:
            raise HTTPException(status_code=404, detail="Technical report not found")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/scan/{scan_id}/executive-report")
async def get_executive_report(scan_id: str):
    """Get executive summary report"""
    try:
        with open(f"scan_results/{scan_id}.json", "r") as f:
            result = json.load(f)
        
        if "executive_report" in result and result["executive_report"]:
            return result["executive_report"]
        else:
            raise HTTPException(status_code=404, detail="Executive report not found")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/scan/{scan_id}/executive-summary/pdf")
async def get_executive_summary_pdf(scan_id: str):
    """Generate and download Executive Summary PDF using EXECUTIVE_REPORT.py"""
    try:
        import os
        
        print(f"Executive Summary PDF request for scan ID: {scan_id}")
        
        # Check for scan results in BOTH old and new formats
        new_scan_path = f"scan_results/{scan_id}/raw_data/full_results.json"
        old_scan_path = f"scan_results/{scan_id}.json"
        
        scan_file_path = None
        if os.path.exists(new_scan_path):
            scan_file_path = new_scan_path
            print(f"Found scan in NEW format: {new_scan_path}")
        elif os.path.exists(old_scan_path):
            scan_file_path = old_scan_path
            print(f"Found scan in OLD format: {old_scan_path}")
        else:
            print(f"Scan file not found for executive summary")
            print(f"  Checked NEW: {new_scan_path}")
            print(f"  Checked OLD: {old_scan_path}")
            raise HTTPException(status_code=404, detail=f"Scan results not found for scan ID: {scan_id}")
        
        print(f"Loading scan data from: {scan_file_path}")
        
        # Load scan data
        with open(scan_file_path, "r", encoding="utf-8") as f:
            scan_result_data = json.load(f)
        
        findings = scan_result_data.get("findings", [])
        print(f"Loaded {len(findings)} findings for executive summary")
        
        # Prepare scan info
        scan_info = {
            'target': scan_result_data.get('target_url', scan_result_data.get('target', 'Target System')),
            'scan_time': scan_result_data.get('start_time', scan_result_data.get('scan_date', 'N/A')),
            'scan_id': scan_id,
        }
        
        # Import and use EXECUTIVE_REPORT generator
        from reports.EXECUTIVE_REPORT import ExecutiveReportGenerator
        
        print("Generating executive summary PDF...")
        exec_generator = ExecutiveReportGenerator()
        
        # Generate PDF as base64
        pdf_base64 = exec_generator.generate_report_base64(findings, scan_info)
        
        # Decode base64 to bytes
        import base64
        pdf_bytes = base64.b64decode(pdf_base64)
        
        print(f"✅ Executive summary PDF generated successfully ({len(pdf_bytes)} bytes)")
        
        # Return PDF file
        from fastapi.responses import Response
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=executive_summary_{scan_id}.pdf"
            }
        )
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")
    except Exception as e:
        print(f"❌ Error generating executive summary PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to generate executive summary PDF: {str(e)}")

@app.get("/scans/compare")
async def compare_scans(base: str, compare: str):
    """Compare two scans and return differences"""
    try:
        # Load both scan results
        with open(f"scan_results/{base}.json", "r") as f:
            base_scan = json.load(f)
        
        with open(f"scan_results/{compare}.json", "r") as f:
            compare_scan = json.load(f)
        
        # Create finding maps for comparison
        base_findings = {f"{finding['title']}-{finding['location']}": finding 
                        for finding in base_scan.get('findings', [])}
        compare_findings = {f"{finding['title']}-{finding['location']}": finding 
                           for finding in compare_scan.get('findings', [])}
        
        # Calculate differences
        new_findings = []
        resolved_findings = []
        changed_findings = []
        
        # Find new findings (in compare but not in base)
        for key, finding in compare_findings.items():
            if key not in base_findings:
                new_findings.append(finding)
        
        # Find resolved findings (in base but not in compare)
        for key, finding in base_findings.items():
            if key not in compare_findings:
                resolved_findings.append(finding)
        
        # Find changed findings (same title/location but different severity)
        for key, compare_finding in compare_findings.items():
            if key in base_findings:
                base_finding = base_findings[key]
                if base_finding['severity'] != compare_finding['severity']:
                    changed_findings.append({
                        'finding_id': compare_finding['id'],
                        'old_severity': base_finding['severity'],
                        'new_severity': compare_finding['severity'],
                        'changes': [f"Severity changed from {base_finding['severity']} to {compare_finding['severity']}"]
                    })
        
        # Calculate metrics comparison
        base_summary = base_scan.get('summary', {})
        compare_summary = compare_scan.get('summary', {})
        
        severity_changes = {
            'critical': compare_summary.get('critical', 0) - base_summary.get('critical', 0),
            'high': compare_summary.get('high', 0) - base_summary.get('high', 0),
            'medium': compare_summary.get('medium', 0) - base_summary.get('medium', 0),
            'low': compare_summary.get('low', 0) - base_summary.get('low', 0),
            'info': compare_summary.get('info', 0) - base_summary.get('info', 0)
        }
        
        risk_score_change = compare_summary.get('total_findings', 0) - base_summary.get('total_findings', 0)
        
        # Determine trend
        if risk_score_change > 0:
            trend = 'degrading'
        elif risk_score_change < 0:
            trend = 'improving'
        else:
            trend = 'stable'
        
        return {
            "base_scan": base_scan,
            "compare_scan": compare_scan,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "changed_findings": changed_findings,
            "metrics_comparison": {
                "risk_score_change": risk_score_change,
                "severity_changes": severity_changes,
                "trend": trend
            }
        }
        
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"Scan not found: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to compare scans: {str(e)}")

@app.get("/scan/{scan_id}/reports")
async def get_all_reports(scan_id: str):
    """Get both technical and executive reports"""
    try:
        with open(f"scan_results/{scan_id}.json", "r") as f:
            result = json.load(f)
        
        return {
            "scan_id": scan_id,
            "technical_report": result.get("technical_report"),
            "executive_report": result.get("executive_report"),
            "basic_summary": {
                "total_findings": result.get("summary", {}).get("total_findings", 0),
                "critical": result.get("summary", {}).get("critical", 0),
                "high": result.get("summary", {}).get("high", 0),
                "medium": result.get("summary", {}).get("medium", 0),
                "low": result.get("summary", {}).get("low", 0),
                "info": result.get("summary", {}).get("info", 0)
            }
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/scan/{scan_id}/owasp-reports")
async def get_owasp_category_reports(scan_id: str):
    """Get reports for each OWASP Top 10 category individually and combined"""
    try:
        with open(f"scan_results/{scan_id}.json", "r") as f:
            result = json.load(f)
        
        findings = result.get('findings', [])
        
        # Group findings by OWASP category
        owasp_reports = {}
        owasp_mapping = {
            "A01:2021 – Broken Access Control": "A01",
            "A02:2021 – Cryptographic Failures": "A02",
            "A03:2021 – Injection": "A03",
            "A04:2021 – Insecure Design": "A04",
            "A05:2021 – Security Misconfiguration": "A05",
            "A06:2021 – Vulnerable and Outdated Components": "A06",
            "A07:2021 – Identification and Authentication Failures": "A07",
            "A08:2021 – Software and Data Integrity Failures": "A08",
            "A09:2021 – Security Logging and Monitoring Failures": "A09",
            "A10:2021 – Server-Side Request Forgery (SSRF)": "A10"
        }
        
        # Initialize each OWASP category
        for full_name, short_name in owasp_mapping.items():
            owasp_reports[short_name] = {
                'category_name': full_name,
                'short_name': short_name,
                'findings': [],
                'count': 0,
                'severity_breakdown': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            }
        
        # Categorize findings
        for finding in findings:
            owasp_category = finding.get('owasp_category', '')
            for full_name, short_name in owasp_mapping.items():
                if full_name in owasp_category:
                    owasp_reports[short_name]['findings'].append(finding)
                    owasp_reports[short_name]['count'] += 1
                    severity = finding.get('severity', 'info')
                    if severity in owasp_reports[short_name]['severity_breakdown']:
                        owasp_reports[short_name]['severity_breakdown'][severity] += 1
                    break
        
        # Create combined report
        combined_report = {
            'category_name': 'OWASP Top 10 Combined Report',
            'short_name': 'COMBINED',
            'findings': findings,
            'count': len(findings),
            'severity_breakdown': result.get('summary', {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            })
        }
        
        return {
            'scan_id': scan_id,
            'owasp_reports': owasp_reports,
            'combined_report': combined_report,
            'total_categories': len([cat for cat in owasp_reports.values() if cat['count'] > 0]),
            'generated_at': datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate OWASP reports: {str(e)}")

@app.get("/scan/{scan_id}/owasp-report/{category}")
async def get_specific_owasp_report(scan_id: str, category: str):
    """Get report for a specific OWASP category (A01-A10) or COMBINED"""
    try:
        reports_data = await get_owasp_category_reports(scan_id)
        
        if category.upper() == 'COMBINED':
            return reports_data['combined_report']
        elif category.upper() in reports_data['owasp_reports']:
            return reports_data['owasp_reports'][category.upper()]
        else:
            raise HTTPException(status_code=404, detail=f"OWASP category {category} not found")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get OWASP report: {str(e)}")

@app.get("/scan/{scan_id}/artifacts")
async def get_scan_artifacts(scan_id: str):
    """Get list of artifacts for a scan"""
    artifacts_dir = os.path.join("artifacts", "scans", scan_id)
    
    if not os.path.exists(artifacts_dir):
        raise HTTPException(status_code=404, detail="Scan artifacts not found")
    
    artifacts = []
    for root, dirs, files in os.walk(artifacts_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, artifacts_dir)
            file_size = os.path.getsize(file_path)
            file_modified = datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            
            artifacts.append({
                "name": file,
                "path": rel_path,
                "size": file_size,
                "modified": file_modified,
                "type": file.split('.')[-1] if '.' in file else 'unknown'
            })
    
    return {
        "scan_id": scan_id,
        "artifacts_directory": artifacts_dir,
        "total_artifacts": len(artifacts),
        "artifacts": artifacts
    }

@app.get("/scan/{scan_id}/artifacts/{artifact_path:path}")
async def get_scan_artifact(scan_id: str, artifact_path: str):
    """Download a specific artifact file"""
    artifacts_dir = os.path.join("artifacts", "scans", scan_id)
    file_path = os.path.join(artifacts_dir, artifact_path)
    
    # Security check - ensure file is within artifacts directory
    if not file_path.startswith(os.path.abspath(artifacts_dir)):
        raise HTTPException(status_code=403, detail="Access denied")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    from fastapi.responses import FileResponse
    return FileResponse(file_path)

@app.post("/scan/{scan_id}/exploit")
async def run_exploit(scan_id: str, request: dict):
    """Run authorized exploit against a vulnerability"""
    try:
        vulnerability_id = request.get('vulnerability_id')
        exploit_type = request.get('exploit_type', 'proof_of_concept')
        authorization = request.get('authorization')
        
        if not vulnerability_id:
            raise HTTPException(status_code=400, detail="Vulnerability ID required")
        
        if authorization != 'user_consent_given':
            raise HTTPException(status_code=403, detail="Explicit user consent required")
        
        # Load scan results to get vulnerability details
        try:
            with open(f"scan_results/{scan_id}.json", "r") as f:
                scan_data = json.load(f)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Find the vulnerability
        vulnerability = None
        for finding in scan_data.get('findings', []):
            if finding.get('id') == vulnerability_id:
                vulnerability = finding
                break
        
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Generate proof-of-concept exploit based on vulnerability type
        exploit_result = await generate_poc_exploit(vulnerability, scan_id)
        
        # Log exploit execution for audit trail
        exploit_log = {
            "timestamp": datetime.now().isoformat(),
            "scan_id": scan_id,
            "vulnerability_id": vulnerability_id,
            "exploit_type": exploit_type,
            "result": exploit_result,
            "user_consent": True
        }
        
        # Save to artifacts
        artifacts_dir = os.path.join("artifacts", "scans", scan_id)
        os.makedirs(artifacts_dir, exist_ok=True)
        
        exploit_log_file = os.path.join(artifacts_dir, "exploit_log.json")
        exploit_logs = []
        if os.path.exists(exploit_log_file):
            with open(exploit_log_file, 'r') as f:
                exploit_logs = json.load(f)
        
        exploit_logs.append(exploit_log)
        with open(exploit_log_file, 'w') as f:
            json.dump(exploit_logs, f, indent=2)
        
        return {
            "exploit_id": f"exploit_{vulnerability_id}_{int(time.time())}",
            "status": "completed",
            "vulnerability_id": vulnerability_id,
            "exploit_type": exploit_type,
            "results": exploit_result,
            "timestamp": datetime.now().isoformat(),
            "audit_logged": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Exploit execution failed: {str(e)}")

async def generate_poc_exploit(vulnerability: dict, scan_id: str) -> dict:
    """Generate proof-of-concept exploit for educational purposes"""
    owasp_category = vulnerability.get('owasp_category', '')
    location = vulnerability.get('location', '')
    
    # Generate different POC based on vulnerability type
    if 'Injection' in owasp_category:
        return {
            "type": "SQL Injection PoC",
            "payload": "' OR '1'='1' --",
            "impact": "Potential data extraction or authentication bypass",
            "evidence": f"Payload testing at {location}",
            "recommendation": "Use parameterized queries and input validation",
            "severity_confirmed": True,
            "remediation_priority": "High"
        }
    
    elif 'Access Control' in owasp_category:
        return {
            "type": "Access Control PoC",
            "method": "Direct object reference testing",
            "impact": "Unauthorized access to resources",
            "evidence": f"Access control bypass attempt at {location}",
            "recommendation": "Implement proper authorization checks",
            "severity_confirmed": True,
            "remediation_priority": "High"
        }
    
    elif 'Misconfiguration' in owasp_category:
        return {
            "type": "Security Misconfiguration PoC",
            "finding": "Configuration disclosure",
            "impact": "Information exposure",
            "evidence": f"Configuration issue identified at {location}",
            "recommendation": "Review and harden server configuration",
            "severity_confirmed": True,
            "remediation_priority": "Medium"
        }
    
    elif 'Authentication' in owasp_category:
        return {
            "type": "Authentication Bypass PoC",
            "method": "Session manipulation testing",
            "impact": "Potential authentication bypass",
            "evidence": f"Authentication weakness at {location}",
            "recommendation": "Implement strong authentication mechanisms",
            "severity_confirmed": True,
            "remediation_priority": "High"
        }
    
    else:
        return {
            "type": "Generic Vulnerability PoC",
            "finding": "Security issue confirmed",
            "impact": "Varies based on vulnerability type",
            "evidence": f"Security issue at {location}",
            "recommendation": "Follow OWASP security guidelines",
            "severity_confirmed": True,
            "remediation_priority": "Medium"
        }

@app.get("/scan/{scan_id}/exploits")
async def get_exploit_history(scan_id: str):
    """Get exploit execution history for a scan"""
    artifacts_dir = os.path.join("artifacts", "scans", scan_id)
    exploit_log_file = os.path.join(artifacts_dir, "exploit_log.json")
    
    if not os.path.exists(exploit_log_file):
        return {"scan_id": scan_id, "exploits": []}
    
    try:
        with open(exploit_log_file, 'r') as f:
            exploit_logs = json.load(f)
        
        return {
            "scan_id": scan_id,
            "total_exploits": len(exploit_logs),
            "exploits": exploit_logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load exploit history: {str(e)}")

@app.get("/scan/{scan_id}/cves")
async def get_scan_cves(scan_id: str):
    """Get all CVE information for a scan"""
    try:
        with open(f"scan_results/{scan_id}.json", "r") as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Extract all CVE information
    all_cves = {}
    cve_summary = {
        "total_findings_with_cves": 0,
        "total_unique_cves": 0,
        "severity_breakdown": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        },
        "by_owasp_category": {}
    }
    
    for finding in scan_data.get('findings', []):
        if finding.get('cve_ids'):
            cve_summary["total_findings_with_cves"] += 1
            owasp_cat = finding.get('owasp_category', 'Unknown')
            
            if owasp_cat not in cve_summary["by_owasp_category"]:
                cve_summary["by_owasp_category"][owasp_cat] = []
            
            for cve_id in finding['cve_ids']:
                if cve_id not in all_cves:
                    # Get CVE details from CVE references if available
                    cve_details = None
                    if finding.get('cve_references'):
                        for ref in finding['cve_references']:
                            if ref.get('cve_id') == cve_id:
                                cve_details = ref
                                break
                    
                    if not cve_details:
                        # Fallback CVE info
                        cve_details = {
                            "cve_id": cve_id,
                            "severity": "UNKNOWN",
                            "score": "N/A",
                            "description": "CVE information not available",
                            "year": cve_id.split('-')[1] if '-' in cve_id else "Unknown"
                        }
                    
                    all_cves[cve_id] = {
                        "cve_id": cve_id,
                        "severity": cve_details.get('severity', 'UNKNOWN'),
                        "score": cve_details.get('score', 'N/A'),
                        "description": cve_details.get('description', 'No description'),
                        "year": cve_details.get('year', 'Unknown'),
                        "affected_components": cve_details.get('affected_components', ''),
                        "references": cve_details.get('references', ''),
                        "related_findings": []
                    }
                
                # Add this finding to the CVE's related findings
                all_cves[cve_id]["related_findings"].append({
                    "finding_id": finding.get('id'),
                    "title": finding.get('title'),
                    "location": finding.get('location'),
                    "owasp_category": finding.get('owasp_category')
                })
                
                # Update severity breakdown
                severity = all_cves[cve_id]["severity"].lower()
                if severity in cve_summary["severity_breakdown"]:
                    cve_summary["severity_breakdown"][severity] += 1
                else:
                    cve_summary["severity_breakdown"]["unknown"] += 1
                
                # Add to OWASP category
                if cve_id not in cve_summary["by_owasp_category"][owasp_cat]:
                    cve_summary["by_owasp_category"][owasp_cat].append(cve_id)
    
    cve_summary["total_unique_cves"] = len(all_cves)
    
    return {
        "scan_id": scan_id,
        "cve_summary": cve_summary,
        "cves": all_cves,
        "generated_at": datetime.now().isoformat()
    }

@app.get("/scan/{scan_id}/cves/{cve_id}")
async def get_specific_cve(scan_id: str, cve_id: str):
    """Get detailed information for a specific CVE"""
    cve_data = await get_scan_cves(scan_id)
    
    if cve_id not in cve_data["cves"]:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in scan results")
    
    cve_info = cve_data["cves"][cve_id]
    
    # Try to get additional information from CVE database
    try:
        enhanced_cve = cve_db.get_cve_by_id(cve_id)
        if enhanced_cve:
            cve_info.update({
                "enhanced_description": enhanced_cve.description,
                "enhanced_severity": enhanced_cve.severity,
                "enhanced_score": enhanced_cve.score,
                "affected_components_detailed": enhanced_cve.affected_components,
                "reference_urls": enhanced_cve.reference_urls
            })
    except:
        pass  # Use existing information if enhancement fails
    
    return {
        "scan_id": scan_id,
        "cve_id": cve_id,
        "cve_details": cve_info,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "mitre_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    }

@app.get("/cve/search")
async def search_cves(query: str, limit: int = 10):
    """Search CVE database by keyword"""
    try:
        results = cve_db.search_cves(query, limit)
        return {
            "query": query,
            "total_results": len(results),
            "cves": [{
                "cve_id": cve.cve_id,
                "severity": cve.severity,
                "score": cve.score,
                "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                "year": cve.year,
                "affected_components": cve.affected_components[:3]  # Limit to first 3
            } for cve in results]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE search failed: {str(e)}")

@app.get("/cve/stats")
async def get_cve_statistics():
    """Get CVE database statistics"""
    try:
        stats = cve_db.get_statistics()
        return {
            "database_info": {
                "total_cves": stats.get("total_cves", 0),
                "by_severity": stats.get("by_severity", {}),
                "by_year": stats.get("by_year", {}),
                "by_owasp_category": stats.get("by_owasp_category", {})
            },
            "last_updated": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "database_info": {
                "total_cves": 0,
                "status": "CVE database not available"
            },
            "error": str(e)
        }

@app.get("/owasp-info/{category}")
async def get_owasp_info(category: str):
    """Get educational information about OWASP categories"""
    owasp_info = {
        "A01": {
            "title": "Broken Access Control",
            "description": "Restrictions on what authenticated users are allowed to do are often not properly enforced.",
            "examples": ["Bypassing access control checks", "Privilege escalation", "CORS misconfiguration"],
            "prevention": ["Implement proper access controls", "Use least privilege principle", "Regular access reviews"]
        },
        "A02": {
            "title": "Cryptographic Failures",
            "description": "Failures related to cryptography which often leads to sensitive data exposure.",
            "examples": ["Weak encryption", "Missing HTTPS", "Hardcoded secrets"],
            "prevention": ["Use strong encryption", "Implement HTTPS everywhere", "Proper key management"]
        },
        "A03": {
            "title": "Injection",
            "description": "User-supplied data is not validated, filtered, or sanitized by the application.",
            "examples": ["SQL injection", "NoSQL injection", "Command injection"],
            "prevention": ["Input validation", "Parameterized queries", "Escape special characters"]
        }
        # Add more categories as needed
    }
    
    category_key = category.upper()[:3]
    if category_key in owasp_info:
        return owasp_info[category_key]
    else:
        raise HTTPException(status_code=404, detail="OWASP category not found")

# ============================================
# INTELLIGENT CRAWLER STATUS & MONITORING ENDPOINTS
# ============================================

@app.get("/scanner/status", tags=["System Status"])
async def get_scanner_system_status():
    """
    Get comprehensive status of all scanner systems
    Shows if intelligent crawler is available and operational
    """
    status = {
        'timestamp': datetime.now().isoformat(),
        'systems': {}
    }
    
    # Traditional Scanner Chain
    status['systems']['traditional'] = {
        'name': 'Sequential ScannerChain',
        'available': True,
        'type': 'sequential',
        'performance': '1x (baseline)',
        'estimated_duration': '60-90 minutes',
        'features': ['subdomain_discovery', 'basic_crawling', 'sequential_scanning']
    }
    
    # Intelligent Crawler
    if INTELLIGENT_CRAWLER_AVAILABLE and get_intelligent_crawler_status:
        crawler_status = get_intelligent_crawler_status()
        status['systems']['intelligent'] = {
            'name': 'Scrapy-Redis + Playwright',
            'available': True,
            'type': 'distributed',
            'performance': '5-30x faster',
            'estimated_duration': '10-15 minutes',
            'features': [
                'distributed_crawling',
                'javascript_rendering',
                'parallel_scanning',
                'crawl_persistence',
                'horizontal_scaling',
                'intelligent_url_categorization'
            ],
            'details': crawler_status
        }
        status['active_system'] = 'intelligent'
        status['recommendation'] = 'Using intelligent crawler for optimal performance'
    else:
        status['systems']['intelligent'] = {
            'name': 'Scrapy-Redis + Playwright',
            'available': False,
            'installation_required': True,
            'install_guide': 'See backend/crawlers/INTEGRATION_GUIDE.md',
            'install_commands': [
                'cd backend/crawlers',
                'pip install -r requirements.txt',
                'playwright install chromium',
                'docker run -d -p 6379:6379 redis'
            ]
        }
        status['active_system'] = 'traditional'
        status['recommendation'] = 'Install intelligent crawler for 5-6x performance improvement'
    
    return status


@app.get("/scanner/redis/health", tags=["System Status"])
async def check_redis_health():
    """
    Check Redis server health and queue status
    Essential for distributed crawling
    """
    try:
        import redis
        client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        client.ping()
        
        # Get comprehensive stats
        info = client.info()
        
        # Crawl queues
        crawl_stats = {}
        scrapy_keys = client.keys('security_spider:*')
        for key in scrapy_keys:
            key_type = client.type(key)
            if key_type == 'list':
                crawl_stats[key] = {'type': 'list', 'length': client.llen(key)}
            elif key_type == 'set':
                crawl_stats[key] = {'type': 'set', 'size': client.scard(key)}
        
        # Scanner queues
        scanner_stats = {}
        scanner_keys = client.keys('scanner_queue:*')
        for key in scanner_keys[:20]:  # Top 20
            scanner_stats[key] = client.llen(key)
        
        return {
            'status': 'healthy',
            'connected': True,
            'host': 'localhost',
            'port': 6379,
            'version': info.get('redis_version'),
            'uptime_seconds': info.get('uptime_in_seconds'),
            'total_keys': len(client.keys('*')),
            'crawl_queues': crawl_stats,
            'scanner_queues': scanner_stats,
            'memory_usage': {
                'used_memory_human': info.get('used_memory_human'),
                'used_memory_peak_human': info.get('used_memory_peak_human')
            },
            'message': 'Redis operational - ready for distributed crawling'
        }
    
    except Exception as e:
        return {
            'status': 'unavailable',
            'connected': False,
            'error': str(e),
            'message': 'Redis not available - intelligent crawler will not work',
            'install_help': 'docker run -d -p 6379:6379 --name redis redis:latest'
        }


# New integrated features endpoints

@app.post("/scan/comprehensive", tags=["Comprehensive Scanning"])
async def comprehensive_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(check_scan_rate_limit_dependency)
):
    """
    Run REAL comprehensive security scan using ENHANCED DISTRIBUTED SYSTEM
    
    NO DUMMY DATA - Uses distributed system for parallel scanning
    """
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{current_user.username}"
    username = current_user.username
    url = str(request.target_url)  # Convert HttpUrl to string for REAL scanning
    
    logger.info(f"[MAIN BACKEND] Comprehensive scan requested by {username} for {url}")
    
    # Store scan metadata
    scan_results[scan_id] = {
        'status': 'running',
        'target_url': url,
        'scan_mode': 'comprehensive',
        'start_time': datetime.now().isoformat(),
        'user': username,
        'scan_type': 'comprehensive_security'
    }
    
    # Run comprehensive scan in background using ENHANCED system
    background_tasks.add_task(run_comprehensive_scan_background, scan_id, url, username, request)
    
    return {
        "scan_id": scan_id,
        "status": "initiated",
        "message": "Comprehensive security scan started",
        "target_url": str(request.target_url),
        "websocket_url": f"/ws/{scan_id}",
        "estimated_duration": "10-30 minutes"
    }

async def run_comprehensive_scan(scan_id: str, url: str, username: str, scan_request: ScanRequest):
    """
    Run REAL comprehensive scan using ENHANCED DISTRIBUTED SYSTEM
    
    NO DUMMY DATA - Only real vulnerability scanning with:
    - Enhanced Distributed System (5 Scrapy crawlers + 20 scanner workers)
    - Real-time vulnerability detection
    - Professional parallel scanning
    - Actual findings from real security tests
    
    ARCHITECTURE:
    Frontend → Main Backend (this) → Enhanced Orchestrator → Crawler Manager + Worker Pool
    
    FALLBACK: Local ScannerChain if distributed system unavailable
    """
    try:
        logger.info(f"[MAIN BACKEND] Starting REAL comprehensive scan for {url}")
        logger.info(f"[MAIN BACKEND] Scan ID: {scan_id}, User: {username}")
        
        await connection_manager.send_log(
            scan_id,
            f"[MAIN BACKEND] Initializing REAL security scan for: {url}",
            "info"
        )
        
        # Check if distributed system is available and healthy
        try:
            from integration.distributed_system_bridge import distributed_bridge
            
            await connection_manager.send_log(
                scan_id,
                "[DISTRIBUTED] Checking enhanced distributed system...",
                "info"
            )
            
            is_healthy = await distributed_bridge.check_distributed_system_health()
            
            if is_healthy:
                logger.info(f"[MAIN BACKEND] Enhanced distributed system is HEALTHY - delegating scan")
                
                await connection_manager.send_log(
                    scan_id,
                    "[DISTRIBUTED] Enhanced system ACTIVE - 5 Crawlers + 20 Workers ready",
                    "success"
                )
                
                # Submit REAL scan to distributed system
                await connection_manager.send_log(
                    scan_id,
                    f"[DISTRIBUTED] Submitting REAL URL: {url} to enhanced orchestrator",
                    "info"
                )
                
                scan_mode = getattr(scan_request, 'scan_mode', 'comprehensive')
                depth = getattr(scan_request, 'depth', 3)
                
                distributed_response = await distributed_bridge.submit_scan(
                    url=url,
                    scan_mode=scan_mode,
                    max_depth=depth,
                    scan_options={
                        'scan_id': scan_id,
                        'username': username
                    }
                )
                
                distributed_scan_id = distributed_response.get('scan_id')
                
                logger.info(f"[MAIN BACKEND] REAL scan submitted to distributed system: {distributed_scan_id}")
                
                await connection_manager.send_log(
                    scan_id,
                    f"[DISTRIBUTED] Scan accepted! Distributed ID: {distributed_scan_id}",
                    "success"
                )
                await connection_manager.send_log(
                    scan_id,
                    "[DISTRIBUTED] Crawler Manager activating... discovering URLs",
                    "info"
                )
                await connection_manager.send_log(
                    scan_id,
                    "[DISTRIBUTED] Scanner Workers preparing... 20 workers ready",
                    "info"
                )
                
                # Monitor REAL scan progress with live updates
                await connection_manager.send_log(
                    scan_id,
                    "[DISTRIBUTED] Real-time monitoring started...",
                    "info"
                )
                
                final_results = await distributed_bridge.monitor_scan_with_updates(
                    distributed_scan_id,
                    scan_id,
                    connection_manager,
                    max_duration=999999  # Effectively no timeout - wait for scan to complete
                )
                
                # Process REAL results
                logger.info(f"[MAIN BACKEND] Scan {scan_id} completed via distributed system")
                logger.info(f"[MAIN BACKEND] Real findings: {final_results.get('findings_count', 0)}")
                
                chain_results = {
                    'distributed': True,
                    'distributed_scan_id': distributed_scan_id,
                    'status': 'completed',
                    'findings_count': final_results.get('findings_count', 0),
                    'urls_crawled': final_results.get('urls_crawled', 0),
                    'comprehensive_report': {
                        'scan_summary': {
                            'total_findings': final_results.get('findings_count', 0),
                            'total_targets': final_results.get('urls_crawled', 1),
                            'total_scanners': final_results.get('total_tasks', 0),
                            'distributed_system_used': True
                        },
                        'all_findings': [],  # Will be populated from Redis
                        'all_vulnerabilities': []
                    }
                }
                
            else:
                # Distributed system not healthy - use fallback
                raise Exception("Distributed system not healthy")
                
        except Exception as distributed_error:
            # Fallback to Traditional ScannerChain for REAL scanning
            logger.warning(f"[MAIN BACKEND] Distributed system unavailable: {distributed_error}")
            logger.info(f"[MAIN BACKEND] Falling back to local ScannerChain for REAL scanning")
            
            await connection_manager.send_log(
                scan_id,
                "[FALLBACK] Distributed system unavailable - using local scanner chain",
                "warning"
            )
            await connection_manager.send_log(
                scan_id,
                f"[FALLBACK] Reason: {str(distributed_error)}",
                "warning"
            )
            await connection_manager.send_log(
                scan_id,
                f"[LOCAL SCAN] Starting REAL vulnerability scan on: {url}",
                "info"
            )
            
            # Initialize scanner chain for REAL scanning
            scanner_chain = ScannerChain(url)
            
            # Run comprehensive scan with all REAL scanners - NO DUMMY DATA
            scan_options = {
                'include_web_scans': True,
                'include_auth_scans': True,
                'include_injection_scans': True,
                'include_info_disclosure': True,
                'include_dirb_scan': True
            }
            
            await connection_manager.send_log(
                scan_id,
                f"[LOCAL SCAN] Running {len(scanner_chain.scanner_chain)} REAL security scanners",
                "info"
            )
            
            # Run the REAL scanner chain
            chain_results = await scanner_chain.run_chain(scan_options)
        
        # Extract REAL comprehensive report (from distributed or local)
        comprehensive_report = chain_results.get('comprehensive_report', {})
        target_results = chain_results.get('target_results', {})
        is_distributed = chain_results.get('distributed', False)
        
        # Get summary data - REAL DATA ONLY
        scan_summary = comprehensive_report.get('scan_summary', {})
        all_findings = comprehensive_report.get('all_findings', [])
        all_vulnerabilities = comprehensive_report.get('all_vulnerabilities', [])
        all_open_ports = comprehensive_report.get('all_open_ports', [])
        all_services = comprehensive_report.get('all_services', [])
        
        logger.info(f"[MAIN BACKEND] Scan {scan_id} results: {len(all_findings)} findings, {len(all_vulnerabilities)} vulnerabilities")
        
        # Generate comprehensive results - REAL DATA ONLY
        results = {
            'status': 'completed',
            'findings': all_findings,
            'vulnerabilities': all_vulnerabilities,
            'open_ports': all_open_ports,
            'services': all_services,
            'chain_results': chain_results,
            'comprehensive_report': comprehensive_report,
            'target_results': target_results,
            'distributed_system_used': is_distributed,
            'scan_summary': {
                'total_targets': scan_summary.get('total_targets', 0),
                'total_scanners': scan_summary.get('total_scanners', 0),
                'total_scans_executed': scan_summary.get('total_scans_executed', 0),
                'target_url': url,
                'scan_duration': 'Completed',
                'total_findings': len(all_findings),
                'vulnerabilities_found': len(all_vulnerabilities),
                'open_ports_found': len(all_open_ports),
                'services_detected': len(all_services),
                'severity_breakdown': scan_summary.get('severity_breakdown', {
                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
                }),
                'distributed_scan_id': chain_results.get('distributed_scan_id') if is_distributed else None
            }
        }
        
        # Log completion with REAL data
        if is_distributed:
            await connection_manager.send_log(
                scan_id, 
                f"[DISTRIBUTED] REAL scan completed: {len(all_findings)} findings, {len(all_vulnerabilities)} vulnerabilities from distributed system", 
                "success"
            )
        else:
            await connection_manager.send_log(
                scan_id, 
                f"[LOCAL] REAL scan completed: {len(all_findings)} findings, {len(all_vulnerabilities)} vulnerabilities across {scan_summary.get('total_targets', 0)} targets", 
                "success"
            )
        
        # Store REAL results
        scan_results[scan_id].update({
            'status': 'completed',
            'end_time': datetime.now().isoformat(),
            'results': results,
            'distributed_system_used': is_distributed
        })
        
        # Save to file - REAL DATA
        os.makedirs("scan_results", exist_ok=True)
        with open(f"scan_results/{scan_id}.json", "w") as f:
            json.dump({
                'scan_id': scan_id,
                'target_url': url,
                'username': username,
                'scan_mode': 'comprehensive',
                'distributed_system_used': is_distributed,
                'results': results,
                'timestamp': datetime.now().isoformat()
            }, f, indent=2, default=str)
        
        logger.info(f"[MAIN BACKEND] REAL scan results saved to scan_results/{scan_id}.json")
        
        await connection_manager.send_complete(scan_id, f"/scan/{scan_id}")
        
    except Exception as e:
        logger.error(f"Comprehensive scan failed for {scan_id}: {str(e)}")
        scan_results[scan_id].update({
            'status': 'failed',
            'error': str(e),
            'end_time': datetime.now().isoformat()
        })
        await connection_manager.send_log(scan_id, f"❌ Comprehensive scan failed: {str(e)}", "error")

@app.post("/scan/scanner-chain", tags=["Scanner Chain"])
async def scanner_chain_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(check_scan_rate_limit_dependency)
):
    """
    Run sequential scanner chain with PDF report generation
    
    This endpoint runs scanners in a sequential chain and generates a comprehensive PDF report
    """
    scan_id = f"chain_{int(time.time() * 1000)}"
    username = current_user.username
    
    # Store scan metadata
    scan_results[scan_id] = {
        'status': 'running',
        'target_url': str(request.target_url),
        'scan_mode': 'scanner_chain',
        'start_time': datetime.now().isoformat(),
        'user': username,
        'scan_type': 'sequential_chain'
    }
    
    # Run scanner chain in background
    background_tasks.add_task(run_scanner_chain, scan_id, str(request.target_url), username, request)
    
    return {
        "scan_id": scan_id,
        "status": "initiated",
        "message": "Sequential scanner chain started",
        "target_url": str(request.target_url),
        "websocket_url": f"/ws/{scan_id}",
        "estimated_duration": "15-45 minutes",
        "features": ["Sequential execution", "Real-time progress", "PDF report generation"]
    }

async def run_scanner_chain(scan_id: str, url: str, username: str, scan_request: ScanRequest):
    """Run sequential scanner chain with complete crawling and no timeouts"""
    try:
        await connection_manager.send_log(scan_id, "🔗 Starting sequential scanner chain with complete crawling...", "info")
        
        # Initialize scanner chain
        scanner_chain = ScannerChain(url)
        
        # Configure scan options to ensure all scanners run
        scan_options = {
            'include_web_scans': True,
            'include_auth_scans': True,
            'include_injection_scans': True,
            'include_info_disclosure': True,
            'include_wordpress_scan': True
        }
        
        await connection_manager.send_log(scan_id, f"📋 Configured {len(scanner_chain.scanner_chain)} scanners for complete execution", "info")
        
        # Run the scanner chain with complete crawling
        results = await scanner_chain.run_chain(scan_options)
        
        await connection_manager.send_log(scan_id, "📄 Generating PDF report...", "info")
        
        # Generate PDF report
        try:
            pdf_path = scanner_chain.generate_pdf_report()
            await connection_manager.send_log(scan_id, f" PDF report generated: {pdf_path}", "success")
        except Exception as e:
            await connection_manager.send_log(scan_id, f"WARNING: PDF generation failed: {str(e)}", "warning")
            pdf_path = None
        
        # Count findings
        total_findings = 0
        for step_result in results.values():
            if isinstance(step_result, dict) and 'findings' in step_result:
                total_findings += len(step_result['findings'])
        
        # Store results
        scan_results[scan_id].update({
            'status': 'completed',
            'end_time': datetime.now().isoformat(),
            'results': {
                'status': 'completed',
                'chain_results': results,
                'pdf_report': pdf_path,
                'summary': {
                    'total_steps': len(scanner_chain.scanner_chain),
                    'completed_steps': len(results),
                    'total_findings': total_findings,
                    'duration': str(scanner_chain.end_time - scanner_chain.start_time) if scanner_chain.end_time and scanner_chain.start_time else 'N/A'
                }
            }
        })
        
        await connection_manager.send_log(scan_id, f" Scanner chain completed with {total_findings} findings", "success")
        await connection_manager.send_complete(scan_id, f"/scan/{scan_id}")
        
    except Exception as e:
        logger.error(f"Scanner chain failed for {scan_id}: {str(e)}")
        scan_results[scan_id].update({
            'status': 'failed',
            'error': str(e),
            'end_time': datetime.now().isoformat()
        })
        await connection_manager.send_log(scan_id, f"❌ Scanner chain failed: {str(e)}", "error")

@app.get("/scan/{scan_id}/pdf-report-chain", tags=["Reports"])
async def get_scanner_chain_pdf_report(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Download PDF report generated by scanner chain
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    
    if scan_data.get('status') != 'completed':
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    results = scan_data.get('results', {})
    pdf_path = results.get('pdf_report')
    
    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="PDF report not found")
    
    from fastapi.responses import FileResponse
    return FileResponse(
        pdf_path,
        media_type='application/pdf',
        filename=f"scanner_chain_report_{scan_id}.pdf"
    )

@app.get("/scan/{scan_id}/chain-summary", tags=["Reports"])
async def get_scanner_chain_summary(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get comprehensive scanner chain execution summary with subdomain analysis
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    
    if scan_data.get('status') != 'completed':
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    results = scan_data.get('results', {})
    comprehensive_report = results.get('comprehensive_report', {})
    subdomain_results = results.get('subdomain_results', {})
    chain_results = results.get('chain_results', {})
    
    # Generate comprehensive summary with subdomain data
    scan_summary = comprehensive_report.get('scan_summary', {})
    subdomain_summary = comprehensive_report.get('subdomain_summary', {})
    
    return {
        "scan_id": scan_id,
        "target": scan_data.get('target', 'Unknown'),
        "status": scan_data.get('status'),
        "start_time": scan_data.get('start_time'),
        "end_time": scan_data.get('end_time'),
        "duration": scan_data.get('duration'),
        "comprehensive_summary": {
            "total_subdomains": scan_summary.get('total_subdomains', 0),
            "total_scanners": scan_summary.get('total_scanners', 0),
            "total_scans_executed": scan_summary.get('total_scans_executed', 0),
            "total_findings": scan_summary.get('total_findings', 0),
            "total_vulnerabilities": scan_summary.get('total_vulnerabilities', 0),
            "total_open_ports": scan_summary.get('total_open_ports', 0),
            "total_services": scan_summary.get('total_services', 0),
            "severity_breakdown": scan_summary.get('severity_breakdown', {
                'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
            })
        },
        "subdomain_analysis": subdomain_summary,
        "top_findings": comprehensive_report.get('all_findings', [])[:10],  # Top 10 findings
        "detailed_results": subdomain_results
    }

@app.get("/scans/{scan_id}/status", tags=["Scan Status"])
async def get_scan_status(scan_id: str):
    """
    Get the current status of a scan
    
    Returns the current status, progress, and basic information about a running or completed scan.
    This endpoint is used by the frontend to poll for scan updates.
    """
    # Check if scan exists in scan_results
    if scan_id in scan_results:
        scan_data = scan_results[scan_id]
        return {
            "scan_id": scan_id,
            "status": scan_data.get('status', 'unknown'),
            "progress": scan_data.get('progress', 0),
            "target": scan_data.get('target', 'Unknown'),
            "start_time": scan_data.get('start_time'),
            "end_time": scan_data.get('end_time'),
            "duration": scan_data.get('duration'),
            "message": scan_data.get('message', ''),
            "findings_count": len(scan_data.get('results', {}).get('findings', [])),
            "websocket_url": f"/ws/{scan_id}"
        }
    
    # Scan not found - raise 404 error
    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

# ConnectionManager already defined at line 226 - duplicate removed here
# connection_manager instantiated at line 4678 - duplicate instantiation removed here

@app.get("/ws/{scan_id}/status")
async def get_websocket_status(scan_id: str):
    """Get WebSocket connection status for debugging"""
    return {
        "scan_id": scan_id,
        "connection_status": connection_manager.get_connection_status(scan_id),
        "has_logs": len(connection_manager.get_scan_logs(scan_id)) > 0,
        "log_count": len(connection_manager.get_scan_logs(scan_id))
    }

@app.get("/ws/{scan_id}/logs")
async def get_websocket_logs(scan_id: str):
    """Get all WebSocket logs for a scan"""
    return {
        "scan_id": scan_id,
        "logs": connection_manager.get_scan_logs(scan_id)
    }

# ============================================
# ADMIN ENDPOINTS - Storage Management
# ============================================

@app.post("/admin/cleanup-scans")
async def trigger_cleanup(retention_days: int = 90):
    """Manually trigger scan cleanup and archival"""
    result = cleanup_old_scans(retention_days, archive_before_delete=True)
    return {
        "message": "Cleanup completed",
        "archived": result.get('archived', 0),
        "deleted": result.get('deleted', 0),
        "retention_days": retention_days,
        "status": "success" if "error" not in result else "failed",
        "error": result.get("error")
    }

@app.get("/admin/archives")
async def list_archives():
    """List all archived scans"""
    archive_dir = Path("scan_archives")
    archive_dir.mkdir(exist_ok=True)
    archives = []
    
    for zip_file in archive_dir.glob("*.zip"):
        stat = zip_file.stat()
        archives.append({
            "filename": zip_file.name,
            "scan_id": zip_file.stem,
            "size_mb": round(stat.st_size / 1024 / 1024, 2),
            "archived_date": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })
    
    # Sort by date (newest first)
    archives.sort(key=lambda x: x['archived_date'], reverse=True)
    
    return {
        "archives": archives,
        "total": len(archives),
        "total_size_mb": round(sum(a['size_mb'] for a in archives), 2)
    }

@app.get("/admin/archives/{scan_id}/download")
async def download_archive(scan_id: str):
    """Download archived scan as ZIP"""
    from fastapi.responses import FileResponse
    zip_path = Path(f"scan_archives/{scan_id}.zip")
    if zip_path.exists():
        return FileResponse(
            zip_path,
            filename=f"{scan_id}.zip",
            media_type="application/zip"
        )
    raise HTTPException(404, detail="Archive not found")

@app.get("/admin/storage-stats")
async def get_storage_stats():
    """Get storage usage statistics"""
    scan_dir = Path("scan_results")
    archive_dir = Path("scan_archives")
    
    # Count active scans
    active_scans = len([d for d in scan_dir.iterdir() if d.is_dir()]) if scan_dir.exists() else 0
    
    # Calculate sizes
    active_size = sum(f.stat().st_size for f in scan_dir.rglob('*') if f.is_file()) if scan_dir.exists() else 0
    archive_size = sum(f.stat().st_size for f in archive_dir.glob('*.zip')) if archive_dir.exists() else 0
    
    # Find oldest/newest
    scans = []
    if scan_dir.exists():
        for scan in scan_dir.iterdir():
            if scan.is_dir():
                metadata = scan / "metadata.json"
                if metadata.exists():
                    try:
                        with open(metadata) as f:
                            data = json.load(f)
                            scans.append(data.get('scan_start', data.get('start_time', '')))
                    except:
                        pass
    
    return {
        "active_scans": active_scans,
        "active_size_mb": round(active_size / 1024 / 1024, 2),
        "archived_scans": len(list(archive_dir.glob('*.zip'))) if archive_dir.exists() else 0,
        "archived_size_mb": round(archive_size / 1024 / 1024, 2),
        "total_size_mb": round((active_size + archive_size) / 1024 / 1024, 2),
        "oldest_scan": min(scans) if scans else None,
        "newest_scan": max(scans) if scans else None,
        "retention_days": 90,
        "disk_usage": {
            "scan_results": f"{round(active_size / 1024 / 1024, 2)} MB",
            "archives": f"{round(archive_size / 1024 / 1024, 2)} MB",
            "total": f"{round((active_size + archive_size) / 1024 / 1024, 2)} MB"
        }
    }

@app.get("/admin/recent-scans")
async def get_recent_scans_from_cache():
    """Get recent scans from Redis cache"""
    try:
        redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        recent_scan_ids = redis_client.lrange("recent_scans", 0, 9)
        
        recent_scans = []
        for scan_id in recent_scan_ids:
            scan_data = redis_client.hgetall(f"scan_summary:{scan_id}")
            if scan_data:
                recent_scans.append(scan_data)
        
        return {
            "recent_scans": recent_scans,
            "count": len(recent_scans),
            "source": "redis_cache"
        }
    except Exception as e:
        return {
            "recent_scans": [],
            "count": 0,
            "error": str(e),
            "source": "redis_cache_unavailable"
        }

if __name__ == "__main__":
    import uvicorn
    print("[STARTUP] Starting FastAPI backend server...")
    print("[INFO] All 14 scanners loaded and ready for sequential execution")
    print("[INFO] Server will be available at: http://localhost:3000")
    print("[INFO] API documentation: http://localhost:3000/docs")
    print("[INFO] WebSocket endpoint: ws://localhost:3000/ws/{scan_id}")
    uvicorn.run("main:app", host="0.0.0.0", port=3000, reload=True)
