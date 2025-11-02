"""
Scan Service - Core compliance scanning logic with PII detection and rule checking
"""
 
import os
import json
import re
import ast
from datetime import datetime
from typing import Dict, List, Optional, Any
from utils.pii_patterns import PIIPatterns
from utils.compliance_rules import ComplianceRules
from services.file_service import FileService
 
class ScanService:
    def __init__(self):
        self.file_service = FileService()
        self.pii_patterns = PIIPatterns()
        self.compliance_rules = ComplianceRules()
       
        # Persistent storage for scan results
        self.scan_results_file = "uploads/scan_results.json"
        self.scan_status_file = "uploads/scan_status.json"
        self.scan_results = self._load_scan_results()
        self.scan_status = self._load_scan_status()
        # root for per-user scan archives
        self.user_scans_root = os.path.join('uploads', 'users')
   
    def _load_scan_results(self) -> Dict:
        """Load scan results from file"""
        try:
            if os.path.exists(self.scan_results_file):
                with open(self.scan_results_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error loading scan results: {e}")
            return {}
   
    def _save_scan_results(self):
        """Save scan results to file"""
        try:
            with open(self.scan_results_file, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
        except Exception as e:
            print(f"Error saving scan results: {e}")
   
    def _load_scan_status(self) -> Dict:
        """Load scan status from file"""
        try:
            if os.path.exists(self.scan_status_file):
                with open(self.scan_status_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error loading scan status: {e}")
            return {}
   
    def _save_scan_status(self):
        """Save scan status to file"""
        try:
            with open(self.scan_status_file, 'w') as f:
                json.dump(self.scan_status, f, indent=2)
        except Exception as e:
            print(f"Error saving scan status: {e}")
 
    async def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Return current status for a scan (progress + counts)"""
        return self.scan_status.get(scan_id)
   
    async def start_scan(self, file_id: str, scan_id: str, username: Optional[str] = None) -> Dict:
        """
        Start a compliance scan for a file or repository
       
        Args:
            file_id: The file or repository ID to scan
            scan_id: Unique scan identifier
            username: Optional username for associating scan results
       
        Returns:
            Initial scan status
        """
        try:
            # Initialize scan status with phase
            started_at = datetime.now()
            self.scan_status[scan_id] = {
                "scan_id": scan_id,
                "file_id": file_id,
                "status": "in_progress",
                "phase": "scanning",
                "started_at": started_at.isoformat(),
                "progress": 0,
                "total_files": 0,
                "processed_files": 0,
                "timing": {
                    "scan_start_ts": started_at.isoformat(),
                    "scanning_ms": 0,
                    "aggregation_ms": 0,
                    "total_ms": 0
                }
            }
            self._save_scan_status()
           
            # Get file/repository metadata
            metadata = await self.file_service.get_upload_status(file_id)
            if not metadata:
                raise Exception(f"File or repository {file_id} not found")
 
            # Initialize total_files early for immediate UI feedback
            if metadata.get("type") in {"repository", "azure_repository"}:
                files_list = metadata.get("processed_files", []) or []
                self.scan_status[scan_id]["total_files"] = len(files_list)
                self._save_scan_status()
           
            # Perform the actual scan
            try:
                scan_results = await self._perform_scan(file_id, scan_id, metadata)
                if username:
                    scan_results["user"] = username
            except Exception as e:
                # Create a minimal scan result with error info
                scan_results = {
                    "scan_id": scan_id,
                    "file_id": file_id,
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": "comprehensive",
                    "files_scanned": [],
                    "issues_found": [],
                    "compliance_violations": [],
                    "summary": {
                        "total_files": 0,
                        "files_with_issues": 0,
                        "total_issues": 1,
                        "critical_issues": 0,
                        "high_issues": 0,
                        "medium_issues": 0,
                        "low_issues": 1,
                        "compliance_score": 0
                    },
                    "error": str(e)
                }
           
            # Store results (final status + timing handled inside _perform_scan)
            self.scan_results[scan_id] = scan_results
            self._save_scan_results()
            # Persist per-user copy if username available
            if username:
                self._persist_user_scan(username, scan_id, scan_results)
                self._prune_user_scans(username)
           
            # Return the full scan results for the tracker
            return scan_results
           
        except Exception as e:
            # Update scan status to failed
            self.scan_status[scan_id] = {
                "scan_id": scan_id,
                "file_id": file_id,
                "status": "failed",
                "started_at": self.scan_status.get(scan_id, {}).get("started_at"),
                "failed_at": datetime.now().isoformat(),
                "error": str(e)
            }
            raise Exception(f"Scan failed: {str(e)}")
   
    async def perform_quick_scan(self, file_id: str, scan_id: str, username: Optional[str] = None) -> Dict:
        """
        Perform a quick compliance scan with immediate results
       
        Args:
            file_id: The file or repository ID to scan
            scan_id: Unique scan identifier
            username: Optional username for associating scan results
       
        Returns:
            Scan results
        """
        try:
            # Get file/repository metadata
            metadata = await self.file_service.get_upload_status(file_id)
            if not metadata:
                raise Exception(f"File or repository {file_id} not found")
           
            # Perform quick scan
            scan_results = await self._perform_scan(file_id, scan_id, metadata, quick_mode=True)
            if username:
                scan_results["user"] = username
           
            # Store results
            self.scan_results[scan_id] = scan_results
            self._save_scan_results()
            if username:
                self._persist_user_scan(username, scan_id, scan_results)
                self._prune_user_scans(username)
           
            return scan_results
           
        except Exception as e:
            raise Exception(f"Quick scan failed: {str(e)}")
   
    async def _perform_scan(self, file_id: str, scan_id: str, metadata: Dict, quick_mode: bool = False) -> Dict:
        """
        Internal method to perform the actual scanning
       
        Args:
            file_id: The file or repository ID
            scan_id: Unique scan identifier
            metadata: File/repository metadata
            quick_mode: Whether to run in quick mode
       
        Returns:
            Detailed scan results
        """
        scan_phase_start = datetime.now()
        scan_results = {
            "scan_id": scan_id,
            "file_id": file_id,
            "scan_type": "quick" if quick_mode else "comprehensive",
            "scan_timestamp": datetime.now().isoformat(),
            "files_scanned": [],
            "issues_found": [],
            "compliance_violations": [],
            "summary": {
                "total_files": 0,
                "files_with_issues": 0,
                "total_issues": 0,
                "critical_issues": 0,
                "high_issues": 0,
                "medium_issues": 0,
                "low_issues": 0,
                "compliance_score": 0
            }
        }
       
        if metadata["type"] == "file":
            # Scan single file
            file_results = await self._scan_single_file(metadata["file_path"], metadata["filename"])
            scan_results["files_scanned"].append(file_results)
           
        else:
            # Scan repository files
            processed_files = metadata["processed_files"]
            scan_results["summary"]["total_files"] = len(processed_files)
            skipped_errors = 0
           
            for file_info in processed_files:
                if quick_mode and len(scan_results["files_scanned"]) >= 10:
                    break  # Limit files in quick mode
               
                # Skip files that failed ingestion (retain count, mark skipped)
                if file_info.get("ingest_error"):
                    skipped_errors += 1
                    continue
 
                try:
                    file_results = await self._scan_single_file(
                        file_info["absolute_path"],
                        file_info["relative_path"]
                    )
                    scan_results["files_scanned"].append(file_results)
                except Exception as e:
                    print(f"Error scanning file {file_info['absolute_path']}: {e}")
                    # Add error file result instead of crashing
                    scan_results["files_scanned"].append({
                        "filename": file_info["relative_path"],
                        "file_path": file_info["absolute_path"],
                        "file_size": 0,
                        "issues": [{
                            "violation_type": "Scan Error",
                            "severity": "low",
                            "framework": "SYSTEM",
                            "description": f"Failed to scan file: {str(e)}",
                            "line_number": 0
                        }],
                        "pii_detected": [],
                        "compliance_violations": [],
                        "risk_score": 0
                    })
               
                # Update progress
                if scan_id in self.scan_status:
                    status_ref = self.scan_status[scan_id]
                    status_ref["processed_files"] = len(scan_results["files_scanned"])
                    status_ref["total_files"] = len(processed_files)
                    # Scale scanning progress 0-90
                    status_ref["progress"] = min(90, (len(scan_results["files_scanned"]) / len(processed_files)) * 90)
                    # Update scanning elapsed
                    status_ref["timing"]["scanning_ms"] = int((datetime.now() - scan_phase_start).total_seconds() * 1000)
                    status_ref["timing"]["total_ms"] = status_ref["timing"]["scanning_ms"]
                    self._save_scan_status()
        # Store skipped ingestion errors count for repositories
        if metadata.get("type") != "file":
            scan_results["skipped_files_due_to_ingest_error"] = skipped_errors
 
        # Transition to aggregation phase
        if scan_id in self.scan_status:
            agg_start = datetime.now()
            status_ref = self.scan_status[scan_id]
            status_ref["phase"] = "finalizing"
            # Jump progress to 95 to signal finalization
            status_ref["progress"] = max(status_ref.get("progress", 0), 95)
            self._save_scan_status()
        else:
            agg_start = datetime.now()
 
        # Aggregate results (final compute phase)
        scan_results = self._aggregate_scan_results(scan_results)
 
        # Finish timings + status
        if scan_id in self.scan_status:
            status_ref = self.scan_status[scan_id]
            status_ref["phase"] = "completed"
            status_ref["status"] = "completed"
            status_ref["progress"] = 100
            status_ref["completed_at"] = datetime.now().isoformat()
            status_ref["timing"]["aggregation_ms"] = int((datetime.now() - agg_start).total_seconds() * 1000)
            # Recompute totals
            status_ref["timing"]["total_ms"] = status_ref["timing"]["scanning_ms"] + status_ref["timing"]["aggregation_ms"]
            self._save_scan_status()
 
        # Note: AI analysis is added separately when requested via the AI summary endpoint
        return scan_results
   
   
    async def _scan_single_file(self, file_path: str, filename: str) -> Dict:
        """
        Scan a single file for compliance issues
       
        Args:
            file_path: Path to the file
            filename: Name of the file
       
        Returns:
            File scan results
        """
        try:
            # Read file content
            content = await self.file_service.read_file_content(file_path)
           
            # Initialize file results
            file_results = {
                "filename": filename,
                "file_path": file_path,
                "file_size": len(content),
                "issues": [],
                "pii_detected": [],
                "compliance_violations": [],
                "risk_score": 0
            }
           
            # Detect PII patterns
            pii_results = await self.pii_patterns.detect_pii(content, filename)
            file_results["pii_detected"] = pii_results["detected"]
            file_results["issues"].extend(pii_results["issues"])
           
            # Check compliance rules
            compliance_results = await self.compliance_rules.check_compliance(content, filename)
            file_results["compliance_violations"] = compliance_results["violations"]
            file_results["issues"].extend(compliance_results["issues"])
           
            # Perform static analysis for Python files
            if filename.endswith('.py'):
                static_analysis = await self._perform_static_analysis(content, filename)
                file_results["issues"].extend(static_analysis["issues"])
                file_results["static_analysis"] = static_analysis
           
            # Calculate risk score
            file_results["risk_score"] = self._calculate_file_risk_score(file_results)
           
            return file_results
           
        except Exception as e:
            return {
                "filename": filename,
                "file_path": file_path,
                "error": f"Failed to scan file: {str(e)}",
                "issues": [],
                "pii_detected": [],
                "compliance_violations": [],
                "risk_score": 0
            }
   
    async def _perform_static_analysis(self, content: str, filename: str) -> Dict:
        """
        Perform static analysis on Python files
       
        Args:
            content: File content
            filename: File name
       
        Returns:
            Static analysis results
        """
        issues = []
       
        try:
            # Parse AST
            tree = ast.parse(content, filename=filename)
           
            # Check for common security issues
            for node in ast.walk(tree):
                # Check for hardcoded secrets
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if target.id.lower() in ['password', 'secret', 'key', 'token']:
                                issues.append({
                                    "type": "hardcoded_secret",
                                    "severity": "high",
                                    "line": node.lineno,
                                    "description": f"Potential hardcoded secret: {target.id}",
                                    "recommendation": "Use environment variables or secure configuration management"
                                })
               
                # Check for SQL injection risks
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'execute' and hasattr(node.func.value, 'id'):
                            if node.func.value.id.lower() in ['cursor', 'db']:
                                issues.append({
                                    "type": "sql_injection_risk",
                                    "severity": "medium",
                                    "line": node.lineno,
                                    "description": "Potential SQL injection risk with direct string execution",
                                    "recommendation": "Use parameterized queries or ORM"
                                })
               
                # Check for eval() usage
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                        issues.append({
                            "type": "eval_usage",
                            "severity": "high",
                            "line": node.lineno,
                            "description": "Use of eval() function detected",
                            "recommendation": "Avoid eval() as it can execute arbitrary code"
                        })
       
        except SyntaxError:
            issues.append({
                "type": "syntax_error",
                "severity": "low",
                "line": 0,
                "description": "Syntax error in Python file",
                "recommendation": "Fix syntax errors before scanning"
            })
        except Exception as e:
            issues.append({
                "type": "analysis_error",
                "severity": "low",
                "line": 0,
                "description": f"Static analysis error: {str(e)}",
                "recommendation": "Review file for potential issues"
            })
       
        return {
            "issues": issues,
            "analysis_type": "static_analysis",
            "language": "python"
        }
   
    def _calculate_file_risk_score(self, file_results: Dict) -> int:
        """
        Calculate risk score for a file based on detected issues
       
        Args:
            file_results: File scan results
       
        Returns:
            Risk score (0-100)
        """
        score = 0
       
        # Weight different types of issues
        severity_weights = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5
        }
       
        # Calculate score based on issues
        for issue in file_results["issues"]:
            severity = issue.get("severity", "low")
            score += severity_weights.get(severity, 5)
       
        # Add PII detection penalty
        pii_count = len(file_results["pii_detected"])
        score += min(pii_count * 10, 30)  # Max 30 points for PII
       
        return min(score, 100)  # Cap at 100
   
    def _aggregate_scan_results(self, scan_results: Dict) -> Dict:
        """
        Aggregate individual file results into overall scan summary
       
        Args:
            scan_results: Individual scan results
       
        Returns:
            Aggregated scan results
        """
        summary = {
            "total_files": len(scan_results["files_scanned"]),
            "files_with_issues": 0,
            "total_issues": 0,
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0,
            "compliance_score": 0,
            "average_risk_score": 0
        }
       
        total_risk_score = 0
       
        for file_result in scan_results["files_scanned"]:
            if file_result.get("issues"):
                summary["files_with_issues"] += 1
           
            # Count issues by severity
            for issue in file_result.get("issues", []):
                summary["total_issues"] += 1
                severity = issue.get("severity", "low")
                if severity in summary:
                    summary[f"{severity}_issues"] += 1
           
            total_risk_score += file_result.get("risk_score", 0)
       
        # Calculate average risk score
        if summary["total_files"] > 0:
            summary["average_risk_score"] = total_risk_score / summary["total_files"]
       
        # Calculate compliance score (inverse of risk)
        summary["compliance_score"] = max(0, 100 - summary["average_risk_score"])
       
        # Update scan results
        scan_results["summary"] = summary
       
        return scan_results
   
    async def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """
        Get the status of a scan
       
        Args:
            scan_id: The scan ID
       
        Returns:
            Scan status information
        """
        return self.scan_status.get(scan_id)
   
    def get_scan_results(self, scan_id: str) -> Optional[Dict]:
        """
        Get the results of a completed scan
       
        Args:
            scan_id: The scan ID
       
        Returns:
            Scan results
        """
        return self.scan_results.get(scan_id)
   
    def get_user_scans(self, username: str) -> List[Dict]:
        """
        Get all scans associated with a user
       
        Args:
            username: The username to filter scans
       
        Returns:
            List of scan results for the user
        """
        return [r for r in self.scan_results.values() if r.get("user") == username]
 
    def compute_user_stats(self, username: str) -> Dict[str, Any]:
        """Aggregate scan metrics for a user for dashboard consumption."""
        scans = sorted(self.get_user_scans(username), key=lambda r: r.get('scan_timestamp', r.get('scan_id', '')))
        total_scans = len(scans)
        critical = high = medium = low = 0
        compliance_scores = []
        issue_distribution = {}
        trend_points = []
 
        for s in scans:
            summary = s.get('summary', {})
            # Severity counts
            critical += summary.get('critical_issues', 0)
            high += summary.get('high_issues', 0)
            medium += summary.get('medium_issues', 0)
            low += summary.get('low_issues', 0)
            # Compliance score
            if 'compliance_score' in summary:
                compliance_scores.append(summary['compliance_score'])
            # Issue distribution via frameworks in file results
            for f in s.get('files_scanned', []):
                for v in f.get('compliance_violations', []):
                    fw = v.get('framework', 'OTHER')
                    issue_distribution[fw] = issue_distribution.get(fw, 0) + 1
            # Trend point
            ts = s.get('scan_timestamp') or s.get('timestamp')
            trend_points.append({
                'ts': ts,
                'score': summary.get('compliance_score', 0),
                'scan_id': s.get('scan_id')
            })
 
        avg_compliance = round(sum(compliance_scores)/len(compliance_scores), 2) if compliance_scores else 0
        # Convert issue distribution to list sorted desc
        distribution_list = [
            {'framework': k, 'count': v, 'percent': (v / sum(issue_distribution.values()) * 100) if issue_distribution else 0}
            for k, v in issue_distribution.items()
        ]
        distribution_list.sort(key=lambda x: x['count'], reverse=True)
        # Keep top 6 trend points (latest chronological)
        trend_points = trend_points[-6:]
        return {
            'total_scans': total_scans,
            'critical_issues': critical,
            'high_issues': high,
            'medium_issues': medium,
            'low_issues': low,
            'avg_compliance_score': avg_compliance,
            'issue_distribution': distribution_list,
            'trend': trend_points
        }
 
    # --- new helpers ---
    def _persist_user_scan(self, username: str, scan_id: str, scan_results: Dict):
        """Write a copy of scan results into the user's folder for isolation."""
        # mirror sanitization used by AuthService
        safe_name = username.lower().replace('@', '__at__').replace('.', '_')
        user_dir = os.path.join(self.user_scans_root, safe_name)
        os.makedirs(user_dir, exist_ok=True)
        scans_dir = os.path.join(user_dir, 'scans')
        os.makedirs(scans_dir, exist_ok=True)
        # per-scan file
        out_file = os.path.join(scans_dir, f"{scan_id}.json")
        try:
            with open(out_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
        except Exception as e:
            print(f"Failed persisting user scan {scan_id} for {username}: {e}")
 
    def _prune_user_scans(self, username: str, max_scans: int = 7):
        """Keep only the latest `max_scans` for the user; remove oldest from user folder and global store."""
        user_scans = [r for r in self.scan_results.values() if r.get('user') == username]
        # Determine timestamp key robustly
        def get_ts(r):
            return r.get('scan_timestamp') or r.get('timestamp') or ''
        # Sort by timestamp ascending (oldest first). Invalid timestamps go first.
        try:
            user_scans.sort(key=lambda r: get_ts(r))
        except Exception:
            pass
        if len(user_scans) <= max_scans:
            return
        excess = len(user_scans) - max_scans
        to_remove = user_scans[:excess]
        # Prepare path details
        safe_name = username.lower().replace('@', '__at__').replace('.', '_')
        scans_dir = os.path.join(self.user_scans_root, safe_name, 'scans')
        removed_ids = []
        for r in to_remove:
            sid = r.get('scan_id')
            if not sid:
                continue
            # Remove per-user file
            fpath = os.path.join(scans_dir, f"{sid}.json")
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception:
                    pass
            # Remove from global structures
            if sid in self.scan_results:
                self.scan_results.pop(sid, None)
            if sid in self.scan_status:
                self.scan_status.pop(sid, None)
            removed_ids.append(sid)
        if removed_ids:
            self._save_scan_results()
            self._save_scan_status()
            print(f"[ScanService] Pruned {len(removed_ids)} old scans for {username} (kept latest {max_scans}).")
 
    def reset_all_scans(self):
        """Delete global scan results & statuses and clear per-user scan JSONs."""
        self.scan_results = {}
        self.scan_status = {}
        self._save_scan_results()
        self._save_scan_status()
        # wipe user scan json files only (not profiles)
        if os.path.isdir(self.user_scans_root):
            for uname in os.listdir(self.user_scans_root):
                scans_dir = os.path.join(self.user_scans_root, uname, 'scans')
                if os.path.isdir(scans_dir):
                    for f in os.listdir(scans_dir):
                        try:
                            os.remove(os.path.join(scans_dir, f))
                        except Exception:
                            pass
 