"""
Scan Tracker - Enhanced scan tracking and pipeline management
"""
 
import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
 
class ScanTracker:
    def __init__(self):
        self.scans_file = "uploads/scan_pipeline.json"
        os.makedirs("uploads", exist_ok=True)
        self.scans = self._load_scans()
   
    def _load_scans(self) -> Dict:
        """Load scan pipeline data from file"""
        try:
            if os.path.exists(self.scans_file):
                with open(self.scans_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error loading scan pipeline: {e}")
            return {}
   
    def _save_scans(self):
        """Save scan pipeline data to file"""
        try:
            with open(self.scans_file, 'w') as f:
                json.dump(self.scans, f, indent=2)
        except Exception as e:
            print(f"Error saving scan pipeline: {e}")
   
    def create_scan_pipeline(self, file_id: str, scan_type: str = "comprehensive") -> str:
        """
        Create a new scan pipeline entry
       
        Args:
            file_id: The file or repository ID
            scan_type: Type of scan (comprehensive, quick, etc.)
       
        Returns:
            Unique pipeline ID
        """
        pipeline_id = str(uuid.uuid4())
       
        self.scans[pipeline_id] = {
            "pipeline_id": pipeline_id,
            "file_id": file_id,
            "scan_type": scan_type,
            "status": "created",
            "created_at": f"{datetime.now().strftime('%Y-%m-%d')}T{datetime.now().strftime('%H:%M:%S')}",
            "updated_at": datetime.now().isoformat(),
            "scan_history": [],
            "current_scan_id": None,
            "total_scans": 0,
            "metadata": {
                "source_type": "unknown",
                "filename": "unknown",
                "file_count": 0
            }
        }
       
        self._save_scans()
        return pipeline_id
   
    def start_scan(self, pipeline_id: str, scan_id: str) -> bool:
        """
        Start a scan within a pipeline
       
        Args:
            pipeline_id: The pipeline ID
            scan_id: The scan ID
       
        Returns:
            True if successful
        """
        if pipeline_id not in self.scans:
            return False
       
        self.scans[pipeline_id]["current_scan_id"] = scan_id
        self.scans[pipeline_id]["status"] = "scanning"
        self.scans[pipeline_id]["updated_at"] = datetime.now().isoformat()
       
        # Add to scan history
        self.scans[pipeline_id]["scan_history"].append({
            "scan_id": scan_id,
            "started_at": datetime.now().isoformat(),
            "status": "scanning"
        })
       
        self.scans[pipeline_id]["total_scans"] += 1
        self._save_scans()
        return True
   
    def complete_scan(self, pipeline_id: str, scan_id: str, results: Dict) -> bool:
        """
        Mark a scan as completed within a pipeline
       
        Args:
            pipeline_id: The pipeline ID
            scan_id: The scan ID
            results: Scan results
       
        Returns:
            True if successful
        """
        if pipeline_id not in self.scans:
            return False
       
        # Update pipeline status
        self.scans[pipeline_id]["status"] = "completed"
        self.scans[pipeline_id]["updated_at"] = datetime.now().isoformat()
       
        # Extract summary data from various possible structures
        summary = results.get("summary", {})
        if not summary:
            # Try to calculate from files_scanned if summary is missing
            files_scanned = results.get("files_scanned", [])
            total_issues = sum(len(file.get("issues", [])) for file in files_scanned)
            critical_issues = sum(
                len([issue for issue in file.get("issues", []) if issue.get("severity") == "critical"])
                for file in files_scanned
            )
            compliance_score = max(0, 100 - (total_issues * 10))  # Simple scoring
        else:
            total_issues = summary.get("total_issues", 0)
            critical_issues = summary.get("critical_issues", 0)
            compliance_score = summary.get("compliance_score", 0)
       
        # Update pipeline metadata with scan results
        if "metadata" not in self.scans[pipeline_id]:
            self.scans[pipeline_id]["metadata"] = {}
       
        # Store latest scan results in pipeline metadata
        self.scans[pipeline_id]["metadata"].update({
            "latest_scan_id": scan_id,
            "latest_compliance_score": compliance_score,
            "latest_total_issues": total_issues,
            "latest_critical_issues": critical_issues,
            "total_files_scanned": summary.get("total_files", len(results.get("files_scanned", []))),
            "last_scan_date": datetime.now().isoformat()
        })
       
        # Debug logging
        print(f"Scan Tracker - Pipeline {pipeline_id}, Scan {scan_id}")
        print(f"  Results summary: {summary}")
        print(f"  Total issues: {total_issues}, Critical: {critical_issues}, Score: {compliance_score}")
       
        # Update scan history
        for scan_entry in self.scans[pipeline_id]["scan_history"]:
            if scan_entry["scan_id"] == scan_id:
                scan_entry["completed_at"] = datetime.now().isoformat()
                scan_entry["status"] = "completed"
                scan_entry["results_summary"] = {
                    "total_issues": total_issues,
                    "critical_issues": critical_issues,
                    "compliance_score": compliance_score,
                    "high_issues": summary.get("high_issues", 0),
                    "medium_issues": summary.get("medium_issues", 0),
                    "low_issues": summary.get("low_issues", 0),
                    "total_files": summary.get("total_files", len(results.get("files_scanned", [])))
                }
                break
       
        self._save_scans()
        return True
   
    def get_pipeline(self, pipeline_id: str) -> Optional[Dict]:
        """Get pipeline information"""
        return self.scans.get(pipeline_id)
   
    def get_all_pipelines(self) -> List[Dict]:
        """Get all pipelines sorted by creation date (newest first)"""
        pipelines = list(self.scans.values())
        return sorted(pipelines, key=lambda x: x["created_at"], reverse=True)
   
    def update_pipeline_metadata(self, pipeline_id: str, metadata: Dict) -> bool:
        """Update pipeline metadata"""
        if pipeline_id not in self.scans:
            return False
       
        self.scans[pipeline_id]["metadata"].update(metadata)
        self.scans[pipeline_id]["updated_at"] = datetime.now().isoformat()
        self._save_scans()
        return True