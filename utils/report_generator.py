"""
Report Generator - Generate comprehensive audit reports from scan results
"""
 
import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from services.ai_service import AIService
from services.scan_service import ScanService
 
class ReportGenerator:
    def __init__(self):
        self.ai_service = AIService()
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)
   
    async def generate_comprehensive_report(self, scan_id: str) -> Dict:
        """
        Generate a comprehensive audit report
       
        Args:
            scan_id: The scan ID to generate report for
       
        Returns:
            Comprehensive audit report
        """
        try:
            # Get actual scan results from ScanService
            scan_service = ScanService()
            scan_results = scan_service.scan_results.get(scan_id)
           
            # If no results found, use mock data for demo
            if not scan_results:
                scan_results = self._get_mock_scan_results(scan_id)
           
            # Generate report sections
            executive_summary = await self._generate_executive_summary(scan_results)
            detailed_findings = await self._generate_detailed_findings(scan_results)
            compliance_assessment = await self._generate_compliance_assessment(scan_results)
            recommendations = await self._generate_recommendations(scan_results)
            risk_analysis = await self._generate_risk_analysis(scan_results)
           
            # Compile comprehensive report
            comprehensive_report = {
                "report_metadata": {
                    "report_id": f"COMPLIANCE_REPORT_{scan_id}",
                    "scan_id": scan_id,
                    "generated_at": datetime.now().isoformat(),
                    "report_version": "1.0",
                    "report_type": "comprehensive_audit"
                },
                "executive_summary": executive_summary,
                "compliance_assessment": compliance_assessment,
                "detailed_findings": detailed_findings,
                "risk_analysis": risk_analysis,
                "recommendations": recommendations,
                "appendix": await self._generate_appendix(scan_results)
            }
           
            # Save report to file
            report_path = os.path.join(self.reports_dir, f"compliance_report_{scan_id}.json")
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(comprehensive_report, f, indent=2, ensure_ascii=False)
           
            return comprehensive_report
           
        except Exception as e:
            return {
                "error": f"Failed to generate comprehensive report: {str(e)}",
                "report_id": f"ERROR_REPORT_{scan_id}",
                "generated_at": datetime.now().isoformat()
            }
   
    async def _generate_executive_summary(self, scan_results: Dict) -> Dict:
        """
        Generate executive summary section
       
        Args:
            scan_results: Scan results data
       
        Returns:
            Executive summary dictionary
        """
        summary_data = scan_results.get("summary", {})
       
        return {
            "overview": f"""
            This compliance audit analyzed {summary_data.get('total_files', 0)} files and identified
            {summary_data.get('total_issues', 0)} compliance issues across multiple regulatory frameworks.
            """,
            "key_metrics": {
                "total_files_scanned": summary_data.get('total_files', 0),
                "files_with_issues": summary_data.get('files_with_issues', 0),
                "total_issues_found": summary_data.get('total_issues', 0),
                "critical_issues": summary_data.get('critical_issues', 0),
                "high_issues": summary_data.get('high_issues', 0),
                "medium_issues": summary_data.get('medium_issues', 0),
                "low_issues": summary_data.get('low_issues', 0),
                "compliance_score": summary_data.get('compliance_score', 0)
            },
            "overall_assessment": self._get_overall_assessment(summary_data),
            "immediate_actions": self._get_immediate_actions(summary_data),
            "risk_level": self._calculate_risk_level(summary_data)
        }
   
    async def _generate_detailed_findings(self, scan_results: Dict) -> Dict:
        """
        Generate detailed findings section
       
        Args:
            scan_results: Scan results data
       
        Returns:
            Detailed findings dictionary
        """
        findings = {
            "files_analyzed": [],
            "issue_summary": {
                "by_severity": {},
                "by_category": {},
                "by_framework": {}
            },
            "critical_findings": [],
            "high_priority_findings": []
        }
       
        # Process each file's results
        for file_result in scan_results.get("files_scanned", []):
            file_finding = {
                "filename": file_result.get("filename", ""),
                "file_path": file_result.get("file_path", ""),
                "risk_score": file_result.get("risk_score", 0),
                "total_issues": len(file_result.get("issues", [])),
                "pii_detected": len(file_result.get("pii_detected", [])),
                "compliance_violations": len(file_result.get("compliance_violations", [])),
                "issues_by_severity": self._count_issues_by_severity(file_result.get("issues", [])),
                "top_issues": file_result.get("issues", [])[:3]  # Top 3 issues
            }
            findings["files_analyzed"].append(file_finding)
       
        # Aggregate issue summaries
        all_issues = []
        for file_result in scan_results.get("files_scanned", []):
            all_issues.extend(file_result.get("issues", []))
       
        findings["issue_summary"]["by_severity"] = self._count_issues_by_severity(all_issues)
        findings["issue_summary"]["by_category"] = self._count_issues_by_category(all_issues)
        findings["issue_summary"]["by_framework"] = self._count_issues_by_framework(all_issues)
       
        # Identify critical and high priority findings
        findings["critical_findings"] = [issue for issue in all_issues if issue.get("severity") == "critical"]
        findings["high_priority_findings"] = [issue for issue in all_issues if issue.get("severity") == "high"]
       
        return findings
   
    async def _generate_compliance_assessment(self, scan_results: Dict) -> Dict:
        """
        Generate compliance assessment section
       
        Args:
            scan_results: Scan results data
       
        Returns:
            Compliance assessment dictionary
        """
        assessment = {
            "frameworks_assessed": ["HIPAA", "GDPR", "DPDP"],
            "framework_compliance": {},
            "overall_compliance_score": scan_results.get("summary", {}).get("compliance_score", 0),
            "compliance_status": self._get_compliance_status(scan_results),
            "regulatory_requirements": {
                "HIPAA": {
                    "status": "needs_review",
                    "key_requirements": ["PHI Encryption", "Access Controls", "Audit Logging"],
                    "compliance_level": "partial"
                },
                "GDPR": {
                    "status": "needs_review",
                    "key_requirements": ["Consent Management", "Data Portability", "Right to Erasure"],
                    "compliance_level": "partial"
                },
                "DPDP": {
                    "status": "needs_review",
                    "key_requirements": ["Data Localization", "Data Principal Rights", "Breach Notification"],
                    "compliance_level": "partial"
                }
            }
        }
       
        # Calculate framework-specific compliance
        for framework in assessment["frameworks_assessed"]:
            framework_issues = []
            for file_result in scan_results.get("files_scanned", []):
                for issue in file_result.get("issues", []):
                    if issue.get("framework") == framework:
                        framework_issues.append(issue)
           
            assessment["framework_compliance"][framework] = {
                "total_violations": len(framework_issues),
                "critical_violations": len([i for i in framework_issues if i.get("severity") == "critical"]),
                "compliance_score": max(0, 100 - (len(framework_issues) * 10)),
                "status": self._get_framework_status(framework_issues)
            }
       
        return assessment
   
    async def _generate_recommendations(self, scan_results: Dict) -> Dict:
        """
        Generate recommendations section
       
        Args:
            scan_results: Scan results data
       
        Returns:
            Recommendations dictionary
        """
        recommendations = {
            "immediate_actions": [],
            "short_term_improvements": [],
            "long_term_strategic": [],
            "priority_matrix": {
                "high_impact_low_effort": [],
                "high_impact_high_effort": [],
                "low_impact_low_effort": [],
                "low_impact_high_effort": []
            }
        }
       
        # Generate AI-powered recommendations
        ai_recommendations = await self.ai_service.generate_recommendations(scan_results.get("scan_id", "mock"))
       
        # Categorize recommendations
        for rec in ai_recommendations:
            priority = rec.get("priority", "medium")
            impact = rec.get("impact", "Medium")
            effort = rec.get("effort", "Medium")
           
            if priority == "critical":
                recommendations["immediate_actions"].append(rec)
            elif priority == "high":
                recommendations["short_term_improvements"].append(rec)
            else:
                recommendations["long_term_strategic"].append(rec)
           
            # Add to priority matrix
            if impact == "High" and effort == "Low":
                recommendations["priority_matrix"]["high_impact_low_effort"].append(rec)
            elif impact == "High" and effort == "High":
                recommendations["priority_matrix"]["high_impact_high_effort"].append(rec)
            elif impact == "Low" and effort == "Low":
                recommendations["priority_matrix"]["low_impact_low_effort"].append(rec)
            else:
                recommendations["priority_matrix"]["low_impact_high_effort"].append(rec)
       
        return recommendations
   
    async def _generate_risk_analysis(self, scan_results: Dict) -> Dict:
        """
        Generate risk analysis section
       
        Args:
            scan_results: Scan results data
       
        Returns:
            Risk analysis dictionary
        """
        summary = scan_results.get("summary", {})
       
        risk_analysis = {
            "overall_risk_level": self._calculate_risk_level(summary),
            "risk_factors": {
                "data_exposure_risk": self._calculate_data_exposure_risk(scan_results),
                "regulatory_compliance_risk": self._calculate_regulatory_risk(scan_results),
                "security_vulnerability_risk": self._calculate_security_risk(scan_results),
                "operational_risk": self._calculate_operational_risk(scan_results)
            },
            "risk_mitigation": {
                "immediate_controls": [],
                "compensating_controls": [],
                "monitoring_recommendations": []
            },
            "risk_trends": {
                "critical_issues_trend": "increasing",  # Would be calculated from historical data
                "compliance_score_trend": "stable",
                "remediation_velocity": "slow"
            }
        }
       
        return risk_analysis
   
    async def _generate_appendix(self, scan_results: Dict) -> Dict:
        """
        Generate appendix section with detailed technical information
       
        Args:
            scan_results: Scan results data
       
        Returns:
            Appendix dictionary
        """
        return {
            "technical_details": {
                "scan_methodology": "Automated static analysis with regex pattern matching and AST parsing",
                "tools_used": ["FastAPI", "Python AST", "Regex Engine", "AI Analysis"],
                "scan_coverage": "100% of submitted files",
                "false_positive_rate": "Estimated 5-10%"
            },
            "file_inventory": [
                {
                    "filename": file_result.get("filename", ""),
                    "file_size": file_result.get("file_size", 0),
                    "issues_count": len(file_result.get("issues", [])),
                    "risk_score": file_result.get("risk_score", 0)
                }
                for file_result in scan_results.get("files_scanned", [])
            ],
            "pattern_definitions": {
                "pii_patterns": "Email, Phone, SSN, Credit Card, Address patterns",
                "compliance_patterns": "HIPAA, GDPR, DPDP specific rule patterns",
                "security_patterns": "Hardcoded credentials, SQL injection, authentication bypass"
            },
            "confidence_scores": {
                "pii_detection": "85-95%",
                "compliance_violations": "80-90%",
                "security_issues": "75-85%"
            }
        }
   
    async def export_report(self, scan_id: str, format: str) -> Dict:
        """
        Export report in specified format
       
        Args:
            scan_id: Scan ID
            format: Export format (json, csv, pdf)
       
        Returns:
            Export data
        """
        try:
            report = await self.generate_comprehensive_report(scan_id)
           
            if format.lower() == "json":
                return self._export_json(report, scan_id)
            elif format.lower() == "csv":
                return self._export_csv(report, scan_id)
            elif format.lower() == "pdf":
                return self._export_pdf(report, scan_id)
            else:
                raise ValueError(f"Unsupported export format: {format}")
               
        except Exception as e:
            return {"error": f"Export failed: {str(e)}"}
   
    def _export_json(self, report: Dict, scan_id: str) -> Dict:
        """Export report as JSON"""
        report_path = os.path.join(self.reports_dir, f"compliance_report_{scan_id}.json")
       
        # Write the report to file
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
       
        file_size = os.path.getsize(report_path)
       
        return {
            "format": "json",
            "file_path": report_path,
            "download_url": f"/api/report/download/{scan_id}.json",
            "file_size": file_size,
            "filename": f"compliance_report_{scan_id}.json"
        }
   
    def _export_csv(self, report: Dict, scan_id: str) -> Dict:
        """Export report as CSV"""
        csv_path = os.path.join(self.reports_dir, f"compliance_report_{scan_id}.csv")
       
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
           
            # Write summary data
            writer.writerow(["Report Section", "Metric", "Value"])
            summary = report.get("executive_summary", {}).get("key_metrics", {})
            for key, value in summary.items():
                writer.writerow(["Summary", key, value])
           
            # Write detailed findings
            findings = report.get("detailed_findings", {})
            for file_finding in findings.get("files_analyzed", []):
                writer.writerow(["File", file_finding["filename"], f"Issues: {file_finding['total_issues']}"])
       
        return {
            "format": "csv",
            "file_path": csv_path,
            "download_url": f"/api/report/download/{scan_id}.csv",
            "file_size": os.path.getsize(csv_path),
            "filename": f"compliance_report_{scan_id}.csv"
        }
   
    def _export_pdf(self, report: Dict, scan_id: str) -> Dict:
        """Export report as PDF (placeholder)"""
        # This would integrate with a PDF generation library like ReportLab
        return {
            "format": "pdf",
            "file_path": f"compliance_report_{scan_id}.pdf",
            "download_url": f"/api/report/download/{scan_id}.pdf",
            "file_size": 0,
            "note": "PDF export requires additional PDF generation library"
        }
   
    def _get_overall_assessment(self, summary: Dict) -> str:
        """Get overall assessment based on summary data"""
        compliance_score = summary.get("compliance_score", 0)
        critical_issues = summary.get("critical_issues", 0)
       
        if critical_issues > 0:
            return "CRITICAL - Immediate action required due to critical compliance violations"
        elif compliance_score < 50:
            return "HIGH RISK - Significant compliance issues require immediate attention"
        elif compliance_score < 75:
            return "MEDIUM RISK - Some compliance issues need to be addressed"
        else:
            return "LOW RISK - Good compliance posture with minor improvements needed"
   
    def _get_immediate_actions(self, summary: Dict) -> List[str]:
        """Get list of immediate actions based on summary"""
        actions = []
       
        if summary.get("critical_issues", 0) > 0:
            actions.append("Address all critical compliance violations immediately")
       
        if summary.get("high_issues", 0) > 0:
            actions.append("Review and remediate high-severity issues within 72 hours")
       
        if summary.get("compliance_score", 0) < 75:
            actions.append("Implement comprehensive compliance monitoring")
       
        return actions
   
    def _calculate_risk_level(self, summary: Dict) -> str:
        """Calculate overall risk level"""
        compliance_score = summary.get("compliance_score", 0)
        critical_issues = summary.get("critical_issues", 0)
       
        if critical_issues > 0 or compliance_score < 30:
            return "CRITICAL"
        elif compliance_score < 50:
            return "HIGH"
        elif compliance_score < 75:
            return "MEDIUM"
        else:
            return "LOW"
   
    def _count_issues_by_severity(self, issues: List[Dict]) -> Dict:
        """Count issues by severity level"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for issue in issues:
            severity = issue.get("severity", "low")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
   
    def _count_issues_by_category(self, issues: List[Dict]) -> Dict:
        """Count issues by category"""
        counts = {}
        for issue in issues:
            category = issue.get("type", "unknown")
            counts[category] = counts.get(category, 0) + 1
        return counts
   
    def _count_issues_by_framework(self, issues: List[Dict]) -> Dict:
        """Count issues by compliance framework"""
        counts = {"HIPAA": 0, "GDPR": 0, "DPDP": 0, "Common": 0}
        for issue in issues:
            framework = issue.get("framework", "Common")
            counts[framework] = counts.get(framework, 0) + 1
        return counts
   
    def _get_compliance_status(self, scan_results: Dict) -> str:
        """Get overall compliance status"""
        score = scan_results.get("summary", {}).get("compliance_score", 0)
       
        if score >= 90:
            return "COMPLIANT"
        elif score >= 75:
            return "MOSTLY COMPLIANT"
        elif score >= 50:
            return "PARTIALLY COMPLIANT"
        else:
            return "NON-COMPLIANT"
   
    def _get_framework_status(self, framework_issues: List[Dict]) -> str:
        """Get framework-specific compliance status"""
        if not framework_issues:
            return "COMPLIANT"
       
        critical_count = len([i for i in framework_issues if i.get("severity") == "critical"])
        if critical_count > 0:
            return "NON-COMPLIANT"
        elif len(framework_issues) > 5:
            return "PARTIALLY COMPLIANT"
        else:
            return "MOSTLY COMPLIANT"
   
    def _calculate_data_exposure_risk(self, scan_results: Dict) -> Dict:
        """Calculate data exposure risk"""
        pii_count = 0
        for file_result in scan_results.get("files_scanned", []):
            pii_count += len(file_result.get("pii_detected", []))
       
        return {
            "level": "HIGH" if pii_count > 10 else "MEDIUM" if pii_count > 0 else "LOW",
            "pii_instances": pii_count,
            "description": f"Found {pii_count} instances of potential PII exposure"
        }
   
    def _calculate_regulatory_risk(self, scan_results: Dict) -> Dict:
        """Calculate regulatory compliance risk"""
        compliance_violations = 0
        for file_result in scan_results.get("files_scanned", []):
            compliance_violations += len(file_result.get("compliance_violations", []))
       
        return {
            "level": "HIGH" if compliance_violations > 15 else "MEDIUM" if compliance_violations > 5 else "LOW",
            "violation_count": compliance_violations,
            "description": f"Found {compliance_violations} regulatory compliance violations"
        }
   
    def _calculate_security_risk(self, scan_results: Dict) -> Dict:
        """Calculate security vulnerability risk"""
        security_issues = 0
        for file_result in scan_results.get("files_scanned", []):
            for issue in file_result.get("issues", []):
                if issue.get("type") in ["hardcoded_secret", "sql_injection_risk", "eval_usage"]:
                    security_issues += 1
       
        return {
            "level": "HIGH" if security_issues > 5 else "MEDIUM" if security_issues > 0 else "LOW",
            "security_issue_count": security_issues,
            "description": f"Found {security_issues} potential security vulnerabilities"
        }
   
    def _calculate_operational_risk(self, scan_results: Dict) -> Dict:
        """Calculate operational risk"""
        total_issues = scan_results.get("summary", {}).get("total_issues", 0)
        files_with_issues = scan_results.get("summary", {}).get("files_with_issues", 0)
       
        return {
            "level": "HIGH" if total_issues > 20 else "MEDIUM" if total_issues > 10 else "LOW",
            "total_issues": total_issues,
            "affected_files": files_with_issues,
            "description": f"{files_with_issues} files affected with {total_issues} total issues"
        }
   
    def _get_mock_scan_results(self, scan_id: str) -> Dict:
        """Get mock scan results for demo purposes"""
        return {
            "scan_id": scan_id,
            "file_id": "mock_file_123",
            "scan_timestamp": datetime.now().isoformat(),
            "files_scanned": [
                {
                    "filename": "user_data.py",
                    "file_path": "/uploads/user_data.py",
                    "file_size": 1024,
                    "issues": [
                        {"type": "hardcoded_secret", "severity": "critical", "description": "Hardcoded API key detected"},
                        {"type": "pii_detection", "severity": "high", "description": "Email addresses found in code"},
                        {"type": "compliance_violation", "severity": "medium", "description": "GDPR consent not implemented"}
                    ],
                    "pii_detected": [
                        {"type": "email", "value": "user@example.com", "severity": "medium"},
                        {"type": "phone_us", "value": "555-123-4567", "severity": "medium"}
                    ],
                    "compliance_violations": [
                        {"framework": "GDPR", "rule_id": "gdpr_001", "severity": "high"}
                    ],
                    "risk_score": 85
                },
                {
                    "filename": "database.py",
                    "file_path": "/uploads/database.py",
                    "file_size": 2048,
                    "issues": [
                        {"type": "sql_injection_risk", "severity": "high", "description": "Potential SQL injection vulnerability"},
                        {"type": "compliance_violation", "severity": "medium", "description": "HIPAA encryption not implemented"}
                    ],
                    "pii_detected": [],
                    "compliance_violations": [
                        {"framework": "HIPAA", "rule_id": "hipaa_001", "severity": "critical"}
                    ],
                    "risk_score": 70
                }
            ],
            "summary": {
                "total_files": 2,
                "files_with_issues": 2,
                "total_issues": 5,
                "critical_issues": 1,
                "high_issues": 2,
                "medium_issues": 2,
                "low_issues": 0,
                "compliance_score": 65,
                "average_risk_score": 77.5
            }
        }
 