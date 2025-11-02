from openai import AzureOpenAI
import json
import os
from typing import Dict, List, Optional
import logging
from services.ai_usage_service import ai_usage_service
 
logger = logging.getLogger(__name__)
 
class AIService:
    def __init__(self):
        """Initialize Azure OpenAI client.
 
        SECURITY: Removed hard-coded fallback API key. The key MUST be supplied via environment.
        If missing, client is set to None and all generation calls will return fallback summaries.
        """
        api_key = os.getenv("OPENAI_API_KEY")  # no insecure fallback
        api_version = os.getenv("OPENAI_API_VERSION") or "2024-02-15-preview"
        azure_endpoint = os.getenv("OPENAI_API_BASE") or "https://genai-sharedservice-americas.pwc.com"
        self.model = os.getenv("OPENAI_MODEL") or "azure.gpt-4o"  # deployment name
        if not api_key:
            logger.warning("OPENAI_API_KEY not set. AIService will operate in fallback mode only.")
            self.client = None
        else:
            self.client = AzureOpenAI(
                api_key=api_key,
                api_version=api_version,
                azure_endpoint=azure_endpoint
            )
   
    def generate_compliance_summary(self, scan_results: Dict) -> Dict:
        """
        Generate AI-powered compliance summary from scan results
        """
        # Extract key information from scan results (outside try block for fallback access)
        summary = scan_results.get("summary", {})
        files_scanned = scan_results.get("files_scanned", [])
       
        # Count issues by severity and framework - calculate from actual files if summary is wrong
        if summary.get("total_issues", 0) == 0 and files_scanned:
            # Recalculate from actual files
            total_issues = sum(len(file.get("issues", [])) for file in files_scanned)
            critical_issues = sum(
                len([issue for issue in file.get("issues", []) if issue.get("severity", "").lower() == "critical"])
                for file in files_scanned
            )
            high_issues = sum(
                len([issue for issue in file.get("issues", []) if issue.get("severity", "").lower() == "high"])
                for file in files_scanned
            )
            medium_issues = sum(
                len([issue for issue in file.get("issues", []) if issue.get("severity", "").lower() == "medium"])
                for file in files_scanned
            )
            low_issues = sum(
                len([issue for issue in file.get("issues", []) if issue.get("severity", "").lower() == "low"])
                for file in files_scanned
            )
        else:
            total_issues = summary.get("total_issues", 0)
            critical_issues = summary.get("critical_issues", 0)
            high_issues = summary.get("high_issues", 0)
            medium_issues = summary.get("medium_issues", 0)
            low_issues = summary.get("low_issues", 0)
       
        try:
            usage_prompt_tokens = 0
            usage_completion_tokens = 0
           
            # Analyze violations by framework (simplified for demo performance)
            framework_violations = {"HIPAA": 0, "GDPR": 0, "DPDP": 0}
            violation_examples = []
           
            for file_data in files_scanned:
                filename = file_data.get("filename", "Unknown")
                for issue in file_data.get("issues", []):
                    framework = issue.get("framework", "Unknown")
                    if framework in framework_violations:
                        framework_violations[framework] += 1
                   
                    if len(violation_examples) < 5:  # Collect up to 5 examples for summary
                        violation_examples.append({
                            "file": filename,
                            "framework": framework,
                            "type": issue.get("violation_type", "Unknown"),
                            "description": issue.get("description", "No description")
                        })
           
            # Create prompt for AI
            prompt = f"""
            You are a compliance expert analyzing a security scan report. Please provide a comprehensive executive summary and recommendations.
           
            SCAN RESULTS:
            - Total Issues Found: {total_issues}
            - Critical Issues: {critical_issues}
            - High Issues: {high_issues}
            - Medium Issues: {medium_issues}
            - Low Issues: {low_issues}
           
            FRAMEWORK VIOLATIONS:
            - HIPAA: {framework_violations['HIPAA']} violations
            - GDPR: {framework_violations['GDPR']} violations
            - DPDP: {framework_violations['DPDP']} violations
           
            SAMPLE VIOLATIONS:
            {json.dumps(violation_examples, indent=2)}
           
            Please provide:
            1. EXECUTIVE SUMMARY: A 2-3 sentence overview of the compliance status
            2. KEY FINDINGS: Top 3-5 most critical issues
            3. RECOMMENDATIONS: Specific action items prioritized by severity
            4. COMPLIANCE SCORE EXPLANATION: Why the score is what it is
            5. NEXT STEPS: Immediate actions to take
           
            Format your response as JSON with these exact keys:
            {{
                "executive_summary": "...",
                "key_findings": ["...", "...", "..."],
                "recommendations": ["...", "...", "..."],
                "compliance_explanation": "...",
                "next_steps": ["...", "...", "..."]
            }}
            """
           
            # Call Azure OpenAI via new client
            if not self.client:
                raise RuntimeError("Azure OpenAI client unavailable (no API key).")
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity compliance expert specializing in HIPAA, GDPR, and DPDP regulations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            # Extract token usage if available
            try:
                usage = getattr(response, 'usage', None)
                if usage:
                    usage_prompt_tokens = getattr(usage, 'prompt_tokens', 0) or 0
                    usage_completion_tokens = getattr(usage, 'completion_tokens', 0) or 0
            except Exception:
                pass
           
            # Parse the response
            ai_content = response.choices[0].message.content.strip()
           
            # Remove markdown code blocks if present
            if ai_content.startswith('```json'):
                ai_content = ai_content[7:]  # Remove ```json
            if ai_content.endswith('```'):
                ai_content = ai_content[:-3]  # Remove ```
            ai_content = ai_content.strip()
           
            # Try to parse as JSON, fallback to text if it fails
            try:
                ai_summary = json.loads(ai_content)
            except json.JSONDecodeError:
                # If not valid JSON, create a structured response
                ai_summary = {
                    "executive_summary": ai_content[:200] + "..." if len(ai_content) > 200 else ai_content,
                    "key_findings": ["AI analysis completed", "Review detailed findings below"],
                    "recommendations": ["Address critical issues first", "Implement security best practices"],
                    "compliance_explanation": "Compliance score based on total violations found",
                    "next_steps": ["Review and fix violations", "Re-run scan to verify fixes"]
                }
           
            ai_usage_service.record_call(
                success=True,
                fallback_used=False,
                model=self.model,
                prompt_tokens=usage_prompt_tokens,
                completion_tokens=usage_completion_tokens,
                error=None
            )
            return {
                "success": True,
                "ai_summary": ai_summary,
                "model_used": self.model,
                "generated_at": "2025-10-11T12:00:00Z",
                "prompt_tokens": usage_prompt_tokens,
                "completion_tokens": usage_completion_tokens
            }
           
        except Exception as e:
            logger.error(f"AI summary generation failed: {str(e)}")
            fallback_summary = {
                "executive_summary": f"Scan completed with {total_issues} total issues found. {critical_issues} critical issues require immediate attention.",
                "key_findings": [
                    f"Found {total_issues} total compliance violations",
                    f"{critical_issues} critical issues need immediate resolution",
                    "Multiple frameworks affected: HIPAA, GDPR, DPDP"
                ],
                "recommendations": [
                    "Prioritize critical and high-severity issues",
                    "Review and update data handling practices",
                    "Implement proper encryption and access controls"
                ],
                "compliance_explanation": f"Current compliance score reflects {total_issues} violations across multiple security frameworks.",
                "next_steps": [
                    "Review detailed findings in the report below",
                    "Address critical issues first",
                    "Re-run scan after implementing fixes"
                ]
            }
            ai_usage_service.record_call(
                success=False,
                fallback_used=True,
                model=self.model,
                prompt_tokens=0,
                completion_tokens=0,
                error=str(e)
            )
            return {
                "success": False,
                "error": str(e),
                "fallback_summary": fallback_summary
            }
 
    def _analyze_individual_issue(self, issue: dict, filename: str) -> dict:
        """
        Generate AI analysis for an individual compliance issue
        """
        try:
            violation_type = issue.get("violation_type", "Unknown")
            severity = issue.get("severity", "Unknown")
            framework = issue.get("framework", "Unknown")
            description = issue.get("description", "No description")
           
            # Create focused prompt for individual issue analysis
            prompt = f"""
            Analyze this specific compliance violation and provide detailed insights:
           
            File: {filename}
            Violation Type: {violation_type}
            Severity: {severity}
            Framework: {framework}
            Description: {description}
           
            Please provide:
            1. RISK ASSESSMENT: What are the specific risks and potential impacts?
            2. BUSINESS IMPACT: How does this affect business operations and compliance?
            3. TECHNICAL ANALYSIS: What caused this violation and why?
            4. REMEDIATION STRATEGY: Specific steps to fix this issue
            5. PREVENTION: How to prevent similar violations in the future
            6. COMPLIANCE NOTES: Any specific regulatory requirements
           
            Format your response as JSON:
            {{
                "risk_assessment": "...",
                "business_impact": "...",
                "technical_analysis": "...",
                "remediation_strategy": "...",
                "prevention": "...",
                "compliance_notes": "..."
            }}
            """
           
            # Call Azure OpenAI
            if not self.client:
                raise RuntimeError("Azure OpenAI client unavailable (no API key).")
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": f"You are a cybersecurity compliance expert specializing in {framework} regulations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
           
            # Parse response
            ai_content = response.choices[0].message.content.strip()
           
            # Remove markdown code blocks if present
            if ai_content.startswith('```json'):
                ai_content = ai_content[7:]
            if ai_content.endswith('```'):
                ai_content = ai_content[:-3]
            ai_content = ai_content.strip()
           
            try:
                analysis = json.loads(ai_content)
                return analysis
            except json.JSONDecodeError:
                # Fallback analysis
                return {
                    "risk_assessment": f"This {severity.lower()}-severity {framework} violation poses significant compliance risks.",
                    "business_impact": f"Non-compliance with {framework} regulations could result in fines and reputational damage.",
                    "technical_analysis": f"The violation involves {violation_type.lower()} which indicates data handling issues.",
                    "remediation_strategy": "Review the specific violation and implement appropriate safeguards.",
                    "prevention": "Establish proper data handling procedures and regular compliance checks.",
                    "compliance_notes": f"Ensure adherence to {framework} regulatory requirements."
                }
               
        except Exception as e:
            logger.error(f"Individual issue analysis failed: {str(e)}")
            return {
                "risk_assessment": f"This {issue.get('severity', 'Unknown').lower()}-severity violation requires attention.",
                "business_impact": "Potential compliance and security risks.",
                "technical_analysis": f"Analysis of {issue.get('violation_type', 'violation')} in {filename}.",
                "remediation_strategy": "Review and implement appropriate fixes.",
                "prevention": "Implement proper safeguards and monitoring.",
                "compliance_notes": "Ensure regulatory compliance."
            }
 
    # --- Async wrapper methods expected by report routes ---
    async def generate_summary_with_ai(self, scan_id: str) -> Optional[Dict]:
        """Route-compatible async method returning simplified AI summary dict for a scan ID."""
        try:
            from services.scan_service import ScanService  # local import to avoid circular
            scan_service = ScanService()
            results = scan_service.get_scan_results(scan_id)
            if not results:
                return None
            response = self.generate_compliance_summary(results)
            if response.get("success"):
                return response.get("ai_summary")
            # fallback structure
            return response.get("fallback_summary")
        except Exception as e:
            logger.error(f"generate_summary_with_ai failed: {e}")
            return None
 
    async def generate_recommendations(self, scan_id: str) -> Optional[List[str]]:
        """Return recommendations list for a scan (derives from summary)."""
        summary = await self.generate_summary_with_ai(scan_id)
        if not summary:
            return None
        return summary.get("recommendations") or []
 
    async def generate_audit_summary(self, report: Dict) -> Dict:
        """Produce audit summary for comprehensive report generation.
 
        Reuses compliance summary logic treating report as scan_results shape.
        Returns only the ai_summary content (not wrapper)."""
        try:
            response = self.generate_compliance_summary(report)
            if response.get("success"):
                return response.get("ai_summary")
            return response.get("fallback_summary")
        except Exception as e:
            logger.error(f"generate_audit_summary failed: {e}")
            return {
                "executive_summary": "Audit summary unavailable (AI error).",
                "key_findings": ["AI service error"],
                "recommendations": ["Retry later"],
                "compliance_explanation": "Fallback due to AI error.",
                "next_steps": ["Check AI configuration", "Re-run report"]
            }
 
    def quick_probe(self) -> Dict:
        """Minimal model call to validate API key & deployment availability.
 
        Returns dict: { success: bool, model: str, error?: str }
        Uses a tiny prompt & low max_tokens to avoid cost.
        """
        try:
            if not self.client:
                return {"success": False, "model": self.model, "error": "client_unavailable"}
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Answer with OK"}],
                max_tokens=1,
                temperature=0
            )
            content = response.choices[0].message.content.strip()
            return {"success": True, "model": self.model, "reply": content}
        except Exception as e:
            return {"success": False, "model": self.model, "error": str(e)}