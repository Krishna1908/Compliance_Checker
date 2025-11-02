"""
Compliance Rules - Check code against HIPAA, GDPR, and DPDP regulations
"""
 
import json
import re
import os
from typing import Dict, List, Optional
from datetime import datetime
 
class ComplianceRules:
    def __init__(self):
        self.rules_file = os.path.join(os.path.dirname(__file__), "compliance_rules.json")
        self.rules = self._load_compliance_rules()
        # Cache for compiled regex patterns
        self._compiled_patterns = {}
   
    def _load_compliance_rules(self) -> Dict:
        """
        Load compliance rules from JSON file
       
        Returns:
            Dictionary containing compliance rules
        """
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading compliance rules: {e}")
            return self._get_default_rules()
   
    def _get_default_rules(self) -> Dict:
        """
        Get default compliance rules if file loading fails
       
        Returns:
            Default rules dictionary
        """
        return {
            "version": "1.0.0",
            "frameworks": {
                "HIPAA": {"rules": []},
                "GDPR": {"rules": []},
                "DPDP": {"rules": []}
            },
            "common_violations": [],
            "severity_levels": {
                "critical": {"score_impact": 40},
                "high": {"score_impact": 25},
                "medium": {"score_impact": 15},
                "low": {"score_impact": 5}
            }
        }
   
    async def check_compliance(self, content: str, filename: str = "") -> Dict:
        """
        Check content against compliance rules
       
        Args:
            content: Text content to check
            filename: Name of the file being checked
       
        Returns:
            Dictionary with compliance violations and issues
        """
        violations = []
        issues = []
       
        try:
            # Check against framework-specific rules
            framework_violations = await self._check_framework_rules(content, filename)
            violations.extend(framework_violations["violations"])
            issues.extend(framework_violations["issues"])
           
            # Check against common violations
            common_violations = await self._check_common_violations(content, filename)
            violations.extend(common_violations["violations"])
            issues.extend(common_violations["issues"])
           
            # Calculate compliance score
            compliance_score = self._calculate_compliance_score(issues)
           
            return {
                "violations": violations,
                "issues": issues,
                "compliance_score": compliance_score,
                "frameworks_checked": list(self.rules["frameworks"].keys()),
                "total_violations": len(violations),
                "critical_violations": len([v for v in violations if v.get("severity") == "critical"]),
                "high_violations": len([v for v in violations if v.get("severity") == "high"]),
                "medium_violations": len([v for v in violations if v.get("severity") == "medium"]),
                "low_violations": len([v for v in violations if v.get("severity") == "low"]),
                "scan_timestamp": datetime.now().isoformat()
            }
           
        except Exception as e:
            # Try to determine framework based on filename and content
            detected_framework = self._detect_framework_from_error(filename, content, str(e))
           
            return {
                "violations": [{
                    "rule_id": "system_error",
                    "framework": detected_framework,
                    "rule_name": "System Error",
                    "description": f"Compliance check error: {str(e)}",
                    "severity": "low",
                    "position": {"start": 0, "end": 0, "line": 0},
                    "matched_text": "System Error",
                    "context": "Error during compliance checking",
                    "filename": filename,
                    "title": f"{detected_framework} Violation: System Error",
                    "remediation": "Review file manually for compliance issues",
                    "code_snippet": self._extract_code_snippet_from_error(content, str(e))
                }],
                "issues": [{
                    "type": "compliance_check_error",
                    "severity": "low",
                    "line": 0,
                    "description": f"Compliance check error: {str(e)}",
                    "recommendation": "Review file manually for compliance issues",
                    "framework": detected_framework,
                    "title": f"{detected_framework} Violation: System Error",
                    "confidence": 1.0,
                    "code_snippet": self._extract_code_snippet_from_error(content, str(e))
                }],
                "compliance_score": 0,
                "frameworks_checked": ["HIPAA", "GDPR", "DPDP"],
                "total_violations": 1,
                "critical_violations": 0,
                "high_violations": 0,
                "medium_violations": 0,
                "low_violations": 1,
                "error": str(e)
            }
   
    async def _check_framework_rules(self, content: str, filename: str) -> Dict:
        """
        Check content against framework-specific rules (HIPAA, GDPR, DPDP)
       
        Args:
            content: Text content to check
            filename: Name of the file
       
        Returns:
            Dictionary with framework violations
        """
        violations = []
        issues = []
       
        frameworks = self.rules.get("frameworks", {})
       
        for framework_name, framework_data in frameworks.items():
            rules = framework_data.get("rules", [])
           
            for rule in rules:
                rule_violations = await self._check_single_rule(content, filename, rule, framework_name)
                violations.extend(rule_violations["violations"])
                issues.extend(rule_violations["issues"])
       
        return {
            "violations": violations,
            "issues": issues
        }
   
    async def _check_common_violations(self, content: str, filename: str) -> Dict:
        """
        Check content against common compliance violations
       
        Args:
            content: Text content to check
            filename: Name of the file
       
        Returns:
            Dictionary with common violations
        """
        violations = []
        issues = []
       
        common_violations = self.rules.get("common_violations", [])
       
        for violation in common_violations:
            violation_results = await self._check_single_violation(content, filename, violation)
            violations.extend(violation_results["violations"])
            issues.extend(violation_results["issues"])
       
        return {
            "violations": violations,
            "issues": issues
        }
   
    async def _check_single_rule(self, content: str, filename: str, rule: Dict, framework: str) -> Dict:
        """
        Check content against a single framework rule
       
        Args:
            content: Text content to check
            filename: Name of the file
            rule: Rule definition
            framework: Framework name
       
        Returns:
            Dictionary with rule violations
        """
        violations = []
        issues = []
       
        patterns = rule.get("patterns", [])
       
        for pattern_info in patterns:
            pattern_type = pattern_info.get("type")
           
            if pattern_type == "keyword_search":
                matches = await self._check_keyword_pattern(content, pattern_info, rule, framework)
            elif pattern_type == "code_analysis":
                matches = await self._check_code_pattern(content, pattern_info, rule, framework)
            elif pattern_type == "regex":
                matches = await self._check_regex_pattern(content, pattern_info, rule, framework)
            else:
                continue
           
            violations.extend(matches["violations"])
            issues.extend(matches["issues"])
       
        return {
            "violations": violations,
            "issues": issues
        }
   
    async def _check_single_violation(self, content: str, filename: str, violation: Dict) -> Dict:
        """
        Check content against a single common violation
       
        Args:
            content: Text content to check
            filename: Name of the file
            violation: Violation definition
       
        Returns:
            Dictionary with violation results
        """
        violations = []
        issues = []
       
        patterns = violation.get("patterns", [])
       
        for pattern_info in patterns:
            pattern_type = pattern_info.get("type")
           
            if pattern_type == "regex":
                matches = await self._check_regex_pattern(content, pattern_info, violation, "Common")
            elif pattern_type == "contextual":
                matches = await self._check_contextual_pattern(content, pattern_info, violation)
            elif pattern_type == "code_analysis":
                matches = await self._check_code_pattern(content, pattern_info, violation, "Common")
            else:
                continue
           
            violations.extend(matches["violations"])
            issues.extend(matches["issues"])
       
        return {
            "violations": violations,
            "issues": issues
        }
   
    async def _check_keyword_pattern(self, content: str, pattern_info: Dict, rule: Dict, framework: str) -> Dict:
        """
        Check for keyword patterns
       
        Args:
            content: Text content
            pattern_info: Pattern definition
            rule: Rule definition
            framework: Framework name
       
        Returns:
            Dictionary with matches
        """
        violations = []
        issues = []
       
        pattern = pattern_info.get("pattern", "")
        context = pattern_info.get("context", "")
       
        if not pattern:
            return {"violations": violations, "issues": issues}
       
        # Create regex pattern for keyword search
        regex_pattern = re.compile(pattern, re.IGNORECASE)
        matches = regex_pattern.finditer(content)
       
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
           
            # Check context if specified
            if context and not self._check_context(content, match.start(), match.end(), context):
                continue
           
            violation = {
                "rule_id": rule.get("id", "unknown"),
                "framework": framework,
                "rule_name": rule.get("name", "Unknown Rule"),
                "description": rule.get("description", ""),
                "severity": rule.get("severity", "medium"),
                "position": {
                    "start": match.start(),
                    "end": match.end(),
                    "line": line_number
                },
                "matched_text": match.group(),
                "context": content[max(0, match.start()-50):min(len(content), match.end()+50)],
                "filename": filename
            }
           
            violations.append(violation)
           
            issue = {
                "violation_type": f"{framework} Violation",
                "type": "compliance_violation",
                "severity": rule.get("severity", "medium"),
                "line_number": line_number,
                "description": f"{framework} Violation: {rule.get('name', 'Unknown Rule')}",
                "remediation": rule.get("remediation", "Review compliance requirements"),
                "framework": framework,
                "rule_id": rule.get("id", "unknown"),
                "confidence": 0.8
            }
           
            issues.append(issue)
       
        return {"violations": violations, "issues": issues}
   
    async def _check_regex_pattern(self, content: str, pattern_info: Dict, rule: Dict, framework: str) -> Dict:
        """
        Check for regex patterns
       
        Args:
            content: Text content
            pattern_info: Pattern definition
            rule: Rule definition
            framework: Framework name
       
        Returns:
            Dictionary with matches
        """
        violations = []
        issues = []
       
        pattern = pattern_info.get("pattern", "")
        case_sensitive = pattern_info.get("case_sensitive", False)
       
        if not pattern:
            return {"violations": violations, "issues": issues}
       
        # Use cached compiled pattern for performance
        regex_pattern = self._get_compiled_pattern(pattern, case_sensitive)
        matches = regex_pattern.finditer(content)
       
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
           
            # Extract code snippet around the match
            code_snippet = self._extract_code_snippet(content, match.start(), match.end(), line_number)
           
            violation = {
                "rule_id": rule.get("id", "unknown"),
                "framework": framework,
                "rule_name": rule.get("name", "Unknown Rule"),
                "description": rule.get("description", ""),
                "severity": rule.get("severity", "medium"),
                "position": {
                    "start": match.start(),
                    "end": match.end(),
                    "line": line_number
                },
                "matched_text": match.group(),
                "context": content[max(0, match.start()-50):min(len(content), match.end()+50)],
                "code_snippet": code_snippet,
                "filename": filename,
                "title": f"{framework} Violation: {rule.get('name', 'Unknown Rule')}",
                "remediation": rule.get("remediation", "Review compliance requirements")
            }
           
            violations.append(violation)
           
            issue = {
                "violation_type": f"{framework} Violation",
                "type": "compliance_violation",
                "severity": rule.get("severity", "medium"),
                "line_number": line_number,
                "description": f"{framework} Violation: {rule.get('name', 'Unknown Rule')}",
                "remediation": rule.get("remediation", "Review compliance requirements"),
                "framework": framework,
                "rule_id": rule.get("id", "unknown"),
                "confidence": 0.9,
                "title": f"{framework} Violation: {rule.get('name', 'Unknown Rule')}",
                "code_snippet": code_snippet
            }
           
            issues.append(issue)
       
        return {"violations": violations, "issues": issues}
   
    async def _check_code_pattern(self, content: str, pattern_info: Dict, rule: Dict, framework: str, filename: str="unknown") -> Dict:
        """
        Check for code analysis patterns
       
        Args:
            content: Text content
            pattern_info: Pattern definition
            rule: Rule definition
            framework: Framework name
       
        Returns:
            Dictionary with matches
        """
        violations = []
        issues = []
       
        pattern = pattern_info.get("pattern", "")
        context = pattern_info.get("context", "")
       
        if not pattern:
            return {"violations": violations, "issues": issues}
       
        # Create regex pattern for code analysis
        regex_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        matches = regex_pattern.finditer(content)
       
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
           
            # Check context if specified
            if context and not self._check_context(content, match.start(), match.end(), context):
                continue
           
            violation = {
                "rule_id": rule.get("id", "unknown"),
                "framework": framework,
                "rule_name": rule.get("name", "Unknown Rule"),
                "description": rule.get("description", ""),
                "severity": rule.get("severity", "medium"),
                "position": {
                    "start": match.start(),
                    "end": match.end(),
                    "line": line_number
                },
                "matched_text": match.group(),
                "context": content[max(0, match.start()-100):min(len(content), match.end()+100)],
                "filename": filename
            }
           
            violations.append(violation)
           
            issue = {
                "type": "compliance_violation",
                "severity": rule.get("severity", "medium"),
                "line": line_number,
                "description": f"{framework} Violation: {rule.get('name', 'Unknown Rule')}",
                "recommendation": rule.get("remediation", "Review compliance requirements"),
                "framework": framework,
                "rule_id": rule.get("id", "unknown"),
                "confidence": 0.85
            }
           
            issues.append(issue)
       
        return {"violations": violations, "issues": issues}
   
    async def _check_contextual_pattern(self, content: str, pattern_info: Dict, violation: Dict) -> Dict:
        """
        Check for contextual patterns
       
        Args:
            content: Text content
            pattern_info: Pattern definition
            violation: Violation definition
       
        Returns:
            Dictionary with matches
        """
        violations = []
        issues = []
       
        pattern = pattern_info.get("pattern", "")
        context = pattern_info.get("context", "")
       
        if not pattern:
            return {"violations": violations, "issues": issues}
       
        # Create regex pattern
        regex_pattern = re.compile(pattern, re.IGNORECASE)
        matches = regex_pattern.finditer(content)
       
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
           
            # Check context if specified
            if context and not self._check_context(content, match.start(), match.end(), context):
                continue
           
            violation_record = {
                "rule_id": violation.get("id", "unknown"),
                "framework": "Common",
                "rule_name": violation.get("name", "Unknown Violation"),
                "description": violation.get("description", ""),
                "severity": violation.get("severity", "medium"),
                "position": {
                    "start": match.start(),
                    "end": match.end(),
                    "line": line_number
                },
                "matched_text": match.group(),
                "context": content[max(0, match.start()-50):min(len(content), match.end()+50)],
                "filename": filename
            }
           
            violations.append(violation_record)
           
            issue = {
                "type": "compliance_violation",
                "severity": violation.get("severity", "medium"),
                "line": line_number,
                "description": f"Common Violation: {violation.get('name', 'Unknown Violation')}",
                "recommendation": violation.get("remediation", "Review compliance requirements"),
                "framework": "Common",
                "rule_id": violation.get("id", "unknown"),
                "confidence": 0.75
            }
           
            issues.append(issue)
       
        return {"violations": violations, "issues": issues}
   
    def _check_context(self, content: str, start_pos: int, end_pos: int, context_type: str) -> bool:
        """
        Check if a match is in the specified context
       
        Args:
            content: Full content
            start_pos: Start position of match
            end_pos: End position of match
            context_type: Type of context to check
       
        Returns:
            True if match is in specified context
        """
        # Extract surrounding context
        context_start = max(0, start_pos - 100)
        context_end = min(len(content), end_pos + 100)
        surrounding_context = content[context_start:context_end].lower()
       
        # Define context checks
        context_checks = {
            "unencrypted": lambda ctx: "encrypt" not in ctx and "hash" not in ctx,
            "no_authentication": lambda ctx: "auth" not in ctx and "login" not in ctx and "token" not in ctx,
            "excessive_collection": lambda ctx: "minimal" not in ctx and "necessary" not in ctx,
            "no_consent": lambda ctx: "consent" not in ctx and "permission" not in ctx,
            "permanent_deletion": lambda ctx: "delete" in ctx or "remove" in ctx,
            "data_export": lambda ctx: "export" in ctx or "download" in ctx,
            "privacy_violation": lambda ctx: "public" in ctx or "share" in ctx,
            "data_localization": lambda ctx: "india" in ctx or "local" in ctx,
            "data_rights": lambda ctx: "right" in ctx or "access" in ctx,
            "breach_notification": lambda ctx: "breach" in ctx or "incident" in ctx,
            "purpose_limitation": lambda ctx: "purpose" in ctx or "use" in ctx,
            "sql_injection": lambda ctx: "execute" in ctx or "query" in ctx,
            "access_control": lambda ctx: "public" in ctx or "unprotected" in ctx,
            "no_logging": lambda ctx: "log" not in ctx and "audit" not in ctx
        }
       
        check_function = context_checks.get(context_type)
        if check_function:
            return check_function(surrounding_context)
       
        return True  # Default to True if context type not found
   
    def _calculate_compliance_score(self, issues: List[Dict]) -> int:
        """
        Calculate compliance score based on issues found
       
        Args:
            issues: List of compliance issues
       
        Returns:
            Compliance score (0-100)
        """
        base_score = self.rules.get("scoring", {}).get("base_score", 100)
       
        severity_impacts = self.rules.get("severity_levels", {})
       
        total_deduction = 0
        for issue in issues:
            severity = issue.get("severity", "low")
            impact = severity_impacts.get(severity, {}).get("score_impact", 5)
            total_deduction += impact
       
        compliance_score = max(0, base_score - total_deduction)
        return compliance_score
   
    def get_framework_summary(self) -> Dict:
        """
        Get summary of available compliance frameworks
       
        Returns:
            Dictionary with framework summary
        """
        frameworks = self.rules.get("frameworks", {})
       
        summary = {}
        for framework_name, framework_data in frameworks.items():
            rules = framework_data.get("rules", [])
            summary[framework_name] = {
                "name": framework_data.get("name", framework_name),
                "description": framework_data.get("description", ""),
                "total_rules": len(rules),
                "severity_breakdown": {}
            }
           
            # Count rules by severity
            for rule in rules:
                severity = rule.get("severity", "medium")
                summary[framework_name]["severity_breakdown"][severity] = \
                    summary[framework_name]["severity_breakdown"].get(severity, 0) + 1
       
        return summary
   
    def _extract_code_snippet(self, content: str, start_pos: int, end_pos: int, line_number: int, context_lines: int = 3) -> Dict:
        """
        Extract code snippet around a violation with proper formatting
       
        Args:
            content: Full content
            start_pos: Start position of violation
            end_pos: End position of violation
            line_number: Line number of violation
            context_lines: Number of lines before/after to include
           
        Returns:
            Dictionary with formatted code snippet
        """
        lines = content.split('\n')
        total_lines = len(lines)
       
        # Calculate start and end line indices
        start_line = max(0, line_number - 1 - context_lines)
        end_line = min(total_lines, line_number + context_lines)
       
        # Extract the relevant lines
        snippet_lines = []
        for i in range(start_line, end_line):
            line_num = i + 1
            line_content = lines[i]
           
            # Mark the violation line
            if line_num == line_number:
                # Find the exact position within the line
                line_start_pos = content.find(line_content)
                relative_start = max(0, start_pos - line_start_pos)
                relative_end = min(len(line_content), end_pos - line_start_pos)
               
                # Create highlighted line with better formatting
                violation_text = line_content[relative_start:relative_end]
                highlighted_line = (
                    line_content[:relative_start] +
                    f"🔴 {violation_text} 🔴" +
                    line_content[relative_end:]
                )
                snippet_lines.append({
                    "line_number": line_num,
                    "content": highlighted_line,
                    "is_violation": True,
                    "violation_range": [relative_start, relative_end]
                })
            else:
                snippet_lines.append({
                    "line_number": line_num,
                    "content": line_content,
                    "is_violation": False
                })
       
        return {
            "lines": snippet_lines,
            "violation_line": line_number,
            "total_lines": len(snippet_lines),
            "language": self._detect_language(content)
        }
   
    def _detect_language(self, content: str) -> str:
        """
        Detect programming language from content
       
        Args:
            content: File content
           
        Returns:
            Language name
        """
        # Simple language detection based on keywords and patterns
        if 'import ' in content or 'from ' in content or 'def ' in content:
            return "python"
        elif 'function ' in content or 'const ' in content or 'let ' in content:
            return "javascript"
        elif '<?php' in content or 'echo ' in content:
            return "php"
        elif '<html' in content or '<div' in content:
            return "html"
        elif 'SELECT ' in content or 'INSERT ' in content:
            return "sql"
        else:
            return "text"
   
    def _get_compiled_pattern(self, pattern: str, case_sensitive: bool = False):
        """
        Get or compile regex pattern with caching for performance
       
        Args:
            pattern: Regex pattern string
            case_sensitive: Whether pattern should be case sensitive
           
        Returns:
            Compiled regex pattern
        """
        cache_key = f"{pattern}_{case_sensitive}"
        if cache_key not in self._compiled_patterns:
            flags = 0 if case_sensitive else re.IGNORECASE
            self._compiled_patterns[cache_key] = re.compile(pattern, flags)
        return self._compiled_patterns[cache_key]
   
    def _detect_framework_from_error(self, filename: str, content: str, error_message: str) -> str:
        """
        Try to determine which framework a file belongs to based on filename and content
       
        Args:
            filename: Name of the file
            content: File content
            error_message: Error that occurred
           
        Returns:
            Framework name (HIPAA, GDPR, DPDP)
        """
        # Check filename for clues
        filename_lower = filename.lower()
        content_lower = content.lower()
       
        # Healthcare/Medical indicators -> HIPAA
        healthcare_keywords = ['patient', 'medical', 'health', 'hospital', 'doctor', 'clinic', 'healthcare', 'diagnosis', 'treatment']
        if any(keyword in filename_lower or keyword in content_lower for keyword in healthcare_keywords):
            return "HIPAA"
       
        # Financial/Payment indicators -> GDPR
        financial_keywords = ['payment', 'credit', 'card', 'bank', 'financial', 'transaction', 'billing', 'invoice', 'money']
        if any(keyword in filename_lower or keyword in content_lower for keyword in financial_keywords):
            return "GDPR"
       
        # Government/Identity indicators -> DPDP (India)
        government_keywords = ['aadhaar', 'pan', 'voter', 'government', 'official', 'identity', 'citizen', 'indian']
        if any(keyword in filename_lower or keyword in content_lower for keyword in government_keywords):
            return "DPDP"
       
        # Database/SQL files often contain personal data -> GDPR
        if filename_lower.endswith(('.sql', '.db', '.database')) or 'select' in content_lower or 'insert' in content_lower:
            return "GDPR"
       
        # Python files with data processing -> GDPR (general personal data)
        if filename_lower.endswith('.py') and ('data' in content_lower or 'user' in content_lower or 'email' in content_lower):
            return "GDPR"
       
        # Default to GDPR for general data processing
        return "GDPR"
   
    def _extract_code_snippet_from_error(self, content: str, error_message: str, context_lines: int = 5) -> Dict:
        """
        Extract a code snippet when an error occurs, showing relevant parts of the file
       
        Args:
            content: File content
            error_message: Error message
            context_lines: Number of lines to show
           
        Returns:
            Dictionary with code snippet information
        """
        lines = content.split('\n')
        total_lines = len(lines)
       
        # If file is small, show all lines
        if total_lines <= context_lines * 2:
            snippet_lines = []
            for i, line in enumerate(lines):
                snippet_lines.append({
                    "line_number": i + 1,
                    "content": line,
                    "is_violation": False
                })
        else:
            # Show first few lines and last few lines
            snippet_lines = []
            for i in range(min(context_lines, total_lines)):
                snippet_lines.append({
                    "line_number": i + 1,
                    "content": lines[i],
                    "is_violation": False
                })
           
            # Add separator if there are more lines
            if total_lines > context_lines * 2:
                snippet_lines.append({
                    "line_number": "...",
                    "content": f"  ... ({total_lines - context_lines * 2} lines omitted) ...",
                    "is_violation": False
                })
           
            # Add last few lines
            for i in range(max(context_lines, total_lines - context_lines), total_lines):
                snippet_lines.append({
                    "line_number": i + 1,
                    "content": lines[i],
                    "is_violation": False
                })
       
        return {
            "lines": snippet_lines,
            "violation_line": 0,  # No specific violation line for errors
            "total_lines": len(snippet_lines),
            "language": self._detect_language_from_filename(content),
            "error_context": f"Error: {error_message}"
        }
   
    def _detect_language_from_filename(self, content: str) -> str:
        """
        Detect programming language from content
       
        Args:
            content: File content
           
        Returns:
            Language name
        """
        if 'import ' in content or 'from ' in content or 'def ' in content:
            return "python"
        elif 'function ' in content or 'const ' in content or 'let ' in content:
            return "javascript"
        elif '<?php' in content or 'echo ' in content:
            return "php"
        elif '<html' in content or '<div' in content:
            return "html"
        elif 'SELECT ' in content or 'INSERT ' in content:
            return "sql"
        else:
            return "text"
 
 

 