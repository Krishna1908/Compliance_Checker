
"""
PII Patterns - Regex-based detection of Personally Identifiable Information
"""
 
import re
from typing import Dict, List, Optional
import json
 
class PIIPatterns:
    def __init__(self):
        # Cache for compiled regex patterns
        self._compiled_patterns = {}
       
        # Define comprehensive PII detection patterns
        self.patterns = {
            # Email addresses (improved to avoid false positives)
            "email": {
                "pattern": r'\b(?<![\w._-])(?![a-zA-Z0-9._%+-]*\.(?:example|test|sample|demo)\.)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b(?![\w._-])',
                "severity": "medium",
                "category": "contact_info",
                "description": "Email address detected",
                "confidence_threshold": 0.8,
                "exclude_patterns": [r'example\.com', r'test@test', r'sample@sample', r'demo@demo']
            },
           
            # Phone numbers (improved to avoid false positives)
            "phone_us": {
                "pattern": r'\b(?:\+?1[-.\s]?)?\(?([2-9][0-9]{2})\)?[-.\s]?([2-9][0-9]{2})[-.\s]?([0-9]{4})\b',
                "severity": "medium",
                "category": "contact_info",
                "description": "US phone number detected",
                "confidence_threshold": 0.9,
                "exclude_patterns": [r'123-456-7890', r'000-000-0000', r'111-111-1111']
            },
           
            "phone_international": {
                "pattern": r'\b(?:\+?[1-9]\d{7,14})\b',
                "severity": "medium",
                "category": "contact_info",
                "description": "International phone number detected",
                "confidence_threshold": 0.8,
                "exclude_patterns": [r'\+1234567890', r'\+0000000000']
            },
           
            # Social Security Numbers (US)
            "ssn": {
                "pattern": r'\b(?!000|666|9\d{2})\d{3}[-.]?(?!00)\d{2}[-.]?(?!0000)\d{4}\b',
                "severity": "critical",
                "category": "government_id",
                "description": "Social Security Number detected"
            },
           
            # Credit Card Numbers
            "credit_card": {
                "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                "severity": "critical",
                "category": "financial",
                "description": "Credit card number detected"
            },
           
            # IP Addresses
            "ip_address": {
                "pattern": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                "severity": "low",
                "category": "network",
                "description": "IP address detected"
            },
           
            # MAC Addresses
            "mac_address": {
                "pattern": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
                "severity": "low",
                "category": "network",
                "description": "MAC address detected"
            },
           
            # Names (common patterns)
            "name_pattern": {
                "pattern": r'\b(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b',
                "severity": "low",
                "category": "personal_info",
                "description": "Potential name with title detected"
            },
           
            # Address patterns
            "address": {
                "pattern": r'\b\d+\s+[A-Za-z0-9\s,.-]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)\b',
                "severity": "medium",
                "category": "location",
                "description": "Street address detected"
            },
           
            # ZIP Codes (US)
            "zip_code": {
                "pattern": r'\b\d{5}(?:-\d{4})?\b',
                "severity": "low",
                "category": "location",
                "description": "US ZIP code detected"
            },
           
            # Passwords (common patterns)
            "password": {
                "pattern": r'(?:password|pwd|pass)\s*[:=]\s*["\']?[^"\'\s]{6,}["\']?',
                "severity": "high",
                "category": "credentials",
                "description": "Hardcoded password detected"
            },
           
            # API Keys (common patterns)
            "api_key": {
                "pattern": r'(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9+/]{20,}["\']?',
                "severity": "high",
                "category": "credentials",
                "description": "API key detected"
            },
           
            # Database connection strings
            "db_connection": {
                "pattern": r'(?:mysql|postgresql|mongodb|sqlite)://[^\s\'"]+',
                "severity": "high",
                "category": "credentials",
                "description": "Database connection string detected"
            },
           
            # JWT Tokens
            "jwt_token": {
                "pattern": r'\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b',
                "severity": "high",
                "category": "credentials",
                "description": "JWT token detected"
            },
           
            # Date of Birth patterns
            "date_of_birth": {
                "pattern": r'\b(?:DOB|date_of_birth|birth_date)\s*[:=]\s*["\']?(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}["\']?',
                "severity": "medium",
                "category": "personal_info",
                "description": "Date of birth detected"
            },
           
            # Driver's License
            "drivers_license": {
                "pattern": r'\b[A-Z]{1,2}\d{6,8}\b',
                "severity": "high",
                "category": "government_id",
                "description": "Potential driver's license number detected"
            },
           
            # Bank Account Numbers
            "bank_account": {
                "pattern": r'\b\d{8,17}\b',
                "severity": "critical",
                "category": "financial",
                "description": "Potential bank account number detected",
                "context_required": True  # Requires additional context validation
            }
        }
       
        # Context keywords that might indicate sensitive data
        self.context_keywords = {
            "sensitive": ["password", "secret", "key", "token", "credential", "auth"],
            "personal": ["name", "address", "phone", "email", "dob", "ssn"],
            "financial": ["account", "card", "payment", "billing", "transaction"],
            "medical": ["patient", "diagnosis", "treatment", "medical", "health"]
        }
   
    async def detect_pii(self, content: str, filename: str = "") -> Dict:
        """
        Detect PII patterns in content
       
        Args:
            content: Text content to scan
            filename: Name of the file being scanned
       
        Returns:
            Dictionary with detected PII and issues
        """
        detected = []
        issues = []
       
        try:
            # Scan content for each pattern
            for pattern_name, pattern_info in self.patterns.items():
                # Use cached compiled pattern for performance
                compiled_pattern = self._get_compiled_pattern(pattern_name, pattern_info["pattern"])
                matches = compiled_pattern.finditer(content)
               
                for match in matches:
                    # Get match details
                    match_text = match.group()
                    start_pos = match.start()
                    end_pos = match.end()
                   
                    # Calculate line number (approximate)
                    line_number = content[:start_pos].count('\n') + 1
                   
                    # Skip if match is in exclude patterns
                    if pattern_info.get("exclude_patterns"):
                        for exclude_pattern in pattern_info["exclude_patterns"]:
                            if re.search(exclude_pattern, match_text, re.IGNORECASE):
                                continue
                   
                    # Skip if in comment or documentation
                    if self._is_in_comment_or_doc(content, start_pos, line_number):
                        continue
                   
                    # Calculate confidence score
                    confidence = self._calculate_confidence(match_text, pattern_name, content, start_pos, end_pos)
                   
                    # Skip if confidence is below threshold
                    threshold = pattern_info.get("confidence_threshold", 0.7)
                    if confidence < threshold:
                        continue
                   
                    # Validate match based on context if required
                    if pattern_info.get("context_required", False):
                        if not self._validate_context(content, start_pos, end_pos, pattern_name):
                            continue
                   
                    # Create detection record
                    detection = {
                        "type": pattern_name,
                        "value": match_text,
                        "position": {
                            "start": start_pos,
                            "end": end_pos,
                            "line": line_number
                        },
                        "severity": pattern_info["severity"],
                        "category": pattern_info["category"],
                        "description": pattern_info["description"],
                        "filename": filename,
                        "context": self._extract_context(content, start_pos, end_pos)
                    }
                   
                    detected.append(detection)
                   
                    # Extract code snippet around the match
                    code_snippet = self._extract_code_snippet(content, start_pos, end_pos, line_number)
                   
                    # Determine framework based on pattern type
                    framework = self._get_framework_for_pattern(pattern_name)
                   
                    # Create issue record
                    issue = {
                        "violation_type": f"{framework} Violation",
                        "type": "pii_detection",
                        "severity": pattern_info["severity"],
                        "line_number": line_number,
                        "description": f"{pattern_info['description']}: {self._mask_sensitive_data(match_text)}",
                        "remediation": self._get_recommendation(pattern_name, pattern_info["category"]),
                        "pattern_type": pattern_name,
                        "confidence": confidence,
                        "framework": framework,
                        "code_snippet": code_snippet,
                        "title": f"{framework} Violation: {pattern_info['description']}"
                    }
                   
                    issues.append(issue)
           
            # Additional context-based detection
            context_detections = await self._detect_contextual_pii(content, filename)
            detected.extend(context_detections["detected"])
            issues.extend(context_detections["issues"])
           
            return {
                "detected": detected,
                "issues": issues,
                "total_detections": len(detected),
                "high_severity": len([d for d in detected if d["severity"] == "critical" or d["severity"] == "high"]),
                "scan_timestamp": None  # Will be set by caller
            }
           
        except Exception as e:
            return {
                "detected": [],
                "issues": [{
                    "type": "scan_error",
                    "severity": "low",
                    "line": 0,
                    "description": f"PII detection error: {str(e)}",
                    "recommendation": "Review file manually for potential PII"
                }],
                "total_detections": 0,
                "high_severity": 0,
                "error": str(e)
            }
   
    def _validate_context(self, content: str, start_pos: int, end_pos: int, pattern_type: str) -> bool:
        """
        Validate if a detected pattern is in a sensitive context
       
        Args:
            content: Full content
            start_pos: Start position of match
            end_pos: End position of match
            pattern_type: Type of pattern detected
       
        Returns:
            True if pattern is in sensitive context
        """
        # Extract surrounding context
        context_start = max(0, start_pos - 50)
        context_end = min(len(content), end_pos + 50)
        context = content[context_start:context_end].lower()
       
        # Check for context keywords
        if pattern_type == "bank_account":
            financial_keywords = ["account", "routing", "bank", "checking", "savings"]
            return any(keyword in context for keyword in financial_keywords)
       
        return True  # Default to valid if no specific validation
   
    def _extract_context(self, content: str, start_pos: int, end_pos: int, context_size: int = 30) -> str:
        """
        Extract surrounding context for a detected match
       
        Args:
            content: Full content
            start_pos: Start position of match
            end_pos: End position of match
            context_size: Number of characters to include before/after
       
        Returns:
            Context string
        """
        context_start = max(0, start_pos - context_size)
        context_end = min(len(content), end_pos + context_size)
        return content[context_start:context_end].strip()
   
    def _mask_sensitive_data(self, data: str) -> str:
        """
        Mask sensitive data for display purposes
       
        Args:
            data: Original data
       
        Returns:
            Masked data
        """
        if len(data) <= 4:
            return "*" * len(data)
       
        # Show first 2 and last 2 characters, mask the middle
        return data[:2] + "*" * (len(data) - 4) + data[-2:]
   
    def _get_recommendation(self, pattern_type: str, category: str) -> str:
        """
        Get recommendation for detected PII type
       
        Args:
            pattern_type: Type of PII detected
            category: Category of PII
       
        Returns:
            Recommendation string
        """
        recommendations = {
            "credentials": "Remove hardcoded credentials and use environment variables or secure configuration management",
            "contact_info": "Encrypt or hash personally identifiable contact information",
            "government_id": "Remove or encrypt government identification numbers immediately",
            "financial": "Implement PCI DSS compliance and encrypt financial data",
            "personal_info": "Apply data minimization principles and encrypt personal information",
            "location": "Consider if location data is necessary and implement appropriate safeguards",
            "network": "Review if network identifiers need to be stored and implement access controls"
        }
       
        return recommendations.get(category, "Review and apply appropriate data protection measures")
   
    def _calculate_confidence(self, match_text: str, pattern_type: str) -> float:
        """
        Calculate confidence score for a detected match
       
        Args:
            match_text: Detected text
            pattern_type: Type of pattern
       
        Returns:
            Confidence score (0.0 to 1.0)
        """
        # Base confidence by pattern type
        base_confidence = {
            "email": 0.95,
            "phone_us": 0.90,
            "phone_international": 0.70,
            "ssn": 0.95,
            "credit_card": 0.85,
            "ip_address": 0.80,
            "mac_address": 0.90,
            "password": 0.85,
            "api_key": 0.80,
            "jwt_token": 0.95
        }
       
        confidence = base_confidence.get(pattern_type, 0.70)
       
        # Adjust based on match characteristics
        if len(match_text) < 5:
            confidence *= 0.8  # Shorter matches are less reliable
       
        # Check for common false positives
        false_positive_patterns = ["127.0.0.1", "localhost", "example.com"]
        if any(fp in match_text.lower() for fp in false_positive_patterns):
            confidence *= 0.5
       
        return min(confidence, 1.0)
   
    async def _detect_contextual_pii(self, content: str, filename: str) -> Dict:
        """
        Detect PII based on context and variable names
       
        Args:
            content: Text content to scan
            filename: Name of the file
       
        Returns:
            Dictionary with contextually detected PII
        """
        detected = []
        issues = []
       
        # Look for suspicious variable names or comments
        suspicious_patterns = [
            (r'(?:user_|person_|patient_|customer_)(?:name|email|phone|address|ssn|dob)', "personal_info"),
            (r'(?:password|pwd|pass|secret|key|token)\s*[:=]', "credentials"),
            (r'(?:credit|card|account|bank|routing)\s*[:=]', "financial"),
            (r'(?:medical|health|diagnosis|treatment)\s*[:=]', "medical")
        ]
       
        for pattern, category in suspicious_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
           
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
               
                detection = {
                    "type": "contextual_pii",
                    "value": match.group(),
                    "position": {
                        "start": match.start(),
                        "end": match.end(),
                        "line": line_number
                    },
                    "severity": "medium",
                    "category": category,
                    "description": f"Potential {category} data handling detected",
                    "filename": filename,
                    "context": self._extract_context(content, match.start(), match.end())
                }
               
                detected.append(detection)
               
                # Extract code snippet and determine framework
                code_snippet = self._extract_code_snippet(content, match.start(), match.end(), line_number)
                framework = self._get_framework_for_contextual(category)
               
                issue = {
                    "violation_type": f"{framework} Violation",
                    "type": "contextual_pii",
                    "severity": "medium",
                    "line_number": line_number,
                    "description": f"Potential {category} data handling: {match.group()}",
                    "remediation": self._get_recommendation("contextual", category),
                    "pattern_type": "contextual",
                    "confidence": 0.60,
                    "framework": framework,
                    "code_snippet": code_snippet,
                    "title": f"{framework} Violation: Potential {category} data handling"
                }
               
                issues.append(issue)
       
        return {
            "detected": detected,
            "issues": issues
        }
   
    def _get_compiled_pattern(self, pattern_name: str, pattern: str):
        """
        Get or compile regex pattern with caching for performance
       
        Args:
            pattern_name: Name of the pattern
            pattern: Regex pattern string
           
        Returns:
            Compiled regex pattern
        """
        if pattern_name not in self._compiled_patterns:
            self._compiled_patterns[pattern_name] = re.compile(pattern, re.IGNORECASE)
        return self._compiled_patterns[pattern_name]
   
    def _get_framework_for_pattern(self, pattern_name: str) -> str:
        """
        Determine which compliance framework a pattern belongs to
       
        Args:
            pattern_name: Name of the PII pattern
           
        Returns:
            Framework name (HIPAA, GDPR, DPDP)
        """
        framework_mapping = {
            # HIPAA patterns (healthcare data)
            "ssn": "HIPAA",
            "medical_record": "HIPAA",
            "patient_id": "HIPAA",
            "health_insurance": "HIPAA",
           
            # GDPR patterns (EU personal data)
            "email": "GDPR",
            "phone_us": "GDPR",
            "phone_international": "GDPR",
            "credit_card": "GDPR",
            "passport": "GDPR",
            "driver_license": "GDPR",
            "address": "GDPR",
            "date_of_birth": "GDPR",
           
            # DPDP patterns (Indian personal data)
            "aadhaar": "DPDP",
            "pan_card": "DPDP",
            "voter_id": "DPDP",
            "bank_account": "DPDP",
           
            # General patterns (apply to all frameworks)
            "ip_address": "GDPR",
            "mac_address": "GDPR",
            "imei": "GDPR",
            "biometric": "HIPAA"
        }
       
        return framework_mapping.get(pattern_name, "GDPR")  # Default to GDPR for general personal data
   
    def _get_framework_for_contextual(self, category: str) -> str:
        """
        Determine framework for contextual PII detection
       
        Args:
            category: Category of contextual data
           
        Returns:
            Framework name (HIPAA, GDPR, DPDP)
        """
        contextual_mapping = {
            "healthcare": "HIPAA",
            "medical": "HIPAA",
            "patient": "HIPAA",
            "health": "HIPAA",
            "financial": "GDPR",
            "payment": "GDPR",
            "credit": "GDPR",
            "personal": "GDPR",
            "contact": "GDPR",
            "identification": "DPDP",
            "government": "DPDP",
            "official": "DPDP"
        }
       
        return contextual_mapping.get(category.lower(), "GDPR")
   
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
   
    def _is_in_comment_or_doc(self, content: str, position: int, line_number: int) -> bool:
        """
        Check if the match is in a comment or documentation
       
        Args:
            content: Full content
            position: Position of the match
            line_number: Line number of the match
           
        Returns:
            True if in comment or doc, False otherwise
        """
        # Get the line containing the match
        lines = content.split('\n')
        if line_number <= len(lines):
            line = lines[line_number - 1]
           
            # Check for Python comments
            if '#' in line:
                comment_pos = line.find('#')
                match_in_line = position - content[:content.find(line)].count('\n')
                if match_in_line > comment_pos:
                    return True
           
            # Check for documentation keywords
            doc_keywords = ['example', 'test', 'sample', 'demo', 'TODO', 'FIXME']
            line_lower = line.lower()
            for keyword in doc_keywords:
                if keyword in line_lower:
                    return True
           
            # Check for common test patterns
            if any(word in line_lower for word in ['example.com', 'test@test', 'sample@sample']):
                return True
       
        return False
   
    def _calculate_confidence(self, match_text: str, pattern_name: str, content: str, start_pos: int, end_pos: int) -> float:
        """
        Calculate confidence score for a PII match
       
        Args:
            match_text: The matched text
            pattern_name: Name of the pattern
            content: Full content
            start_pos: Start position
            end_pos: End position
           
        Returns:
            Confidence score between 0 and 1
        """
        confidence = 0.7  # Base confidence
       
        # Increase confidence for realistic patterns
        if pattern_name == "email":
            if not any(word in match_text.lower() for word in ['example', 'test', 'sample', 'demo']):
                confidence += 0.2
            if '.' in match_text.split('@')[1] and len(match_text.split('@')[1]) > 4:
                confidence += 0.1
       
        elif pattern_name == "phone_us":
            # Check for realistic area codes (not 000, 111, 123, etc.)
            if len(match_text) >= 10:
                area_code = match_text[:3] if match_text[0].isdigit() else match_text[1:4]
                if area_code not in ['000', '111', '123', '999']:
                    confidence += 0.2
       
        elif pattern_name == "ssn":
            # SSN validation - check for invalid patterns
            ssn_digits = re.sub(r'[^\d]', '', match_text)
            if len(ssn_digits) == 9:
                if not ssn_digits.startswith('000') and not ssn_digits.startswith('666'):
                    confidence += 0.3
       
        elif pattern_name == "credit_card":
            # Basic Luhn algorithm check
            digits = re.sub(r'[^\d]', '', match_text)
            if len(digits) >= 13 and self._luhn_check(digits):
                confidence += 0.2
       
        # Decrease confidence for common test patterns
        test_patterns = ['123-456-7890', '000-000-0000', 'test@example.com', 'sample@test.com']
        if any(pattern in match_text.lower() for pattern in test_patterns):
            confidence -= 0.4
       
        return min(1.0, max(0.0, confidence))
   
    def _luhn_check(self, card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm
       
        Args:
            card_number: Credit card number as string
           
        Returns:
            True if valid, False otherwise
        """
        def digits_of(n):
            return [int(d) for d in str(n)]
       
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        return checksum % 10 == 0
   
    def get_pattern_statistics(self) -> Dict:
        """
        Get statistics about available PII patterns
       
        Returns:
            Dictionary with pattern statistics
        """
        categories = {}
        severities = {}
       
        for pattern_name, pattern_info in self.patterns.items():
            category = pattern_info["category"]
            severity = pattern_info["severity"]
           
            categories[category] = categories.get(category, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1
       
        return {
            "total_patterns": len(self.patterns),
            "categories": categories,
            "severities": severities,
            "context_keywords": self.context_keywords
        }
 