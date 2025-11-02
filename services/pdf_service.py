from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os
import tempfile
 
class PDFService:
    def __init__(self):
        self.styles = getSampleStyleSheet()
       
        # Custom styles
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
       
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
       
        self.subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=colors.darkgreen
        )
       
        self.body_style = ParagraphStyle(
            'CustomBody',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            alignment=TA_JUSTIFY
        )
       
        self.code_style = ParagraphStyle(
            'CodeStyle',
            parent=self.styles['Code'],
            fontSize=9,
            backColor=colors.lightgrey,
            borderColor=colors.black,
            borderWidth=1,
            leftIndent=20,
            rightIndent=20,
            spaceAfter=6
        )
 
    def generate_compliance_report(self, scan_results: dict, ai_summary: dict = None) -> str:
        """
        Generate a comprehensive compliance report PDF
       
        Args:
            scan_results: The scan results data
            ai_summary: Optional AI-generated summary
           
        Returns:
            Path to the generated PDF file
        """
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_path = temp_file.name
        temp_file.close()
       
        # Create PDF document
        doc = SimpleDocTemplate(temp_path, pagesize=A4,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
       
        # Build content
        story = []
       
        # Title
        story.append(Paragraph("Compliance Audit Report", self.title_style))
        story.append(Spacer(1, 12))
       
        # Report metadata
        story.append(self._create_metadata_section(scan_results))
        story.append(Spacer(1, 20))
       
        # Executive Summary
        if ai_summary and ai_summary.get('executive_summary'):
            story.append(Paragraph("Executive Summary", self.heading_style))
            story.append(Paragraph(ai_summary['executive_summary'], self.body_style))
            story.append(Spacer(1, 12))
       
        # Scan Summary
        story.append(Paragraph("Scan Summary", self.heading_style))
        story.append(self._create_summary_table(scan_results))
        story.append(Spacer(1, 20))
       
        # AI Recommendations
        if ai_summary:
            story.append(Paragraph("AI Recommendations", self.heading_style))
            recommendations_elements = self._create_recommendations_section(ai_summary)
            for element in recommendations_elements:
                story.append(element)
            story.append(Spacer(1, 20))
       
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", self.heading_style))
        findings_elements = self._create_findings_section(scan_results)
        for element in findings_elements:
            story.append(element)
       
        # Build PDF
        doc.build(story)
       
        return temp_path
 
    def _create_metadata_section(self, scan_results: dict) -> Table:
        """Create report metadata table"""
        scan_id = scan_results.get('scan_id', 'N/A')
        timestamp = scan_results.get('timestamp', datetime.now().isoformat())
       
        data = [
            ['Scan ID:', scan_id],
            ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Scan Date:', timestamp],
            ['Report Type:', 'Compliance Audit']
        ]
       
        table = Table(data, colWidths=[1.5*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
       
        return table
 
    def _create_summary_table(self, scan_results: dict) -> Table:
        """Create scan summary table"""
        summary = scan_results.get('summary', {})
        files_scanned = scan_results.get('files_scanned', [])
       
        # Calculate actual counts from files if summary is wrong
        if summary.get('total_issues', 0) == 0 and files_scanned:
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
            total_issues = summary.get('total_issues', 0)
            critical_issues = summary.get('critical_issues', 0)
            high_issues = summary.get('high_issues', 0)
            medium_issues = summary.get('medium_issues', 0)
            low_issues = summary.get('low_issues', 0)
       
        data = [
            ['Metric', 'Count'],
            ['Total Files Scanned', str(len(files_scanned) if files_scanned else summary.get('total_files', 0))],
            ['Total Issues Found', str(total_issues)],
            ['Critical Issues', str(critical_issues)],
            ['High Issues', str(high_issues)],
            ['Medium Issues', str(medium_issues)],
            ['Low Issues', str(low_issues)],
            ['Compliance Score', f"{summary.get('compliance_score', 0)}%"]
        ]
       
        table = Table(data, colWidths=[2.5*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
       
        return table
 
    def _create_recommendations_section(self, ai_summary: dict) -> list:
        """Create AI recommendations section"""
        elements = []
       
        # Key Findings
        if ai_summary.get('key_findings'):
            elements.append(Paragraph("Key Findings", self.subheading_style))
            for finding in ai_summary['key_findings']:
                elements.append(Paragraph(f"• {finding}", self.body_style))
            elements.append(Spacer(1, 8))
       
        # Recommendations
        if ai_summary.get('recommendations'):
            elements.append(Paragraph("Recommendations", self.subheading_style))
            for rec in ai_summary['recommendations']:
                elements.append(Paragraph(f"• {rec}", self.body_style))
            elements.append(Spacer(1, 8))
       
        # Next Steps
        if ai_summary.get('next_steps'):
            elements.append(Paragraph("Next Steps", self.subheading_style))
            for step in ai_summary['next_steps']:
                elements.append(Paragraph(f"• {step}", self.body_style))
       
        return elements
 
    def _create_findings_section(self, scan_results: dict) -> list:
        """Create detailed findings section"""
        elements = []
       
        files_scanned = scan_results.get('files_scanned', [])
       
        for file_data in files_scanned:
            filename = file_data.get('filename', 'Unknown')
            issues = file_data.get('issues', [])
           
            if not issues:
                continue
           
            # File header
            elements.append(Paragraph(f"File: {filename}", self.subheading_style))
            elements.append(Spacer(1, 6))
           
            # Issues table
            issue_data = [['Issue', 'Severity', 'Framework', 'Description']]
           
            for issue in issues:
                severity = issue.get('severity', 'Unknown')
                if severity.lower() == 'critical':
                    severity = 'CRITICAL'
                elif severity.lower() == 'high':
                    severity = 'HIGH'
                elif severity.lower() == 'medium':
                    severity = 'MEDIUM'
                elif severity.lower() == 'low':
                    severity = 'LOW'
               
                issue_data.append([
                    issue.get('violation_type', 'Unknown'),
                    severity,
                    issue.get('framework', 'Unknown'),
                    issue.get('description', 'No description')[:80] + '...' if len(issue.get('description', '')) > 80 else issue.get('description', 'No description')
                ])
           
            if len(issue_data) > 1:  # More than just header
                table = Table(issue_data, colWidths=[1.2*inch, 0.8*inch, 0.8*inch, 2.7*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
               
                elements.append(table)
                elements.append(Spacer(1, 12))
               
                # Note: Per-issue AI analysis removed for demo performance
       
        return elements