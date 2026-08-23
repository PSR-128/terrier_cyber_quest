"""
PDF Audit Report Generator for Cyber-Reasoning Platform.
Generates competition-grade vulnerability reports with CVSS v4.0 metrics, IST timestamps,
Gemini cyber-reasoning verdicts, dynamic proof telemetry, and verified regression status.
"""

import os
import io
import datetime
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from backend.utils.timezone import format_ist_display, get_ist_now

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor('#dc2626'),
    "HIGH": colors.HexColor('#ea580c'),
    "MEDIUM": colors.HexColor('#d97706'),
    "LOW": colors.HexColor('#2563eb'),
    "NONE": colors.HexColor('#64748b'),
    "INFO": colors.HexColor('#64748b')
}


class PDFReportGenerator:
    @staticmethod
    def generate_report(scan_data: Dict[str, Any], output_path: Optional[str] = None) -> bytes:
        """
        Generate a multi-page PDF executive and technical audit report.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography Styles
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#0f172a')
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#475569')
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=17,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#0f172a'),
            backColor=colors.HexColor('#f1f5f9')
        )

        story = []

        # 1. Header & Title with IST timestamp
        story.append(Paragraph("TERRIER CYBER QUEST", ParagraphStyle('SuperTitle', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#3b82f6'))))
        story.append(Paragraph("AI-Powered Web Vulnerability & Cyber-Reasoning Audit Report", title_style))
        story.append(Paragraph(f"Authorized Target: <b>{scan_data.get('target_url')}</b> | Generated: <b>{format_ist_display(get_ist_now())}</b>", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#3b82f6'), spaceAfter=15))

        # 2. Executive Summary Box
        story.append(Paragraph("Executive Summary", h2_style))
        
        findings = scan_data.get('findings', [])
        endpoints = scan_data.get('endpoints', [])
        patches = scan_data.get('patches', [])

        crit_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')
        med_count = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        low_count = sum(1 for f in findings if f.get('severity') == 'LOW')

        summary_data = [
            [Paragraph("<b>Target URL</b>", body_style), Paragraph(str(scan_data.get('target_url')), body_style)],
            [Paragraph("<b>Scan Status</b>", body_style), Paragraph(f"<b>{scan_data.get('status')}</b>", body_style)],
            [Paragraph("<b>Scan Initiated (IST)</b>", body_style), Paragraph(format_ist_display(scan_data.get('started_at')), body_style)],
            [Paragraph("<b>Discovered Endpoints</b>", body_style), Paragraph(str(len(endpoints)), body_style)],
            [Paragraph("<b>Total Vulnerabilities Found</b>", body_style), Paragraph(f"<b>{len(findings)}</b>", body_style)],
            [
                Paragraph("<b>CVSS v4.0 Severity Breakdown</b>", body_style),
                Paragraph(f"<font color='#dc2626'><b>CRITICAL: {crit_count}</b></font> | <font color='#ea580c'><b>HIGH: {high_count}</b></font> | <font color='#d97706'><b>MEDIUM: {med_count}</b></font> | <font color='#2563eb'><b>LOW: {low_count}</b></font>", body_style)
            ],
            [Paragraph("<b>Verified Fixes (Staging)</b>", body_style), Paragraph(f"{len([p for p in patches if p.get('regression_status') == 'FIXED'])} verified", body_style)]
        ]

        summary_table = Table(summary_data, colWidths=[150, 380])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 15))

        # 3. Detailed Findings & Cyber Reasoning
        story.append(Paragraph("Vulnerability Findings & CVSS v4.0 Classification", h2_style))

        if not findings:
            story.append(Paragraph("No vulnerabilities were identified during this scan.", body_style))
        else:
            for i, f in enumerate(findings, 1):
                sev = f.get('severity', 'MEDIUM')
                sev_color = SEVERITY_COLORS.get(sev, colors.HexColor('#475569'))
                conf = f.get('confidence', 0.0)
                status = f.get('status', 'Requires Verification')
                cvss_score = f.get('cvss_score', 0.0)
                cvss_vec = f.get('cvss_vector', 'N/A')

                finding_elements = []
                
                # Title Bar
                title_p = Paragraph(
                    f"<b>#{i}. {f.get('vuln_type', 'Vulnerability').replace('_', ' ')}</b> — <font color='{sev_color.hexval()}'><b>[CVSS v4.0: {cvss_score} {sev}]</b></font> (Confidence: <b>{conf:.1f}%</b> | Status: <b>{status}</b>)",
                    ParagraphStyle('FTitle', fontName='Helvetica-Bold', fontSize=11, leading=14, textColor=colors.HexColor('#0f172a'))
                )
                finding_elements.append(title_p)
                finding_elements.append(Spacer(1, 4))

                # Meta table
                f_meta = [
                    [Paragraph("<b>Affected URL:</b>", body_style), Paragraph(f"<code>{f.get('http_method', 'GET')} {f.get('url')}</code>", code_style)],
                    [Paragraph("<b>CVSS v4.0 Vector:</b>", body_style), Paragraph(f"<code>{cvss_vec}</code>", code_style)],
                    [Paragraph("<b>Exact Location:</b>", body_style), Paragraph(f"<code>{f.get('exact_location') or (f.get('http_method', 'GET') + ' ' + f.get('url') + ' [param: ' + str(f.get('parameter')) + ']')}</code>", code_style)],
                    [Paragraph("<b>ML Dataset Prediction:</b>", body_style), Paragraph(f"Class: <b>{f.get('ml_prediction', {}).get('category', 'N/A')}</b> (Confidence: {f.get('ml_prediction', {}).get('confidence', 0)}%)", body_style)]
                ]
                meta_tbl = Table(f_meta, colWidths=[130, 400])
                meta_tbl.setStyle(TableStyle([
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 0), (-1, -1), 2),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                    ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ]))
                finding_elements.append(meta_tbl)
                finding_elements.append(Spacer(1, 5))

                if f.get('brief_info'):
                    finding_elements.append(Paragraph(f"<b>Vulnerability Overview:</b> {f.get('brief_info')}", body_style))
                    finding_elements.append(Spacer(1, 3))

                # Cyber Reasoning
                reasoning_text = f.get('llm_reasoning', '').replace('\n', '<br/>')
                finding_elements.append(Paragraph("<b>Cyber-Reasoning Synthesis & Telemetry:</b>", body_style))
                finding_elements.append(Paragraph(reasoning_text, ParagraphStyle('ReasoningP', parent=body_style, backColor=colors.HexColor('#f8fafc'), borderPadding=6)))
                finding_elements.append(Spacer(1, 5))

                # Remediation
                brief_rem = f.get('brief_remediation') or f.get('remediation', '')
                finding_elements.append(Paragraph(f"<b>Remediation Guidance:</b> {brief_rem}", body_style))

                # Uncertainty Warning if present
                if f.get('uncertainty_warning'):
                    finding_elements.append(Spacer(1, 3))
                    finding_elements.append(Paragraph(f"<i><b>Uncertainty Note:</b> {f.get('uncertainty_warning')}</i>", ParagraphStyle('WarnP', parent=body_style, textColor=colors.HexColor('#b45309'))))

                finding_elements.append(Spacer(1, 8))
                finding_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0'), spaceAfter=10))

                story.append(KeepTogether(finding_elements))

        # 4. Automated Patching and Verification Section
        if patches:
            story.append(Paragraph("Automated Staging Patching & Regression Verification", h2_style))
            for p in patches:
                p_status = p.get('regression_status', 'UNVERIFIED')
                p_color = colors.HexColor('#16a34a') if p_status == 'FIXED' else colors.HexColor('#dc2626')
                
                patch_box = [
                    Paragraph(f"<b>Patch Target:</b> <code>{p.get('target_file')}</code> | Verification: <font color='{p_color.hexval()}'><b>[{p_status}]</b></font>", body_style),
                    Spacer(1, 4),
                    Paragraph("<b>Unified Diff Preview:</b>", body_style),
                    Paragraph(f"<pre>{p.get('diff_text', '')[:600]}</pre>", code_style),
                    Spacer(1, 8)
                ]
                story.append(KeepTogether(patch_box))

        doc.build(story)
        
        if output_path and os.path.exists(output_path):
            with open(output_path, "wb") as f:
                f.write(buffer.getvalue())
                
        return buffer.getvalue()
