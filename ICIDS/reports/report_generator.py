"""
ICIDS - Report Generator Module
Handles PDF and CSV report generation for security alerts and statistics
"""

import csv
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from fpdf import FPDF
from flask import current_app
import json

# Assume these are imported from your models
# from database.models import db, Report, Alert


class ReportGenerator:
    """
    Generate security reports in PDF and CSV formats
    Provides statistical analysis and threat summaries
    """
    
    def __init__(self, title: str = "ICIDS Security Report"):
        """
        Initialize report generator
        
        Args:
            title: Report title
        """
        self.title = title
        self.generated_at = datetime.now()
        self.report_data = {}
        
    def generate_pdf_report(
        self,
        alerts: List[Dict[str, Any]],
        filename: str,
        sections: Optional[Dict[str, bool]] = None
    ) -> bool:
        """
        Generate PDF report from alerts data
        
        Args:
            alerts: List of alert dictionaries
            filename: Output PDF filename
            sections: Dictionary of sections to include
                - alerts: Include alerts & incidents
                - network: Include network statistics
                - threats: Include threat analysis
                - recommendations: Include recommendations
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if sections is None:
                sections = {
                    'alerts': True,
                    'network': True,
                    'threats': True,
                    'recommendations': True
                }
            
            pdf = FPDF(orientation='P', unit='mm', format='A4')
            pdf.add_page()
            
            # Set up fonts
            pdf.set_font('Arial', 'B', 24)
            pdf.set_text_color(37, 99, 235)  # Primary blue
            
            # Title
            pdf.cell(0, 20, self.title, ln=True, align='C')
            
            # Metadata
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 10, f"Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}", 
                     ln=True, align='C')
            pdf.cell(0, 10, f"Total Alerts: {len(alerts)}", ln=True, align='C')
            pdf.ln(10)
            
            # Executive Summary
            pdf.set_font('Arial', 'B', 14)
            pdf.set_text_color(31, 41, 55)
            pdf.cell(0, 10, "Executive Summary", ln=True)
            pdf.set_font('Arial', '', 11)
            pdf.set_text_color(107, 114, 128)
            
            summary = self._generate_summary(alerts)
            pdf.multi_cell(0, 5, summary)
            pdf.ln(5)
            
            # Alerts & Incidents Section
            if sections.get('alerts', True):
                pdf.add_page()
                self._add_alerts_section(pdf, alerts)
            
            # Network Statistics Section
            if sections.get('network', True):
                self._add_network_section(pdf, alerts)
            
            # Threat Analysis Section
            if sections.get('threats', True):
                if pdf.get_y() > 250:
                    pdf.add_page()
                self._add_threat_analysis_section(pdf, alerts)
            
            # Recommendations Section
            if sections.get('recommendations', True):
                pdf.add_page()
                self._add_recommendations_section(pdf, alerts)
            
            # Footer with page numbers
            def footer(pdf_obj):
                pdf_obj.set_y(-15)
                pdf_obj.set_font('Arial', 'I', 8)
                pdf_obj.set_text_color(150, 150, 150)
                pdf_obj.cell(0, 10, f"Page {pdf_obj.page_no()}", align='C')
            
            pdf.footer = footer
            
            # Save PDF
            pdf.output(filename)
            return True
            
        except Exception as e:
            current_app.logger.error(f"Error generating PDF report: {str(e)}")
            return False
    
    def generate_csv_report(
        self,
        alerts: List[Dict[str, Any]],
        filename: str
    ) -> bool:
        """
        Generate CSV report from alerts data
        
        Args:
            alerts: List of alert dictionaries
            filename: Output CSV filename
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if not alerts:
                # Create empty CSV with headers
                with open(filename, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        'Timestamp', 'Type', 'Severity', 'Description',
                        'Source IP', 'Destination IP', 'Port', 'Status',
                        'Action Taken', 'Threat Score'
                    ])
                return True
            
            # Prepare data
            formatted_data = self._format_alert_data(alerts)
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'Timestamp', 'Type', 'Severity', 'Description',
                    'Source IP', 'Destination IP', 'Port', 'Status',
                    'Action Taken', 'Threat Score'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header
                writer.writeheader()
                
                # Write data rows
                for row in formatted_data:
                    writer.writerow(row)
            
            return True
            
        except Exception as e:
            current_app.logger.error(f"Error generating CSV report: {str(e)}")
            return False
    
    def get_report_summary(
        self,
        alerts: List[Dict[str, Any]],
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive report summary statistics
        
        Args:
            alerts: List of alert dictionaries
            start_date: Start date for filtering
            end_date: End date for filtering
        
        Returns:
            Dictionary with summary statistics
        """
        # Filter by date if provided
        filtered_alerts = alerts
        if start_date and end_date:
            filtered_alerts = [
                a for a in alerts
                if start_date <= datetime.fromisoformat(a.get('timestamp', '')) <= end_date
            ]
        
        # Calculate statistics
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        type_count = {}
        status_count = {'Open': 0, 'Acknowledged': 0, 'Resolved': 0}
        
        for alert in filtered_alerts:
            severity = alert.get('severity', 'Unknown')
            if severity in severity_count:
                severity_count[severity] += 1
            
            alert_type = alert.get('type', 'Unknown')
            type_count[alert_type] = type_count.get(alert_type, 0) + 1
            
            status = alert.get('status', 'Open')
            if status in status_count:
                status_count[status] += 1
        
        # Calculate threat score
        total_threat_score = sum(
            self._calculate_threat_score(alert)
            for alert in filtered_alerts
        )
        avg_threat_score = total_threat_score / len(filtered_alerts) if filtered_alerts else 0
        
        return {
            'total_alerts': len(filtered_alerts),
            'severity_breakdown': severity_count,
            'type_breakdown': type_count,
            'status_breakdown': status_count,
            'average_threat_score': round(avg_threat_score, 2),
            'critical_count': severity_count['Critical'],
            'resolved_count': status_count['Resolved'],
            'open_count': status_count['Open'],
            'report_period': {
                'start': start_date.isoformat() if start_date else 'N/A',
                'end': end_date.isoformat() if end_date else 'N/A'
            }
        }
    
    def _format_alert_data(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Prepare and format alert data for reporting
        
        Args:
            alerts: List of alert dictionaries
        
        Returns:
            Formatted list of alert data
        """
        formatted = []
        
        for alert in alerts:
            formatted.append({
                'Timestamp': alert.get('timestamp', '-'),
                'Type': alert.get('type', '-'),
                'Severity': alert.get('severity', '-'),
                'Description': alert.get('description', '-'),
                'Source IP': alert.get('sourceIp', '-'),
                'Destination IP': alert.get('destIp', '-'),
                'Port': str(alert.get('port', '-')),
                'Status': alert.get('status', '-'),
                'Action Taken': alert.get('actionTaken', '-'),
                'Threat Score': str(self._calculate_threat_score(alert))
            })
        
        return formatted
    
    def _calculate_threat_score(self, alert: Dict[str, Any]) -> int:
        """
        Calculate threat score for an alert (0-100)
        
        Args:
            alert: Alert dictionary
        
        Returns:
            Threat score 0-100
        """
        score = 0
        
        # Base score by severity
        severity = alert.get('severity', 'Low')
        severity_scores = {
            'Critical': 100,
            'High': 75,
            'Medium': 50,
            'Low': 25
        }
        score = severity_scores.get(severity, 25)
        
        # Adjust by status
        if alert.get('status') == 'Open':
            score += 10
        elif alert.get('status') == 'Acknowledged':
            score += 5
        
        # Adjust by type
        high_risk_types = ['DDoS', 'SQL Injection', 'Malware', 'Privilege Escalation']
        if alert.get('type') in high_risk_types:
            score += 10
        
        return min(score, 100)
    
    def _generate_summary(self, alerts: List[Dict[str, Any]]) -> str:
        """
        Generate executive summary text
        
        Args:
            alerts: List of alerts
        
        Returns:
            Summary text
        """
        summary_stats = self.get_report_summary(alerts)
        
        summary = f"""
Total Alerts Detected: {summary_stats['total_alerts']}
Critical Alerts: {summary_stats['critical_count']}
Resolved Alerts: {summary_stats['resolved_count']}
Open Alerts: {summary_stats['open_count']}
Average Threat Score: {summary_stats['average_threat_score']}/100

This report provides a comprehensive overview of security incidents detected by the ICIDS system during the reporting period. All major threat categories have been analyzed and recommendations provided.
        """
        return summary.strip()
    
    def _add_alerts_section(self, pdf: FPDF, alerts: List[Dict[str, Any]]) -> None:
        """Add alerts & incidents section to PDF"""
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(31, 41, 55)
        pdf.cell(0, 10, "Alerts & Incidents", ln=True)
        pdf.ln(5)
        
        # Table header
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(37, 99, 235)
        
        col_widths = [30, 25, 20, 35, 25, 30]
        headers = ['Timestamp', 'Type', 'Severity', 'Description', 'Source IP', 'Status']
        
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 8, header, border=1, fill=True, align='C')
        pdf.ln()
        
        # Table rows
        pdf.set_font('Arial', '', 8)
        pdf.set_text_color(100, 100, 100)
        
        for alert in alerts[:50]:  # Limit to 50 for readability
            timestamp = alert.get('timestamp', '-')[:10]
            alert_type = alert.get('type', '-')[:20]
            severity = alert.get('severity', '-')
            desc = alert.get('description', '-')[:30]
            source_ip = alert.get('sourceIp', '-')
            status = alert.get('status', '-')
            
            pdf.cell(col_widths[0], 7, timestamp, border=1)
            pdf.cell(col_widths[1], 7, alert_type, border=1)
            pdf.cell(col_widths[2], 7, severity, border=1)
            pdf.cell(col_widths[3], 7, desc, border=1)
            pdf.cell(col_widths[4], 7, source_ip, border=1)
            pdf.cell(col_widths[5], 7, status, border=1)
            pdf.ln()
    
    def _add_network_section(self, pdf: FPDF, alerts: List[Dict[str, Any]]) -> None:
        """Add network statistics section to PDF"""
        if pdf.get_y() > 250:
            pdf.add_page()
        
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(31, 41, 55)
        pdf.cell(0, 10, "Network Statistics", ln=True)
        pdf.ln(5)
        
        # Count unique IPs
        source_ips = set(a.get('sourceIp') for a in alerts if a.get('sourceIp'))
        dest_ips = set(a.get('destIp') for a in alerts if a.get('destIp'))
        
        pdf.set_font('Arial', '', 11)
        pdf.set_text_color(107, 114, 128)
        
        stats_text = f"""
Total Unique Source IPs: {len(source_ips)}
Total Unique Destination IPs: {len(dest_ips)}
Total Packets Analyzed: {len(alerts)}
        """
        
        pdf.multi_cell(0, 5, stats_text.strip())
    
    def _add_threat_analysis_section(self, pdf: FPDF, alerts: List[Dict[str, Any]]) -> None:
        """Add threat analysis section to PDF"""
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(31, 41, 55)
        pdf.cell(0, 10, "Threat Analysis", ln=True)
        pdf.ln(5)
        
        summary = self.get_report_summary(alerts)
        
        pdf.set_font('Arial', 'B', 11)
        pdf.set_text_color(31, 41, 55)
        pdf.cell(0, 8, "Severity Breakdown:", ln=True)
        
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(107, 114, 128)
        for severity, count in summary['severity_breakdown'].items():
            pdf.cell(0, 6, f"  • {severity}: {count}", ln=True)
        
        pdf.ln(5)
        pdf.set_font('Arial', 'B', 11)
        pdf.set_text_color(31, 41, 55)
        pdf.cell(0, 8, "Top Attack Types:", ln=True)
        
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(107, 114, 128)
        sorted_types = sorted(
            summary['type_breakdown'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        for attack_type, count in sorted_types:
            pdf.cell(0, 6, f"  • {attack_type}: {count}", ln=True)
    
    def _add_recommendations_section(self, pdf: FPDF, alerts: List[Dict[str, Any]]) -> None:
        """Add recommendations section to PDF"""
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(31, 41, 55)
        pdf.cell(0, 10, "Recommendations", ln=True)
        pdf.ln(5)
        
        pdf.set_font('Arial', '', 11)
        pdf.set_text_color(107, 114, 128)
        
        recommendations = """
1. Increase firewall protection on critical ports
2. Implement rate limiting for suspicious IPs
3. Enable detailed packet capture for forensics
4. Review and update security policies
5. Consider deploying additional IDS sensors
6. Implement real-time alerting system
7. Conduct regular penetration testing
8. Train staff on incident response procedures
        """
        
        pdf.multi_cell(0, 5, recommendations.strip())
    
    @staticmethod
    def save_report_record(
        filename: str,
        report_type: str,
        user_id: int,
        file_size: int = 0
    ) -> Optional[Dict[str, Any]]:
        """
        Save report record to database
        
        Args:
            filename: Report filename
            report_type: Type of report (Daily, Weekly, Monthly, Custom)
            user_id: User ID who generated report
            file_size: File size in bytes
        
        Returns:
            Report record dictionary or None
        """
        try:
            from database.models import db, Report
            
            report = Report(
                name=os.path.basename(filename),
                type=report_type,
                filename=filename,
                generated_by=user_id,
                file_size=file_size,
                status='Completed',
                generated_at=datetime.now()
            )
            
            db.session.add(report)
            db.session.commit()
            
            return {
                'id': report.id,
                'name': report.name,
                'type': report.type,
                'generated_at': report.generated_at.isoformat(),
                'status': report.status
            }
            
        except Exception as e:
            current_app.logger.error(f"Error saving report record: {str(e)}")
            if db.session:
                db.session.rollback()
            return None
