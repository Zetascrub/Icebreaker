"""
Notification and alerting system.
"""
from __future__ import annotations
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
import json
import os


class NotificationService:
    """Service for sending notifications."""

    def __init__(self):
        self.client = httpx.Client(timeout=30.0)

    async def send_notification(
        self,
        notification_config: Dict[str, Any],
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ):
        """
        Send notification based on configuration.

        Args:
            notification_config: Notification configuration
            scan_id: Scan ID
            scan_name: Scan name/run ID
            findings: List of findings
            summary: Scan summary
        """
        notification_type = notification_config.get("type")

        # Filter findings by severity if configured
        min_severity = notification_config.get("min_severity", "low")
        filtered_findings = self._filter_by_severity(findings, min_severity)

        if not filtered_findings and notification_config.get("only_on_findings", False):
            return  # Don't send notification if no findings match criteria

        if notification_type == "email":
            await self._send_email(
                notification_config,
                scan_id,
                scan_name,
                filtered_findings,
                summary
            )
        elif notification_type == "slack":
            await self._send_slack(
                notification_config,
                scan_id,
                scan_name,
                filtered_findings,
                summary
            )
        elif notification_type == "discord":
            await self._send_discord(
                notification_config,
                scan_id,
                scan_name,
                filtered_findings,
                summary
            )
        elif notification_type == "teams":
            await self._send_teams(
                notification_config,
                scan_id,
                scan_name,
                filtered_findings,
                summary
            )
        elif notification_type == "webhook":
            await self._send_webhook(
                notification_config,
                scan_id,
                scan_name,
                filtered_findings,
                summary
            )

    def _filter_by_severity(
        self,
        findings: List[Dict[str, Any]],
        min_severity: str
    ) -> List[Dict[str, Any]]:
        """Filter findings by minimum severity."""
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_index = severity_order.index(min_severity.lower())

        return [
            f for f in findings
            if severity_order.index(f.get("severity", "info").lower()) >= min_index
        ]

    async def _send_email(
        self,
        config: Dict[str, Any],
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ):
        """Send email notification."""
        try:
            smtp_server = config.get("smtp_server", os.getenv("SMTP_SERVER", "localhost"))
            smtp_port = config.get("smtp_port", int(os.getenv("SMTP_PORT", "587")))
            smtp_username = config.get("smtp_username", os.getenv("SMTP_USERNAME"))
            smtp_password = config.get("smtp_password", os.getenv("SMTP_PASSWORD"))
            from_email = config.get("from_email", smtp_username)
            to_emails = config.get("to_emails", [])

            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"Icebreaker Scan Complete: {scan_name}"
            msg["From"] = from_email
            msg["To"] = ", ".join(to_emails)

            # Create email body
            body = self._create_email_body(scan_id, scan_name, findings, summary)
            msg.attach(MIMEText(body, "html"))

            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_username and smtp_password:
                    server.starttls()
                    server.login(smtp_username, smtp_password)
                server.send_message(msg)

        except Exception as e:
            print(f"Error sending email notification: {e}")

    def _create_email_body(
        self,
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ) -> str:
        """Create HTML email body."""
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        medium_count = sum(1 for f in findings if f.get("severity") == "medium")
        low_count = sum(1 for f in findings if f.get("severity") == "low")

        findings_html = ""
        for finding in findings[:10]:  # Show top 10
            severity_color = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#17a2b8"
            }.get(finding.get("severity", "low"), "#6c757d")

            findings_html += f"""
            <div style="margin: 10px 0; padding: 10px; border-left: 4px solid {severity_color};">
                <strong style="color: {severity_color};">{finding.get('severity', 'UNKNOWN').upper()}</strong>:
                {finding.get('title', 'Unknown Finding')}
                <br>
                <small>{finding.get('description', '')}</small>
            </div>
            """

        return f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2>Icebreaker Security Scan Complete</h2>
            <p><strong>Scan:</strong> {scan_name}</p>
            <p><strong>Scan ID:</strong> {scan_id}</p>

            <h3>Summary</h3>
            <ul>
                <li><span style="color: #dc3545;">●</span> Critical: {critical_count}</li>
                <li><span style="color: #fd7e14;">●</span> High: {high_count}</li>
                <li><span style="color: #ffc107;">●</span> Medium: {medium_count}</li>
                <li><span style="color: #17a2b8;">●</span> Low: {low_count}</li>
            </ul>

            <h3>Top Findings</h3>
            {findings_html}

            {f"<p><em>...and {len(findings) - 10} more findings</em></p>" if len(findings) > 10 else ""}

            <p><a href="http://localhost:9000/scans/{scan_id}">View Full Scan Report</a></p>
        </body>
        </html>
        """

    async def _send_slack(
        self,
        config: Dict[str, Any],
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ):
        """Send Slack notification."""
        webhook_url = config.get("webhook_url", os.getenv("SLACK_WEBHOOK_URL"))
        if not webhook_url:
            return

        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")

        color = "#dc3545" if critical_count > 0 else "#ffc107" if high_count > 0 else "#28a745"

        message = {
            "attachments": [
                {
                    "color": color,
                    "title": f"Security Scan Complete: {scan_name}",
                    "fields": [
                        {
                            "title": "Scan ID",
                            "value": str(scan_id),
                            "short": True
                        },
                        {
                            "title": "Total Findings",
                            "value": str(len(findings)),
                            "short": True
                        },
                        {
                            "title": "Critical",
                            "value": str(critical_count),
                            "short": True
                        },
                        {
                            "title": "High",
                            "value": str(high_count),
                            "short": True
                        }
                    ],
                    "footer": "Icebreaker Security Scanner"
                }
            ]
        }

        try:
            response = self.client.post(webhook_url, json=message)
            response.raise_for_status()
        except Exception as e:
            print(f"Error sending Slack notification: {e}")

    async def _send_discord(
        self,
        config: Dict[str, Any],
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ):
        """Send Discord notification."""
        webhook_url = config.get("webhook_url", os.getenv("DISCORD_WEBHOOK_URL"))
        if not webhook_url:
            return

        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")

        color = 0xdc3545 if critical_count > 0 else 0xffc107 if high_count > 0 else 0x28a745

        message = {
            "embeds": [
                {
                    "title": f"🔒 Security Scan Complete: {scan_name}",
                    "color": color,
                    "fields": [
                        {"name": "Scan ID", "value": str(scan_id), "inline": True},
                        {"name": "Total Findings", "value": str(len(findings)), "inline": True},
                        {"name": "Critical", "value": str(critical_count), "inline": True},
                        {"name": "High", "value": str(high_count), "inline": True},
                    ],
                    "footer": {"text": "Icebreaker Security Scanner"}
                }
            ]
        }

        try:
            response = self.client.post(webhook_url, json=message)
            response.raise_for_status()
        except Exception as e:
            print(f"Error sending Discord notification: {e}")

    async def _send_teams(
        self,
        config: Dict[str, Any],
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ):
        """Send Microsoft Teams notification."""
        webhook_url = config.get("webhook_url", os.getenv("TEAMS_WEBHOOK_URL"))
        if not webhook_url:
            return

        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")

        message = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"Security Scan: {scan_name}",
            "themeColor": "dc3545" if critical_count > 0 else "ffc107",
            "title": f"Security Scan Complete: {scan_name}",
            "sections": [
                {
                    "facts": [
                        {"name": "Scan ID", "value": str(scan_id)},
                        {"name": "Total Findings", "value": str(len(findings))},
                        {"name": "Critical", "value": str(critical_count)},
                        {"name": "High", "value": str(high_count)}
                    ]
                }
            ]
        }

        try:
            response = self.client.post(webhook_url, json=message)
            response.raise_for_status()
        except Exception as e:
            print(f"Error sending Teams notification: {e}")

    async def _send_webhook(
        self,
        config: Dict[str, Any],
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ):
        """Send custom webhook notification."""
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            return

        payload = {
            "scan_id": scan_id,
            "scan_name": scan_name,
            "findings_count": len(findings),
            "findings": findings,
            "summary": summary
        }

        try:
            headers = config.get("headers", {})
            response = self.client.post(webhook_url, json=payload, headers=headers)
            response.raise_for_status()
        except Exception as e:
            print(f"Error sending webhook notification: {e}")

    def close(self):
        """Close the HTTP client."""
        self.client.close()
