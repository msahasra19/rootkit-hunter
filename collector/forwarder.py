#!/usr/bin/env python3
"""
Data Forwarder Module

This module handles forwarding detection results and system data
to external systems, SIEM platforms, or logging services.
"""

import os
import json
import time
import requests
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin


class DataForwarder:
    """Handles forwarding of detection data to external systems."""
    
    def __init__(self, config_file="forwarder_config.json"):
        self.config_file = Path(config_file)
        self.config = self._load_config()
        self.setup_logging()
    
    def _load_config(self) -> Dict:
        """Load forwarding configuration."""
        default_config = {
            "endpoints": {
                "siem": {
                    "url": "https://siem.example.com/api/alerts",
                    "enabled": False,
                    "auth": {
                        "type": "bearer",
                        "token": ""
                    }
                },
                "slack": {
                    "webhook_url": "",
                    "enabled": False,
                    "channel": "#security-alerts"
                },
                "email": {
                    "smtp_server": "localhost",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "from_addr": "rootkit-hunter@example.com",
                    "to_addrs": [],
                    "enabled": False
                },
                "file": {
                    "path": "alerts",
                    "enabled": True,
                    "format": "json"
                }
            },
            "filters": {
                "min_severity": "medium",
                "include_snapshot_data": False,
                "max_alert_frequency": 300  # seconds
            }
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except (json.JSONDecodeError, KeyError) as e:
                logging.warning(f"Error loading config: {e}. Using defaults.")
        
        return default_config
    
    def setup_logging(self):
        """Setup logging configuration."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / "forwarder.log"),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def forward_alert(self, alert_data: Dict) -> Dict[str, bool]:
        """Forward an alert to all enabled endpoints."""
        # Apply filters
        if not self._should_forward(alert_data):
            return {"filtered": True}
        
        # Prepare alert payload
        payload = self._prepare_payload(alert_data)
        
        results = {}
        
        # Forward to file
        if self.config["endpoints"]["file"]["enabled"]:
            results["file"] = self._forward_to_file(payload)
        
        # Forward to SIEM
        if self.config["endpoints"]["siem"]["enabled"]:
            results["siem"] = self._forward_to_siem(payload)
        
        # Forward to Slack
        if self.config["endpoints"]["slack"]["enabled"]:
            results["slack"] = self._forward_to_slack(payload)
        
        # Forward to email
        if self.config["endpoints"]["email"]["enabled"]:
            results["email"] = self._forward_to_email(payload)
        
        return results
    
    def _should_forward(self, alert_data: Dict) -> bool:
        """Check if alert should be forwarded based on filters."""
        filters = self.config["filters"]
        
        # Check severity
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        alert_severity = alert_data.get("severity", "low")
        min_severity = filters.get("min_severity", "medium")
        
        if severity_levels.get(alert_severity, 0) < severity_levels.get(min_severity, 2):
            return False
        
        # Check rate limiting
        if not self._check_rate_limit(alert_data):
            return False
        
        return True
    
    def _check_rate_limit(self, alert_data: Dict) -> bool:
        """Check if we're within rate limits for forwarding."""
        max_frequency = self.config["filters"].get("max_alert_frequency", 300)
        
        # Simple rate limiting - in production, use Redis or similar
        rate_limit_file = Path("rate_limit.json")
        
        if not rate_limit_file.exists():
            with open(rate_limit_file, 'w') as f:
                json.dump({"last_alert": 0}, f)
            return True
        
        try:
            with open(rate_limit_file, 'r') as f:
                rate_data = json.load(f)
            
            last_alert = rate_data.get("last_alert", 0)
            current_time = time.time()
            
            if current_time - last_alert < max_frequency:
                self.logger.info("Rate limit exceeded, skipping alert")
                return False
            
            # Update last alert time
            with open(rate_limit_file, 'w') as f:
                json.dump({"last_alert": current_time}, f)
            
            return True
            
        except (json.JSONDecodeError, OSError):
            return True
    
    def _prepare_payload(self, alert_data: Dict) -> Dict:
        """Prepare alert payload for forwarding."""
        payload = {
            "timestamp": alert_data.get("timestamp", datetime.now().isoformat()),
            "rule": alert_data.get("rule"),
            "severity": alert_data.get("severity"),
            "description": alert_data.get("description"),
            "hostname": os.uname().nodename if hasattr(os, 'uname') else "unknown",
            "matches": alert_data.get("matches", [])
        }
        
        # Include snapshot data if configured
        if self.config["filters"].get("include_snapshot_data", False):
            payload["snapshot_data"] = alert_data.get("snapshot_data")
        
        return payload
    
    def _forward_to_file(self, payload: Dict) -> bool:
        """Forward alert to file."""
        try:
            file_config = self.config["endpoints"]["file"]
            output_dir = Path(file_config["path"])
            output_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"alert_{timestamp}.json"
            filepath = output_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(payload, f, indent=2)
            
            self.logger.info(f"Alert forwarded to file: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error forwarding to file: {e}")
            return False
    
    def _forward_to_siem(self, payload: Dict) -> bool:
        """Forward alert to SIEM system."""
        try:
            siem_config = self.config["endpoints"]["siem"]
            url = siem_config["url"]
            
            headers = {
                "Content-Type": "application/json"
            }
            
            # Add authentication
            auth = siem_config.get("auth", {})
            if auth.get("type") == "bearer" and auth.get("token"):
                headers["Authorization"] = f"Bearer {auth['token']}"
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("Alert forwarded to SIEM successfully")
                return True
            else:
                self.logger.error(f"SIEM forward failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error forwarding to SIEM: {e}")
            return False
    
    def _forward_to_slack(self, payload: Dict) -> bool:
        """Forward alert to Slack webhook."""
        try:
            slack_config = self.config["endpoints"]["slack"]
            webhook_url = slack_config["webhook_url"]
            
            if not webhook_url:
                self.logger.warning("Slack webhook URL not configured")
                return False
            
            # Format message for Slack
            severity_emoji = {
                "low": "🟡",
                "medium": "🟠", 
                "high": "🔴",
                "critical": "🚨"
            }
            
            emoji = severity_emoji.get(payload["severity"], "⚠️")
            
            slack_message = {
                "channel": slack_config.get("channel", "#security-alerts"),
                "text": f"{emoji} Rootkit Hunter Alert",
                "attachments": [
                    {
                        "color": self._get_severity_color(payload["severity"]),
                        "fields": [
                            {
                                "title": "Rule",
                                "value": payload["rule"],
                                "short": True
                            },
                            {
                                "title": "Severity",
                                "value": payload["severity"].upper(),
                                "short": True
                            },
                            {
                                "title": "Description",
                                "value": payload["description"],
                                "short": False
                            },
                            {
                                "title": "Hostname",
                                "value": payload["hostname"],
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": payload["timestamp"],
                                "short": True
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(
                webhook_url,
                json=slack_message,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("Alert forwarded to Slack successfully")
                return True
            else:
                self.logger.error(f"Slack forward failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error forwarding to Slack: {e}")
            return False
    
    def _forward_to_email(self, payload: Dict) -> bool:
        """Forward alert via email."""
        try:
            email_config = self.config["endpoints"]["email"]
            
            if not email_config.get("to_addrs"):
                self.logger.warning("No email recipients configured")
                return False
            
            # In a real implementation, you would use smtplib
            # For now, we'll just log the email content
            self.logger.info(f"Email alert would be sent to: {email_config['to_addrs']}")
            self.logger.info(f"Subject: Rootkit Hunter Alert - {payload['severity'].upper()}")
            self.logger.info(f"Body: {json.dumps(payload, indent=2)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email: {e}")
            return False
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            "low": "good",
            "medium": "warning",
            "high": "danger",
            "critical": "danger"
        }
        return colors.get(severity, "warning")
    
    def bulk_forward(self, alerts: List[Dict]) -> Dict[str, int]:
        """Forward multiple alerts."""
        results = {"success": 0, "failed": 0, "filtered": 0}
        
        for alert in alerts:
            forward_results = self.forward_alert(alert)
            
            if forward_results.get("filtered"):
                results["filtered"] += 1
            elif any(forward_results.values()):
                results["success"] += 1
            else:
                results["failed"] += 1
        
        return results
    
    def test_endpoints(self) -> Dict[str, bool]:
        """Test connectivity to all configured endpoints."""
        test_alert = {
            "rule": "test_rule",
            "severity": "low",
            "description": "Test alert for endpoint connectivity",
            "timestamp": datetime.now().isoformat(),
            "matches": []
        }
        
        return self.forward_alert(test_alert)


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Rootkit Hunter Data Forwarder")
    parser.add_argument("--config", default="forwarder_config.json", 
                       help="Configuration file path")
    parser.add_argument("--test", action="store_true", 
                       help="Test endpoint connectivity")
    parser.add_argument("--alert-file", help="Forward alerts from JSON file")
    
    args = parser.parse_args()
    
    forwarder = DataForwarder(args.config)
    
    if args.test:
        print("Testing endpoint connectivity...")
        results = forwarder.test_endpoints()
        
        print("\nEndpoint Test Results:")
        for endpoint, success in results.items():
            status = "✓" if success else "✗"
            print(f"{status} {endpoint}")
    
    if args.alert_file:
        try:
            with open(args.alert_file, 'r') as f:
                alerts = json.load(f)
            
            if isinstance(alerts, list):
                results = forwarder.bulk_forward(alerts)
            else:
                results = forwarder.forward_alert(alerts)
            
            print(f"Forwarding results: {results}")
            
        except FileNotFoundError:
            print(f"Error: Alert file '{args.alert_file}' not found")
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in alert file '{args.alert_file}'")


if __name__ == "__main__":
    main()
