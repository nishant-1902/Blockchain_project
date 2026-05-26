import logging
import json
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from database.models import db, Alert
except ImportError:
    from ICIDS.database.models import db, Alert

try:
    from blockchain.blockchain import Blockchain
except ImportError:
    from ICIDS.blockchain.blockchain import Blockchain

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Manages security alerts, including creation, retrieval, status updates,
    and blockchain persistence for immutable audit trail.
    """
    
    def __init__(self, blockchain=None):
        """
        Initialize the AlertManager.
        
        Args:
            blockchain (Blockchain, optional): Blockchain instance for immutable storage.
        """
        self.blockchain = blockchain
        logger.info("AlertManager initialized")
    
    def create_alert(self, attack_type, severity, src_ip, dst_ip, protocol,
                     port=None, description=None):
        """
        Create and store a new security alert.
        
        Args:
            attack_type (str): Type of attack (DoS, Probe, R2L, U2R, etc.)
            severity (str): Severity level (Low, Medium, High, Critical)
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            protocol (str): Network protocol (tcp, udp, icmp, etc.)
            port (int, optional): Port number involved
            description (str, optional): Detailed description of the alert
        
        Returns:
            Alert: Created alert object or None if creation failed
        """
        try:
            alert = Alert(
                attack_type=attack_type,
                severity=severity,
                source_ip=src_ip,
                dest_ip=dst_ip,
                protocol=protocol,
                port=port,
                description=description or f"Detected {attack_type} attack",
                status="unresolved",
                is_active=True,
            )
            
            db.session.add(alert)
            db.session.commit()
            
            logger.info(f"Alert created: ID={alert.id}, Type={attack_type}, Severity={severity}")
            
            # Persist to blockchain if available
            if self.blockchain:
                self.log_to_blockchain(alert)
            
            return alert
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            db.session.rollback()
            return None
    
    def get_alert(self, alert_id):
        """
        Retrieve a specific alert by ID.
        
        Args:
            alert_id (int): Alert ID
        
        Returns:
            Alert: Alert object or None if not found
        """
        try:
            alert = Alert.query.get(alert_id)
            return alert
        except Exception as e:
            logger.error(f"Error retrieving alert {alert_id}: {e}")
            return None
    
    def get_recent_alerts(self, limit=20):
        """
        Retrieve recently created alerts.
        
        Args:
            limit (int): Maximum number of alerts to retrieve. Defaults to 20.
        
        Returns:
            list: List of Alert objects sorted by timestamp (newest first)
        """
        try:
            alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
            logger.info(f"Retrieved {len(alerts)} recent alerts")
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving recent alerts: {e}")
            return []
    
    def get_alerts_by_severity(self, severity):
        """
        Retrieve alerts filtered by severity level.
        
        Args:
            severity (str): Severity level (Low, Medium, High, Critical)
        
        Returns:
            list: List of Alert objects matching the severity
        """
        try:
            alerts = Alert.query.filter_by(severity=severity).order_by(
                Alert.timestamp.desc()
            ).all()
            logger.info(f"Retrieved {len(alerts)} alerts with severity: {severity}")
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving alerts by severity {severity}: {e}")
            return []
    
    def get_alerts_by_type(self, attack_type):
        """
        Retrieve alerts filtered by attack type.
        
        Args:
            attack_type (str): Type of attack (DoS, Probe, R2L, U2R, Normal)
        
        Returns:
            list: List of Alert objects matching the attack type
        """
        try:
            alerts = Alert.query.filter_by(attack_type=attack_type).order_by(
                Alert.timestamp.desc()
            ).all()
            logger.info(f"Retrieved {len(alerts)} alerts of type: {attack_type}")
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving alerts by type {attack_type}: {e}")
            return []
    
    def get_alerts_by_status(self, status):
        """
        Retrieve alerts filtered by status.
        
        Args:
            status (str): Status (resolved, unresolved, investigating)
        
        Returns:
            list: List of Alert objects matching the status
        """
        try:
            alerts = Alert.query.filter_by(status=status).order_by(
                Alert.timestamp.desc()
            ).all()
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving alerts by status {status}: {e}")
            return []
    
    def update_alert_status(self, alert_id, status):
        """
        Update the status of an alert.
        
        Args:
            alert_id (int): Alert ID
            status (str): New status (resolved, unresolved, investigating, acknowledged)
        
        Returns:
            bool: True if update was successful, False otherwise
        """
        try:
            alert = Alert.query.get(alert_id)
            if not alert:
                logger.warning(f"Alert {alert_id} not found")
                return False
            
            alert.status = status
            db.session.commit()
            
            logger.info(f"Alert {alert_id} status updated to: {status}")
            return True
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            db.session.rollback()
            return False
    
    def resolve_alert(self, alert_id):
        """
        Mark an alert as resolved.
        
        Args:
            alert_id (int): Alert ID
        
        Returns:
            bool: True if resolved successfully
        """
        return self.update_alert_status(alert_id, "resolved")
    
    def acknowledge_alert(self, alert_id):
        """
        Mark an alert as acknowledged.
        
        Args:
            alert_id (int): Alert ID
        
        Returns:
            bool: True if acknowledged successfully
        """
        return self.update_alert_status(alert_id, "acknowledged")
    
    def get_alert_statistics(self):
        """
        Generate statistics about all alerts.
        
        Returns:
            dict: Statistics including counts by type, severity, and status
        """
        try:
            all_alerts = Alert.query.all()
            
            stats = {
                "total_alerts": len(all_alerts),
                "by_type": {},
                "by_severity": {},
                "by_status": {},
                "last_24h": 0,
                "critical_unresolved": 0,
            }
            
            # Count by attack type
            for alert in all_alerts:
                attack_type = alert.attack_type or "Unknown"
                stats["by_type"][attack_type] = stats["by_type"].get(attack_type, 0) + 1
                
                # Count by severity
                severity = alert.severity or "Unknown"
                stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
                
                # Count by status
                status = alert.status or "Unknown"
                stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
                
                # Count critical unresolved
                if severity == "Critical" and status == "unresolved":
                    stats["critical_unresolved"] += 1
            
            # Count alerts from last 24 hours
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            recent_alerts = Alert.query.filter(Alert.timestamp >= cutoff_time).all()
            stats["last_24h"] = len(recent_alerts)
            
            logger.info(f"Alert statistics: {stats}")
            return stats
        except Exception as e:
            logger.error(f"Error generating alert statistics: {e}")
            return {}
    
    def log_to_blockchain(self, alert):
        """
        Store alert data in the blockchain for immutable audit trail.
        
        Args:
            alert (Alert): Alert object to store in blockchain
        
        Returns:
            bool: True if blockchain logging was successful
        """
        if not self.blockchain:
            logger.warning("Blockchain not initialized. Skipping blockchain logging.")
            return False
        
        try:
            alert_data = {
                "id": alert.id,
                "attack_type": alert.attack_type,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "dest_ip": alert.dest_ip,
                "protocol": alert.protocol,
                "port": alert.port,
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "description": alert.description,
            }
            
            # Ensure blockchain has genesis block
            if not self.blockchain.chain:
                self.blockchain.create_genesis_block()
            
            # Add block with alert data
            block = self.blockchain.add_block(alert_data)
            
            # Update alert with blockchain hash
            alert.attach_blockchain_hash(block.hash)
            db.session.commit()
            
            # Save blockchain to database
            self.blockchain.save_chain_to_db()
            
            logger.info(f"Alert {alert.id} logged to blockchain with hash: {block.hash}")
            return True
        except Exception as e:
            logger.error(f"Error logging alert to blockchain: {e}")
            return False
    
    def get_alert_trend(self, hours=24):
        """
        Get alert trend data for the specified number of hours.
        
        Args:
            hours (int): Number of hours to look back
        
        Returns:
            dict: Hourly alert counts
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            alerts = Alert.query.filter(Alert.timestamp >= cutoff_time).all()
            
            trend = defaultdict(int)
            for alert in alerts:
                hour_key = alert.timestamp.strftime("%Y-%m-%d %H:00") if alert.timestamp else "Unknown"
                trend[hour_key] += 1
            
            return dict(sorted(trend.items()))
        except Exception as e:
            logger.error(f"Error generating alert trend: {e}")
            return {}
    
    def get_top_attack_types(self, limit=5):
        """
        Get the most common attack types.
        
        Args:
            limit (int): Number of top types to return
        
        Returns:
            list: List of tuples (attack_type, count)
        """
        try:
            stats = self.get_alert_statistics()
            top_types = sorted(
                stats.get("by_type", {}).items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
            return top_types
        except Exception as e:
            logger.error(f"Error getting top attack types: {e}")
            return []
    
    def get_top_source_ips(self, limit=5):
        """
        Get the most active source IPs (attackers).
        
        Args:
            limit (int): Number of top IPs to return
        
        Returns:
            list: List of tuples (source_ip, count)
        """
        try:
            all_alerts = Alert.query.all()
            ip_counts = defaultdict(int)
            
            for alert in all_alerts:
                ip_counts[alert.source_ip] += 1
            
            top_ips = sorted(
                ip_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
            
            return top_ips
        except Exception as e:
            logger.error(f"Error getting top source IPs: {e}")
            return []
