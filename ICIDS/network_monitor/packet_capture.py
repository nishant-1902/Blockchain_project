import threading
import time
import logging
from datetime import datetime
from collections import deque
import json

try:
    from database.models import db, NetworkLog
except ImportError:
    from ICIDS.database.models import db, NetworkLog

try:
    from intrusion_detection.detect_attack import analyze_network_packet, load_model
except ImportError:
    from ICIDS.intrusion_detection.detect_attack import analyze_network_packet, load_model

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Main packet capture and processing engine for ICIDS.
    
    Handles live packet capture, feature extraction, anomaly detection,
    and persistent storage of network logs and alerts.
    """
    
    def __init__(self, max_packets=1000):
        """
        Initialize the packet capture system.
        
        Args:
            max_packets (int): Maximum number of packets to keep in memory.
        """
        self.is_capturing = False
        self.packets = deque(maxlen=max_packets)
        self.capture_thread = None
        self.model = load_model()
        self.packet_count = 0
        logger.info("PacketCapture initialized")
    
    def start_capture(self, interface=None, packet_source="scapy", db_session=None):
        """
        Start live packet capture on the specified network interface.
        
        Args:
            interface (str): Network interface name (e.g., 'eth0', 'wlan0'). 
                           If None, uses 'lo' or generates simulated packets.
            packet_source (str): Source of packets ('scapy' or 'pyshark'). Defaults to 'scapy'.
            db_session: SQLAlchemy session for database operations.
        
        Returns:
            bool: True if capture started successfully, False otherwise.
        """
        if self.is_capturing:
            logger.warning("Packet capture is already running")
            return False
        
        self.is_capturing = True
        self.db_session = db_session or self._get_db_session()
        
        try:
            if packet_source == "pyshark":
                from .pyshark_monitor import capture_with_pyshark
                capture_func = lambda: capture_with_pyshark(interface or "lo", timeout=None)
            else:
                from .scapy_monitor import capture_with_scapy
                capture_func = lambda: capture_with_scapy(interface or "lo", count=0)
            
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                args=(capture_func,),
                daemon=True
            )
            self.capture_thread.start()
            logger.info(f"Packet capture started on interface: {interface or 'lo'} using {packet_source}")
            return True
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
            self.is_capturing = False
            return False
    
    def stop_capture(self):
        """
        Stop the packet capture and cleanup resources.
        
        Returns:
            bool: True if capture was stopped, False if not running.
        """
        if not self.is_capturing:
            logger.warning("Packet capture is not running")
            return False
        
        self.is_capturing = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
            logger.info(f"Packet capture stopped. Total packets captured: {self.packet_count}")
        
        return True
    
    def get_captured_packets(self, limit=None):
        """
        Retrieve captured packets from the in-memory buffer.
        
        Args:
            limit (int): Maximum number of packets to return. If None, returns all.
        
        Returns:
            list: List of packet dictionaries.
        """
        packets_list = list(self.packets)
        
        if limit:
            packets_list = packets_list[-limit:]
        
        logger.info(f"Retrieved {len(packets_list)} packets from buffer")
        return packets_list
    
    def extract_features(self, packet_info):
        """
        Extract ML features from packet data for anomaly detection.
        
        Args:
            packet_info (dict): Packet information including src_ip, dst_ip, 
                              protocol, port, size, flags.
        
        Returns:
            dict: Feature vector suitable for ML model input.
        """
        try:
            features = {
                "duration": packet_info.get("duration", 0),
                "protocol_type": packet_info.get("protocol", "tcp"),
                "src_bytes": packet_info.get("src_bytes", packet_info.get("size", 0)),
                "dst_bytes": packet_info.get("dst_bytes", 0),
                "flag": packet_info.get("flags", "SF"),
                "land": 1 if packet_info.get("src_ip") == packet_info.get("dst_ip") else 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 0,
                "num_failed_logins": 0,
                "logged_in": 0,
                "num_compromised": 0,
                "root_shell": 0,
                "su_attempted": 0,
                "num_root": 0,
                "num_file_creations": 0,
                "num_shells": 0,
                "num_access_files": 0,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": 1,
                "srv_count": 1,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "srv_diff_host_rate": 0.0,
                "dst_host_count": 1,
                "dst_host_srv_count": 1,
            }
            
            return features
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def send_to_detector(self, features):
        """
        Send extracted features to the intrusion detection model.
        
        Args:
            features (dict): Feature vector from extract_features.
        
        Returns:
            dict: Analysis result with attack type, severity, confidence.
        """
        if not self.model:
            logger.warning("Model not loaded. Skipping detection.")
            return None
        
        try:
            import numpy as np
            feature_vector = [
                features.get("duration", 0),
                features.get("src_bytes", 0),
                features.get("dst_bytes", 0),
                features.get("land", 0),
                features.get("wrong_fragment", 0),
                features.get("urgent", 0),
                features.get("hot", 0),
                features.get("num_failed_logins", 0),
                features.get("logged_in", 0),
                features.get("num_compromised", 0),
                features.get("root_shell", 0),
                features.get("su_attempted", 0),
                features.get("num_root", 0),
                features.get("num_file_creations", 0),
                features.get("count", 1),
                features.get("srv_count", 1),
                features.get("serror_rate", 0.0),
                features.get("srv_serror_rate", 0.0),
                features.get("rerror_rate", 0.0),
                features.get("same_srv_rate", 1.0),
            ]
            
            analysis = analyze_network_packet(self.model, feature_vector)
            logger.info(f"Detection result: {analysis}")
            return analysis
        except Exception as e:
            logger.error(f"Error in attack detection: {e}")
            return None
    
    def save_to_db(self, packet_info, analysis=None):
        """
        Save packet information and analysis results to SQLite database.
        
        Args:
            packet_info (dict): Packet data with src_ip, dst_ip, protocol, port, size.
            analysis (dict): Optional detection analysis results.
        
        Returns:
            bool: True if save was successful.
        """
        if not self.db_session:
            logger.warning("No database session available")
            return False
        
        try:
            network_log = NetworkLog(
                source_ip=packet_info.get("src_ip", "0.0.0.0"),
                dest_ip=packet_info.get("dst_ip", "0.0.0.0"),
                protocol=packet_info.get("protocol", "tcp").upper(),
                port=packet_info.get("port", 0),
                packet_size=packet_info.get("size", 0),
                is_suspicious=analysis.get("is_threat", False) if analysis else False,
                prediction=analysis.get("attack_type", "Normal") if analysis else "Normal",
            )
            
            self.db_session.add(network_log)
            self.db_session.commit()
            
            logger.debug(f"Network log saved: {packet_info.get('src_ip')} -> {packet_info.get('dst_ip')}")
            return True
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            self.db_session.rollback()
            return False
    
    def process_packet(self, packet_info):
        """
        Complete packet processing pipeline: extract features, detect attacks, save logs.
        
        Args:
            packet_info (dict): Raw packet information.
        
        Returns:
            dict: Processing result including analysis.
        """
        self.packet_count += 1
        
        # Extract features
        features = self.extract_features(packet_info)
        if not features:
            return None
        
        # Detect attacks
        analysis = self.send_to_detector(features)
        
        # Save to database
        self.save_to_db(packet_info, analysis)
        
        # Store in memory
        self.packets.append({
            "packet_info": packet_info,
            "features": features,
            "analysis": analysis,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        return analysis
    
    def _capture_loop(self, capture_func):
        """
        Internal loop for continuous packet capture.
        
        Args:
            capture_func: Callable that yields packet data.
        """
        try:
            for packet_info in capture_func():
                if not self.is_capturing:
                    break
                
                self.process_packet(packet_info)
        except Exception as e:
            logger.error(f"Error in capture loop: {e}")
            self.is_capturing = False
    
    def _get_db_session(self):
        """Get database session."""
        try:
            from database.models import db
            return db.session
        except ImportError:
            try:
                from ICIDS.database.models import db
                return db.session
            except ImportError:
                return None
    
    def get_statistics(self):
        """
        Get capture statistics.
        
        Returns:
            dict: Statistics including packet count, threats detected, etc.
        """
        packets_list = list(self.packets)
        threats = sum(1 for p in packets_list if p.get("analysis", {}).get("is_threat", False))
        
        return {
            "total_packets": self.packet_count,
            "buffered_packets": len(packets_list),
            "threats_detected": threats,
            "is_capturing": self.is_capturing,
        }
