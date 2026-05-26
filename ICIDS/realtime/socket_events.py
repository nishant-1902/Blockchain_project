import logging
import threading
import time
from datetime import datetime

from flask import current_app
from flask_socketio import emit, join_room, leave_room, rooms

try:
    from database.models import db, Alert, NetworkLog
except ImportError:
    from ICIDS.database.models import db, Alert, NetworkLog

try:
    from realtime.alerts import AlertManager
except ImportError:
    from ICIDS.realtime.alerts import AlertManager

try:
    from network_monitor.packet_capture import PacketCapture
except ImportError:
    from ICIDS.network_monitor.packet_capture import PacketCapture

logger = logging.getLogger(__name__)

# Global instances
alert_manager = None
packet_capturer = None
stats_broadcast_thread = None
is_broadcasting = False


def init_realtime(socketio, blockchain=None):
    """
    Initialize realtime module with SocketIO and optional blockchain.
    
    Args:
        socketio: Flask-SocketIO instance
        blockchain: Optional Blockchain instance
    """
    global alert_manager, packet_capturer
    
    alert_manager = AlertManager(blockchain=blockchain)
    packet_capturer = PacketCapture(max_packets=1000)
    
    logger.info("Realtime module initialized")


def start_stats_broadcast(socketio, interval=3):
    """
    Start background thread that broadcasts statistics every N seconds.
    
    Args:
        socketio: Flask-SocketIO instance
        interval (int): Broadcast interval in seconds. Defaults to 3.
    """
    global stats_broadcast_thread, is_broadcasting
    
    if is_broadcasting:
        logger.warning("Stats broadcast already running")
        return
    
    is_broadcasting = True
    
    def broadcast_loop():
        while is_broadcasting:
            try:
                with current_app.app_context():
                    stats = alert_manager.get_alert_statistics()
                    
                    broadcast_data = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "statistics": stats,
                        "capture_stats": packet_capturer.get_statistics() if packet_capturer else {},
                    }
                    
                    socketio.emit("live_stats_update", broadcast_data, broadcast=True)
                    
                    time.sleep(interval)
            except Exception as e:
                logger.error(f"Error in stats broadcast loop: {e}")
                time.sleep(interval)
    
    stats_broadcast_thread = threading.Thread(target=broadcast_loop, daemon=True)
    stats_broadcast_thread.start()
    logger.info(f"Stats broadcast started (interval: {interval}s)")


def stop_stats_broadcast():
    """Stop the background stats broadcast thread."""
    global is_broadcasting
    is_broadcasting = False
    logger.info("Stats broadcast stopped")


def emit_new_alert(socketio, alert_data):
    """
    Emit a new alert to all connected clients.
    
    Args:
        socketio: Flask-SocketIO instance
        alert_data (dict): Alert information
    """
    try:
        event_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert": alert_data,
        }
        
        socketio.emit("new_alert", event_data, broadcast=True)
        logger.info(f"Alert emitted: {alert_data.get('attack_type')}")
    except Exception as e:
        logger.error(f"Error emitting alert: {e}")


def emit_packet_stats(socketio, stats):
    """
    Emit packet capture statistics to connected clients.
    
    Args:
        socketio: Flask-SocketIO instance
        stats (dict): Packet statistics
    """
    try:
        event_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "stats": stats,
        }
        
        socketio.emit("packet_stats_update", event_data, broadcast=True)
    except Exception as e:
        logger.error(f"Error emitting packet stats: {e}")


def emit_attack_graph_data(socketio, data):
    """
    Emit attack trend data for graph visualization.
    
    Args:
        socketio: Flask-SocketIO instance
        data (dict): Graph data with labels and datasets
    """
    try:
        event_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "graph_data": data,
        }
        
        socketio.emit("attack_graph_update", event_data, broadcast=True)
    except Exception as e:
        logger.error(f"Error emitting attack graph data: {e}")


# SocketIO Event Handlers
def register_socket_events(socketio):
    """
    Register all SocketIO event handlers.
    
    Args:
        socketio: Flask-SocketIO instance
    """
    
    @socketio.on("connect")
    def handle_connect():
        """Handle client connection."""
        logger.info(f"Client connected: {id}")
        emit("connection_response", {
            "status": "connected",
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Connected to ICIDS realtime server",
        })
        
        # Send current statistics to new client
        if alert_manager:
            stats = alert_manager.get_alert_statistics()
            emit("live_stats_update", {
                "timestamp": datetime.utcnow().isoformat(),
                "statistics": stats,
            })
    
    @socketio.on("disconnect")
    def handle_disconnect():
        """Handle client disconnection."""
        logger.info(f"Client disconnected")
    
    @socketio.on("request_alerts")
    def handle_request_alerts(data):
        """
        Handle request for recent alerts.
        
        Expected data:
        {
            "limit": 20,
            "severity": "Critical" (optional),
            "status": "unresolved" (optional)
        }
        """
        try:
            if not alert_manager:
                emit("error", {"message": "Alert manager not initialized"})
                return
            
            limit = data.get("limit", 20)
            severity = data.get("severity")
            status = data.get("status")
            
            if severity:
                alerts = alert_manager.get_alerts_by_severity(severity)
            elif status:
                alerts = alert_manager.get_alerts_by_status(status)
            else:
                alerts = alert_manager.get_recent_alerts(limit)
            
            alert_list = [alert.to_dict() for alert in alerts[:limit]]
            
            emit("alerts_response", {
                "timestamp": datetime.utcnow().isoformat(),
                "alerts": alert_list,
                "count": len(alert_list),
            })
        except Exception as e:
            logger.error(f"Error handling alert request: {e}")
            emit("error", {"message": str(e)})
    
    @socketio.on("request_statistics")
    def handle_request_statistics():
        """Handle request for alert statistics."""
        try:
            if not alert_manager:
                emit("error", {"message": "Alert manager not initialized"})
                return
            
            stats = alert_manager.get_alert_statistics()
            trend = alert_manager.get_alert_trend(hours=24)
            top_types = alert_manager.get_top_attack_types(limit=5)
            top_ips = alert_manager.get_top_source_ips(limit=5)
            
            emit("statistics_response", {
                "timestamp": datetime.utcnow().isoformat(),
                "statistics": stats,
                "trend": trend,
                "top_attack_types": [{"type": t[0], "count": t[1]} for t in top_types],
                "top_source_ips": [{"ip": t[0], "count": t[1]} for t in top_ips],
            })
        except Exception as e:
            logger.error(f"Error handling statistics request: {e}")
            emit("error", {"message": str(e)})
    
    @socketio.on("update_alert_status")
    def handle_update_alert_status(data):
        """
        Handle alert status update.
        
        Expected data:
        {
            "alert_id": 1,
            "status": "resolved"
        }
        """
        try:
            if not alert_manager:
                emit("error", {"message": "Alert manager not initialized"})
                return
            
            alert_id = data.get("alert_id")
            status = data.get("status")
            
            if not alert_id or not status:
                emit("error", {"message": "Missing alert_id or status"})
                return
            
            success = alert_manager.update_alert_status(alert_id, status)
            
            if success:
                alert = alert_manager.get_alert(alert_id)
                emit("alert_status_updated", {
                    "timestamp": datetime.utcnow().isoformat(),
                    "alert": alert.to_dict(),
                }, broadcast=True)
            else:
                emit("error", {"message": f"Failed to update alert {alert_id}"})
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            emit("error", {"message": str(e)})
    
    @socketio.on("start_monitoring")
    def handle_start_monitoring(data):
        """
        Start packet capture and monitoring.
        
        Expected data:
        {
            "interface": "eth0" (optional, defaults to 'lo')
        }
        """
        try:
            if not packet_capturer:
                emit("error", {"message": "Packet capturer not initialized"})
                return
            
            interface = data.get("interface", "lo")
            
            success = packet_capturer.start_capture(interface=interface)
            
            if success:
                emit("monitoring_started", {
                    "timestamp": datetime.utcnow().isoformat(),
                    "interface": interface,
                    "message": f"Monitoring started on {interface}",
                }, broadcast=True)
                
                logger.info(f"Monitoring started on interface: {interface}")
            else:
                emit("error", {"message": "Failed to start monitoring"})
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            emit("error", {"message": str(e)})
    
    @socketio.on("stop_monitoring")
    def handle_stop_monitoring():
        """Stop packet capture and monitoring."""
        try:
            if not packet_capturer:
                emit("error", {"message": "Packet capturer not initialized"})
                return
            
            success = packet_capturer.stop_capture()
            
            if success:
                stats = packet_capturer.get_statistics()
                emit("monitoring_stopped", {
                    "timestamp": datetime.utcnow().isoformat(),
                    "message": "Monitoring stopped",
                    "final_stats": stats,
                }, broadcast=True)
                
                logger.info("Monitoring stopped")
            else:
                emit("error", {"message": "Monitoring was not running"})
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
            emit("error", {"message": str(e)})
    
    @socketio.on("request_packet_stats")
    def handle_request_packet_stats():
        """Handle request for current packet capture statistics."""
        try:
            if not packet_capturer:
                emit("error", {"message": "Packet capturer not initialized"})
                return
            
            stats = packet_capturer.get_statistics()
            
            emit("packet_stats_response", {
                "timestamp": datetime.utcnow().isoformat(),
                "stats": stats,
            })
        except Exception as e:
            logger.error(f"Error retrieving packet stats: {e}")
            emit("error", {"message": str(e)})
    
    @socketio.on("get_alert_details")
    def handle_get_alert_details(data):
        """
        Get detailed information for a specific alert.
        
        Expected data:
        {
            "alert_id": 1
        }
        """
        try:
            if not alert_manager:
                emit("error", {"message": "Alert manager not initialized"})
                return
            
            alert_id = data.get("alert_id")
            if not alert_id:
                emit("error", {"message": "Missing alert_id"})
                return
            
            alert = alert_manager.get_alert(alert_id)
            
            if alert:
                emit("alert_details", {
                    "timestamp": datetime.utcnow().isoformat(),
                    "alert": alert.to_dict(),
                })
            else:
                emit("error", {"message": f"Alert {alert_id} not found"})
        except Exception as e:
            logger.error(f"Error retrieving alert details: {e}")
            emit("error", {"message": str(e)})
