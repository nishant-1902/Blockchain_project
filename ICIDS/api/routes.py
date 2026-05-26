import logging
from datetime import datetime
from functools import wraps

from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt

try:
    from database.models import db, User, Alert, NetworkLog, BlockchainRecord, Report
except ImportError:
    from ICIDS.database.models import db, User, Alert, NetworkLog, BlockchainRecord, Report

try:
    from auth.roles import admin_required, user_required
except ImportError:
    from ICIDS.auth.roles import admin_required, user_required

try:
    from blockchain.blockchain import Blockchain
except ImportError:
    from ICIDS.blockchain.blockchain import Blockchain

try:
    from realtime.alerts import AlertManager
except ImportError:
    from ICIDS.realtime.alerts import AlertManager

try:
    from network_monitor.packet_capture import PacketCapture
except ImportError:
    from ICIDS.network_monitor.packet_capture import PacketCapture

logger = logging.getLogger(__name__)

# Create API Blueprint
api_bp = Blueprint("api", __name__, url_prefix="/api")

# Global instances (set from app initialization)
blockchain = None
alert_manager = None
packet_capturer = None


def init_api(app, _blockchain=None, _alert_manager=None, _packet_capturer=None):
    """
    Initialize API with global instances.
    
    Args:
        app: Flask app instance
        _blockchain: Blockchain instance
        _alert_manager: AlertManager instance
        _packet_capturer: PacketCapture instance
    """
    global blockchain, alert_manager, packet_capturer
    blockchain = _blockchain
    alert_manager = _alert_manager
    packet_capturer = _packet_capturer
    app.register_blueprint(api_bp)
    logger.info("API blueprint registered")


def paginated_response(query, page=1, per_page=20):
    """Helper to paginate database query results."""
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return {
        "items": [item.to_dict() for item in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page,
    }


# ============================================================================
# AUTH ENDPOINTS
# ============================================================================

@api_bp.route("/auth/register", methods=["POST"])
def register():
    """Register a new user (public endpoint)."""
    try:
        from auth.register import register as register_user
    except ImportError:
        from ICIDS.auth.register import register as register_user
    
    return register_user()


@api_bp.route("/auth/login", methods=["POST"])
def login():
    """Login and get JWT tokens."""
    try:
        from auth.login import login as login_user
    except ImportError:
        from ICIDS.auth.login import login as login_user
    
    return login_user()


@api_bp.route("/auth/logout", methods=["POST"])
@jwt_required()
def logout():
    """Logout and revoke current token."""
    try:
        from auth.jwt_auth import revoke_current_token
    except ImportError:
        from ICIDS.auth.jwt_auth import revoke_current_token
    
    try:
        revoke_current_token()
        return jsonify({
            "success": True,
            "message": "Successfully logged out",
        }), 200
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({"success": False, "message": "Logout failed"}), 500


@api_bp.route("/auth/refresh", methods=["POST"])
def refresh():
    """Refresh access token using refresh token."""
    try:
        from auth.login import create_tokens_from_refresh
    except ImportError:
        from ICIDS.auth.login import create_tokens_from_refresh
    
    return create_tokens_from_refresh()


# ============================================================================
# ALERT ENDPOINTS
# ============================================================================

@api_bp.route("/alerts", methods=["GET"])
@jwt_required()
def get_alerts():
    """Get all alerts with pagination and filtering."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        severity = request.args.get("severity")
        status = request.args.get("status")
        attack_type = request.args.get("attack_type")
        
        query = Alert.query
        
        if severity:
            query = query.filter_by(severity=severity)
        if status:
            query = query.filter_by(status=status)
        if attack_type:
            query = query.filter_by(attack_type=attack_type)
        
        query = query.order_by(Alert.timestamp.desc())
        
        result = paginated_response(query, page, per_page)
        
        return jsonify({
            "success": True,
            "data": result,
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/alerts/<int:alert_id>", methods=["GET"])
@jwt_required()
def get_alert(alert_id):
    """Get a specific alert."""
    try:
        alert = Alert.query.get(alert_id)
        
        if not alert:
            return jsonify({"success": False, "message": "Alert not found"}), 404
        
        return jsonify({
            "success": True,
            "data": alert.to_dict(),
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving alert {alert_id}: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/alerts/<int:alert_id>/status", methods=["PUT"])
@jwt_required()
def update_alert_status(alert_id):
    """Update alert status."""
    try:
        data = request.get_json() or {}
        status = data.get("status")
        
        if not status:
            return jsonify({"success": False, "message": "Status is required"}), 400
        
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({"success": False, "message": "Alert not found"}), 404
        
        alert.status = status
        db.session.commit()
        
        logger.info(f"Alert {alert_id} status updated to {status}")
        
        return jsonify({
            "success": True,
            "message": "Alert status updated",
            "data": alert.to_dict(),
        }), 200
    except Exception as e:
        logger.error(f"Error updating alert status: {e}")
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/alerts/<int:alert_id>", methods=["DELETE"])
@admin_required
def delete_alert(alert_id):
    """Delete an alert (admin only)."""
    try:
        alert = Alert.query.get(alert_id)
        
        if not alert:
            return jsonify({"success": False, "message": "Alert not found"}), 404
        
        db.session.delete(alert)
        db.session.commit()
        
        logger.info(f"Alert {alert_id} deleted by admin")
        
        return jsonify({
            "success": True,
            "message": "Alert deleted",
        }), 200
    except Exception as e:
        logger.error(f"Error deleting alert: {e}")
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/alerts/statistics", methods=["GET"])
@jwt_required()
def get_alert_statistics():
    """Get alert statistics."""
    try:
        if not alert_manager:
            return jsonify({"success": False, "message": "Alert manager not available"}), 503
        
        stats = alert_manager.get_alert_statistics()
        trend = alert_manager.get_alert_trend(hours=24)
        top_types = alert_manager.get_top_attack_types(limit=5)
        top_ips = alert_manager.get_top_source_ips(limit=5)
        
        return jsonify({
            "success": True,
            "data": {
                "statistics": stats,
                "trend": trend,
                "top_attack_types": [{"type": t[0], "count": t[1]} for t in top_types],
                "top_source_ips": [{"ip": t[0], "count": t[1]} for t in top_ips],
            },
        }), 200
    except Exception as e:
        logger.error(f"Error getting alert statistics: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ============================================================================
# NETWORK ENDPOINTS
# ============================================================================

@api_bp.route("/network/logs", methods=["GET"])
@jwt_required()
def get_network_logs():
    """Get network logs with pagination."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        is_suspicious = request.args.get("is_suspicious", type=lambda x: x.lower() == 'true')
        
        query = NetworkLog.query
        
        if is_suspicious is not None:
            query = query.filter_by(is_suspicious=is_suspicious)
        
        query = query.order_by(NetworkLog.timestamp.desc())
        
        result = paginated_response(query, page, per_page)
        
        return jsonify({
            "success": True,
            "data": result,
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving network logs: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/network/start-capture", methods=["POST"])
@jwt_required()
def start_capture():
    """Start packet capture on specified interface."""
    try:
        if not packet_capturer:
            return jsonify({"success": False, "message": "Packet capturer not available"}), 503
        
        data = request.get_json() or {}
        interface = data.get("interface", "lo")
        
        if packet_capturer.is_capturing:
            return jsonify({
                "success": False,
                "message": "Capture already running",
            }), 409
        
        success = packet_capturer.start_capture(interface=interface)
        
        if success:
            return jsonify({
                "success": True,
                "message": f"Packet capture started on {interface}",
                "data": {"interface": interface},
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Failed to start capture",
            }), 500
    except Exception as e:
        logger.error(f"Error starting packet capture: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/network/stop-capture", methods=["POST"])
@jwt_required()
def stop_capture():
    """Stop packet capture."""
    try:
        if not packet_capturer:
            return jsonify({"success": False, "message": "Packet capturer not available"}), 503
        
        if not packet_capturer.is_capturing:
            return jsonify({
                "success": False,
                "message": "Capture is not running",
            }), 409
        
        success = packet_capturer.stop_capture()
        stats = packet_capturer.get_statistics()
        
        if success:
            return jsonify({
                "success": True,
                "message": "Packet capture stopped",
                "data": stats,
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Failed to stop capture",
            }), 500
    except Exception as e:
        logger.error(f"Error stopping packet capture: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/network/live-stats", methods=["GET"])
@jwt_required()
def get_live_stats():
    """Get live network capture statistics."""
    try:
        if not packet_capturer:
            return jsonify({"success": False, "message": "Packet capturer not available"}), 503
        
        stats = packet_capturer.get_statistics()
        
        return jsonify({
            "success": True,
            "data": {
                "timestamp": datetime.utcnow().isoformat(),
                "stats": stats,
            },
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving live stats: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ============================================================================
# BLOCKCHAIN ENDPOINTS
# ============================================================================

@api_bp.route("/blockchain/chain", methods=["GET"])
@jwt_required()
def get_blockchain_chain():
    """Get the complete blockchain."""
    try:
        if not blockchain:
            return jsonify({"success": False, "message": "Blockchain not available"}), 503
        
        chain_data = blockchain.get_chain()
        
        return jsonify({
            "success": True,
            "data": {
                "chain": chain_data,
                "length": len(chain_data),
                "difficulty": blockchain.difficulty,
            },
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving blockchain: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/blockchain/validate", methods=["GET"])
@jwt_required()
def validate_blockchain():
    """Validate blockchain integrity."""
    try:
        if not blockchain:
            return jsonify({"success": False, "message": "Blockchain not available"}), 503
        
        is_valid = blockchain.is_chain_valid()
        tamper_status = blockchain.tamper_detection()
        
        return jsonify({
            "success": True,
            "data": {
                "is_valid": is_valid,
                "tamper_detection": tamper_status,
            },
        }), 200
    except Exception as e:
        logger.error(f"Error validating blockchain: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/blockchain/block/<int:index>", methods=["GET"])
@jwt_required()
def get_block(index):
    """Get a specific block by index."""
    try:
        if not blockchain:
            return jsonify({"success": False, "message": "Blockchain not available"}), 503
        
        block = blockchain.get_block_by_index(index)
        
        if not block:
            return jsonify({"success": False, "message": "Block not found"}), 404
        
        return jsonify({
            "success": True,
            "data": block.to_dict(),
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving block: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ============================================================================
# REPORT ENDPOINTS
# ============================================================================

@api_bp.route("/reports", methods=["GET"])
@jwt_required()
def get_reports():
    """Get all reports with pagination."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        report_type = request.args.get("report_type")
        
        query = Report.query
        
        if report_type:
            query = query.filter_by(report_type=report_type)
        
        query = query.order_by(Report.generated_at.desc())
        
        result = paginated_response(query, page, per_page)
        
        return jsonify({
            "success": True,
            "data": result,
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving reports: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/reports/generate", methods=["POST"])
@jwt_required()
def generate_report():
    """Generate a new report."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        
        data = request.get_json() or {}
        report_type = data.get("report_type", "summary")
        title = data.get("title", f"ICIDS Report - {datetime.utcnow().strftime('%Y-%m-%d')}")
        
        try:
            from reports.report_generator import generate_report as gen_report
        except ImportError:
            from ICIDS.reports.report_generator import generate_report as gen_report
        
        filepath = gen_report(report_type)
        
        if not filepath:
            return jsonify({
                "success": False,
                "message": "Failed to generate report",
            }), 500
        
        report = Report(
            title=title,
            generated_by=user_id,
            file_path=filepath,
            report_type=report_type,
        )
        
        db.session.add(report)
        db.session.commit()
        
        logger.info(f"Report generated: {report.id} by user {user_id}")
        
        return jsonify({
            "success": True,
            "message": "Report generated successfully",
            "data": report.to_dict(),
        }), 201
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/reports/download/<int:report_id>", methods=["GET"])
@jwt_required()
def download_report(report_id):
    """Download a report file."""
    try:
        report = Report.query.get(report_id)
        
        if not report:
            return jsonify({"success": False, "message": "Report not found"}), 404
        
        import os
        if not os.path.exists(report.file_path):
            return jsonify({
                "success": False,
                "message": "Report file not found",
            }), 404
        
        return send_file(report.file_path, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ============================================================================
# USER ENDPOINTS (ADMIN ONLY)
# ============================================================================

@api_bp.route("/users", methods=["GET"])
@admin_required
def get_users():
    """Get all users (admin only)."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        role = request.args.get("role")
        
        query = User.query
        
        if role:
            query = query.filter_by(role=role)
        
        query = query.order_by(User.created_at.desc())
        
        result = paginated_response(query, page, per_page)
        
        return jsonify({
            "success": True,
            "data": result,
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving users: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/users/<int:user_id>/role", methods=["PUT"])
@admin_required
def update_user_role(user_id):
    """Update user role (admin only)."""
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        
        data = request.get_json() or {}
        new_role = data.get("role")
        
        if not new_role:
            return jsonify({"success": False, "message": "Role is required"}), 400
        
        valid_roles = ["user", "admin"]
        if new_role not in valid_roles:
            return jsonify({
                "success": False,
                "message": f"Invalid role. Must be one of: {', '.join(valid_roles)}",
            }), 400
        
        user.role = new_role
        db.session.commit()
        
        logger.info(f"User {user_id} role updated to {new_role} by admin")
        
        return jsonify({
            "success": True,
            "message": "User role updated",
            "data": user.to_dict(),
        }), 200
    except Exception as e:
        logger.error(f"Error updating user role: {e}")
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@api_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    """Delete a user (admin only)."""
    try:
        current_user_id = get_jwt_identity()
        
        if user_id == current_user_id:
            return jsonify({
                "success": False,
                "message": "Cannot delete your own account",
            }), 403
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        
        db.session.delete(user)
        db.session.commit()
        
        logger.info(f"User {user_id} deleted by admin")
        
        return jsonify({
            "success": True,
            "message": "User deleted",
        }), 200
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
