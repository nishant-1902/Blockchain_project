import logging
from pathlib import Path

from flask import Blueprint, Flask, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_socketio import SocketIO

try:
    from config import configure_app
    from database.models import Alert, NetworkLog, User, db
    from auth.jwt_auth import init_auth
    from auth.login import bcrypt as login_bcrypt, login_bp
    from auth.register import bcrypt as register_bcrypt, register_bp
except ImportError:
    from ICIDS.config import configure_app
    from ICIDS.database.models import Alert, NetworkLog, User, db
    from ICIDS.auth.jwt_auth import init_auth
    from ICIDS.auth.login import bcrypt as login_bcrypt, login_bp
    from ICIDS.auth.register import bcrypt as register_bcrypt, register_bp

try:
    from api.routes import api_bp
except (ImportError, ModuleNotFoundError, AttributeError):
    api_bp = Blueprint("api_bp", __name__, url_prefix="/api")

    @api_bp.route("/status", methods=["GET"])
    def api_status():
        return jsonify({"success": True, "message": "API blueprint is registered."}), 200

try:
    from realtime.socket_events import realtime_bp
except (ImportError, ModuleNotFoundError, AttributeError):
    realtime_bp = Blueprint("realtime_bp", __name__, url_prefix="/realtime")

    @realtime_bp.route("/status", methods=["GET"])
    def realtime_status():
        return jsonify({"success": True, "message": "Realtime blueprint is registered."}), 200

bcrypt = Bcrypt()
socketio = SocketIO()


def configure_logging(app):
    base_dir = Path(app.root_path)
    log_dir = Path(app.config.get("LOG_DIR", base_dir / "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    system_handler = logging.FileHandler(log_dir / "system.log", encoding="utf-8")
    system_handler.setLevel(logging.INFO)
    system_handler.setFormatter(formatter)

    attack_handler = logging.FileHandler(log_dir / "attack.log", encoding="utf-8")
    attack_handler.setLevel(logging.WARNING)
    attack_handler.setFormatter(formatter)

    system_logger = logging.getLogger("system")
    system_logger.setLevel(logging.INFO)
    system_logger.addHandler(system_handler)
    system_logger.propagate = False

    attack_logger = logging.getLogger("attack")
    attack_logger.setLevel(logging.WARNING)
    attack_logger.addHandler(attack_handler)
    attack_logger.propagate = False

    app.system_logger = system_logger
    app.attack_logger = attack_logger

    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(system_handler)


def register_blueprints(app):
    app.register_blueprint(login_bp)
    app.register_blueprint(register_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(realtime_bp)


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    configure_app(app)
    configure_logging(app)

    db.init_app(app)
    bcrypt.init_app(app)
    login_bcrypt.init_app(app)
    register_bcrypt.init_app(app)
    init_auth(app)

    socketio.init_app(
        app,
        cors_allowed_origins=app.config.get("SOCKETIO_CORS_ALLOWED_ORIGINS", "*"),
        async_mode=app.config.get("SOCKETIO_ASYNC_MODE", "eventlet"),
    )

    CORS(
        app,
        resources={r"/*": {"origins": app.config.get("SOCKETIO_CORS_ALLOWED_ORIGINS", "*")}},
    )

    register_blueprints(app)

    @app.route("/", methods=["GET"])
    def health_check():
        return jsonify({"success": True, "message": "ICIDS Flask application is running."}), 200

    @app.errorhandler(403)
    def handle_forbidden(error):
        app.system_logger.warning("403 Forbidden: %s", error)
        return jsonify({"success": False, "error": "Forbidden", "message": "Access denied."}), 403

    @app.errorhandler(404)
    def handle_not_found(error):
        app.system_logger.warning("404 Not Found: %s", error)
        return jsonify({"success": False, "error": "Not Found", "message": "Resource does not exist."}), 404

    @app.errorhandler(500)
    def handle_server_error(error):
        app.system_logger.error("500 Internal Server Error: %s", error, exc_info=True)
        app.attack_logger.error("500 Internal Server Error: %s", error, exc_info=True)
        return jsonify({"success": False, "error": "Server Error", "message": "An unexpected error occurred."}), 500

    return app


def create_database_tables(app):
    with app.app_context():
        db.create_all()
        app.system_logger.info("Database tables created or verified.")


def seed_dummy_data(app):
    with app.app_context():
        if User.query.first() or Alert.query.first() or NetworkLog.query.first():
            app.system_logger.info("Existing data detected. Skipping dummy data seeding.")
            return

        app.system_logger.info("Seeding dummy users, alerts, and network logs.")

        users = [
            ("admin1", "admin1@example.com", "AdminPass123!", "admin"),
            ("admin2", "admin2@example.com", "AdminPass123!", "admin"),
            ("user1", "user1@example.com", "UserPass123!", "user"),
            ("user2", "user2@example.com", "UserPass123!", "user"),
        ]

        for username, email, password, role in users:
            password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
            user = User(username=username, email=email, password_hash=password_hash, role=role)
            db.session.add(user)

        alert_templates = [
            {"attack_type": "SQL Injection", "severity": "high", "source_ip": "10.0.0.11", "dest_ip": "10.0.0.1", "protocol": "TCP", "port": 80, "status": "unresolved", "description": "Multiple suspicious SQL patterns detected."},
            {"attack_type": "Port Scan", "severity": "medium", "source_ip": "10.0.0.22", "dest_ip": "10.0.0.2", "protocol": "TCP", "port": 443, "status": "unresolved", "description": "Port sweep behavior from source IP."},
            {"attack_type": "Brute Force", "severity": "high", "source_ip": "172.16.0.45", "dest_ip": "10.0.0.3", "protocol": "TCP", "port": 22, "status": "unresolved", "description": "Repeated login failures detected."},
            {"attack_type": "DNS Amplification", "severity": "high", "source_ip": "203.0.113.12", "dest_ip": "10.0.0.4", "protocol": "UDP", "port": 53, "status": "unresolved", "description": "Large DNS response traffic observed."},
            {"attack_type": "Malware C2", "severity": "critical", "source_ip": "198.51.100.5", "dest_ip": "10.0.0.5", "protocol": "TCP", "port": 8080, "status": "unresolved", "description": "Command and control communication pattern found."},
            {"attack_type": "XSS", "severity": "medium", "source_ip": "192.168.2.30", "dest_ip": "10.0.0.6", "protocol": "HTTP", "port": 80, "status": "unresolved", "description": "Cross-site scripting attempts detected in query strings."},
            {"attack_type": "ARP Spoofing", "severity": "high", "source_ip": "172.16.1.99", "dest_ip": "10.0.0.7", "protocol": "ARP", "port": None, "status": "unresolved", "description": "Suspicious ARP responses observed on the local network."},
            {"attack_type": "Data Exfiltration", "severity": "critical", "source_ip": "10.1.1.12", "dest_ip": "198.51.100.20", "protocol": "TCP", "port": 443, "status": "unresolved", "description": "Large outbound file transfer detected to an unknown destination."},
            {"attack_type": "Privilege Escalation", "severity": "high", "source_ip": "10.0.0.13", "dest_ip": "10.0.0.8", "protocol": "TCP", "port": 3389, "status": "unresolved", "description": "Suspicious remote desktop authentication attempts."},
            {"attack_type": "Botnet Traffic", "severity": "medium", "source_ip": "203.0.113.55", "dest_ip": "10.0.0.9", "protocol": "TCP", "port": 12345, "status": "unresolved", "description": "Repeated beacon traffic consistent with a botnet C2 channel."},
        ]

        for idx, template in enumerate(alert_templates, start=1):
            alert = Alert(
                attack_type=template["attack_type"],
                severity=template["severity"],
                source_ip=template["source_ip"],
                dest_ip=template["dest_ip"],
                protocol=template["protocol"],
                port=template["port"],
                status=template["status"],
                description=template["description"],
                blockchain_hash=f"seeded_hash_{idx}",
            )
            db.session.add(alert)
            app.attack_logger.warning("Seed alert created: %s from %s", alert.attack_type, alert.source_ip)

        network_logs = [
            {"source_ip": "10.0.0.11", "dest_ip": "10.0.0.1", "protocol": "TCP", "port": 80, "packet_size": 550, "is_suspicious": False, "prediction": "normal"},
            {"source_ip": "10.0.0.22", "dest_ip": "10.0.0.2", "protocol": "TCP", "port": 22, "packet_size": 128, "is_suspicious": True, "prediction": "suspicious"},
            {"source_ip": "172.16.0.45", "dest_ip": "10.0.0.3", "protocol": "UDP", "port": 53, "packet_size": 1024, "is_suspicious": True, "prediction": "suspicious"},
            {"source_ip": "203.0.113.12", "dest_ip": "10.0.0.4", "protocol": "TCP", "port": 443, "packet_size": 420, "is_suspicious": False, "prediction": "normal"},
            {"source_ip": "198.51.100.5", "dest_ip": "10.0.0.5", "protocol": "TCP", "port": 8080, "packet_size": 760, "is_suspicious": True, "prediction": "suspicious"},
        ]

        for log in network_logs:
            network_log = NetworkLog(
                source_ip=log["source_ip"],
                dest_ip=log["dest_ip"],
                protocol=log["protocol"],
                port=log["port"],
                packet_size=log["packet_size"],
                is_suspicious=log["is_suspicious"],
                prediction=log["prediction"],
            )
            db.session.add(network_log)

        db.session.commit()
        app.system_logger.info("Dummy data seeded successfully.")


app = create_app()

with app.app_context():
    create_database_tables(app)
    seed_dummy_data(app)

if __name__ == "__main__":
    app.debug = True
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
