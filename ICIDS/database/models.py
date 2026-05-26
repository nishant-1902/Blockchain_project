import hashlib
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    last_login = db.Column(db.DateTime, nullable=True)

    reports = db.relationship("Report", back_populates="author", lazy=True)

    def __repr__(self):
        return f"<User id={self.id} username={self.username} email={self.email} role={self.role}>"

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_active": self.is_active,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def activate(self):
        self.is_active = True

    def deactivate(self):
        self.is_active = False

    def update_last_login(self, timestamp=None):
        self.last_login = timestamp or datetime.utcnow()


class Alert(db.Model):
    __tablename__ = "alert"

    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(120), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    dest_ip = db.Column(db.String(45), nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    port = db.Column(db.Integer, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default="unresolved")
    description = db.Column(db.Text, nullable=True)
    blockchain_hash = db.Column(db.String(128), nullable=True)

    def __repr__(self):
        return f"<Alert id={self.id} attack_type={self.attack_type} severity={self.severity} status={self.status}>"

    def to_dict(self):
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "protocol": self.protocol,
            "port": self.port,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "status": self.status,
            "description": self.description,
            "blockchain_hash": self.blockchain_hash,
        }

    def mark_resolved(self):
        self.status = "resolved"

    def mark_unresolved(self):
        self.status = "unresolved"

    def attach_blockchain_hash(self, blockchain_hash):
        self.blockchain_hash = blockchain_hash


class NetworkLog(db.Model):
    __tablename__ = "network_log"

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False)
    dest_ip = db.Column(db.String(45), nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    port = db.Column(db.Integer, nullable=True)
    packet_size = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_suspicious = db.Column(db.Boolean, nullable=False, default=False)
    prediction = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return f"<NetworkLog id={self.id} source_ip={self.source_ip} dest_ip={self.dest_ip} suspicious={self.is_suspicious}>"

    def to_dict(self):
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "protocol": self.protocol,
            "port": self.port,
            "packet_size": self.packet_size,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "is_suspicious": self.is_suspicious,
            "prediction": self.prediction,
        }

    def flag_suspicious(self):
        self.is_suspicious = True

    def clear_suspicious(self):
        self.is_suspicious = False

    def set_prediction(self, prediction):
        self.prediction = prediction


class BlockchainRecord(db.Model):
    __tablename__ = "blockchain_record"

    id = db.Column(db.Integer, primary_key=True)
    block_index = db.Column(db.Integer, unique=True, nullable=False)
    block_hash = db.Column(db.String(128), unique=True, nullable=False)
    previous_hash = db.Column(db.String(128), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Integer, nullable=False, default=0)

    def __repr__(self):
        return f"<BlockchainRecord index={self.block_index} hash={self.block_hash[:12]}...>"

    def to_dict(self):
        return {
            "id": self.id,
            "block_index": self.block_index,
            "block_hash": self.block_hash,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "data": self.data,
            "nonce": self.nonce,
        }

    def compute_hash(self):
        payload = f"{self.block_index}{self.previous_hash}{self.timestamp.isoformat()}{self.data}{self.nonce}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def update_nonce(self, nonce):
        self.nonce = nonce
        self.block_hash = self.compute_hash()

    def set_data(self, data):
        self.data = data
        self.block_hash = self.compute_hash()


class Report(db.Model):
    __tablename__ = "report"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    generated_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    generated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    file_path = db.Column(db.String(255), nullable=False)
    report_type = db.Column(db.String(100), nullable=False)

    author = db.relationship("User", back_populates="reports")

    def __repr__(self):
        return f"<Report id={self.id} title={self.title} type={self.report_type}>"

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "generated_by": self.generated_by,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "file_path": self.file_path,
            "report_type": self.report_type,
        }

    def set_file_path(self, file_path):
        self.file_path = file_path

    def set_report_type(self, report_type):
        self.report_type = report_type

    def assign_author(self, user):
        self.author = user
        self.generated_by = user.id if user else None
