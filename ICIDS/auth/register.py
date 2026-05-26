import re
from flask import Blueprint, jsonify, request
from flask_bcrypt import Bcrypt

try:
    from database.models import db, User
except ImportError:
    from ICIDS.database.models import db, User

register_bp = Blueprint("register_bp", __name__, url_prefix="/api/auth")
bcrypt = Bcrypt()

EMAIL_PATTERN = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{4,30}$")
PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':\",.<>/?]).{12,}$")


def validate_email(email):
    return bool(EMAIL_PATTERN.match(email))


def validate_username(username):
    return bool(USERNAME_PATTERN.match(username))


def validate_password(password):
    return bool(PASSWORD_PATTERN.match(password))


@register_bp.route("/register", methods=["POST"])
def register():
    """Register a new user with secured password hashing and basic validation."""
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "").strip()
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")

    errors = []
    if not username:
        errors.append("Username is required.")
    elif not validate_username(username):
        errors.append(
            "Username must be 4-30 characters and contain only letters, numbers, or underscores."
        )

    if not email:
        errors.append("Email is required.")
    elif not validate_email(email):
        errors.append("Email address is not valid.")

    if not password:
        errors.append("Password is required.")
    elif not validate_password(password):
        errors.append(
            "Password must be at least 12 characters and include uppercase, lowercase, digit, and special character."
        )

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "errors": ["Username is already registered."]}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "errors": ["Email is already registered."]}), 400

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(username=username, email=email, password_hash=password_hash, role="user")

    db.session.add(user)
    db.session.commit()

    return (
        jsonify(
            {
                "success": True,
                "message": "User registered successfully.",
                "user": user.to_dict(),
            }
        ),
        201,
    )
