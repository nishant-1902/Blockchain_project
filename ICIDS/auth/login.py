from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_bcrypt import Bcrypt
from flask_login import login_user

try:
    from database.models import db, User
except ImportError:
    from ICIDS.database.models import db, User

try:
    from auth.jwt_auth import create_tokens
except ImportError:
    from ICIDS.auth.jwt_auth import create_tokens

login_bp = Blueprint("login_bp", __name__, url_prefix="/api/auth")
bcrypt = Bcrypt()


@login_bp.route("/login", methods=["POST"])
def login():
    """Authenticate a user and return access/refresh JWT tokens."""
    payload = request.get_json(silent=True) or {}
    identifier = payload.get("identifier", "").strip()
    password = payload.get("password", "")

    if not identifier or not password:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Username/email and password are required.",
                }
            ),
            400,
        )

    user = User.query.filter_by(email=identifier.lower()).first()
    if not user:
        user = User.query.filter_by(username=identifier).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return (
            jsonify({"success": False, "message": "Invalid credentials."}),
            401,
        )

    if not user.is_active:
        return (
            jsonify({"success": False, "message": "User account is not active."}),
            403,
        )

    user.last_login = datetime.utcnow()
    db.session.commit()

    login_user(user)
    tokens = create_tokens(user)

    return (
        jsonify(
            {
                "success": True,
                "message": "Login successful.",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "user": user.to_dict(),
            }
        ),
        200,
    )


@login_bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh the access token using a valid refresh token."""
    return create_tokens_from_refresh()


def create_tokens_from_refresh():
    """Helper to generate a fresh access token from a refresh token."""
    from flask_jwt_extended import jwt_required, get_jwt_identity

    @jwt_required(refresh=True)
    def _refresh():
        identity = get_jwt_identity()
        user = User.query.get(identity)
        if not user or not user.is_active:
            return (
                jsonify({"success": False, "message": "Invalid refresh token or inactive user."}),
                401,
            )

        tokens = create_tokens(user)
        return (
            jsonify(
                {
                    "success": True,
                    "access_token": tokens["access_token"],
                }
            ),
            200,
        )

    return _refresh()
