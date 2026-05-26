import os
from functools import wraps
from flask import jsonify, current_app
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from flask_login import LoginManager

try:
    from database.models import User
except ImportError:
    from ICIDS.database.models import User

login_manager = LoginManager()
jwt_manager = JWTManager()

# In-memory token blocklist for revoked JWTs.
# For production, replace this with a persistent store such as Redis or database table.
token_blocklist = set()


@login_manager.user_loader
def load_user(user_id):
    """Return a User instance for Flask-Login session management."""
    if not user_id:
        return None
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None


def init_auth(app):
    """Initialize Flask-Login and JWT extensions on the application."""
    login_manager.init_app(app)
    jwt_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"


@jwt_manager.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Check whether the current JWT is revoked."""
    jti = jwt_payload.get("jti")
    return jti in token_blocklist


@jwt_manager.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({"success": False, "message": "Token has been revoked."}), 401


@jwt_manager.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"success": False, "message": "Token has expired."}), 401


@jwt_manager.invalid_token_loader
def invalid_token_callback(error_string):
    return jsonify({"success": False, "message": "Invalid token."}), 401


@jwt_manager.unauthorized_loader
def missing_token_callback(error_string):
    return jsonify({"success": False, "message": "Authorization token is required."}), 401


def create_tokens(user):
    """Create a fresh access token and refresh token for the authenticated user."""
    claims = {
        "role": user.role,
        "username": user.username,
    }
    access_token = create_access_token(
        identity=user.id,
        additional_claims=claims,
        fresh=True,
    )
    refresh_token = create_refresh_token(identity=user.id)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


def refresh_access_token():
    """Issue a new access token using a valid refresh token."""
    verify_jwt_in_request(refresh=True)
    identity = get_jwt_identity()
    user = User.query.get(identity)
    if not user or not user.is_active:
        return jsonify({"success": False, "message": "User account is not active."}), 401

    claims = {
        "role": user.role,
        "username": user.username,
    }
    access_token = create_access_token(identity=user.id, additional_claims=claims, fresh=False)
    return jsonify({"success": True, "access_token": access_token}), 200


def revoke_token(jti):
    """Mark a JWT identifier as revoked."""
    if jti:
        token_blocklist.add(jti)
        return True
    return False


def revoke_current_token():
    """Revoke the currently active JWT."""
    jwt_data = get_jwt()
    jti = jwt_data.get("jti")
    return revoke_token(jti)


def token_required(fn):
    """Decorator that verifies a valid non-revoked access token."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        return fn(*args, **kwargs)

    return wrapper
