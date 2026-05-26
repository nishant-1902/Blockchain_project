from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt, verify_jwt_in_request


def role_check(required_roles):
    """Return a decorator that validates the current JWT role claim."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            user_role = claims.get("role", "")
            if user_role not in required_roles:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Insufficient privileges to access this resource.",
                        }
                    ),
                    403,
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator


admin_required = role_check(["admin"])
user_required = role_check(["user", "admin"])


def has_role(required_roles, current_role):
    """Helper to evaluate whether the provided role satisfies required roles."""
    return current_role in required_roles
