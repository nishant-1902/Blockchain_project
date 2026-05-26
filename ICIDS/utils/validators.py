"""
ICIDS - Input Validators Module
Validation functions for user inputs and data integrity
"""

import re
from typing import Optional, List, Tuple, Any, Dict


def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Validate email address format
    
    Args:
        email: Email address to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"
    
    email = email.strip().lower()
    
    # Check length
    if len(email) > 254:
        return False, "Email is too long (max 254 characters)"
    
    # RFC 5322 simplified email regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(pattern, email):
        return False, "Invalid email format"
    
    return True, None


def validate_password(password: str, min_length: int = 8) -> Tuple[bool, Optional[str]]:
    """
    Validate password strength
    
    Requirements:
    - Minimum length (default 8 characters)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character (!@#$%^&*)
    
    Args:
        password: Password to validate
        min_length: Minimum password length
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    # Check length
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long"
    
    if len(password) > 128:
        return False, "Password is too long (max 128 characters)"
    
    # Check for uppercase
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    # Check for lowercase
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    # Check for digit
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    # Check for special characters
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?]', password):
        return False, "Password must contain at least one special character (!@#$%^&*)"
    
    return True, None


def validate_username(username: str) -> Tuple[bool, Optional[str]]:
    """
    Validate username format
    
    Requirements:
    - 3-20 characters
    - Alphanumeric and underscore only
    - Cannot start with number
    
    Args:
        username: Username to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    username = username.strip()
    
    # Check length
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(username) > 20:
        return False, "Username must not exceed 20 characters"
    
    # Check format
    pattern = r'^[a-zA-Z][a-zA-Z0-9_]*$'
    if not re.match(pattern, username):
        return False, "Username must start with a letter and contain only letters, numbers, and underscores"
    
    return True, None


def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
    """
    Validate IPv4 address format
    
    Args:
        ip: IP address to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip:
        return False, "IP address is required"
    
    ip = ip.strip()
    
    # IPv4 format check
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False, "Invalid IP address format"
    
    # Check octets range
    octets = ip.split('.')
    for octet in octets:
        try:
            num = int(octet)
            if num < 0 or num > 255:
                return False, "Each octet must be between 0 and 255"
        except ValueError:
            return False, "IP address must contain only digits and dots"
    
    return True, None


def validate_port(port: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate port number
    
    Args:
        port: Port number to validate (int or str)
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        return False, "Port must be a number"
    
    if port_num < 0:
        return False, "Port cannot be negative"
    
    if port_num > 65535:
        return False, "Port must be between 0 and 65535"
    
    return True, None


def validate_required_fields(
    data: Dict[str, Any],
    fields: List[str]
) -> Tuple[bool, Optional[str]]:
    """
    Validate that required fields are present and not empty
    
    Args:
        data: Dictionary of data to validate
        fields: List of required field names
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    
    missing_fields = []
    empty_fields = []
    
    for field in fields:
        if field not in data:
            missing_fields.append(field)
        elif not data[field]:
            empty_fields.append(field)
    
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    if empty_fields:
        return False, f"Empty required fields: {', '.join(empty_fields)}"
    
    return True, None


def validate_json(data: str) -> Tuple[bool, Optional[str], Optional[Any]]:
    """
    Validate JSON string format
    
    Args:
        data: JSON string to validate
    
    Returns:
        Tuple of (is_valid, error_message, parsed_data)
    """
    import json
    
    if not data:
        return False, "JSON data is required", None
    
    try:
        parsed = json.loads(data)
        return True, None, parsed
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON format: {str(e)}", None


def validate_date_format(date_str: str, format: str = '%Y-%m-%d') -> Tuple[bool, Optional[str]]:
    """
    Validate date string format
    
    Args:
        date_str: Date string to validate
        format: Expected date format
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not date_str:
        return False, "Date is required"
    
    try:
        from datetime import datetime
        datetime.strptime(date_str, format)
        return True, None
    except ValueError as e:
        return False, f"Invalid date format. Expected {format}: {str(e)}"


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate URL format
    
    Args:
        url: URL to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, "URL is required"
    
    url = url.strip()
    
    # URL regex pattern
    pattern = r'^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&/=]*)$'
    
    if not re.match(pattern, url):
        return False, "Invalid URL format"
    
    return True, None


def validate_severity(severity: str) -> Tuple[bool, Optional[str]]:
    """
    Validate alert severity level
    
    Args:
        severity: Severity level to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_severities = ['Critical', 'High', 'Medium', 'Low']
    
    if not severity:
        return False, "Severity is required"
    
    if severity not in valid_severities:
        return False, f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
    
    return True, None


def validate_alert_type(alert_type: str) -> Tuple[bool, Optional[str]]:
    """
    Validate alert type
    
    Args:
        alert_type: Alert type to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_types = [
        'DDoS', 'Port Scan', 'Brute Force', 'SQL Injection',
        'Malware', 'Privilege Escalation', 'RCE', 'Ransomware',
        'XSS', 'CSRF', 'Zero-Day', 'Anomaly'
    ]
    
    if not alert_type:
        return False, "Alert type is required"
    
    if alert_type not in valid_types:
        return False, f"Invalid alert type. Must be one of: {', '.join(valid_types)}"
    
    return True, None


def validate_status(status: str) -> Tuple[bool, Optional[str]]:
    """
    Validate alert status
    
    Args:
        status: Status to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_statuses = ['Open', 'Acknowledged', 'Resolved', 'Dismissed']
    
    if not status:
        return False, "Status is required"
    
    if status not in valid_statuses:
        return False, f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
    
    return True, None


def validate_pagination_params(
    page: Any,
    per_page: Any,
    max_per_page: int = 100
) -> Tuple[bool, Optional[str], Optional[Tuple[int, int]]]:
    """
    Validate pagination parameters
    
    Args:
        page: Page number
        per_page: Items per page
        max_per_page: Maximum items per page allowed
    
    Returns:
        Tuple of (is_valid, error_message, (page, per_page))
    """
    try:
        page = int(page) if page else 1
        per_page = int(per_page) if per_page else 20
    except (ValueError, TypeError):
        return False, "Page and per_page must be integers", None
    
    if page < 1:
        return False, "Page must be at least 1", None
    
    if per_page < 1:
        return False, "per_page must be at least 1", None
    
    if per_page > max_per_page:
        return False, f"per_page cannot exceed {max_per_page}", None
    
    return True, None, (page, per_page)


def validate_search_query(query: str, min_length: int = 1, max_length: int = 100) -> Tuple[bool, Optional[str]]:
    """
    Validate search query
    
    Args:
        query: Search query string
        min_length: Minimum query length
        max_length: Maximum query length
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not query:
        return False, "Search query is required"
    
    query = query.strip()
    
    if len(query) < min_length:
        return False, f"Search query must be at least {min_length} character(s)"
    
    if len(query) > max_length:
        return False, f"Search query must not exceed {max_length} characters"
    
    # Check for SQL injection patterns
    dangerous_patterns = [
        r"(\sunion\s|\sunion\sall\s)", 
        r"(\sdrop\s|\sdelete\s)",
        r"(;|\-\-|/\*|\*/)"
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return False, "Search query contains invalid characters or patterns"
    
    return True, None


def validate_api_key(api_key: str) -> Tuple[bool, Optional[str]]:
    """
    Validate API key format
    
    Args:
        api_key: API key to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not api_key:
        return False, "API key is required"
    
    if len(api_key) < 32:
        return False, "API key must be at least 32 characters"
    
    if len(api_key) > 256:
        return False, "API key is too long"
    
    # API keys should be alphanumeric with optional dashes/underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', api_key):
        return False, "API key contains invalid characters"
    
    return True, None


def validate_cron_expression(expression: str) -> Tuple[bool, Optional[str]]:
    """
    Basic validation of cron expression format
    
    Args:
        expression: Cron expression string
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not expression:
        return False, "Cron expression is required"
    
    parts = expression.split()
    
    if len(parts) != 5:
        return False, "Cron expression must have 5 parts (minute hour day month dayofweek)"
    
    return True, None
