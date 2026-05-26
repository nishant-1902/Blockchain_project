"""
ICIDS - Helper Functions Module
Utility functions for common operations across the application
"""

import re
import hashlib
from datetime import datetime
from typing import Optional, Tuple, Any, List, Dict
from urllib.parse import quote
import requests
from flask import current_app


def format_datetime(dt: Optional[datetime]) -> str:
    """
    Format datetime object to readable string
    
    Args:
        dt: Datetime object
    
    Returns:
        Formatted datetime string (YYYY-MM-DD HH:MM:SS)
    """
    if not dt:
        return '-'
    
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def format_date(dt: Optional[datetime]) -> str:
    """
    Format datetime to date string only
    
    Args:
        dt: Datetime object
    
    Returns:
        Formatted date string (YYYY-MM-DD)
    """
    if not dt:
        return '-'
    
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    
    return dt.strftime('%Y-%m-%d')


def format_time(dt: Optional[datetime]) -> str:
    """
    Format datetime to time string only
    
    Args:
        dt: Datetime object
    
    Returns:
        Formatted time string (HH:MM:SS)
    """
    if not dt:
        return '-'
    
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    
    return dt.strftime('%H:%M:%S')


def paginate_query(query, page: int = 1, per_page: int = 20) -> Tuple[List, Dict]:
    """
    Paginate a SQLAlchemy query
    
    Args:
        query: SQLAlchemy query object
        page: Page number (1-indexed)
        per_page: Items per page
    
    Returns:
        Tuple of (items, pagination_info)
        - items: List of query results for current page
        - pagination_info: Dictionary with pagination metadata
    """
    if page < 1:
        page = 1
    
    offset = (page - 1) * per_page
    
    total_count = query.count()
    total_pages = (total_count + per_page - 1) // per_page
    
    items = query.offset(offset).limit(per_page).all()
    
    pagination_info = {
        'page': page,
        'per_page': per_page,
        'total': total_count,
        'pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
        'prev_page': page - 1 if page > 1 else None,
        'next_page': page + 1 if page < total_pages else None
    }
    
    return items, pagination_info


def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """
    Get geolocation data for an IP address
    Note: Returns dummy data for now. Integrate with real GeoIP service as needed.
    
    Args:
        ip: IP address string
    
    Returns:
        Dictionary with location information
    """
    # Dummy geolocation data - replace with real API call
    dummy_locations = {
        '192.168.1.1': {'country': 'United States', 'city': 'New York', 'lat': 40.7128, 'lon': -74.0060},
        '10.0.0.1': {'country': 'United States', 'city': 'San Francisco', 'lat': 37.7749, 'lon': -122.4194},
        '172.16.0.1': {'country': 'United Kingdom', 'city': 'London', 'lat': 51.5074, 'lon': -0.1278},
    }
    
    if ip in dummy_locations:
        return dummy_locations[ip]
    
    # For real implementation, use GeoIP2 or similar service
    try:
        # Example with free service (remove in production)
        response = requests.get(
            f'https://ipapi.co/{quote(ip)}/json/',
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'lat': float(data.get('latitude', 0)),
                'lon': float(data.get('longitude', 0)),
                'isp': data.get('org', 'Unknown')
            }
    except Exception as e:
        current_app.logger.warning(f"Error fetching geolocation for {ip}: {str(e)}")
    
    # Default fallback
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'lat': 0,
        'lon': 0,
        'isp': 'Unknown'
    }


def calculate_threat_score(alert: Dict[str, Any]) -> int:
    """
    Calculate threat score for an alert (0-100)
    
    Args:
        alert: Alert dictionary with severity, type, etc.
    
    Returns:
        Threat score 0-100
    """
    score = 0
    
    # Base score by severity
    severity = alert.get('severity', 'Low')
    severity_scores = {
        'Critical': 100,
        'High': 75,
        'Medium': 50,
        'Low': 25
    }
    score = severity_scores.get(severity, 25)
    
    # Adjust by status
    if alert.get('status') == 'Open':
        score += 10
    elif alert.get('status') == 'Acknowledged':
        score += 5
    
    # Adjust by alert type
    high_risk_types = [
        'DDoS', 'SQL Injection', 'Malware', 'Privilege Escalation',
        'Brute Force', 'RCE', 'Zero-Day', 'Ransomware'
    ]
    if alert.get('type') in high_risk_types:
        score += 10
    
    # Adjust by recurrence (if available)
    recurrence = alert.get('recurrence_count', 0)
    if recurrence > 5:
        score += 15
    elif recurrence > 3:
        score += 10
    elif recurrence > 1:
        score += 5
    
    # Cap at 100
    return min(score, 100)


def sanitize_input(text: Optional[str], max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent XSS attacks
    Basic HTML/script tag removal
    
    Args:
        text: Input text to sanitize
        max_length: Maximum length of output
    
    Returns:
        Sanitized text
    """
    if not text:
        return ''
    
    # Convert to string if not already
    text = str(text)
    
    # Remove script tags and content
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    
    # Remove event handlers
    text = re.sub(r'\s*on\w+\s*=\s*["\']?[^"\'\s>]*["\']?', '', text, flags=re.IGNORECASE)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Decode HTML entities
    import html
    text = html.unescape(text)
    
    # Strip whitespace
    text = text.strip()
    
    # Limit length
    if len(text) > max_length:
        text = text[:max_length]
    
    return text


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash password using SHA-256 with salt
    Note: Use werkzeug.security.generate_password_hash in production
    
    Args:
        password: Password to hash
        salt: Optional salt (generates new if not provided)
    
    Returns:
        Tuple of (hashed_password, salt)
    """
    import secrets
    
    if not salt:
        salt = secrets.token_hex(16)
    
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed, salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """
    Verify password against hash
    
    Args:
        password: Password to verify
        hashed: Hashed password
        salt: Salt used in hashing
    
    Returns:
        True if password matches, False otherwise
    """
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == hashed


def get_client_ip(request) -> str:
    """
    Get client IP address from request
    Handles X-Forwarded-For header for proxied requests
    
    Args:
        request: Flask request object
    
    Returns:
        Client IP address string
    """
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ.get('HTTP_X_FORWARDED_FOR').split(',')[0]
    
    return request.environ.get('REMOTE_ADDR', 'Unknown')


def bytes_to_human_readable(bytes_count: int) -> str:
    """
    Convert bytes to human-readable format
    
    Args:
        bytes_count: Number of bytes
    
    Returns:
        Human-readable string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    
    return f"{bytes_count:.2f} PB"


def calculate_percentage(part: int, total: int, decimals: int = 2) -> float:
    """
    Calculate percentage
    
    Args:
        part: Part value
        total: Total value
        decimals: Decimal places
    
    Returns:
        Percentage value
    """
    if total == 0:
        return 0.0
    
    return round((part / total) * 100, decimals)


def get_time_difference_string(from_dt: datetime, to_dt: Optional[datetime] = None) -> str:
    """
    Get human-readable time difference
    
    Args:
        from_dt: Start datetime
        to_dt: End datetime (defaults to now)
    
    Returns:
        Human-readable time difference string
    """
    if not to_dt:
        to_dt = datetime.now()
    
    diff = to_dt - from_dt
    
    if diff.days > 365:
        return f"{diff.days // 365} year(s) ago"
    elif diff.days > 30:
        return f"{diff.days // 30} month(s) ago"
    elif diff.days > 0:
        return f"{diff.days} day(s) ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600} hour(s) ago"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60} minute(s) ago"
    else:
        return f"{diff.seconds} second(s) ago"


def generate_unique_id(prefix: str = '') -> str:
    """
    Generate unique ID
    
    Args:
        prefix: Optional prefix for ID
    
    Returns:
        Unique ID string
    """
    import secrets
    import time
    
    timestamp = int(time.time() * 1000)
    random_part = secrets.token_hex(4)
    unique_id = f"{prefix}{timestamp}{random_part}"
    
    return unique_id


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """
    Split list into chunks
    
    Args:
        lst: List to chunk
        chunk_size: Size of each chunk
    
    Returns:
        List of chunks
    """
    chunks = []
    for i in range(0, len(lst), chunk_size):
        chunks.append(lst[i:i + chunk_size])
    return chunks


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
    """
    Flatten nested dictionary
    
    Args:
        d: Dictionary to flatten
        parent_key: Parent key prefix
        sep: Separator between keys
    
    Returns:
        Flattened dictionary
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def merge_dicts(*dicts: Dict) -> Dict:
    """
    Merge multiple dictionaries
    
    Args:
        *dicts: Variable number of dictionaries
    
    Returns:
        Merged dictionary
    """
    result = {}
    for d in dicts:
        if isinstance(d, dict):
            result.update(d)
    return result
