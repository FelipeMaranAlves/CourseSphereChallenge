import html
import re
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple
from flask import Response, jsonify, request

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
SAFE_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CONTROL_CHARS_REGEX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter by client IP and route bucket.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: Dict[str, deque] = defaultdict(deque)

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()

    def check(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int, int]:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._requests[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(window_seconds - (now - bucket[0])))
                return False, 0, retry_after
            bucket.append(now)
            remaining = max(0, limit - len(bucket))
            return True, remaining, window_seconds


rate_limiter = SlidingWindowRateLimiter()


def get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def rate_limit(limit: int = 30, window_seconds: int = 60):
    """
    Decorator that enforces a per-IP sliding window rate limit on a Flask route.
    """

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            client_ip = get_client_ip()
            bucket_key = f"{f.__name__}:{client_ip}"
            allowed, remaining, reset_sec = rate_limiter.check(
                bucket_key, limit, window_seconds
            )
            if not allowed:
                resp = jsonify(
                    {
                        "error": "Too many requests. Please try again later.",
                        "retry_after_seconds": reset_sec,
                    }
                )
                resp.status_code = 429
                resp.headers["Retry-After"] = str(reset_sec)
                resp.headers["X-RateLimit-Limit"] = str(limit)
                resp.headers["X-RateLimit-Remaining"] = "0"
                return resp

            result = f(*args, **kwargs)
            if isinstance(result, tuple):
                response_obj, status_code = result[0], result[1]
                if isinstance(response_obj, Response):
                    response_obj.headers["X-RateLimit-Limit"] = str(limit)
                    response_obj.headers["X-RateLimit-Remaining"] = str(remaining)
                return response_obj, status_code
            if isinstance(result, Response):
                result.headers["X-RateLimit-Limit"] = str(limit)
                result.headers["X-RateLimit-Remaining"] = str(remaining)
            return result

        return wrapped

    return decorator


def apply_security_headers(response: Response) -> Response:
    """
    Applies defense-in-depth HTTP security headers to every API response.
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def sanitize_text(value: Any, max_length: int = 500) -> str:
    """
    Strips control characters, escapes HTML entities, and enforces max length.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("Expected a string value")
    cleaned = CONTROL_CHARS_REGEX.sub("", value).strip()
    if len(cleaned) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length} characters")
    return html.escape(cleaned, quote=True)


def sanitize_string_list(
    values: Any, max_items: int = 25, max_item_length: int = 100
) -> List[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError("Expected a list of strings")
    if len(values) > max_items:
        raise ValueError(f"List exceeds maximum of {max_items} items")
    return [sanitize_text(item, max_length=max_item_length) for item in values]


def validate_email_and_password(
    email: Any, password: Any
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not isinstance(email, str) or not email.strip():
        return None, None, "Email is required"
    clean_email = email.strip()
    if len(clean_email) > 254 or not EMAIL_REGEX.match(clean_email):
        return None, None, "Invalid email format"
    if not isinstance(password, str) or not password:
        return None, None, "Password is required"
    if len(password) < 8 or len(password) > 128:
        return None, None, "Password must be between 8 and 128 characters"
    return clean_email, password, None


def validate_safe_identifier(identifier: str) -> bool:
    """
    Prevents Firebase Realtime Database path injection / traversal in resource IDs.
    """
    return bool(
        isinstance(identifier, str) and SAFE_ID_REGEX.match(identifier)
    )

