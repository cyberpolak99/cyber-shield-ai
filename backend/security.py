"""
security.py – API Key Authentication + Rate Limiting
Usage in threat_api.py:
    from security import require_api_key, rate_limited
    
    @app.route('/api/check/<ip>')
    @require_api_key
    @rate_limited
    def check_ip(ip): ...
"""
import os
import time
import logging
from functools import wraps
from collections import defaultdict
from threading import Lock
from flask import request, jsonify

logger = logging.getLogger("ThreatAPI.Security")

# ─── Configuration ────────────────────────────────────────────────────────────

def _load_api_keys() -> set:
    """Load API keys from environment variable or fallback to test keys."""
    env_val = os.environ.get("THREAT_API_KEYS", "")
    if env_val:
        keys = {k.strip() for k in env_val.split(",") if k.strip()}
        logger.info(f"Loaded {len(keys)} API key(s) from environment.")
        return keys
    
    # ⚠️ FALLBACK – TEST KEYS ONLY. Replace via env in production!
    fallback = {"test-key-1", "test-key-2", "cybershield-dev"}
    logger.warning("THREAT_API_KEYS not set. Using fallback test keys!")
    return fallback


def _load_rate_limit() -> int:
    """Load max requests per minute from env."""
    try:
        return int(os.environ.get("REQUESTS_PER_MINUTE", "60"))
    except ValueError:
        return 60


ALLOWED_API_KEYS: set = _load_api_keys()
REQUESTS_PER_MINUTE: int = _load_rate_limit()
WINDOW_SECONDS: int = 60

# ─── Rate Limit Storage (in-memory, single process) ───────────────────────────

_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = Lock()


def _mask_key(api_key: str) -> str:
    """Returns a masked key for safe logging (last 4 chars only)."""
    if not api_key or len(api_key) < 4:
        return "****"
    suffix = api_key[len(api_key)-4:]
    return f"***{suffix}"


def _check_rate_limit(api_key: str) -> tuple[bool, int]:
    """
    Returns (is_allowed: bool, retry_after_seconds: int).
    Uses a sliding window algorithm.
    """
    now = time.time()
    cutoff = now - WINDOW_SECONDS

    with _rate_lock:
        # Evict timestamps outside the current window
        _rate_store[api_key] = [t for t in _rate_store[api_key] if t > cutoff]

        if len(_rate_store[api_key]) >= REQUESTS_PER_MINUTE:
            oldest = _rate_store[api_key][0]
            retry_after = int(WINDOW_SECONDS - (now - oldest)) + 1
            return False, retry_after

        _rate_store[api_key].append(now)
        return True, 0


# ─── Decorators ───────────────────────────────────────────────────────────────

def require_api_key(f):
    """Decorator: validate X-API-Key header against ALLOWED_API_KEYS."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key", "").strip()

        if not api_key or api_key not in ALLOWED_API_KEYS:
            logger.warning(
                f"Unauthorized request from {request.remote_addr} "
                f"with key: {_mask_key(api_key)}"
            )
            return jsonify({"error": "Invalid or missing API key"}), 401

        logger.debug(f"Auth OK for key ...{_mask_key(api_key)} from {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated


def rate_limited(f):
    """Decorator: enforce per-API-key rate limit (sliding window)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key", "").strip()
        allowed, retry_after = _check_rate_limit(api_key)

        if not allowed:
            logger.warning(
                f"Rate limit exceeded for key {_mask_key(api_key)} "
                f"from {request.remote_addr}. Retry after: {retry_after}s"
            )
            return jsonify({
                "error": "Rate limit exceeded",
                "retry_after_seconds": retry_after
            }), 429

        return f(*args, **kwargs)
    return decorated
