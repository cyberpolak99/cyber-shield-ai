"""
security.py – Unified Auth + Rate Limiting for Threat Intelligence API

Auth logic (in priority order):
  1. If X-RapidAPI-Proxy-Secret header matches env RAPIDAPI_PROXY_SECRET → accepted as RapidAPI request.
     Client identity for rate limiting = X-RapidAPI-User header (or remote_addr fallback).
  2. If X-API-Key header matches ALLOWED_API_KEYS → accepted as direct request.
     Client identity for rate limiting = X-API-Key value.
  3. Otherwise → 401 Unauthorized.

Public endpoints (no auth needed): GET /, GET /api/health
All other endpoints: require auth + rate limiting via @protected decorator.
"""
import os
import time
import logging
from functools import wraps
from collections import defaultdict
from threading import Lock
from flask import request, jsonify

logger = logging.getLogger("ThreatAPI.Security")

# ─── Configuration (loaded once at startup, re-reads env) ─────────────────────

def _load_api_keys() -> set:
    """Load API keys from environment variable or fallback to test keys."""
    env_val = os.environ.get("THREAT_API_KEYS", "")
    if env_val:
        keys = {k.strip() for k in env_val.split(",") if k.strip()}
        logger.info(f"[Security] Loaded {len(keys)} API key(s) from env.")
        return keys
    # ⚠️ FALLBACK – TEST KEYS ONLY. Set THREAT_API_KEYS in production!
    fallback = {"test-key-1", "test-key-2", "cybershield-dev"}
    logger.warning("[Security] THREAT_API_KEYS not set – using fallback test keys!")
    return fallback


def _load_rate_limit() -> int:
    try:
        return int(os.environ.get("REQUESTS_PER_MINUTE", "60"))
    except ValueError:
        return 60


def _load_rapidapi_secret() -> str:
    """
    Returns expected RapidAPI proxy secret, or empty string if not configured.
    Empty string = RapidAPI enforcement disabled (dev mode).
    """
    secret = os.environ.get("RAPIDAPI_PROXY_SECRET", "").strip()
    if not secret:
        logger.warning("[Security] RAPIDAPI_PROXY_SECRET not set – RapidAPI enforcement disabled (dev mode).")
    return secret


ALLOWED_API_KEYS: set = _load_api_keys()
REQUESTS_PER_MINUTE: int = _load_rate_limit()
RAPIDAPI_SECRET: str = _load_rapidapi_secret()
WINDOW_SECONDS: int = 60

# ─── Rate Limit Storage (in-memory, single process) ───────────────────────────

_rate_store: dict = defaultdict(list)
_rate_lock = Lock()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _mask(val: str) -> str:
    """Safe log-friendly representation (last 4 chars)."""
    from collections import deque
    import itertools
    if not val or len(val) < 4:
        return "****"
    # Use deque(maxlen=4) to get last 4 chars without slice (avoids Pyre2 false positives)
    d: deque = deque(maxlen=4)
    for c in val:
        d.append(c)
    return "***" + "".join(d)


def _get_client_identity() -> str:
    """
    Determines a stable identifier for rate limiting:
    - RapidAPI request: use X-RapidAPI-User (stable per subscriber)
    - Direct request: use X-API-Key value
    - Fallback: remote_addr
    """
    rapid_user = request.headers.get("X-RapidAPI-User", "").strip()
    if rapid_user:
        return f"rapidapi:{rapid_user}"

    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        return f"apikey:{api_key}"

    return f"ip:{request.remote_addr}"


def _is_valid_rapidapi_request() -> bool:
    """Returns True if request carries a valid RapidAPI proxy secret."""
    if not RAPIDAPI_SECRET:
        return False  # RapidAPI enforcement not configured
    return request.headers.get("X-RapidAPI-Proxy-Secret", "").strip() == RAPIDAPI_SECRET


def _is_valid_api_key_request() -> bool:
    """Returns True if request carries a valid direct API key."""
    key = request.headers.get("X-API-Key", "").strip()
    return key in ALLOWED_API_KEYS


def _check_rate_limit(identity: str) -> tuple:
    """
    Sliding window rate check.
    Returns (allowed: bool, retry_after_seconds: int).
    """
    now = time.time()
    cutoff = now - WINDOW_SECONDS

    with _rate_lock:
        _rate_store[identity] = [t for t in _rate_store[identity] if t > cutoff]

        if len(_rate_store[identity]) >= REQUESTS_PER_MINUTE:
            oldest = _rate_store[identity][0]
            retry_after = int(WINDOW_SECONDS - (now - oldest)) + 1
            return False, retry_after

        _rate_store[identity].append(now)
        return True, 0


# ─── Main decorator ───────────────────────────────────────────────────────────

def protected(f):
    """
    Single decorator combining:
      1. Auth: X-RapidAPI-Proxy-Secret OR X-API-Key must be valid.
      2. Rate limiting: per client identity (sliding window).

    Usage:
        @app.route('/api/check/<ip>')
        @protected
        def check_ip(ip): ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # ── Step 1: Authentication ──────────────────────────────────────────
        via_rapidapi = _is_valid_rapidapi_request()
        via_api_key  = _is_valid_api_key_request()

        if not via_rapidapi and not via_api_key:
            # Log which header was attempted (masked)
            attempted_key  = request.headers.get("X-API-Key", "")
            attempted_rapid = request.headers.get("X-RapidAPI-Proxy-Secret", "")
            logger.warning(
                f"[Auth] 401 from {request.remote_addr} | "
                f"X-API-Key={_mask(attempted_key)} | "
                f"X-RapidAPI={_mask(attempted_rapid)}"
            )
            return jsonify({"error": "Invalid or missing API key"}), 401

        source = "RapidAPI" if via_rapidapi else "Direct"
        identity = _get_client_identity()
        logger.debug(f"[Auth] OK ({source}) identity={_mask(identity)} from {request.remote_addr}")

        # ── Step 2: Rate Limiting ───────────────────────────────────────────
        allowed, retry_after = _check_rate_limit(identity)
        if not allowed:
            logger.warning(
                f"[RateLimit] 429 identity={_mask(identity)} | retry_after={retry_after}s"
            )
            return jsonify({
                "error": "Rate limit exceeded",
                "retry_after_seconds": retry_after
            }), 429

        return f(*args, **kwargs)
    return decorated


# ─── Backward Compatibility aliases ───────────────────────────────────────────
# These allow old-style @require_api_key + @rate_limited to still work,
# but @protected is the preferred single-decorator approach.
require_api_key = protected
rate_limited = lambda f: f   # no-op: rate limiting is now inside @protected
