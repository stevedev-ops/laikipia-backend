import time
import hashlib
from django.core.cache import cache
from rest_framework import response, status

def get_client_ip(request):
    """Safely extracts client IP address, handling proxies and headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip

def check_rate_limit(request, key_prefix, max_requests, window_seconds, extra_key=""):
    """
    Sliding-window rate limiter backed by Django cache.
    Returns (is_allowed, remaining_requests, retry_after_seconds)
    """
    ip = get_client_ip(request)
    cache_key = f"rl:{key_prefix}:{ip}:{extra_key}"
    now = time.time()
    
    # Retrieve request timestamps from cache
    timestamps = cache.get(cache_key, [])
    # Filter timestamps within the current window
    valid_timestamps = [t for t in timestamps if now - t < window_seconds]
    
    if len(valid_timestamps) >= max_requests:
        oldest = valid_timestamps[0]
        retry_after = int(window_seconds - (now - oldest)) + 1
        return False, 0, max(1, retry_after)
    
    valid_timestamps.append(now)
    cache.set(cache_key, valid_timestamps, timeout=window_seconds + 5)
    remaining = max_requests - len(valid_timestamps)
    return True, remaining, 0

def rate_limit(key_prefix, max_requests=10, window_seconds=60, extra_key_func=None):
    """
    Decorator for DRF APIView methods (get, post) to enforce rate limits.
    """
    def decorator(view_func):
        def wrapped(self, request, *args, **kwargs):
            extra = ""
            if extra_key_func:
                try:
                    extra = extra_key_func(request)
                except Exception:
                    extra = ""
            
            allowed, remaining, retry_after = check_rate_limit(
                request, key_prefix, max_requests, window_seconds, extra
            )
            
            if not allowed:
                return response.Response({
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. Please wait {retry_after} seconds before trying again.",
                    "retry_after": retry_after
                }, status=status.HTTP_429_TOO_MANY_REQUESTS, headers={"Retry-After": str(retry_after)})
            
            res = view_func(self, request, *args, **kwargs)
            res["X-RateLimit-Limit"] = str(max_requests)
            res["X-RateLimit-Remaining"] = str(remaining)
            return res
        return wrapped
    return decorator

def check_honeypot(request, honeypot_fields=('website_url_trap', 'confirm_email_hp')):
    """
    Checks if any decoy bot trap field is filled in request data.
    Returns True if a bot filled the honeypot (request should be blocked).
    """
    data = request.data or {}
    for field in honeypot_fields:
        val = data.get(field)
        if val and str(val).strip():
            return True
    return False
