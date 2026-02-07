"""
Rate Limiter for AI Agent Tools.

Prevents agents from making too many calls in a time window.
Useful for:
- API rate limiting
- Cost control for LLM calls
- Database query throttling
- Preventing runaway agent loops

Example:
    >>> from warden.core.rate_limiter import RateLimiter, check_rate_limit
    >>>
    >>> # Quick check
    >>> if check_rate_limit("my-tool", max_calls=10, window_seconds=60):
    ...     execute_tool()
    >>>
    >>> # Full rate limiter
    >>> limiter = RateLimiter(max_calls=100, window_seconds=60)
    >>> result = limiter.check("api-call")
    >>> if result.allowed:
    ...     make_api_call()
    ... else:
    ...     print(f"Rate limited. Retry after {result.retry_after_seconds}s")
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RateLimitMode(Enum):
    """Rate limiting modes."""

    STRICT = "strict"  # Block when limit exceeded
    MONITOR = "monitor"  # Log but don't block


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    """Whether the request is allowed."""

    current_count: int
    """Current number of calls in the window."""

    max_calls: int
    """Maximum calls allowed in the window."""

    window_seconds: float
    """Time window in seconds."""

    remaining: int
    """Remaining calls allowed in this window."""

    retry_after_seconds: float | None = None
    """Seconds until the next call would be allowed (if rate limited)."""

    key: str = ""
    """The key that was rate limited."""

    def __bool__(self) -> bool:
        """Return True if allowed."""
        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/serialization."""
        return {
            "allowed": self.allowed,
            "current_count": self.current_count,
            "max_calls": self.max_calls,
            "window_seconds": self.window_seconds,
            "remaining": self.remaining,
            "retry_after_seconds": self.retry_after_seconds,
            "key": self.key,
        }


@dataclass
class RateLimitBucket:
    """A single rate limit bucket using sliding window counter."""

    timestamps: list[float] = field(default_factory=list)
    """Timestamps of calls in this bucket."""

    def add(self, timestamp: float) -> None:
        """Add a call timestamp."""
        self.timestamps.append(timestamp)

    def count_in_window(self, now: float, window_seconds: float) -> int:
        """Count calls within the time window."""
        cutoff = now - window_seconds
        # Clean up old timestamps
        self.timestamps = [ts for ts in self.timestamps if ts > cutoff]
        return len(self.timestamps)

    def oldest_in_window(self, now: float, window_seconds: float) -> float | None:
        """Get the oldest timestamp in the window."""
        cutoff = now - window_seconds
        valid = [ts for ts in self.timestamps if ts > cutoff]
        return min(valid) if valid else None


class RateLimiter:
    """
    Rate limiter using sliding window counter algorithm.

    Thread-safe implementation that tracks calls per key within a time window.

    Example:
        >>> limiter = RateLimiter(max_calls=10, window_seconds=60)
        >>>
        >>> # Check and record a call
        >>> result = limiter.check("user-123")
        >>> if result.allowed:
        ...     process_request()
        >>>
        >>> # Check without recording
        >>> result = limiter.peek("user-123")
        >>> print(f"Remaining: {result.remaining}")

    Attributes:
        max_calls: Maximum calls allowed per key in the window.
        window_seconds: Time window in seconds.
        mode: STRICT to block, MONITOR to log only.
    """

    def __init__(
        self,
        max_calls: int = 100,
        window_seconds: float = 60.0,
        mode: RateLimitMode | str = RateLimitMode.STRICT,
    ) -> None:
        """
        Initialize the rate limiter.

        Args:
            max_calls: Maximum calls allowed per key in the window.
            window_seconds: Time window in seconds.
            mode: STRICT to block, MONITOR to log only.
        """
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.mode = RateLimitMode(mode) if isinstance(mode, str) else mode

        self._buckets: dict[str, RateLimitBucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str = "default") -> RateLimitResult:
        """
        Check if a call is allowed and record it.

        Args:
            key: Identifier for rate limiting (e.g., user ID, tool name).

        Returns:
            RateLimitResult with allowed status and metadata.
        """
        now = time.time()

        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = RateLimitBucket()

            bucket = self._buckets[key]
            current_count = bucket.count_in_window(now, self.window_seconds)

            # Check if allowed
            if current_count < self.max_calls:
                # Record the call
                bucket.add(now)
                return RateLimitResult(
                    allowed=True,
                    current_count=current_count + 1,
                    max_calls=self.max_calls,
                    window_seconds=self.window_seconds,
                    remaining=self.max_calls - current_count - 1,
                    key=key,
                )
            else:
                # Rate limited
                oldest = bucket.oldest_in_window(now, self.window_seconds)
                retry_after = (
                    (oldest + self.window_seconds - now) if oldest else self.window_seconds
                )

                # In monitor mode, still allow but flag it
                if self.mode == RateLimitMode.MONITOR:
                    bucket.add(now)
                    return RateLimitResult(
                        allowed=True,  # Allow in monitor mode
                        current_count=current_count + 1,
                        max_calls=self.max_calls,
                        window_seconds=self.window_seconds,
                        remaining=0,
                        retry_after_seconds=retry_after,
                        key=key,
                    )

                return RateLimitResult(
                    allowed=False,
                    current_count=current_count,
                    max_calls=self.max_calls,
                    window_seconds=self.window_seconds,
                    remaining=0,
                    retry_after_seconds=retry_after,
                    key=key,
                )

    def peek(self, key: str = "default") -> RateLimitResult:
        """
        Check rate limit status without recording a call.

        Args:
            key: Identifier for rate limiting.

        Returns:
            RateLimitResult with current status.
        """
        now = time.time()

        with self._lock:
            if key not in self._buckets:
                return RateLimitResult(
                    allowed=True,
                    current_count=0,
                    max_calls=self.max_calls,
                    window_seconds=self.window_seconds,
                    remaining=self.max_calls,
                    key=key,
                )

            bucket = self._buckets[key]
            current_count = bucket.count_in_window(now, self.window_seconds)

            if current_count < self.max_calls:
                return RateLimitResult(
                    allowed=True,
                    current_count=current_count,
                    max_calls=self.max_calls,
                    window_seconds=self.window_seconds,
                    remaining=self.max_calls - current_count,
                    key=key,
                )
            else:
                oldest = bucket.oldest_in_window(now, self.window_seconds)
                retry_after = (
                    (oldest + self.window_seconds - now) if oldest else self.window_seconds
                )
                return RateLimitResult(
                    allowed=False,
                    current_count=current_count,
                    max_calls=self.max_calls,
                    window_seconds=self.window_seconds,
                    remaining=0,
                    retry_after_seconds=retry_after,
                    key=key,
                )

    def reset(self, key: str | None = None) -> None:
        """
        Reset rate limit counters.

        Args:
            key: Specific key to reset, or None to reset all.
        """
        with self._lock:
            if key is None:
                self._buckets.clear()
            elif key in self._buckets:
                del self._buckets[key]

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about all rate limit buckets."""
        now = time.time()
        with self._lock:
            stats = {}
            for key, bucket in self._buckets.items():
                count = bucket.count_in_window(now, self.window_seconds)
                stats[key] = {
                    "current_count": count,
                    "max_calls": self.max_calls,
                    "remaining": max(0, self.max_calls - count),
                    "window_seconds": self.window_seconds,
                }
            return stats


# =============================================================================
# GLOBAL RATE LIMITER REGISTRY
# =============================================================================

_global_limiters: dict[str, RateLimiter] = {}
_global_lock = threading.Lock()


def get_rate_limiter(
    name: str = "default",
    max_calls: int = 100,
    window_seconds: float = 60.0,
    mode: str = "strict",
) -> RateLimiter:
    """
    Get or create a named rate limiter.

    Rate limiters are cached globally, so the same limiter is returned
    for the same name across the application.

    Args:
        name: Name of the rate limiter.
        max_calls: Maximum calls allowed (only used when creating new limiter).
        window_seconds: Time window in seconds.
        mode: 'strict' to block, 'monitor' to log only.

    Returns:
        RateLimiter instance.
    """
    with _global_lock:
        if name not in _global_limiters:
            _global_limiters[name] = RateLimiter(
                max_calls=max_calls,
                window_seconds=window_seconds,
                mode=mode,
            )
        return _global_limiters[name]


def check_rate_limit(
    key: str = "default",
    max_calls: int = 100,
    window_seconds: float = 60.0,
    limiter_name: str = "default",
) -> bool:
    """
    Quick check if a call is allowed by rate limit.

    Convenience function that uses a global rate limiter.

    Args:
        key: Identifier for rate limiting (e.g., tool name, user ID).
        max_calls: Maximum calls allowed in the window.
        window_seconds: Time window in seconds.
        limiter_name: Name of the rate limiter to use.

    Returns:
        True if allowed, False if rate limited.

    Example:
        >>> if check_rate_limit("api-call", max_calls=10, window_seconds=60):
        ...     make_api_call()
        ... else:
        ...     print("Rate limited!")
    """
    limiter = get_rate_limiter(limiter_name, max_calls, window_seconds)
    result = limiter.check(key)
    return result.allowed


def reset_rate_limits(limiter_name: str = "default", key: str | None = None) -> None:
    """
    Reset rate limit counters.

    Args:
        limiter_name: Name of the rate limiter.
        key: Specific key to reset, or None to reset all keys in the limiter.
    """
    with _global_lock:
        if limiter_name in _global_limiters:
            _global_limiters[limiter_name].reset(key)


def clear_all_rate_limiters() -> None:
    """Clear all global rate limiters."""
    with _global_lock:
        _global_limiters.clear()
