"""
Tests for the Rate Limiter.

These tests verify that the RateLimiter correctly:
- Tracks calls within a time window
- Blocks calls when limit exceeded
- Allows calls after window expires
- Supports multiple keys
- Is thread-safe
"""

import threading
import time

import pytest

from warden import (
    RateLimiter,
    RateLimitMode,
    check_rate_limit,
    clear_all_rate_limiters,
    get_rate_limiter,
    reset_rate_limits,
)


# =============================================================================
# BASIC RATE LIMITER TESTS
# =============================================================================


class TestRateLimiter:
    """Test the RateLimiter class."""

    def test_allows_calls_under_limit(self):
        """Calls under the limit should be allowed."""
        limiter = RateLimiter(max_calls=5, window_seconds=60)

        for i in range(5):
            result = limiter.check("test")
            assert result.allowed, f"Call {i+1} should be allowed"
            assert result.remaining == 5 - i - 1

    def test_blocks_calls_over_limit(self):
        """Calls over the limit should be blocked."""
        limiter = RateLimiter(max_calls=3, window_seconds=60)

        # Use up the limit
        for _ in range(3):
            result = limiter.check("test")
            assert result.allowed

        # Next call should be blocked
        result = limiter.check("test")
        assert not result.allowed
        assert result.remaining == 0
        assert result.retry_after_seconds is not None
        assert result.retry_after_seconds > 0

    def test_different_keys_tracked_separately(self):
        """Different keys should have separate limits."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)

        # Use up limit for key1
        limiter.check("key1")
        limiter.check("key1")
        result = limiter.check("key1")
        assert not result.allowed

        # key2 should still be allowed
        result = limiter.check("key2")
        assert result.allowed

    def test_window_expiry(self):
        """Calls should be allowed after window expires."""
        limiter = RateLimiter(max_calls=2, window_seconds=0.1)  # 100ms window

        # Use up the limit
        limiter.check("test")
        limiter.check("test")
        result = limiter.check("test")
        assert not result.allowed

        # Wait for window to expire
        time.sleep(0.15)

        # Should be allowed again
        result = limiter.check("test")
        assert result.allowed

    def test_peek_does_not_count(self):
        """Peek should check status without counting."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)

        # Check current status
        result = limiter.peek("test")
        assert result.allowed
        assert result.current_count == 0
        assert result.remaining == 2

        # Make a call
        limiter.check("test")

        # Peek again - should show 1 call but not add another
        result = limiter.peek("test")
        assert result.allowed
        assert result.current_count == 1
        assert result.remaining == 1

        # Make another call to verify peek didn't count
        result = limiter.check("test")
        assert result.allowed
        assert result.current_count == 2

    def test_reset_specific_key(self):
        """Reset should clear counters for a specific key."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)

        # Use up limit
        limiter.check("key1")
        limiter.check("key1")
        limiter.check("key2")

        # Reset key1 only
        limiter.reset("key1")

        # key1 should be allowed again
        result = limiter.check("key1")
        assert result.allowed
        assert result.current_count == 1

        # key2 should still have its count
        result = limiter.peek("key2")
        assert result.current_count == 1

    def test_reset_all_keys(self):
        """Reset with no key should clear all counters."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)

        limiter.check("key1")
        limiter.check("key2")

        limiter.reset()

        result = limiter.peek("key1")
        assert result.current_count == 0

        result = limiter.peek("key2")
        assert result.current_count == 0

    def test_get_stats(self):
        """Get stats should return all bucket info."""
        limiter = RateLimiter(max_calls=5, window_seconds=60)

        limiter.check("api")
        limiter.check("api")
        limiter.check("db")

        stats = limiter.get_stats()

        assert "api" in stats
        assert stats["api"]["current_count"] == 2
        assert stats["api"]["remaining"] == 3

        assert "db" in stats
        assert stats["db"]["current_count"] == 1

    def test_result_bool_conversion(self):
        """RateLimitResult should be truthy when allowed."""
        limiter = RateLimiter(max_calls=1, window_seconds=60)

        result = limiter.check("test")
        assert result  # Should be truthy
        assert bool(result) is True

        result = limiter.check("test")
        assert not result  # Should be falsy
        assert bool(result) is False

    def test_result_to_dict(self):
        """RateLimitResult should convert to dict."""
        limiter = RateLimiter(max_calls=5, window_seconds=60)
        result = limiter.check("test")

        d = result.to_dict()
        assert d["allowed"] is True
        assert d["max_calls"] == 5
        assert d["window_seconds"] == 60
        assert d["key"] == "test"


class TestMonitorMode:
    """Test monitor mode behavior."""

    def test_monitor_mode_allows_over_limit(self):
        """Monitor mode should allow calls even over limit."""
        limiter = RateLimiter(max_calls=2, window_seconds=60, mode="monitor")

        limiter.check("test")
        limiter.check("test")

        # Third call should still be allowed in monitor mode
        result = limiter.check("test")
        assert result.allowed
        assert result.remaining == 0
        assert result.retry_after_seconds is not None  # But flags it


class TestThreadSafety:
    """Test thread safety of the rate limiter."""

    def test_concurrent_access(self):
        """Rate limiter should be thread-safe."""
        limiter = RateLimiter(max_calls=100, window_seconds=60)
        results = []
        errors = []

        def make_calls():
            try:
                for _ in range(20):
                    result = limiter.check("shared")
                    results.append(result.allowed)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=make_calls) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(results) == 100
        # First 100 should be allowed
        assert sum(results) == 100


# =============================================================================
# CONVENIENCE FUNCTIONS TESTS
# =============================================================================


class TestConvenienceFunctions:
    """Test convenience functions."""

    def setup_method(self):
        """Clear global rate limiters before each test."""
        clear_all_rate_limiters()

    def test_check_rate_limit_basic(self):
        """check_rate_limit should return bool."""
        # First call should be allowed
        result = check_rate_limit("test", max_calls=2, window_seconds=60)
        assert result is True

        result = check_rate_limit("test", max_calls=2, window_seconds=60)
        assert result is True

        # Third call should be blocked
        result = check_rate_limit("test", max_calls=2, window_seconds=60)
        assert result is False

    def test_get_rate_limiter_caches(self):
        """get_rate_limiter should return same instance for same name."""
        limiter1 = get_rate_limiter("test", max_calls=10)
        limiter2 = get_rate_limiter("test", max_calls=999)  # Different config ignored

        assert limiter1 is limiter2
        assert limiter1.max_calls == 10  # Original config preserved

    def test_get_rate_limiter_different_names(self):
        """Different names should get different limiters."""
        limiter1 = get_rate_limiter("api", max_calls=100)
        limiter2 = get_rate_limiter("db", max_calls=50)

        assert limiter1 is not limiter2
        assert limiter1.max_calls == 100
        assert limiter2.max_calls == 50

    def test_reset_rate_limits(self):
        """reset_rate_limits should clear counters."""
        check_rate_limit("key1", max_calls=2, limiter_name="test")
        check_rate_limit("key1", max_calls=2, limiter_name="test")

        # Should be blocked
        assert not check_rate_limit("key1", max_calls=2, limiter_name="test")

        # Reset
        reset_rate_limits("test", "key1")

        # Should be allowed again
        assert check_rate_limit("key1", max_calls=2, limiter_name="test")

    def test_clear_all_rate_limiters(self):
        """clear_all_rate_limiters should remove all limiters."""
        get_rate_limiter("limiter1", max_calls=10)
        get_rate_limiter("limiter2", max_calls=20)

        clear_all_rate_limiters()

        # New limiter should be created with new config
        limiter = get_rate_limiter("limiter1", max_calls=999)
        assert limiter.max_calls == 999


# =============================================================================
# EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Test edge cases."""

    def test_zero_max_calls(self):
        """Zero max calls should block everything."""
        limiter = RateLimiter(max_calls=0, window_seconds=60)
        result = limiter.check("test")
        assert not result.allowed

    def test_very_short_window(self):
        """Very short windows should work correctly."""
        limiter = RateLimiter(max_calls=1, window_seconds=0.01)

        result = limiter.check("test")
        assert result.allowed

        result = limiter.check("test")
        assert not result.allowed

        time.sleep(0.02)

        result = limiter.check("test")
        assert result.allowed

    def test_empty_key(self):
        """Empty key should work."""
        limiter = RateLimiter(max_calls=1, window_seconds=60)
        result = limiter.check("")
        assert result.allowed
        assert result.key == ""

    def test_unicode_key(self):
        """Unicode keys should work."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)

        result = limiter.check("user-\u4e2d\u6587")
        assert result.allowed

        result = limiter.check("user-\u4e2d\u6587")
        assert result.allowed

        result = limiter.check("user-\u4e2d\u6587")
        assert not result.allowed
