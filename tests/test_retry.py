"""
Tests for the Tool Retry with Exponential Backoff.

These tests verify that the retry module correctly:
- Retries on specified exceptions
- Applies exponential/linear/constant/fibonacci backoff
- Respects max attempts and max delay
- Applies jitter correctly
- Works with sync and async functions
"""

import asyncio
import time

import pytest

from warden.core.retry import (
    RetryAttempt,
    RetryConfig,
    RetryHandler,
    RetryOutcome,
    RetryResult,
    RetryStrategy,
    create_retry_handler,
    with_retry,
)


# =============================================================================
# RETRY CONFIG TESTS
# =============================================================================


class TestRetryConfig:
    """Test RetryConfig validation."""

    def test_default_config(self):
        """Default config should have sensible values."""
        config = RetryConfig()
        assert config.max_attempts == 3
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.strategy == RetryStrategy.EXPONENTIAL
        assert config.jitter is True

    def test_custom_config(self):
        """Custom config values should be accepted."""
        config = RetryConfig(
            max_attempts=5,
            base_delay=0.5,
            max_delay=30.0,
            strategy=RetryStrategy.LINEAR,
            jitter=False,
        )
        assert config.max_attempts == 5
        assert config.base_delay == 0.5
        assert config.max_delay == 30.0
        assert config.strategy == RetryStrategy.LINEAR
        assert config.jitter is False

    def test_strategy_from_string(self):
        """Strategy can be specified as string."""
        config = RetryConfig(strategy="linear")
        assert config.strategy == RetryStrategy.LINEAR

        config = RetryConfig(strategy="exponential")
        assert config.strategy == RetryStrategy.EXPONENTIAL

    def test_invalid_max_attempts(self):
        """max_attempts < 1 should raise error."""
        with pytest.raises(ValueError, match="max_attempts must be at least 1"):
            RetryConfig(max_attempts=0)

    def test_invalid_base_delay(self):
        """Negative base_delay should raise error."""
        with pytest.raises(ValueError, match="base_delay must be non-negative"):
            RetryConfig(base_delay=-1)

    def test_invalid_max_delay(self):
        """max_delay < base_delay should raise error."""
        with pytest.raises(ValueError, match="max_delay must be >= base_delay"):
            RetryConfig(base_delay=10, max_delay=5)


# =============================================================================
# RETRY HANDLER TESTS
# =============================================================================


class TestRetryHandler:
    """Test RetryHandler execution."""

    def test_success_on_first_attempt(self):
        """Successful function should not retry."""
        handler = RetryHandler(RetryConfig(max_attempts=3))

        def success():
            return "ok"

        result, retry_result = handler.execute(success)

        assert result == "ok"
        assert retry_result.success is True
        assert retry_result.attempt_count == 1
        assert retry_result.retry_count == 0

    def test_success_after_retries(self):
        """Function that fails then succeeds should retry."""
        handler = RetryHandler(
            RetryConfig(max_attempts=5, base_delay=0.01, jitter=False)
        )

        attempts = 0

        def fail_twice():
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise ConnectionError("Failed")
            return "ok"

        result, retry_result = handler.execute(fail_twice)

        assert result == "ok"
        assert retry_result.success is True
        assert retry_result.attempt_count == 3
        assert retry_result.retry_count == 2

    def test_exhausted_retries(self):
        """Function that always fails should exhaust retries."""
        handler = RetryHandler(
            RetryConfig(max_attempts=3, base_delay=0.01, jitter=False)
        )

        def always_fail():
            raise ValueError("Always fails")

        result, retry_result = handler.execute(always_fail)

        assert result is None
        assert retry_result.success is False
        assert retry_result.attempt_count == 3
        assert retry_result.final_exception is not None
        assert isinstance(retry_result.final_exception, ValueError)

    def test_non_retryable_exception(self):
        """Non-retryable exceptions should not be retried."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=5,
                base_delay=0.01,
                retry_on=(ConnectionError,),  # Only retry ConnectionError
            )
        )

        def raise_value_error():
            raise ValueError("Not retryable")

        result, retry_result = handler.execute(raise_value_error)

        assert result is None
        assert retry_result.success is False
        assert retry_result.attempt_count == 1  # Only one attempt
        assert retry_result.attempts[0].outcome == RetryOutcome.NON_RETRYABLE

    def test_retry_callback(self):
        """on_retry callback should be called on each retry."""
        callback_calls = []

        def on_retry(attempt: RetryAttempt):
            callback_calls.append(attempt)

        handler = RetryHandler(
            RetryConfig(
                max_attempts=3,
                base_delay=0.01,
                jitter=False,
                on_retry=on_retry,
            )
        )

        def always_fail():
            raise ValueError("Fail")

        handler.execute(always_fail)

        # Called on attempts 1 and 2 (not on last attempt)
        assert len(callback_calls) == 2
        assert callback_calls[0].attempt == 1
        assert callback_calls[1].attempt == 2


# =============================================================================
# BACKOFF STRATEGY TESTS
# =============================================================================


class TestBackoffStrategies:
    """Test different backoff strategies."""

    def test_exponential_backoff(self):
        """Exponential backoff should double delay each time."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=5,
                base_delay=1.0,
                max_delay=100.0,
                strategy=RetryStrategy.EXPONENTIAL,
                jitter=False,
            )
        )

        # Attempt 1: 2^0 * 1.0 = 1.0
        assert handler._calculate_delay(1) == 1.0
        # Attempt 2: 2^1 * 1.0 = 2.0
        assert handler._calculate_delay(2) == 2.0
        # Attempt 3: 2^2 * 1.0 = 4.0
        assert handler._calculate_delay(3) == 4.0
        # Attempt 4: 2^3 * 1.0 = 8.0
        assert handler._calculate_delay(4) == 8.0

    def test_linear_backoff(self):
        """Linear backoff should increase linearly."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=5,
                base_delay=1.0,
                strategy=RetryStrategy.LINEAR,
                jitter=False,
            )
        )

        assert handler._calculate_delay(1) == 1.0
        assert handler._calculate_delay(2) == 2.0
        assert handler._calculate_delay(3) == 3.0
        assert handler._calculate_delay(4) == 4.0

    def test_constant_backoff(self):
        """Constant backoff should always use base_delay."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=5,
                base_delay=2.0,
                strategy=RetryStrategy.CONSTANT,
                jitter=False,
            )
        )

        assert handler._calculate_delay(1) == 2.0
        assert handler._calculate_delay(2) == 2.0
        assert handler._calculate_delay(3) == 2.0

    def test_fibonacci_backoff(self):
        """Fibonacci backoff should follow fibonacci sequence."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=10,
                base_delay=1.0,
                max_delay=100.0,
                strategy=RetryStrategy.FIBONACCI,
                jitter=False,
            )
        )

        # Fibonacci: 1, 1, 2, 3, 5, 8, 13, 21...
        assert handler._calculate_delay(1) == 1.0
        assert handler._calculate_delay(2) == 1.0
        assert handler._calculate_delay(3) == 2.0
        assert handler._calculate_delay(4) == 3.0
        assert handler._calculate_delay(5) == 5.0
        assert handler._calculate_delay(6) == 8.0

    def test_max_delay_cap(self):
        """Delay should not exceed max_delay."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=10,
                base_delay=1.0,
                max_delay=5.0,  # Cap at 5 seconds
                strategy=RetryStrategy.EXPONENTIAL,
                jitter=False,
            )
        )

        # Attempt 5 would be 16s without cap
        assert handler._calculate_delay(5) == 5.0
        assert handler._calculate_delay(10) == 5.0

    def test_jitter_adds_variance(self):
        """Jitter should add variance to delays."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=5,
                base_delay=10.0,
                strategy=RetryStrategy.CONSTANT,
                jitter=True,
                jitter_factor=0.5,
            )
        )

        # With jitter, delays should vary
        delays = [handler._calculate_delay(1) for _ in range(100)]

        # All delays should be roughly around 10.0 ± 2.5
        assert all(5.0 <= d <= 15.0 for d in delays)

        # Should have some variance
        assert min(delays) < max(delays)


# =============================================================================
# ASYNC TESTS
# =============================================================================


class TestAsyncRetry:
    """Test async retry functionality."""

    @pytest.mark.asyncio
    async def test_async_success(self):
        """Async function should succeed without retry."""
        handler = RetryHandler(RetryConfig(max_attempts=3))

        async def async_success():
            return "async ok"

        result, retry_result = await handler.execute_async(async_success)

        assert result == "async ok"
        assert retry_result.success is True
        assert retry_result.attempt_count == 1

    @pytest.mark.asyncio
    async def test_async_retry(self):
        """Async function should retry on failure."""
        handler = RetryHandler(
            RetryConfig(max_attempts=3, base_delay=0.01, jitter=False)
        )

        attempts = 0

        async def async_fail_once():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise ConnectionError("Failed")
            return "recovered"

        result, retry_result = await handler.execute_async(async_fail_once)

        assert result == "recovered"
        assert retry_result.success is True
        assert retry_result.attempt_count == 2

    @pytest.mark.asyncio
    async def test_async_exhausted(self):
        """Async function should exhaust retries."""
        handler = RetryHandler(
            RetryConfig(max_attempts=2, base_delay=0.01, jitter=False)
        )

        async def always_fail():
            raise ValueError("Async fail")

        result, retry_result = await handler.execute_async(always_fail)

        assert result is None
        assert retry_result.success is False
        assert retry_result.attempt_count == 2


# =============================================================================
# DECORATOR TESTS
# =============================================================================


class TestWithRetryDecorator:
    """Test @with_retry decorator."""

    def test_decorator_success(self):
        """Decorated function should work normally on success."""

        @with_retry(max_attempts=3, base_delay=0.01)
        def success():
            return "decorated ok"

        assert success() == "decorated ok"

    def test_decorator_retry(self):
        """Decorated function should retry on failure."""
        attempts = 0

        @with_retry(max_attempts=3, base_delay=0.01, jitter=False)
        def fail_once():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise ValueError("First fail")
            return "recovered"

        assert fail_once() == "recovered"
        assert attempts == 2

    def test_decorator_exhausted_reraise(self):
        """Decorator should reraise exception when exhausted."""

        @with_retry(max_attempts=2, base_delay=0.01, reraise=True)
        def always_fail():
            raise ValueError("Always fails")

        with pytest.raises(ValueError, match="Always fails"):
            always_fail()

    def test_decorator_specific_exceptions(self):
        """Decorator should only retry specified exceptions."""
        attempts = 0

        @with_retry(
            max_attempts=3,
            base_delay=0.01,
            retry_on=(ConnectionError,),
        )
        def raise_value_error():
            nonlocal attempts
            attempts += 1
            raise ValueError("Not retryable")

        with pytest.raises(ValueError):
            raise_value_error()

        assert attempts == 1  # Only one attempt

    @pytest.mark.asyncio
    async def test_async_decorator(self):
        """Decorator should work with async functions."""
        attempts = 0

        @with_retry(max_attempts=3, base_delay=0.01, jitter=False)
        async def async_fail_once():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise ConnectionError("Async fail")
            return "async recovered"

        result = await async_fail_once()
        assert result == "async recovered"
        assert attempts == 2


# =============================================================================
# RESULT TESTS
# =============================================================================


class TestRetryResult:
    """Test RetryResult and RetryAttempt."""

    def test_retry_result_to_dict(self):
        """RetryResult should convert to dict."""
        attempts = [
            RetryAttempt(
                attempt=1,
                max_attempts=3,
                exception=ValueError("test"),
                delay_seconds=1.0,
                outcome=RetryOutcome.RETRY,
                elapsed_seconds=0.1,
            ),
            RetryAttempt(
                attempt=2,
                max_attempts=3,
                exception=None,
                delay_seconds=0,
                outcome=RetryOutcome.SUCCESS,
                elapsed_seconds=0.05,
            ),
        ]

        result = RetryResult(
            success=True,
            attempts=attempts,
            total_elapsed_seconds=1.15,
        )

        d = result.to_dict()
        assert d["success"] is True
        assert d["attempt_count"] == 2
        assert d["retry_count"] == 1
        assert len(d["attempts"]) == 2

    def test_retry_attempt_to_dict(self):
        """RetryAttempt should convert to dict."""
        attempt = RetryAttempt(
            attempt=1,
            max_attempts=3,
            exception=ConnectionError("Network error"),
            delay_seconds=1.5,
            outcome=RetryOutcome.RETRY,
            elapsed_seconds=0.2,
        )

        d = attempt.to_dict()
        assert d["attempt"] == 1
        assert d["max_attempts"] == 3
        assert d["exception_type"] == "ConnectionError"
        assert d["exception_message"] == "Network error"
        assert d["delay_seconds"] == 1.5
        assert d["outcome"] == "retry"


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_create_retry_handler(self):
        """create_retry_handler should create configured handler."""
        handler = create_retry_handler(
            max_attempts=5,
            base_delay=0.5,
            strategy="linear",
        )

        assert handler.config.max_attempts == 5
        assert handler.config.base_delay == 0.5
        assert handler.config.strategy == RetryStrategy.LINEAR


# =============================================================================
# TIMING TESTS
# =============================================================================


class TestRetryTiming:
    """Test that retry delays are actually applied."""

    def test_delay_is_applied(self):
        """Retry should actually wait between attempts."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=3,
                base_delay=0.05,  # 50ms
                strategy=RetryStrategy.CONSTANT,
                jitter=False,
            )
        )

        start = time.monotonic()

        def always_fail():
            raise ValueError("Fail")

        handler.execute(always_fail)

        elapsed = time.monotonic() - start

        # Should have waited ~100ms (2 delays of 50ms each)
        assert elapsed >= 0.08  # Allow some tolerance
        assert elapsed < 0.5  # But not too long

    @pytest.mark.asyncio
    async def test_async_delay_is_applied(self):
        """Async retry should actually wait between attempts."""
        handler = RetryHandler(
            RetryConfig(
                max_attempts=3,
                base_delay=0.05,
                strategy=RetryStrategy.CONSTANT,
                jitter=False,
            )
        )

        start = time.monotonic()

        async def always_fail():
            raise ValueError("Fail")

        await handler.execute_async(always_fail)

        elapsed = time.monotonic() - start
        assert elapsed >= 0.08
        assert elapsed < 0.5
