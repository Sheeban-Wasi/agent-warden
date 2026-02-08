"""
Tool Retry with Exponential Backoff.

Provides automatic retry logic for transient failures with configurable
exponential backoff and jitter.

Example:
    >>> from warden import RetryConfig, with_retry
    >>>
    >>> @with_retry(max_retries=3, base_delay=1.0)
    ... def flaky_api_call():
    ...     return requests.get("https://api.example.com/data")
    >>>
    >>> # Or with guard decorator
    >>> @guard(
    ...     sql=True,
    ...     retry=True,
    ...     retry_max_attempts=3,
    ...     retry_on=[ConnectionError, TimeoutError],
    ... )
    ... def query_database(sql: str):
    ...     return db.execute(sql)
"""

from __future__ import annotations

import asyncio
import functools
import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")

logger = logging.getLogger(__name__)


class RetryStrategy(Enum):
    """Retry backoff strategies."""

    EXPONENTIAL = "exponential"  # 2^attempt * base_delay
    LINEAR = "linear"  # attempt * base_delay
    CONSTANT = "constant"  # Always base_delay
    FIBONACCI = "fibonacci"  # Fibonacci sequence * base_delay


class RetryOutcome(Enum):
    """Outcome of a retry attempt."""

    SUCCESS = "success"
    RETRY = "retry"
    EXHAUSTED = "exhausted"  # Max retries reached
    NON_RETRYABLE = "non_retryable"  # Exception not in retry list


@dataclass
class RetryAttempt:
    """Information about a single retry attempt."""

    attempt: int
    max_attempts: int
    exception: Exception | None
    delay_seconds: float
    outcome: RetryOutcome
    elapsed_seconds: float

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "exception_type": type(self.exception).__name__ if self.exception else None,
            "exception_message": str(self.exception) if self.exception else None,
            "delay_seconds": self.delay_seconds,
            "outcome": self.outcome.value,
            "elapsed_seconds": self.elapsed_seconds,
        }


@dataclass
class RetryResult:
    """Result of a retry operation."""

    success: bool
    attempts: list[RetryAttempt]
    total_elapsed_seconds: float
    final_exception: Exception | None = None

    @property
    def attempt_count(self) -> int:
        """Number of attempts made."""
        return len(self.attempts)

    @property
    def retry_count(self) -> int:
        """Number of retries (attempts - 1)."""
        return max(0, len(self.attempts) - 1)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "success": self.success,
            "attempt_count": self.attempt_count,
            "retry_count": self.retry_count,
            "total_elapsed_seconds": self.total_elapsed_seconds,
            "final_exception_type": (
                type(self.final_exception).__name__ if self.final_exception else None
            ),
            "attempts": [a.to_dict() for a in self.attempts],
        }


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_attempts: int = 3
    base_delay: float = 1.0  # Base delay in seconds
    max_delay: float = 60.0  # Maximum delay cap
    strategy: RetryStrategy | str = RetryStrategy.EXPONENTIAL
    jitter: bool = True  # Add randomness to prevent thundering herd
    jitter_factor: float = 0.5  # Jitter range: delay * (1 ± jitter_factor/2)
    retry_on: tuple[type[Exception], ...] = field(
        default_factory=lambda: (Exception,)
    )
    on_retry: Callable[[RetryAttempt], None] | None = None  # Callback on each retry

    def __post_init__(self) -> None:
        """Validate and normalize configuration."""
        if isinstance(self.strategy, str):
            self.strategy = RetryStrategy(self.strategy)

        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.base_delay < 0:
            raise ValueError("base_delay must be non-negative")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")


class RetryHandler:
    """
    Handles retry logic with exponential backoff.

    Example:
        >>> handler = RetryHandler(RetryConfig(max_attempts=3))
        >>>
        >>> def flaky_operation():
        ...     if random.random() < 0.5:
        ...         raise ConnectionError("Network failed")
        ...     return "success"
        >>>
        >>> result = handler.execute(flaky_operation)
        >>> if result.success:
        ...     print(f"Succeeded after {result.attempt_count} attempts")
    """

    # Fibonacci sequence for FIBONACCI strategy
    _FIBONACCI = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]

    def __init__(self, config: RetryConfig | None = None) -> None:
        """
        Initialize retry handler.

        Args:
            config: Retry configuration. Uses defaults if not provided.
        """
        self.config = config or RetryConfig()

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for a given attempt number."""
        strategy = self.config.strategy

        if strategy == RetryStrategy.CONSTANT:
            delay = self.config.base_delay
        elif strategy == RetryStrategy.LINEAR:
            delay = attempt * self.config.base_delay
        elif strategy == RetryStrategy.FIBONACCI:
            idx = min(attempt - 1, len(self._FIBONACCI) - 1)
            delay = self._FIBONACCI[idx] * self.config.base_delay
        else:  # EXPONENTIAL (default)
            delay = (2 ** (attempt - 1)) * self.config.base_delay

        # Apply max delay cap
        delay = min(delay, self.config.max_delay)

        # Apply jitter
        if self.config.jitter:
            jitter_range = delay * self.config.jitter_factor
            delay = delay + random.uniform(-jitter_range / 2, jitter_range / 2)
            delay = max(0, delay)  # Ensure non-negative

        return delay

    def _should_retry(self, exception: Exception) -> bool:
        """Check if exception is retryable."""
        return isinstance(exception, self.config.retry_on)

    def execute(
        self,
        func: Callable[P, R],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> tuple[R | None, RetryResult]:
        """
        Execute function with retry logic.

        Args:
            func: Function to execute.
            *args: Positional arguments for function.
            **kwargs: Keyword arguments for function.

        Returns:
            Tuple of (result, retry_result).
            If successful, result is the function return value.
            If failed, result is None.
        """
        start_time = time.monotonic()
        attempts: list[RetryAttempt] = []
        final_exception: Exception | None = None

        for attempt in range(1, self.config.max_attempts + 1):
            attempt_start = time.monotonic()

            try:
                result = func(*args, **kwargs)

                # Success
                elapsed = time.monotonic() - attempt_start
                attempts.append(
                    RetryAttempt(
                        attempt=attempt,
                        max_attempts=self.config.max_attempts,
                        exception=None,
                        delay_seconds=0,
                        outcome=RetryOutcome.SUCCESS,
                        elapsed_seconds=elapsed,
                    )
                )

                return result, RetryResult(
                    success=True,
                    attempts=attempts,
                    total_elapsed_seconds=time.monotonic() - start_time,
                )

            except Exception as e:
                elapsed = time.monotonic() - attempt_start
                final_exception = e

                # Check if we should retry
                if not self._should_retry(e):
                    attempts.append(
                        RetryAttempt(
                            attempt=attempt,
                            max_attempts=self.config.max_attempts,
                            exception=e,
                            delay_seconds=0,
                            outcome=RetryOutcome.NON_RETRYABLE,
                            elapsed_seconds=elapsed,
                        )
                    )
                    break

                # Check if we have more attempts
                if attempt >= self.config.max_attempts:
                    attempts.append(
                        RetryAttempt(
                            attempt=attempt,
                            max_attempts=self.config.max_attempts,
                            exception=e,
                            delay_seconds=0,
                            outcome=RetryOutcome.EXHAUSTED,
                            elapsed_seconds=elapsed,
                        )
                    )
                    break

                # Calculate delay and wait
                delay = self._calculate_delay(attempt)

                attempt_info = RetryAttempt(
                    attempt=attempt,
                    max_attempts=self.config.max_attempts,
                    exception=e,
                    delay_seconds=delay,
                    outcome=RetryOutcome.RETRY,
                    elapsed_seconds=elapsed,
                )
                attempts.append(attempt_info)

                # Call retry callback if provided
                if self.config.on_retry:
                    try:
                        self.config.on_retry(attempt_info)
                    except Exception:
                        pass  # Don't let callback errors affect retry

                logger.debug(
                    f"Retry attempt {attempt}/{self.config.max_attempts} "
                    f"failed with {type(e).__name__}: {e}. "
                    f"Waiting {delay:.2f}s before next attempt."
                )

                time.sleep(delay)

        return None, RetryResult(
            success=False,
            attempts=attempts,
            total_elapsed_seconds=time.monotonic() - start_time,
            final_exception=final_exception,
        )

    async def execute_async(
        self,
        func: Callable[P, R],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> tuple[R | None, RetryResult]:
        """
        Execute async function with retry logic.

        Args:
            func: Async function to execute.
            *args: Positional arguments for function.
            **kwargs: Keyword arguments for function.

        Returns:
            Tuple of (result, retry_result).
        """
        start_time = time.monotonic()
        attempts: list[RetryAttempt] = []
        final_exception: Exception | None = None

        for attempt in range(1, self.config.max_attempts + 1):
            attempt_start = time.monotonic()

            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                # Success
                elapsed = time.monotonic() - attempt_start
                attempts.append(
                    RetryAttempt(
                        attempt=attempt,
                        max_attempts=self.config.max_attempts,
                        exception=None,
                        delay_seconds=0,
                        outcome=RetryOutcome.SUCCESS,
                        elapsed_seconds=elapsed,
                    )
                )

                return result, RetryResult(
                    success=True,
                    attempts=attempts,
                    total_elapsed_seconds=time.monotonic() - start_time,
                )

            except Exception as e:
                elapsed = time.monotonic() - attempt_start
                final_exception = e

                # Check if we should retry
                if not self._should_retry(e):
                    attempts.append(
                        RetryAttempt(
                            attempt=attempt,
                            max_attempts=self.config.max_attempts,
                            exception=e,
                            delay_seconds=0,
                            outcome=RetryOutcome.NON_RETRYABLE,
                            elapsed_seconds=elapsed,
                        )
                    )
                    break

                # Check if we have more attempts
                if attempt >= self.config.max_attempts:
                    attempts.append(
                        RetryAttempt(
                            attempt=attempt,
                            max_attempts=self.config.max_attempts,
                            exception=e,
                            delay_seconds=0,
                            outcome=RetryOutcome.EXHAUSTED,
                            elapsed_seconds=elapsed,
                        )
                    )
                    break

                # Calculate delay and wait
                delay = self._calculate_delay(attempt)

                attempt_info = RetryAttempt(
                    attempt=attempt,
                    max_attempts=self.config.max_attempts,
                    exception=e,
                    delay_seconds=delay,
                    outcome=RetryOutcome.RETRY,
                    elapsed_seconds=elapsed,
                )
                attempts.append(attempt_info)

                # Call retry callback if provided
                if self.config.on_retry:
                    try:
                        self.config.on_retry(attempt_info)
                    except Exception:
                        pass

                logger.debug(
                    f"Retry attempt {attempt}/{self.config.max_attempts} "
                    f"failed with {type(e).__name__}: {e}. "
                    f"Waiting {delay:.2f}s before next attempt."
                )

                await asyncio.sleep(delay)

        return None, RetryResult(
            success=False,
            attempts=attempts,
            total_elapsed_seconds=time.monotonic() - start_time,
            final_exception=final_exception,
        )


# =============================================================================
# DECORATOR
# =============================================================================


def with_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    strategy: RetryStrategy | str = RetryStrategy.EXPONENTIAL,
    jitter: bool = True,
    retry_on: tuple[type[Exception], ...] | None = None,
    on_retry: Callable[[RetryAttempt], None] | None = None,
    reraise: bool = True,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to add retry logic to a function.

    Args:
        max_attempts: Maximum number of attempts (including first try).
        base_delay: Base delay between retries in seconds.
        max_delay: Maximum delay cap.
        strategy: Backoff strategy (exponential, linear, constant, fibonacci).
        jitter: Add randomness to delays.
        retry_on: Exception types to retry on. Defaults to all exceptions.
        on_retry: Callback function called on each retry.
        reraise: Whether to reraise the final exception on failure.

    Example:
        >>> @with_retry(max_attempts=3, retry_on=(ConnectionError,))
        ... def fetch_data():
        ...     return requests.get("https://api.example.com")
    """
    if retry_on is None:
        retry_on = (Exception,)

    config = RetryConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        strategy=strategy,
        jitter=jitter,
        retry_on=retry_on,
        on_retry=on_retry,
    )

    handler = RetryHandler(config)

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                result, retry_result = await handler.execute_async(func, *args, **kwargs)
                if retry_result.success:
                    return result  # type: ignore
                if reraise and retry_result.final_exception:
                    raise retry_result.final_exception
                return result  # type: ignore

            return async_wrapper  # type: ignore
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                result, retry_result = handler.execute(func, *args, **kwargs)
                if retry_result.success:
                    return result  # type: ignore
                if reraise and retry_result.final_exception:
                    raise retry_result.final_exception
                return result  # type: ignore

            return sync_wrapper

    return decorator


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def create_retry_handler(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    strategy: str = "exponential",
    jitter: bool = True,
    retry_on: tuple[type[Exception], ...] | None = None,
) -> RetryHandler:
    """
    Create a retry handler with the specified configuration.

    Args:
        max_attempts: Maximum attempts.
        base_delay: Base delay in seconds.
        max_delay: Maximum delay cap.
        strategy: Backoff strategy.
        jitter: Add randomness.
        retry_on: Exception types to retry.

    Returns:
        Configured RetryHandler instance.
    """
    if retry_on is None:
        retry_on = (Exception,)

    return RetryHandler(
        RetryConfig(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            strategy=RetryStrategy(strategy),
            jitter=jitter,
            retry_on=retry_on,
        )
    )
