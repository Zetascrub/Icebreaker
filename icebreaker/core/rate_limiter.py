from __future__ import annotations

import asyncio
import time
from typing import Optional


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rates.

    Supports both:
    - Concurrency limiting (max concurrent requests)
    - Rate limiting (max requests per second)
    """

    def __init__(
        self,
        max_concurrent: int = 100,
        rate_per_second: Optional[float] = None
    ):
        """
        Initialize rate limiter.

        Args:
            max_concurrent: Maximum number of concurrent operations
            rate_per_second: Maximum requests per second (None = unlimited)
        """
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_per_second = rate_per_second
        self.last_request_time = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        # First, acquire semaphore for concurrency control
        await self.semaphore.acquire()

        # Then, apply rate limiting if configured
        if self.rate_per_second:
            async with self.lock:
                current_time = time.time()
                time_since_last = current_time - self.last_request_time

                # Calculate required delay to maintain rate
                min_interval = 1.0 / self.rate_per_second
                if time_since_last < min_interval:
                    delay = min_interval - time_since_last
                    await asyncio.sleep(delay)

                self.last_request_time = time.time()

    def release(self) -> None:
        """Release the semaphore."""
        self.semaphore.release()

    async def __aenter__(self):
        """Context manager entry."""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.release()
        return False
