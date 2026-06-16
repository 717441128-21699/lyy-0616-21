import threading
import time
import random


class Call:
    """
    Represents a single in-flight upstream request.

    Multiple waiters can wait on this call via the `wait()` method.
    When the result is set via `set_result()`, all waiters are awakened.
    """

    __slots__ = ("event", "result", "error", "started_at", "waiter_count")

    def __init__(self):
        self.event = threading.Event()
        self.result = None
        self.error = None
        self.started_at = time.time()
        self.waiter_count = 0

    def set_result(self, result, error=None):
        self.result = result
        self.error = error
        self.event.set()

    def wait(self, timeout=None):
        """Wait for the result. Returns (result, error)."""
        self.waiter_count += 1
        self.event.wait(timeout=timeout)
        return self.result, self.error


class Singleflight:
    """
    Singleflight (单飞) pattern: de-duplicate concurrent identical requests.

    When multiple requests arrive for the same key (e.g., same domain+type),
    only one actually triggers the upstream work; the rest wait for and
    reuse the first request's result.

    Key features:
    - Thread-safe
    - Results are shared among all concurrent callers of the same key
    - Caller that "wins" the race executes the work function
    - Automatic key cleanup after result is delivered
    - Timeout support for stuck upstream requests
    """

    def __init__(self, default_timeout=10.0):
        self._calls = {}
        self._lock = threading.Lock()
        self._default_timeout = default_timeout
        self._dedup_count = 0
        self._total_count = 0

    def do(self, key, fn, timeout=None):
        """
        Execute fn for the given key, or wait for an in-flight call with the same key.

        Args:
            key: A hashable key identifying the request (e.g., tuple (name, qtype))
            fn: A callable() -> result that performs the actual upstream work
            timeout: Maximum seconds to wait for the result

        Returns:
            (result, error, is_duplicate)
            - result: the return value from fn (or None on error)
            - error: exception if fn raised, or None
            - is_duplicate: True if this call reused another caller's result
        """
        if timeout is None:
            timeout = self._default_timeout

        with self._lock:
            self._total_count += 1
            existing = self._calls.get(key)
            if existing is not None:
                self._dedup_count += 1
                is_duplicate = True
                call = existing
            else:
                is_duplicate = False
                call = Call()
                self._calls[key] = call

        if is_duplicate:
            result, error = call.wait(timeout=timeout)
            return result, error, True

        try:
            result = fn()
            error = None
        except Exception as e:
            result = None
            error = e

        call.set_result(result, error)

        with self._lock:
            if key in self._calls and self._calls[key] is call:
                del self._calls[key]

        return result, error, False

    def stats(self):
        with self._lock:
            inflight = len(self._calls)
            total = self._total_count
            dedup = self._dedup_count
            saved = (dedup / total * 100) if total > 0 else 0.0
            return {
                "inflight": inflight,
                "total_requests": total,
                "deduped_requests": dedup,
                "saved_percent": saved,
            }

    def reset_stats(self):
        with self._lock:
            self._total_count = 0
            self._dedup_count = 0
