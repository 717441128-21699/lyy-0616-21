import time
import threading
from dns_message import (
    DNSResourceRecord,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_TXT,
    type_to_str,
)


MAX_CACHE_ENTRIES = 10000
MIN_TTL = 0
MAX_TTL = 86400 * 7


class CacheEntry:
    """
    A cache entry holds multiple resource records for the same (name, type) key.
    Each RR has its own independent expiration timestamp derived from its own TTL.
    """

    __slots__ = ("records", "created_at")

    def __init__(self):
        self.records = []
        self.created_at = time.time()

    def add_record(self, rr):
        expires_at = time.time() + max(MIN_TTL, min(rr.ttl, MAX_TTL))
        self.records.append((rr, expires_at))

    def get_valid_records(self, now=None):
        """Return only the records that haven't expired yet, each with its own TTL."""
        if now is None:
            now = time.time()
        valid = []
        for rr, expires_at in self.records:
            remaining = int(expires_at - now)
            if remaining > 0:
                rr_copy = DNSResourceRecord()
                rr_copy.name = rr.name
                rr_copy.rtype = rr.rtype
                rr_copy.rclass = rr.rclass
                rr_copy.ttl = remaining
                rr_copy.rdata = rr.rdata
                valid.append(rr_copy)
        return valid

    def is_empty(self, now=None):
        """Check if all records in this entry have expired."""
        if now is None:
            now = time.time()
        for _, expires_at in self.records:
            if expires_at > now:
                return False
        return True

    def min_ttl(self, now=None):
        """Return the minimum remaining TTL across all records (for negative caching etc.)."""
        if now is None:
            now = time.time()
        remaining = [int(expires_at - now) for _, expires_at in self.records if expires_at > now]
        if not remaining:
            return 0
        return min(remaining)


class DNSCache:
    """
    Thread-safe DNS cache.

    Key design:
    - Cache key is (name_lowercase, qtype)
    - Each key maps to a CacheEntry containing multiple RRs
    - Each RR has its own expiration time derived from its own TTL
    - Background cleanup periodically removes fully-expired entries
    """

    def __init__(self, max_entries=MAX_CACHE_ENTRIES):
        self._cache = {}
        self._lock = threading.RLock()
        self._max_entries = max_entries
        self._hits = 0
        self._misses = 0
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        self._start_cleanup()

    def _start_cleanup(self):
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="dns-cache-cleanup"
        )
        self._cleanup_thread.start()

    def stop(self):
        self._stop_cleanup.set()

    def _cleanup_loop(self):
        while not self._stop_cleanup.is_set():
            time.sleep(60)
            self._cleanup()

    def _cleanup(self):
        """Remove entries where all records have expired."""
        now = time.time()
        with self._lock:
            expired_keys = []
            for key, entry in self._cache.items():
                if entry.is_empty(now):
                    expired_keys.append(key)
            for key in expired_keys:
                del self._cache[key]
            if len(self._cache) > self._max_entries:
                items = sorted(
                    self._cache.items(),
                    key=lambda kv: kv[1].created_at,
                )
                excess = len(self._cache) - self._max_entries
                for key, _ in items[:excess]:
                    del self._cache[key]

    @staticmethod
    def _cache_key(name, qtype):
        return (name.lower(), qtype)

    def get(self, name, qtype):
        """
        Look up cached records for (name, qtype).

        Returns a list of valid (non-expired) DNSResourceRecord objects, or None if no valid records.
        Each returned RR has its TTL adjusted to the remaining time.
        """
        key = self._cache_key(name, qtype)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            valid = entry.get_valid_records()
            if not valid:
                self._misses += 1
                return None
            self._hits += 1
            return valid

    def get_with_cname_follow(self, name, qtype, max_depth=10):
        """
        Look up records, following CNAME chains.

        Returns:
            (records_list, cname_chain_list)
            records_list contains the final matching records for qtype
            cname_chain_list contains all CNAME records followed along the way
        """
        current_name = name.lower()
        cname_chain = []
        visited = set()

        for _ in range(max_depth):
            if current_name in visited:
                return [], cname_chain
            visited.add(current_name)

            records = self.get(current_name, qtype)
            if records:
                return records, cname_chain

            cname_records = self.get(current_name, TYPE_CNAME)
            if cname_records:
                cname_rr = cname_records[0]
                cname_chain.append(cname_rr)
                try:
                    target = cname_rr.parse_rdata()
                    if target:
                        current_name = target.lower()
                        continue
                except Exception:
                    pass
            break

        return [], cname_chain

    def put(self, records):
        """
        Store one or more resource records in the cache.

        Records are grouped by (name, type) into CacheEntry objects.
        Each RR keeps its own TTL and expiration time.
        """
        if not records:
            return
        with self._lock:
            for rr in records:
                if rr.ttl <= 0:
                    continue
                key = self._cache_key(rr.name, rr.rtype)
                entry = self._cache.get(key)
                if entry is None:
                    entry = CacheEntry()
                    self._cache[key] = entry
                entry.add_record(rr)

    def put_response_records(self, message):
        """Cache all resource records from a DNS response."""
        all_records = message.answers + message.authorities + message.additionals
        cacheable = []
        for rr in all_records:
            if rr.rtype in (TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX, TYPE_NS, TYPE_TXT):
                if rr.rclass == 1:
                    cacheable.append(rr)
        self.put(cacheable)

    def stats(self):
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0.0
            return {
                "entries": len(self._cache),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate,
            }

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
