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
    TYPE_SOA,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    type_to_str,
)


MAX_CACHE_ENTRIES = 10000
MIN_TTL = 0
MAX_TTL = 86400 * 7
DEFAULT_NEGATIVE_TTL = 300
MAX_NEGATIVE_TTL = 3600


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
                rr_copy._message_context = getattr(rr, "_message_context", None)
                rr_copy._rdata_offset = getattr(rr, "_rdata_offset", 0)
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
        """Return the minimum remaining TTL across all records."""
        if now is None:
            now = time.time()
        remaining = [int(expires_at - now) for _, expires_at in self.records if expires_at > now]
        if not remaining:
            return 0
        return min(remaining)


class NegativeCacheEntry:
    """
    Negative cache entry for storing NXDOMAIN, SERVFAIL, etc.
    """

    __slots__ = ("rcode", "expires_at", "created_at", "soa_ttl")

    def __init__(self, rcode, ttl):
        self.rcode = rcode
        self.expires_at = time.time() + max(1, min(ttl, MAX_NEGATIVE_TTL))
        self.created_at = time.time()
        self.soa_ttl = ttl

    def is_valid(self, now=None):
        if now is None:
            now = time.time()
        return now < self.expires_at

    def remaining_ttl(self, now=None):
        if now is None:
            now = time.time()
        remaining = int(self.expires_at - now)
        return max(0, remaining)


class DNSCache:
    """
    Thread-safe DNS cache with positive and negative caching.

    Key design:
    - Cache key is (name_lowercase, qtype)
    - Each key maps to a CacheEntry containing multiple RRs
    - Each RR has its own expiration time derived from its own TTL
    - Negative cache stores NXDOMAIN / SERVFAIL responses
    - Background cleanup periodically removes fully-expired entries
    """

    def __init__(self, max_entries=MAX_CACHE_ENTRIES):
        self._cache = {}
        self._negative_cache = {}
        self._lock = threading.RLock()
        self._max_entries = max_entries

        self._hits = 0
        self._misses = 0
        self._negative_hits = 0
        self._negative_stores = 0

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

            neg_expired = []
            for key, entry in self._negative_cache.items():
                if not entry.is_valid(now):
                    neg_expired.append(key)
            for key in neg_expired:
                del self._negative_cache[key]

            if len(self._cache) + len(self._negative_cache) > self._max_entries:
                total = len(self._cache) + len(self._negative_cache)
                excess = total - self._max_entries
                all_items = sorted(
                    [(k, v.created_at, "pos") for k, v in self._cache.items()]
                    + [(k, v.created_at, "neg") for k, v in self._negative_cache.items()],
                    key=lambda x: x[1],
                )
                for key, _, kind in all_items[:excess]:
                    if kind == "pos":
                        del self._cache[key]
                    else:
                        del self._negative_cache[key]

    @staticmethod
    def _cache_key(name, qtype):
        return (name.lower(), qtype)

    def get(self, name, qtype):
        """
        Look up cached records for (name, qtype).

        Returns a list of valid (non-expired) DNSResourceRecord objects,
        or None if no valid records.
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

    def get_negative(self, name, qtype):
        """
        Check if this (name, type) has a negative cache entry.

        Returns (rcode, remaining_ttl) or None.
        """
        key = self._cache_key(name, qtype)
        with self._lock:
            entry = self._negative_cache.get(key)
            if entry is None:
                return None
            if not entry.is_valid():
                del self._negative_cache[key]
                return None
            self._negative_hits += 1
            return entry.rcode, entry.remaining_ttl()

    def put_negative(self, name, qtype, rcode, ttl=None):
        """
        Store a negative cache entry.

        Args:
            name: domain name
            qtype: query type
            rcode: response code (NXDOMAIN, SERVFAIL, etc.)
            ttl: TTL in seconds. If None, uses default.
        """
        if ttl is None:
            ttl = DEFAULT_NEGATIVE_TTL
        if ttl <= 0:
            return

        key = self._cache_key(name, qtype)
        with self._lock:
            entry = NegativeCacheEntry(rcode, ttl)
            self._negative_cache[key] = entry
            self._negative_stores += 1

    def get_with_cname_follow(self, name, qtype, max_depth=10):
        """
        Look up records, following CNAME chains entirely from cache.

        Returns:
            (records_list, cname_chain_list, complete)
            - records_list: final matching records for qtype (may be empty)
            - cname_chain_list: all CNAME records followed from cache
            - complete: True if we found final qtype records, False if chain incomplete
        """
        current_name = name.lower()
        cname_chain = []
        visited = set()

        for _ in range(max_depth):
            if current_name in visited:
                return [], cname_chain, False
            visited.add(current_name)

            records = self.get(current_name, qtype)
            if records:
                return records, cname_chain, True

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

        return [], cname_chain, False

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

    def _extract_soa_min_ttl(self, message):
        """Try to extract SOA TTL or minimum TTL from authority section."""
        for rr in message.authorities:
            if rr.rtype == TYPE_SOA:
                if rr.ttl > 0:
                    return min(rr.ttl, DEFAULT_NEGATIVE_TTL)
        return None

    def put_response_records(self, message, query_name=None, query_type=None):
        """
        Cache all resource records from a DNS response, and handle negative caching.

        Args:
            message: DNSMessage response
            query_name: the original query name (for negative cache key)
            query_type: the original query type (for negative cache key)
        """
        all_records = message.answers + message.authorities + message.additionals
        cacheable = []
        for rr in all_records:
            if rr.rtype in (
                TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX,
                TYPE_NS, TYPE_TXT, TYPE_SOA,
            ):
                if rr.rclass == 1:
                    cacheable.append(rr)
        self.put(cacheable)

        if query_name is not None and query_type is not None:
            if message.header.rcode == RCODE_NXDOMAIN:
                soa_ttl = self._extract_soa_min_ttl(message)
                ttl = soa_ttl if soa_ttl and soa_ttl > 0 else DEFAULT_NEGATIVE_TTL
                self.put_negative(query_name, query_type, RCODE_NXDOMAIN, ttl)
            elif message.header.rcode == RCODE_SERVFAIL:
                self.put_negative(query_name, query_type, RCODE_SERVFAIL, DEFAULT_NEGATIVE_TTL)

    def stats(self):
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0.0
            neg_total = self._negative_hits + self._negative_stores
            return {
                "entries": len(self._cache),
                "negative_entries": len(self._negative_cache),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate,
                "negative_hits": self._negative_hits,
                "negative_stores": self._negative_stores,
            }

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._negative_cache.clear()
            self._hits = 0
            self._misses = 0
            self._negative_hits = 0
            self._negative_stores = 0
