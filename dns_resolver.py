import socket
import struct
import random
import time
import threading
import logging

from dns_message import (
    DNSMessage,
    DNSQuestion,
    DNSResourceRecord,
    DNSHeader,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_ANY,
    TYPE_OPT,
    CLASS_IN,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    parse_domain_name,
    encode_domain_name,
    DNSSecurityError,
    DNSParseError,
    MAX_MESSAGE_SIZE,
    MAX_UDP_PAYLOAD,
    MAX_EDNS_PAYLOAD,
)
from dns_cache import DNSCache
from singleflight import Singleflight


DEFAULT_UPSTREAM = [
    ("8.8.8.8", 53),
    ("8.8.4.4", 53),
    ("1.1.1.1", 53),
    ("1.0.0.1", 53),
]

MAX_CNAME_CHAIN = 10
UPSTREAM_TIMEOUT = 5.0
TOTAL_RESOLVE_TIMEOUT = 30.0
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5
TCP_TIMEOUT = 10.0


logger = logging.getLogger("dns.resolver")


class ResolveError(Exception):
    def __init__(self, message, rcode=RCODE_SERVFAIL):
        super().__init__(message)
        self.rcode = rcode


class DNSResolver:
    """
    Recursive DNS resolver with caching, singleflight, TCP fallback, and EDNS0.

    Key features:
    - Per-query UDP sockets (no shared socket race conditions)
    - TCP fallback when UDP response is truncated (TC bit set)
    - EDNS0 support for larger UDP payloads (4096 bytes)
    - Full CNAME chain collection and return
    - Negative caching for NXDOMAIN / SERVFAIL
    - Singleflight deduplication with long timeout support
    - Exponential backoff retries with multiple upstream servers
    - Detailed statistics tracking
    """

    def __init__(self, upstream_servers=None, cache=None):
        if upstream_servers is None:
            upstream_servers = list(DEFAULT_UPSTREAM)
        self.upstream_servers = upstream_servers
        self.cache = cache if cache is not None else DNSCache()
        self.singleflight = Singleflight(default_timeout=TOTAL_RESOLVE_TIMEOUT)
        self._lock = threading.Lock()
        self._server_rotation = 0
        self._rotation_lock = threading.Lock()

        self._stats = {
            "total_queries": 0,
            "cache_hits": 0,
            "negative_cache_hits": 0,
            "upstream_queries": 0,
            "tcp_fallbacks": 0,
            "singleflight_dedups": 0,
            "cname_followed": 0,
            "nxdomain_count": 0,
            "servfail_count": 0,
            "upstream_time_total": 0.0,
            "upstream_time_count": 0,
            "retries_total": 0,
            "truncated_count": 0,
        }
        self._stats_lock = threading.Lock()

    def _inc_stat(self, key, value=1):
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + value

    def _get_next_server(self):
        """Round-robin server selection."""
        with self._rotation_lock:
            idx = self._server_rotation % len(self.upstream_servers)
            self._server_rotation += 1
            return self.upstream_servers[idx]

    def _build_query(self, name, qtype, id=None, edns=True):
        """Build a DNS query message."""
        query = DNSMessage()
        query.header.id = id if id is not None else random.randint(0, 0xFFFF)
        query.header.rd = 1
        query.header.qdcount = 1

        q = DNSQuestion()
        q.qname = name
        q.qtype = qtype
        q.qclass = CLASS_IN
        query.questions.append(q)

        if edns:
            opt_rr = DNSResourceRecord()
            opt_rr.name = ""
            opt_rr.rtype = TYPE_OPT
            opt_rr.rclass = MAX_EDNS_PAYLOAD
            opt_rr.ttl = 0
            opt_rr.rdata = b""
            query.additionals.append(opt_rr)
            query.header.arcount = 1

        return query

    def _send_udp_query(self, server, query_data, expected_id, timeout):
        """
        Send a UDP DNS query and receive the response.

        Returns response data or None on failure.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query_data, server)
            response_data, _ = sock.recvfrom(MAX_MESSAGE_SIZE)
            return response_data
        except (socket.timeout, OSError):
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _send_tcp_query(self, server, query_data, expected_id, timeout):
        """
        Send a TCP DNS query (with 2-byte length prefix) and receive response.

        Returns response data or None on failure.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(server)

            tcp_query = struct.pack("!H", len(query_data)) + query_data
            sock.sendall(tcp_query)

            length_data = b""
            while len(length_data) < 2:
                chunk = sock.recv(2 - len(length_data))
                if not chunk:
                    return None
                length_data += chunk

            msg_length = struct.unpack("!H", length_data)[0]
            if msg_length > MAX_MESSAGE_SIZE or msg_length < 12:
                return None

            response_data = b""
            while len(response_data) < msg_length:
                chunk = sock.recv(min(4096, msg_length - len(response_data)))
                if not chunk:
                    return None
                response_data += chunk

            return response_data
        except (socket.timeout, OSError, struct.error):
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _validate_response(self, response_data, expected_id):
        """
        Validate a DNS response.

        Returns DNSMessage or None if invalid.
        """
        if not response_data or len(response_data) < 12:
            return None

        try:
            response_id = struct.unpack_from("!H", response_data, 0)[0]
            if response_id != expected_id:
                return None

            response = DNSMessage.unpack(response_data)
            return response
        except (DNSParseError, DNSSecurityError, struct.error):
            return None

    def _query_upstream(self, name, qtype, timeout=UPSTREAM_TIMEOUT, use_tcp=False):
        """
        Send a DNS query to upstream servers with retries.

        Tries each server with retries and exponential backoff.
        Falls back to TCP if UDP returns truncated response.

        Returns (response, used_tcp) or raises ResolveError.
        """
        query_id = random.randint(0, 0xFFFF)
        query = self._build_query(name, qtype, id=query_id, edns=not use_tcp)
        query_data = query.pack(max_size=MAX_MESSAGE_SIZE)

        last_error = None
        servers = list(self.upstream_servers)
        random.shuffle(servers)

        for attempt in range(MAX_RETRIES):
            for server in servers:
                start = time.time()

                if use_tcp:
                    self._inc_stat("tcp_fallbacks")
                    response_data = self._send_tcp_query(
                        server, query_data, query_id, timeout
                    )
                else:
                    response_data = self._send_udp_query(
                        server, query_data, query_id, timeout
                    )

                if response_data is None:
                    last_error = f"No response from {server}"
                    continue

                response = self._validate_response(response_data, query_id)
                if response is None:
                    last_error = f"Invalid response from {server}"
                    continue

                elapsed = time.time() - start
                self._inc_stat("upstream_time_total", elapsed)
                self._inc_stat("upstream_time_count")
                self._inc_stat("upstream_queries")

                if response.header.tc and not use_tcp:
                    self._inc_stat("truncated_count")
                    logger.debug(f"Truncated response from {server}, falling back to TCP")
                    tcp_response = self._query_upstream_tcp_only(name, qtype, timeout)
                    if tcp_response is not None:
                        self._inc_stat("tcp_fallbacks")
                        return tcp_response, True
                    last_error = "TCP fallback failed"
                    continue

                return response, use_tcp

            if attempt < MAX_RETRIES - 1:
                self._inc_stat("retries_total")
                backoff = RETRY_BACKOFF_BASE * (2 ** attempt)
                time.sleep(backoff)

        raise ResolveError(
            f"All upstream servers failed after {MAX_RETRIES} attempts. Last error: {last_error}"
        )

    def _query_upstream_tcp_only(self, name, qtype, timeout):
        """Try TCP query to all servers, return first success or None."""
        query_id = random.randint(0, 0xFFFF)
        query = self._build_query(name, qtype, id=query_id, edns=False)
        query_data = query.pack(max_size=MAX_MESSAGE_SIZE)

        servers = list(self.upstream_servers)
        random.shuffle(servers)

        for server in servers:
            response_data = self._send_tcp_query(server, query_data, query_id, timeout)
            if response_data is None:
                continue
            response = self._validate_response(response_data, query_id)
            if response is not None:
                return response
        return None

    def _resolve_upstream(self, name, qtype):
        """
        Resolve a name by querying upstream, following CNAME chains.

        Returns (full_chain_records, last_response)
        where full_chain_records includes all CNAMEs followed + final answers.
        """
        current_name = name
        visited_cnames = set()
        full_chain = []
        last_response = None

        for depth in range(MAX_CNAME_CHAIN):
            current_name_lower = current_name.lower()
            if current_name_lower in visited_cnames:
                raise ResolveError("CNAME loop detected", RCODE_SERVFAIL)
            visited_cnames.add(current_name_lower)

            negative = self.cache.get_negative(current_name, qtype)
            if negative is not None:
                rcode, ttl = negative
                self._inc_stat("negative_cache_hits")
                if rcode == RCODE_NXDOMAIN:
                    self._inc_stat("nxdomain_count")
                elif rcode == RCODE_SERVFAIL:
                    self._inc_stat("servfail_count")
                raise ResolveError(f"Negative cache hit: rcode={rcode}", rcode)

            response, _ = self._query_upstream(current_name, qtype)
            last_response = response

            self.cache.put_response_records(
                response, query_name=current_name, query_type=qtype
            )

            if response.header.rcode == RCODE_NXDOMAIN:
                self._inc_stat("nxdomain_count")
                raise ResolveError("NXDOMAIN from upstream", RCODE_NXDOMAIN)

            if response.header.rcode != RCODE_NOERROR:
                self._inc_stat("servfail_count")
                raise ResolveError(
                    f"Upstream returned rcode {response.header.rcode}",
                    response.header.rcode,
                )

            direct_answers = [
                rr for rr in response.answers
                if rr.rtype == qtype and rr.name.lower() == current_name_lower
            ]
            if direct_answers:
                full_chain.extend(direct_answers)
                break

            cname_answers = [
                rr for rr in response.answers
                if rr.rtype == TYPE_CNAME and rr.name.lower() == current_name_lower
            ]
            if cname_answers:
                cname_rr = cname_answers[0]
                full_chain.append(cname_rr)
                self._inc_stat("cname_followed")
                try:
                    target = cname_rr.parse_rdata()
                    if target:
                        target_lower = target.lower()
                        chain_target = target_lower
                        chain_visited = {current_name_lower}
                        found_in_response = False
                        for _ in range(MAX_CNAME_CHAIN):
                            if chain_target in chain_visited:
                                break
                            chain_visited.add(chain_target)
                            final_answers = [
                                rr for rr in response.answers
                                if rr.rtype == qtype and rr.name.lower() == chain_target
                            ]
                            if final_answers:
                                full_chain.extend(final_answers)
                                found_in_response = True
                                break
                            next_cname = [
                                rr for rr in response.answers
                                if rr.rtype == TYPE_CNAME and rr.name.lower() == chain_target
                            ]
                            if next_cname:
                                nc = next_cname[0]
                                full_chain.append(nc)
                                self._inc_stat("cname_followed")
                                try:
                                    nt = nc.parse_rdata()
                                    if nt:
                                        chain_target = nt.lower()
                                        continue
                                except Exception:
                                    pass
                            break
                        if found_in_response:
                            break
                        current_name = target
                        continue
                except Exception:
                    pass
                break

            if response.answers:
                full_chain.extend(response.answers)
                break

            break

        return full_chain, last_response

    def resolve(self, name, qtype):
        """
        Resolve a DNS name and type.

        Flow:
        1. Check negative cache
        2. Positive cache lookup (follows CNAME chains)
        3. Singleflight deduplication for upstream queries
        4. Returns full CNAME chain + final answers

        Returns list of DNSResourceRecord.
        Raises ResolveError on failure.
        """
        self._inc_stat("total_queries")

        negative = self.cache.get_negative(name, qtype)
        if negative is not None:
            rcode, ttl = negative
            self._inc_stat("negative_cache_hits")
            if rcode == RCODE_NXDOMAIN:
                self._inc_stat("nxdomain_count")
                raise ResolveError("NXDOMAIN (negative cache)", RCODE_NXDOMAIN)
            elif rcode == RCODE_SERVFAIL:
                self._inc_stat("servfail_count")
                raise ResolveError("SERVFAIL (negative cache)", RCODE_SERVFAIL)

        cached, cname_chain, complete = self.cache.get_with_cname_follow(name, qtype)
        if complete and cached:
            self._inc_stat("cache_hits")
            return cname_chain + cached

        key = (name.lower(), qtype)

        def do_work():
            return self._resolve_upstream(name, qtype)

        result, error, was_dup = self.singleflight.do(
            key, do_work, timeout=TOTAL_RESOLVE_TIMEOUT
        )

        if was_dup:
            self._inc_stat("singleflight_dedups")

        if error is not None:
            raise error

        upstream_chain, _ = result

        cached, cname_chain, complete = self.cache.get_with_cname_follow(name, qtype)
        if complete and cached:
            return cname_chain + cached

        return upstream_chain

    def stats(self):
        """Get detailed resolver statistics."""
        with self._stats_lock:
            s = dict(self._stats)

        cache_stats = self.cache.stats()
        sf_stats = self.singleflight.stats()

        if s["upstream_time_count"] > 0:
            s["avg_upstream_latency_ms"] = int(
                (s["upstream_time_total"] / s["upstream_time_count"]) * 1000
            )
        else:
            s["avg_upstream_latency_ms"] = 0

        s["cache"] = cache_stats
        s["singleflight"] = sf_stats

        return s

    def reset_stats(self):
        """Reset all statistics counters."""
        with self._stats_lock:
            for k in list(self._stats.keys()):
                self._stats[k] = 0
        self.cache.clear()
        self.singleflight.reset_stats()
