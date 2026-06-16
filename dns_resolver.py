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
    CLASS_IN,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    parse_domain_name,
    DNSSecurityError,
    DNSParseError,
    MAX_MESSAGE_SIZE,
    MAX_UDP_PAYLOAD,
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
MAX_RETRIES = 3


logger = logging.getLogger("dns.resolver")


class ResolveError(Exception):
    pass


class DNSResolver:
    """
    Recursive DNS resolver with caching and singleflight deduplication.

    Resolution flow:
    1. Check cache (following CNAME chains)
    2. If not cached, use singleflight to de-duplicate concurrent requests for same (name, type)
    3. Send query to upstream DNS servers (with retries and fallback)
    4. Parse response, follow CNAME chains if needed
    5. Cache all records with their individual TTLs
    6. Return results
    """

    def __init__(self, upstream_servers=None, cache=None):
        if upstream_servers is None:
            upstream_servers = list(DEFAULT_UPSTREAM)
        self.upstream_servers = upstream_servers
        self.cache = cache if cache is not None else DNSCache()
        self.singleflight = Singleflight(default_timeout=UPSTREAM_TIMEOUT * 2)
        self._lock = threading.Lock()
        self._socket = None
        self._ensure_socket()

    def _ensure_socket(self):
        if self._socket is None:
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.settimeout(UPSTREAM_TIMEOUT)
            except OSError:
                self._socket = None

    def _send_query_upstream(self, name, qtype):
        """Send a single DNS query to an upstream server and return the parsed response."""
        query = DNSMessage()
        query.header.id = random.randint(0, 0xFFFF)
        query.header.rd = 1
        query.header.qdcount = 1

        q = DNSQuestion()
        q.qname = name
        q.qtype = qtype
        q.qclass = CLASS_IN
        query.questions.append(q)

        query_data = query.pack(max_size=MAX_UDP_PAYLOAD)

        last_error = None
        servers = list(self.upstream_servers)
        random.shuffle(servers)

        for server in servers:
            for attempt in range(MAX_RETRIES):
                try:
                    self._ensure_socket()
                    if self._socket is None:
                        raise ResolveError("Failed to create socket")

                    self._socket.sendto(query_data, server)
                    try:
                        response_data, _ = self._socket.recvfrom(MAX_MESSAGE_SIZE)
                    except socket.timeout:
                        last_error = f"Timeout querying {server}"
                        continue
                    except OSError as e:
                        last_error = f"Network error from {server}: {e}"
                        self._socket = None
                        continue

                    if len(response_data) < 12:
                        last_error = f"Truncated response from {server}"
                        continue

                    response_id = struct.unpack_from("!H", response_data, 0)[0]
                    if response_id != query.header.id:
                        last_error = f"ID mismatch from {server}"
                        continue

                    try:
                        response = DNSMessage.unpack(response_data)
                        return response
                    except (DNSParseError, DNSSecurityError) as e:
                        last_error = f"Parse error from {server}: {e}"
                        continue
                    except Exception as e:
                        last_error = f"Unexpected error parsing response: {e}"
                        continue

                except Exception as e:
                    last_error = str(e)
                    continue

        raise ResolveError(
            f"All upstream servers failed. Last error: {last_error}"
        )

    def _resolve_upstream(self, name, qtype):
        """
        Resolve a name by querying upstream, following CNAME chains.

        Returns a list of DNSResourceRecord objects (the final answer records).
        """
        current_name = name
        visited_cnames = set()
        all_records = []
        final_answer = []

        for depth in range(MAX_CNAME_CHAIN):
            if current_name.lower() in visited_cnames:
                raise ResolveError("CNAME loop detected")
            visited_cnames.add(current_name.lower())

            response = self._send_query_upstream(current_name, qtype)

            if response.header.rcode == RCODE_NXDOMAIN:
                self.cache.put_response_records(response)
                return [], response

            if response.header.rcode != RCODE_NOERROR:
                raise ResolveError(
                    f"Upstream returned rcode {response.header.rcode}"
                )

            self.cache.put_response_records(response)
            all_records.extend(response.answers)

            direct_answers = [
                rr for rr in response.answers
                if rr.rtype == qtype and rr.name.lower() == current_name.lower()
            ]
            if direct_answers:
                final_answer = direct_answers
                break

            cname_answers = [
                rr for rr in response.answers
                if rr.rtype == TYPE_CNAME and rr.name.lower() == current_name.lower()
            ]
            if cname_answers:
                cname_rr = cname_answers[0]
                try:
                    target = cname_rr.parse_rdata()
                    if target:
                        current_name = target
                        continue
                except Exception:
                    pass
                break

            if response.answers:
                final_answer = list(response.answers)
                break

            if not response.answers and (response.authorities or response.additionals):
                break

        return final_answer, response if 'response' in locals() else None

    def resolve(self, name, qtype):
        """
        Resolve a DNS name and type.

        Uses:
        1. Cache lookup first (following CNAME chains)
        2. Singleflight for upstream deduplication

        Returns list of DNSResourceRecord.
        """
        cached, cname_chain = self.cache.get_with_cname_follow(name, qtype)
        if cached:
            return cname_chain + cached

        key = (name.lower(), qtype)

        def do_work():
            return self._resolve_upstream(name, qtype)

        result, error, was_dup = self.singleflight.do(key, do_work)

        if error is not None:
            raise error

        final_answers, _ = result

        cached, cname_chain = self.cache.get_with_cname_follow(name, qtype)
        if cached:
            return cname_chain + cached

        return final_answers

    def stats(self):
        return {
            "cache": self.cache.stats(),
            "singleflight": self.singleflight.stats(),
        }
