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
TOTAL_RESOLVE_TIMEOUT = 30.0
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5


logger = logging.getLogger("dns.resolver")


class ResolveError(Exception):
    pass


class DNSResolver:
    """
    Recursive DNS resolver with caching and singleflight deduplication.

    Key improvements:
    - Each upstream query uses its own UDP socket (no shared socket race conditions)
    - Full CNAME chain is collected and returned (not just final answers)
    - Longer singleflight timeout matches total possible upstream time
    - Better retry with exponential backoff and server rotation
    - Stable concurrent query handling
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

    def _get_next_server(self):
        """Round-robin server selection."""
        with self._rotation_lock:
            idx = self._server_rotation % len(self.upstream_servers)
            self._server_rotation += 1
            return self.upstream_servers[idx]

    def _send_query_upstream(self, name, qtype, timeout=UPSTREAM_TIMEOUT):
        """
        Send a single DNS query to upstream servers.

        Uses a fresh UDP socket per call to avoid concurrent access issues.
        Tries multiple servers with retries and exponential backoff.
        """
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
        expected_id = query.header.id

        last_error = None
        servers = list(self.upstream_servers)
        random.shuffle(servers)

        for attempt in range(MAX_RETRIES):
            for server in servers:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(timeout)

                    sock.sendto(query_data, server)
                    try:
                        response_data, _ = sock.recvfrom(MAX_MESSAGE_SIZE)
                    except socket.timeout:
                        last_error = f"Timeout querying {server} (attempt {attempt+1})"
                        continue
                    except OSError as e:
                        last_error = f"Network error from {server}: {e}"
                        continue
                    finally:
                        try:
                            sock.close()
                        except Exception:
                            pass

                    if len(response_data) < 12:
                        last_error = f"Truncated response from {server}"
                        continue

                    try:
                        response_id = struct.unpack_from("!H", response_data, 0)[0]
                        if response_id != expected_id:
                            last_error = f"ID mismatch from {server}"
                            continue
                    except Exception as e:
                        last_error = f"Error reading ID from {server}: {e}"
                        continue

                    try:
                        response = DNSMessage.unpack(response_data)
                    except (DNSParseError, DNSSecurityError) as e:
                        last_error = f"Parse error from {server}: {e}"
                        continue
                    except Exception as e:
                        last_error = f"Unexpected error parsing response: {e}"
                        continue

                    return response

                except Exception as e:
                    last_error = str(e)
                    if sock:
                        try:
                            sock.close()
                        except Exception:
                            pass
                    continue

            if attempt < MAX_RETRIES - 1:
                backoff = RETRY_BACKOFF_BASE * (2 ** attempt)
                time.sleep(backoff)

        raise ResolveError(
            f"All upstream servers failed after {MAX_RETRIES} attempts. Last error: {last_error}"
        )

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
                raise ResolveError("CNAME loop detected")
            visited_cnames.add(current_name_lower)

            response = self._send_query_upstream(current_name, qtype)
            last_response = response

            if response.header.rcode == RCODE_NXDOMAIN:
                self.cache.put_response_records(response)
                return full_chain, response

            if response.header.rcode != RCODE_NOERROR:
                raise ResolveError(
                    f"Upstream returned rcode {response.header.rcode}"
                )

            self.cache.put_response_records(response)

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
                try:
                    target = cname_rr.parse_rdata()
                    if target:
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
        1. Cache lookup (follows CNAME chains)
        2. Singleflight deduplication for upstream queries
        3. Returns full CNAME chain + final answers

        Returns list of DNSResourceRecord.
        """
        cached, cname_chain = self.cache.get_with_cname_follow(name, qtype)
        if cached:
            return cname_chain + cached

        key = (name.lower(), qtype)

        def do_work():
            return self._resolve_upstream(name, qtype)

        result, error, was_dup = self.singleflight.do(
            key, do_work, timeout=TOTAL_RESOLVE_TIMEOUT
        )

        if error is not None:
            raise error

        upstream_chain, _ = result

        cached, cname_chain = self.cache.get_with_cname_follow(name, qtype)
        if cached:
            return cname_chain + cached

        return upstream_chain

    def stats(self):
        return {
            "cache": self.cache.stats(),
            "singleflight": self.singleflight.stats(),
        }
