import socket
import threading
import logging
import time
import select

from dns_message import (
    DNSMessage,
    DNSResourceRecord,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_TXT,
    TYPE_ANY,
    CLASS_IN,
    RCODE_NOERROR,
    RCODE_FORMERR,
    RCODE_SERVFAIL,
    RCODE_NXDOMAIN,
    RCODE_REFUSED,
    RCODE_NOTIMP,
    MAX_UDP_PAYLOAD,
    MAX_MESSAGE_SIZE,
    DNSSecurityError,
    DNSParseError,
    type_to_str,
)
from dns_cache import DNSCache
from dns_resolver import DNSResolver, ResolveError
from dns_authority import AuthorityStore


logger = logging.getLogger("dns.server")

MAX_REQUESTS_PER_SECOND = 1000


class DNSServer:
    """
    Full-featured DNS server.

    Features:
    - Authoritative zones with direct answer
    - Recursive resolution with upstream fallback
    - Per-record TTL caching
    - Singleflight concurrent deduplication
    - Security protections against malformed/attack packets
    """

    def __init__(
        self,
        host="0.0.0.0",
        port=53,
        upstream_servers=None,
        allow_recursion=True,
    ):
        self.host = host
        self.port = port
        self.allow_recursion = allow_recursion
        self.cache = DNSCache()
        self.resolver = DNSResolver(upstream_servers=upstream_servers, cache=self.cache)
        self.authority = AuthorityStore()
        self._udp_socket = None
        self._tcp_socket = None
        self._running = False
        self._threads = []
        self._request_times = []
        self._rate_lock = threading.Lock()

    def add_authoritative_zone(self, origin, default_ttl=3600):
        """Create and add an authoritative zone."""
        return self.authority.create_zone(origin, default_ttl)

    def _check_rate_limit(self):
        """Basic rate limiting to prevent abuse."""
        now = time.time()
        with self._rate_lock:
            self._request_times = [
                t for t in self._request_times if now - t < 1.0
            ]
            if len(self._request_times) >= MAX_REQUESTS_PER_SECOND:
                return False
            self._request_times.append(now)
            return True

    def _handle_query(self, query_msg, addr, proto="udp"):
        """
        Process a parsed DNS query and return a response message.

        Flow:
        1. Validate query
        2. Check authoritative records
        3. Check cache
        4. If recursion allowed and needed, resolve upstream via resolver
        """
        response = query_msg.make_response()
        response.header.ra = 1 if self.allow_recursion else 0

        q = query_msg.get_question()
        if q is None:
            response.header.rcode = RCODE_FORMERR
            return response

        qname = q.qname
        qtype = q.qtype
        qclass = q.qclass

        logger.debug(
            "Query from %s: %s %s %s",
            addr,
            type_to_str(qtype),
            qclass,
            qname,
        )

        if qtype in (TYPE_ANY,):
            response.header.rcode = RCODE_NOTIMP
            return response

        authority_records, is_auth, zone_origin = self.authority.lookup(qname, qtype)
        if authority_records:
            response.header.aa = 1 if is_auth else 0
            response.answers = authority_records
            response.header.ancount = len(response.answers)
            return response

        if is_auth and zone_origin:
            cname_records, _, _ = self.authority.lookup(qname, TYPE_CNAME)
            if cname_records:
                response.answers = cname_records
                response.header.ancount = len(response.answers)
                return response

            if self.allow_recursion and query_msg.header.rd:
                cname_check, _, _ = self.authority.lookup(qname, TYPE_CNAME)
                if not cname_check:
                    response.header.aa = 1
                    response.header.rcode = RCODE_NXDOMAIN
                    return response

        if not self.allow_recursion:
            response.header.rcode = RCODE_REFUSED
            return response

        if not query_msg.header.rd:
            return response

        try:
            resolved = self.resolver.resolve(qname, qtype)
            if resolved:
                response.answers = resolved
                response.header.ancount = len(response.answers)
        except ResolveError as e:
            logger.debug("Resolve error for %s: %s", qname, e)
            response.header.rcode = e.rcode
        except DNSSecurityError as e:
            logger.warning("Security error resolving %s: %s", qname, e)
            response.header.rcode = RCODE_SERVFAIL
        except DNSParseError as e:
            logger.warning("Parse error resolving %s: %s", qname, e)
            response.header.rcode = RCODE_SERVFAIL
        except Exception as e:
            logger.warning("Error resolving %s: %s", qname, e)
            response.header.rcode = RCODE_SERVFAIL

        return response

    def _handle_udp_packet(self, data, addr):
        """Handle a single incoming UDP DNS packet."""
        if not self._check_rate_limit():
            return

        if len(data) > MAX_MESSAGE_SIZE:
            return

        if len(data) < 12:
            return

        try:
            query = DNSMessage.unpack(data)
        except DNSSecurityError as e:
            logger.warning("Rejected packet from %s (security): %s", addr, e)
            resp = DNSMessage()
            resp.header.id = 0
            try:
                resp.header.id = int.from_bytes(data[0:2], "big")
            except Exception:
                pass
            resp.header.qr = 1
            resp.header.rcode = RCODE_FORMERR
            try:
                self._udp_socket.sendto(resp.pack(), addr)
            except Exception:
                pass
            return
        except DNSParseError as e:
            logger.debug("Parse error from %s: %s", addr, e)
            return
        except Exception as e:
            logger.debug("Unexpected error parsing from %s: %s", addr, e)
            return

        try:
            response = self._handle_query(query, addr, "udp")
            max_size = MAX_UDP_PAYLOAD
            for rr in query.additionals:
                if rr.rtype == TYPE_OPT:
                    max_size = max(MAX_UDP_PAYLOAD, rr.rclass)
                    opt_rr = DNSResourceRecord()
                    opt_rr.name = ""
                    opt_rr.rtype = TYPE_OPT
                    opt_rr.rclass = min(max_size, MAX_EDNS_PAYLOAD)
                    opt_rr.ttl = 0
                    opt_rr.rdata = b""
                    response.additionals.append(opt_rr)
                    break
            response_data = response.pack(max_size=max_size)
            self._udp_socket.sendto(response_data, addr)
        except Exception as e:
            logger.error("Error handling UDP query from %s: %s", addr, e)

    def _udp_server_loop(self):
        """UDP server main loop."""
        logger.info("Starting UDP DNS server on %s:%d", self.host, self.port)
        try:
            while self._running:
                try:
                    ready, _, _ = select.select(
                        [self._udp_socket], [], [], 0.5
                    )
                    if not ready:
                        continue
                    data, addr = self._udp_socket.recvfrom(MAX_MESSAGE_SIZE)
                    t = threading.Thread(
                        target=self._handle_udp_packet,
                        args=(data, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._running:
                        logger.error("UDP socket error: %s", e)
                    break
                except Exception as e:
                    logger.error("UDP loop error: %s", e)
        finally:
            logger.info("UDP server stopped")

    def start(self):
        """Start the DNS server (UDP)."""
        if self._running:
            return

        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_socket.bind((self.host, self.port))
        self._udp_socket.settimeout(1.0)

        self._running = True
        udp_thread = threading.Thread(
            target=self._udp_server_loop, daemon=True, name="dns-udp"
        )
        udp_thread.start()
        self._threads.append(udp_thread)

        logger.info("DNS server started on %s:%d", self.host, self.port)

    def stop(self):
        """Stop the DNS server."""
        self._running = False
        if self._udp_socket:
            try:
                self._udp_socket.close()
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads = []
        self.cache.stop()
        logger.info("DNS server stopped")

    def stats(self):
        return self.resolver.stats()
