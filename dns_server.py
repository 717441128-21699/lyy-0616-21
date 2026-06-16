import socket
import struct
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
            "Query from %s (%s): %s %s %s",
            addr,
            proto,
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

    def _handle_tcp_connection(self, conn, addr):
        """Handle a single TCP DNS connection."""
        try:
            conn.settimeout(10.0)

            length_data = b""
            while len(length_data) < 2:
                chunk = conn.recv(2 - len(length_data))
                if not chunk:
                    return
                length_data += chunk

            msg_length = struct.unpack("!H", length_data)[0]
            if msg_length > MAX_MESSAGE_SIZE or msg_length < 12:
                logger.warning("Invalid TCP DNS message length from %s: %d", addr, msg_length)
                return

            query_data = b""
            while len(query_data) < msg_length:
                chunk = conn.recv(min(4096, msg_length - len(query_data)))
                if not chunk:
                    return
                query_data += chunk

            if not self._check_rate_limit():
                return

            try:
                query = DNSMessage.unpack(query_data)
            except (DNSSecurityError, DNSParseError) as e:
                logger.debug("Parse error from %s (TCP): %s", addr, e)
                resp = DNSMessage()
                resp.header.id = 0
                try:
                    resp.header.id = int.from_bytes(query_data[0:2], "big")
                except Exception:
                    pass
                resp.header.qr = 1
                resp.header.rcode = RCODE_FORMERR
                resp_data = resp.pack(max_size=MAX_MESSAGE_SIZE)
                tcp_resp = struct.pack("!H", len(resp_data)) + resp_data
                conn.sendall(tcp_resp)
                return

            try:
                response = self._handle_query(query, addr, "tcp")
                response_data = response.pack(max_size=MAX_MESSAGE_SIZE)
                tcp_response = struct.pack("!H", len(response_data)) + response_data
                conn.sendall(tcp_response)
            except Exception as e:
                logger.error("Error handling TCP query from %s: %s", addr, e)
        except socket.timeout:
            logger.debug("TCP connection timeout from %s", addr)
        except OSError as e:
            logger.debug("TCP connection error from %s: %s", addr, e)
        except Exception as e:
            logger.error("Unexpected TCP error from %s: %s", addr, e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _tcp_server_loop(self):
        """TCP server main loop."""
        logger.info("Starting TCP DNS server on %s:%d", self.host, self.port)
        try:
            while self._running:
                try:
                    ready, _, _ = select.select(
                        [self._tcp_socket], [], [], 0.5
                    )
                    if not ready:
                        continue
                    conn, addr = self._tcp_socket.accept()
                    t = threading.Thread(
                        target=self._handle_tcp_connection,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._running:
                        logger.error("TCP socket error: %s", e)
                    break
                except Exception as e:
                    logger.error("TCP loop error: %s", e)
        finally:
            logger.info("TCP server stopped")

    def start(self):
        """Start the DNS server (UDP + TCP)."""
        if self._running:
            return

        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_socket.bind((self.host, self.port))
        self._udp_socket.settimeout(1.0)

        self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_socket.bind((self.host, self.port))
        self._tcp_socket.listen(50)
        self._tcp_socket.settimeout(1.0)

        self._running = True

        udp_thread = threading.Thread(
            target=self._udp_server_loop, daemon=True, name="dns-udp"
        )
        udp_thread.start()
        self._threads.append(udp_thread)

        tcp_thread = threading.Thread(
            target=self._tcp_server_loop, daemon=True, name="dns-tcp"
        )
        tcp_thread.start()
        self._threads.append(tcp_thread)

        logger.info("DNS server started on %s:%d (UDP + TCP)", self.host, self.port)

    def stop(self):
        """Stop the DNS server."""
        self._running = False
        if self._udp_socket:
            try:
                self._udp_socket.close()
            except Exception:
                pass
        if self._tcp_socket:
            try:
                self._tcp_socket.close()
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads = []
        self.cache.stop()
        logger.info("DNS server stopped")

    def stats(self):
        return self.resolver.stats()

    def print_status(self):
        """Print a formatted status report to stdout."""
        s = self.stats()

        lines = []
        lines.append("=" * 60)
        lines.append("  DNS Server Status")
        lines.append("=" * 60)

        lines.append("")
        lines.append("  Query Statistics")
        lines.append("  " + "-" * 40)
        lines.append(f"  Total queries:      {s['total_queries']}")
        lines.append(f"  NXDOMAIN:           {s['nxdomain_count']}")
        lines.append(f"  SERVFAIL:           {s['servfail_count']}")
        lines.append(f"  Retries:            {s['retries_total']}")
        lines.append(f"  Truncated:          {s['truncated_count']}")

        lines.append("")
        lines.append("  Cache Statistics")
        lines.append("  " + "-" * 40)
        lines.append(f"  Positive entries:   {s['cache']['entries']}")
        lines.append(f"  Negative entries:   {s['cache']['negative_entries']}")
        lines.append(f"  Cache hits:         {s['cache']['hits']} ({s['cache_hit_rate']}%)")
        lines.append(f"  Cache misses:       {s['cache']['misses']}")
        lines.append(f"  Negative hits:      {s['cache']['negative_hits']}")

        lines.append("")
        lines.append("  Singleflight")
        lines.append("  " + "-" * 40)
        lines.append(f"  Total requests:     {s['singleflight']['total_requests']}")
        lines.append(f"  Deduped (saved):    {s['singleflight']['deduped_requests']} ({s['singleflight']['saved_percent']:.1f}%)")
        lines.append(f"  Timeouts:           {s['singleflight']['timeout_count']}")

        lines.append("")
        lines.append("  Upstream")
        lines.append("  " + "-" * 40)
        lines.append(f"  Upstream queries:   {s['upstream_queries']}")
        lines.append(f"  Avg latency:        {s['avg_upstream_latency_ms']} ms")
        lines.append(f"  TCP fallbacks:      {s['tcp_fallbacks']}")
        lines.append(f"  Upstream failures:  {s['upstream_failures']}")

        lines.append("")
        lines.append("  Upstream Health")
        lines.append("  " + "-" * 40)
        for server, health in s["upstream_health"].items():
            host, port = server
            status_icon = {
                "healthy": "  [OK]  ",
                "degraded": "[WARN] ",
                "sick":   "[FAIL] ",
            }.get(health["status"], "  [?]  ")
            lines.append(
                f"  {status_icon} {host}:{port:<5} "
                f"status={health['status']:<10} "
                f"weight={health['weight']:<2} "
                f"latency={health['avg_latency_ms']:>4}ms "
                f"ok={health['total_successes']:<4} "
                f"fail={health['total_failures']:<4} "
                f"consec_fail={health['consecutive_failures']}"
            )

        lines.append("")
        lines.append("=" * 60)

        print("\n".join(lines))
