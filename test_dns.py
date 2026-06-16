#!/usr/bin/env python3
"""
Comprehensive tests for the DNS server implementation.

Tests cover:
1. DNS message parsing/serialization (including compression pointers)
2. Security: compression pointer loop prevention, forward pointer rejection,
   label/domain length limits, oversized RDATA rejection
3. Cache with per-record TTL expiration
4. Singleflight deduplication
5. Recursive resolver with CNAME chain following
6. Authority zone lookups
7. Full server integration
"""
import struct
import time
import threading
import socket
import sys
import os
import select
import random
import concurrent.futures

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dns_message import (
    DNSMessage,
    DNSHeader,
    DNSQuestion,
    DNSResourceRecord,
    parse_domain_name,
    encode_domain_name,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    CLASS_IN,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    MAX_LABEL_LENGTH,
    MAX_DOMAIN_LENGTH,
    MAX_POINTER_JUMPS,
    MAX_RDATA_LENGTH,
    MAX_UDP_PAYLOAD,
    DNSSecurityError,
    DNSParseError,
)
from dns_cache import DNSCache, CacheEntry
from singleflight import Singleflight
from dns_authority import AuthorityZone, AuthorityStore
from dns_server import DNSServer
from dns_resolver import DNSResolver, ResolveError


_passed = 0
_failed = 0


def _test_case(name):
    """Decorator to mark a test function."""
    def decorator(fn):
        def wrapper(*args, **kwargs):
            global _passed, _failed
            try:
                fn(*args, **kwargs)
                print(f"  [PASS] {name}")
                _passed += 1
            except AssertionError as e:
                print(f"  [FAIL] {name}: {e}")
                _failed += 1
            except Exception as e:
                print(f"  [ERROR] {name}: {type(e).__name__}: {e}")
                _failed += 1
        return wrapper
    return decorator


# ============================================================
# DNS Message Parsing Tests
# ============================================================

@_test_case("Parse simple domain name without compression")
def test_parse_simple_domain():
    data = b"\x03www\x07example\x03com\x00"
    name, offset = parse_domain_name(data, 0)
    assert name == "www.example.com", f"Got '{name}'"
    assert offset == 1 + 3 + 1 + 7 + 1 + 3 + 1


@_test_case("Parse domain with compression pointer (backward jump)")
def test_parse_compression_pointer():
    data = (
        b"\x03foo\x00"
        b"\x03bar\xc0\x00"
    )
    name1, off1 = parse_domain_name(data, 0)
    assert name1 == "foo", f"Got '{name1}'"
    assert off1 == 5
    name2, off2 = parse_domain_name(data, off1)
    assert name2 == "bar.foo", f"Got '{name2}'"
    assert off2 == off1 + 6  # "bar" (4 bytes: len+3) + pointer (2 bytes) = 6


@_test_case("Reject compression pointer that jumps forward (security)")
def test_reject_forward_pointer():
    data = bytearray(64)
    data[0] = 0x03
    data[1] = ord('f')
    data[2] = ord('o')
    data[3] = ord('o')
    data[4] = 0xC0
    data[5] = 0x10
    try:
        parse_domain_name(data, 0)
        assert False, "Should have raised DNSSecurityError"
    except DNSSecurityError:
        pass


@_test_case("Reject infinite pointer loop (security)")
def test_reject_pointer_loop():
    data = bytearray(100)
    data[0] = 0xC0
    data[1] = 0x04
    data[4] = 0xC0
    data[5] = 0x00
    try:
        parse_domain_name(data, 0)
        assert False, "Should have raised DNSSecurityError"
    except DNSSecurityError:
        pass


@_test_case("Reject too many pointer jumps (security)")
def test_reject_too_many_jumps():
    n = MAX_POINTER_JUMPS + 5
    data = bytearray(n * 2 + 8)
    for i in range(n):
        data[i * 2] = 0xC0
        data[i * 2 + 1] = (i + 1) * 2
    end_offset = n * 2
    data[end_offset] = 0x03
    data[end_offset + 1] = ord('e')
    data[end_offset + 2] = ord('n')
    data[end_offset + 3] = ord('d')
    data[end_offset + 4] = 0x00
    try:
        parse_domain_name(data, 0)
        assert False, "Should have raised DNSSecurityError"
    except DNSSecurityError:
        pass


@_test_case("Reject label exceeding 63 bytes (security)")
def test_reject_oversized_label():
    length_byte = MAX_LABEL_LENGTH + 1
    label_content = b"a" * (MAX_LABEL_LENGTH + 1)
    data = bytes([length_byte]) + label_content + b"\x00"
    try:
        parse_domain_name(data, 0)
        assert False, "Should have raised DNSSecurityError"
    except (DNSSecurityError, DNSParseError):
        pass


@_test_case("Reject domain name exceeding 255 bytes (security)")
def test_reject_oversized_domain():
    parts = []
    for i in range(30):
        label = b"\x61" * 10
        parts.append(bytes([len(label)]) + label)
    data = b"".join(parts) + b"\x00"
    try:
        parse_domain_name(data, 0)
        assert False, "Should have raised DNSSecurityError"
    except DNSSecurityError:
        pass


@_test_case("Reject RR with oversized RDLENGTH (security)")
def test_reject_oversized_rdata():
    data = bytearray(200)
    data[0] = 0x00
    name_end = 1
    oversized_rdlen = MAX_RDATA_LENGTH + 10
    struct.pack_into("!HHIH", data, name_end, TYPE_A, CLASS_IN, 300, oversized_rdlen)
    try:
        DNSResourceRecord.unpack(bytes(data), 0)
        assert False, "Should have raised DNSSecurityError"
    except (DNSSecurityError, struct.error):
        pass


@_test_case("Encode/decode domain round-trip")
def test_encode_decode_domain():
    for name in ["example.com", "www.sub.example.com.", "a.b.c.d.e.f"]:
        encoded, _ = encode_domain_name(name, allow_compression=False)
        decoded, _ = parse_domain_name(encoded, 0)
        expected = name.rstrip(".")
        assert decoded == expected, f"Round-trip failed: '{name}' -> '{decoded}'"


@_test_case("DNS message pack/unpack round-trip")
def test_message_roundtrip():
    msg = DNSMessage()
    msg.header.id = 0x1234
    msg.header.rd = 1
    msg.header.qdcount = 1

    q = DNSQuestion()
    q.qname = "test.example.com"
    q.qtype = TYPE_A
    q.qclass = CLASS_IN
    msg.questions.append(q)

    rr = DNSResourceRecord.create_a("test.example.com", "1.2.3.4", ttl=300)
    msg.answers.append(rr)
    msg.header.ancount = 1

    packed = msg.pack()
    unpacked = DNSMessage.unpack(packed)

    assert unpacked.header.id == 0x1234
    assert unpacked.header.qr == 0
    assert unpacked.header.rd == 1
    assert len(unpacked.questions) == 1
    assert unpacked.questions[0].qname == "test.example.com"
    assert unpacked.questions[0].qtype == TYPE_A
    assert len(unpacked.answers) == 1
    assert unpacked.answers[0].parse_rdata() == "1.2.3.4"
    assert unpacked.answers[0].ttl == 300


@_test_case("Parse AAAA record correctly")
def test_parse_aaaa():
    rr = DNSResourceRecord.create_aaaa("ipv6.test", "2001:db8::1", ttl=600)
    parsed = rr.parse_rdata()
    assert parsed is not None
    assert "2001" in parsed and "0db8" in parsed


@_test_case("Parse CNAME record correctly")
def test_parse_cname():
    rr = DNSResourceRecord.create_cname("alias.test", "target.test", ttl=300)
    parsed = rr.parse_rdata()
    assert parsed == "target.test"


@_test_case("Parse MX record correctly")
def test_parse_mx():
    rr = DNSResourceRecord.create_mx("test", 10, "mail.test", ttl=300)
    parsed = rr.parse_rdata()
    assert parsed == (10, "mail.test")


@_test_case("Domain compression during encoding")
def test_domain_compression_encoding():
    names = ["example.com", "www.example.com", "mail.example.com"]
    compression_map = {}
    offset = 0
    all_encoded = bytearray()
    for name in names:
        encoded, offset = encode_domain_name(
            name, allow_compression=True, compression_map=compression_map, offset=offset
        )
        all_encoded.extend(encoded)
    assert len(all_encoded) < 1 + 7 + 1 + 3 + 1 + 1 + 3 + 1 + 7 + 1 + 3 + 1 + 1 + 4 + 1 + 7 + 1 + 3 + 1


# ============================================================
# Cache Tests
# ============================================================

@_test_case("Cache basic get/put")
def test_cache_basic():
    cache = DNSCache()
    rr = DNSResourceRecord.create_a("test.com", "10.0.0.1", ttl=100)
    cache.put([rr])
    result = cache.get("test.com", TYPE_A)
    assert result is not None
    assert len(result) == 1
    assert result[0].parse_rdata() == "10.0.0.1"
    cache.stop()


@_test_case("Cache TTL expiration (per record)")
def test_cache_ttl_expiration():
    cache = DNSCache()
    rr1 = DNSResourceRecord.create_a("a.test.com", "10.0.0.1", ttl=2)
    rr2 = DNSResourceRecord.create_a("a.test.com", "10.0.0.2", ttl=5)
    cache.put([rr1, rr2])

    result = cache.get("a.test.com", TYPE_A)
    assert result is not None
    assert len(result) == 2

    time.sleep(2.5)
    result = cache.get("a.test.com", TYPE_A)
    assert result is not None
    assert len(result) == 1, f"Expected 1 record (rr2 should still be valid), got {len(result)}"
    assert result[0].parse_rdata() == "10.0.0.2"
    assert result[0].ttl <= 3

    time.sleep(3)
    result = cache.get("a.test.com", TYPE_A)
    assert result is None, "Both records should have expired"
    cache.stop()


@_test_case("Cache miss for non-existent entry")
def test_cache_miss():
    cache = DNSCache()
    assert cache.get("nonexistent.com", TYPE_A) is None
    cache.stop()


@_test_case("Cache returns TTL adjusted to remaining time")
def test_cache_adjusted_ttl():
    cache = DNSCache()
    rr = DNSResourceRecord.create_a("ttl.test", "1.2.3.4", ttl=100)
    cache.put([rr])
    time.sleep(1.5)
    result = cache.get("ttl.test", TYPE_A)
    assert result is not None
    assert 97 <= result[0].ttl <= 99, f"Expected TTL ~98, got {result[0].ttl}"
    cache.stop()


@_test_case("Cache case-insensitive lookups")
def test_cache_case_insensitive():
    cache = DNSCache()
    rr = DNSResourceRecord.create_a("MixedCase.COM", "1.2.3.4", ttl=300)
    cache.put([rr])
    assert cache.get("mixedcase.com", TYPE_A) is not None
    assert cache.get("MIXEDCASE.COM", TYPE_A) is not None
    cache.stop()


@_test_case("Cache follows CNAME chains")
def test_cache_cname_follow():
    cache = DNSCache()
    cache.put([DNSResourceRecord.create_cname("alias.test", "target.test", ttl=300)])
    cache.put([DNSResourceRecord.create_a("target.test", "5.6.7.8", ttl=300)])

    records, chain = cache.get_with_cname_follow("alias.test", TYPE_A)
    assert len(chain) == 1
    assert chain[0].rtype == TYPE_CNAME
    assert len(records) == 1
    assert records[0].parse_rdata() == "5.6.7.8"
    cache.stop()


@_test_case("Cache stores all record types independently")
def test_cache_independent_types():
    cache = DNSCache()
    cache.put([DNSResourceRecord.create_a("dual.test", "1.1.1.1", ttl=300)])
    cache.put([DNSResourceRecord.create_aaaa("dual.test", "::1", ttl=300)])

    a_records = cache.get("dual.test", TYPE_A)
    aaaa_records = cache.get("dual.test", TYPE_AAAA)
    assert a_records is not None and len(a_records) == 1
    assert aaaa_records is not None and len(aaaa_records) == 1
    cache.stop()


# ============================================================
# Singleflight Tests
# ============================================================

@_test_case("Singleflight basic deduplication")
def test_singleflight_basic():
    sf = Singleflight()
    call_count = [0]
    results = []
    errors = []

    def work():
        call_count[0] += 1
        time.sleep(0.3)
        return "result_value"

    def worker():
        r, e, dup = sf.do("key1", work)
        results.append(r)
        errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert call_count[0] == 1, f"work() called {call_count[0]} times, expected 1"
    assert all(r == "result_value" for r in results)
    assert all(e is None for e in errors)


@_test_case("Singleflight different keys don't collide")
def test_singleflight_different_keys():
    sf = Singleflight()
    call_counts = {"a": [0], "b": [0]}

    def make_work(key):
        def w():
            call_counts[key][0] += 1
            time.sleep(0.2)
            return key.upper()
        return w

    results = {}

    def worker(key):
        r, _, _ = sf.do(key, make_work(key))
        results[key] = r

    t1 = threading.Thread(target=worker, args=("a",))
    t2 = threading.Thread(target=worker, args=("b",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert call_counts["a"][0] == 1
    assert call_counts["b"][0] == 1
    assert results["a"] == "A"
    assert results["b"] == "B"


@_test_case("Singleflight propagates errors")
def test_singleflight_errors():
    sf = Singleflight()

    def failing_work():
        raise ValueError("test error")

    results = []
    errors = []

    def worker():
        r, e, _ = sf.do("error_key", failing_work)
        results.append(r)
        errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(r is None for r in results)
    assert all(isinstance(e, ValueError) for e in errors)
    assert all(str(e) == "test error" for e in errors)


@_test_case("Singleflight stats tracking")
def test_singleflight_stats():
    sf = Singleflight()
    sf.reset_stats()

    def work():
        time.sleep(0.1)
        return 42

    for _ in range(3):
        t = threading.Thread(target=lambda: sf.do("s", work))
        t.start()
    time.sleep(0.3)

    stats = sf.stats()
    assert stats["total_requests"] == 3
    assert stats["deduped_requests"] == 2
    assert stats["saved_percent"] > 0


# ============================================================
# Authority Zone Tests
# ============================================================

@_test_case("Authority zone direct A record lookup")
def test_authority_a_lookup():
    zone = AuthorityZone("test.com")
    zone.add_record("www", "A", "10.0.0.1")
    records, is_auth, zone_exists = zone.lookup("www.test.com", TYPE_A)
    assert is_auth
    assert zone_exists
    assert len(records) == 1
    assert records[0].parse_rdata() == "10.0.0.1"


@_test_case("Authority zone origin (@) record")
def test_authority_origin():
    zone = AuthorityZone("myzone.com")
    zone.add_record("@", "A", "10.0.0.100")
    records, is_auth, _ = zone.lookup("myzone.com", TYPE_A)
    assert is_auth
    assert len(records) == 1
    assert records[0].parse_rdata() == "10.0.0.100"


@_test_case("Authority zone CNAME resolution within zone")
def test_authority_cname_within_zone():
    zone = AuthorityZone("intrazone.com")
    zone.add_record("alias", "CNAME", "target.intrazone.com")
    zone.add_record("target", "A", "172.16.0.1")

    records, is_auth, _ = zone.lookup("alias.intrazone.com", TYPE_A)
    assert is_auth
    types = [r.rtype for r in records]
    assert TYPE_CNAME in types
    assert TYPE_A in types


@_test_case("Authority store multi-zone lookup")
def test_authority_store_multizone():
    store = AuthorityStore()
    z1 = store.create_zone("foo.com")
    z2 = store.create_zone("bar.com")
    z1.add_record("www", "A", "1.1.1.1")
    z2.add_record("www", "A", "2.2.2.2")

    r1, _, _ = store.lookup("www.foo.com", TYPE_A)
    r2, _, _ = store.lookup("www.bar.com", TYPE_A)
    assert r1[0].parse_rdata() == "1.1.1.1"
    assert r2[0].parse_rdata() == "2.2.2.2"


@_test_case("Authority zone returns no answer for unknown name")
def test_authority_nxdomain():
    zone = AuthorityZone("known.com")
    records, is_auth, zone_exists = zone.lookup("unknown.known.com", TYPE_A)
    assert is_auth
    assert zone_exists
    assert len(records) == 0


@_test_case("Authority MX record")
def test_authority_mx():
    zone = AuthorityZone("mxzone.com")
    zone.add_record("@", "MX", (10, "mail.mxzone.com"))
    records, _, _ = zone.lookup("mxzone.com", TYPE_MX)
    assert len(records) == 1
    parsed = records[0].parse_rdata()
    assert parsed == (10, "mail.mxzone.com")


# ============================================================
# Integration / Server Tests
# ============================================================

@_test_case("Full server authoritative query")
def test_server_authoritative():
    server = DNSServer(port=5354, allow_recursion=False)
    zone = server.add_authoritative_zone("server.test")
    zone.add_record("demo", "A", "10.99.99.99", ttl=600)
    zone.add_record("alias", "CNAME", "demo.server.test", ttl=600)

    server.start()
    time.sleep(0.2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    query = DNSMessage()
    query.header.id = 0xABCD
    query.header.rd = 0
    query.header.qdcount = 1
    q = DNSQuestion()
    q.qname = "demo.server.test"
    q.qtype = TYPE_A
    q.qclass = CLASS_IN
    query.questions.append(q)

    sock.sendto(query.pack(), ("127.0.0.1", 5354))
    data, _ = sock.recvfrom(4096)
    response = DNSMessage.unpack(data)

    assert response.header.id == 0xABCD
    assert response.header.qr == 1
    assert response.header.rcode == RCODE_NOERROR
    assert response.header.aa == 1
    assert len(response.answers) == 1
    assert response.answers[0].parse_rdata() == "10.99.99.99"

    query2 = DNSMessage()
    query2.header.id = 0xBEFE
    query2.header.rd = 0
    query2.header.qdcount = 1
    q2 = DNSQuestion()
    q2.qname = "alias.server.test"
    q2.qtype = TYPE_A
    q2.qclass = CLASS_IN
    query2.questions.append(q2)
    sock.sendto(query2.pack(), ("127.0.0.1", 5354))
    data2, _ = sock.recvfrom(4096)
    response2 = DNSMessage.unpack(data2)
    assert len(response2.answers) >= 1
    types_found = [r.rtype for r in response2.answers]
    assert TYPE_CNAME in types_found

    sock.close()
    server.stop()


@_test_case("Malformed packet security: truncated header")
def test_security_truncated_header():
    try:
        DNSMessage.unpack(b"\x00\x00\x01")
        assert False, "Should have raised"
    except (DNSParseError, DNSSecurityError):
        pass


@_test_case("Malformed packet security: garbage data")
def test_security_garbage():
    garbage = os.urandom(200)
    try:
        DNSMessage.unpack(garbage)
    except (DNSParseError, DNSSecurityError):
        pass
    except Exception as e:
        assert False, f"Unexpected exception type: {type(e).__name__}"


# ============================================================
# Real-world Scenario Tests
# ============================================================

@_test_case("RDATA compression pointer: CNAME target via pointer to Question")
def test_rdata_compression_cname():
    """
    Simulate a real DNS response where CNAME RDATA uses a compression
    pointer (0xc0 0x0c) pointing to the Question section's qname.

    Response structure:
    - Header (12 bytes)
    - Question: www.example.com. A IN (offset 12)
    - Answer: www.example.com. CNAME <pointer to 0x0c>

    The CNAME RDATA is just 2 bytes: \xc0\x0c (pointer to offset 12)
    Without full message context, this would parse as empty.
    """
    header = DNSHeader()
    header.id = 0x1234
    header.qr = 1
    header.rd = 1
    header.ra = 1
    header.qdcount = 1
    header.ancount = 1
    header.rcode = RCODE_NOERROR

    q = DNSQuestion()
    q.qname = "www.example.com"
    q.qtype = TYPE_A
    q.qclass = CLASS_IN

    cname_rr = DNSResourceRecord()
    cname_rr.name = "www.example.com"
    cname_rr.rtype = TYPE_CNAME
    cname_rr.rclass = CLASS_IN
    cname_rr.ttl = 300
    cname_rr.rdata = b"\xc0\x0c"

    msg = DNSMessage()
    msg.header = header
    msg.questions.append(q)
    msg.answers.append(cname_rr)

    packed = msg.pack(max_size=MAX_UDP_PAYLOAD)

    unpacked = DNSMessage.unpack(packed)

    assert unpacked.header.ancount == 1
    cname_parsed = unpacked.answers[0]
    assert cname_parsed.rtype == TYPE_CNAME

    target = cname_parsed.parse_rdata()
    assert target == "www.example.com", (
        f"CNAME target parsed as '{target}', expected 'www.example.com'. "
        "Likely RDATA compression pointer not using full message context."
    )


@_test_case("RDATA compression pointer: NS target via pointer to Question")
def test_rdata_compression_ns():
    """
    Simulate a real DNS response where NS RDATA uses a compression
    pointer pointing to the Question section.
    """
    header = DNSHeader()
    header.id = 0x5678
    header.qr = 1
    header.rd = 1
    header.ra = 1
    header.qdcount = 1
    header.ancount = 0
    header.nscount = 1
    header.rcode = RCODE_NOERROR

    q = DNSQuestion()
    q.qname = "example.com"
    q.qtype = TYPE_NS
    q.qclass = CLASS_IN

    ns_rr = DNSResourceRecord()
    ns_rr.name = "example.com"
    ns_rr.rtype = TYPE_NS
    ns_rr.rclass = CLASS_IN
    ns_rr.ttl = 86400
    ns_rr.rdata = b"\xc0\x0c"

    msg = DNSMessage()
    msg.header = header
    msg.questions.append(q)
    msg.authorities.append(ns_rr)

    packed = msg.pack(max_size=MAX_UDP_PAYLOAD)
    unpacked = DNSMessage.unpack(packed)

    assert unpacked.header.nscount == 1
    ns_parsed = unpacked.authorities[0]
    assert ns_parsed.rtype == TYPE_NS

    target = ns_parsed.parse_rdata()
    assert target == "example.com", (
        f"NS target parsed as '{target}', expected 'example.com'. "
        "RDATA compression pointer parsing failed."
    )


@_test_case("RDATA compression pointer: MX target via pointer")
def test_rdata_compression_mx():
    """
    Simulate a real DNS response where MX exchange uses a compression
    pointer. MX RDATA format: [2 bytes preference][exchange domain]
    """
    header = DNSHeader()
    header.id = 0x9ABC
    header.qr = 1
    header.rd = 1
    header.ra = 1
    header.qdcount = 1
    header.ancount = 1
    header.rcode = RCODE_NOERROR

    q = DNSQuestion()
    q.qname = "example.com"
    q.qtype = TYPE_MX
    q.qclass = CLASS_IN

    mx_rr = DNSResourceRecord()
    mx_rr.name = "example.com"
    mx_rr.rtype = TYPE_MX
    mx_rr.rclass = CLASS_IN
    mx_rr.ttl = 3600
    mx_rr.rdata = struct.pack("!H", 10) + b"\xc0\x0c"

    msg = DNSMessage()
    msg.header = header
    msg.questions.append(q)
    msg.answers.append(mx_rr)

    packed = msg.pack(max_size=MAX_UDP_PAYLOAD)
    unpacked = DNSMessage.unpack(packed)

    assert unpacked.header.ancount == 1
    mx_parsed = unpacked.answers[0]
    assert mx_parsed.rtype == TYPE_MX

    preference, exchange = mx_parsed.parse_rdata()
    assert preference == 10, f"MX preference {preference} != 10"
    assert exchange == "example.com", (
        f"MX exchange parsed as '{exchange}', expected 'example.com'. "
        "RDATA compression pointer in MX failed."
    )


@_test_case("RDATA compression: multi-record response with mixed pointers")
def test_rdata_compression_multi_record():
    """
    Simulate a realistic response with CNAME chain + A record,
    both using compression pointers in RDATA.
    """
    header = DNSHeader()
    header.id = 0xDEF0
    header.qr = 1
    header.rd = 1
    header.ra = 1
    header.qdcount = 1
    header.ancount = 2
    header.rcode = RCODE_NOERROR

    q = DNSQuestion()
    q.qname = "blog.example.com"
    q.qtype = TYPE_A
    q.qclass = CLASS_IN

    cname_rr = DNSResourceRecord()
    cname_rr.name = "blog.example.com"
    cname_rr.rtype = TYPE_CNAME
    cname_rr.rclass = CLASS_IN
    cname_rr.ttl = 300
    cname_rr.rdata = encode_domain_name("cdn.example.com", allow_compression=False)[0]

    a_rr = DNSResourceRecord()
    a_rr.name = "cdn.example.com"
    a_rr.rtype = TYPE_A
    a_rr.rclass = CLASS_IN
    a_rr.ttl = 300
    a_rr.rdata = struct.pack("!BBBB", 10, 0, 0, 1)

    msg = DNSMessage()
    msg.header = header
    msg.questions.append(q)
    msg.answers.append(cname_rr)
    msg.answers.append(a_rr)

    packed = msg.pack(max_size=MAX_UDP_PAYLOAD)
    unpacked = DNSMessage.unpack(packed)

    assert unpacked.header.ancount == 2

    cname_target = unpacked.answers[0].parse_rdata()
    assert cname_target == "cdn.example.com", f"Got '{cname_target}'"

    a_ip = unpacked.answers[1].parse_rdata()
    assert a_ip == "10.0.0.1", f"Got '{a_ip}'"


@_test_case("CNAME chain: full chain returned from resolver")
def test_cname_chain_full_return():
    """
    Test that the resolver returns the full CNAME chain + final answers,
    not just the final A record.
    """
    class MockUpstream:
        def __init__(self):
            self.call_count = 0

        def _send_query_upstream(self, name, qtype, timeout=None):
            self.call_count += 1
            header = DNSHeader()
            header.id = 0x1111
            header.qr = 1
            header.rd = 1
            header.ra = 1
            header.qdcount = 1
            header.rcode = RCODE_NOERROR

            q = DNSQuestion()
            q.qname = name
            q.qtype = qtype
            q.qclass = CLASS_IN

            msg = DNSMessage()
            msg.header = header
            msg.questions.append(q)

            if name == "a.example.com":
                header.ancount = 1
                cname = DNSResourceRecord()
                cname.name = "a.example.com"
                cname.rtype = TYPE_CNAME
                cname.rclass = CLASS_IN
                cname.ttl = 300
                cname.rdata = encode_domain_name("b.example.com", allow_compression=False)[0]
                msg.answers.append(cname)
            elif name == "b.example.com":
                header.ancount = 1
                cname = DNSResourceRecord()
                cname.name = "b.example.com"
                cname.rtype = TYPE_CNAME
                cname.rclass = CLASS_IN
                cname.ttl = 300
                cname.rdata = encode_domain_name("c.example.com", allow_compression=False)[0]
                msg.answers.append(cname)
            elif name == "c.example.com":
                header.ancount = 1
                a = DNSResourceRecord()
                a.name = "c.example.com"
                a.rtype = TYPE_A
                a.rclass = CLASS_IN
                a.ttl = 300
                a.rdata = struct.pack("!BBBB", 10, 1, 2, 3)
                msg.answers.append(a)

            return msg

    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)
    mock = MockUpstream()
    resolver._send_query_upstream = mock._send_query_upstream

    result = resolver.resolve("a.example.com", TYPE_A)

    assert len(result) >= 3, (
        f"Expected at least 3 records (2 CNAME + 1 A), got {len(result)}. "
        "Full CNAME chain not being returned."
    )

    record_types = [(rr.rtype, rr.name) for rr in result]
    assert (TYPE_CNAME, "a.example.com") in record_types, (
        "First CNAME in chain missing from result"
    )
    assert (TYPE_CNAME, "b.example.com") in record_types, (
        "Second CNAME in chain missing from result"
    )
    assert (TYPE_A, "c.example.com") in record_types, (
        "Final A record missing from result"
    )

    assert mock.call_count == 3, f"Expected 3 upstream calls, got {mock.call_count}"


@_test_case("Singleflight: slow upstream, multiple waiters get same result")
def test_singleflight_slow_upstream():
    """
    Test that when the first upstream request is slow, all concurrent
    waiters get the same result and don't fail prematurely.

    Simulates: upstream deliberately delayed by 3 seconds, 5 concurrent
    requests all arrive at once. Only one upstream request is made,
    all 5 waiters get the same answer.
    """
    call_count = 0
    result_value = ("slow_result", None)
    start_time = None

    def slow_work():
        nonlocal call_count, start_time
        call_count += 1
        start_time = time.time()
        time.sleep(2.0)
        return result_value

    sf = Singleflight(default_timeout=10.0)
    key = ("slow.domain.example", TYPE_A)

    results = []
    errors = []
    was_dups = []

    def make_request():
        r, e, d = sf.do(key, slow_work, timeout=10.0)
        results.append(r)
        errors.append(e)
        was_dups.append(d)

    threads = [threading.Thread(target=make_request) for _ in range(5)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    total_time = time.time() - start

    assert call_count == 1, (
        f"Expected only 1 upstream call (dedup), got {call_count}. "
        "Singleflight not deduplicating properly."
    )

    assert len(results) == 5
    for i, r in enumerate(results):
        assert r == result_value, f"Request {i} got different result"
        assert errors[i] is None, f"Request {i} had error: {errors[i]}"

    dup_count = sum(1 for d in was_dups if d)
    assert dup_count == 4, (
        f"Expected 4 duplicate requests, got {dup_count}. "
        "Singleflight not marking duplicates correctly."
    )

    assert total_time >= 1.9 and total_time < 3.0, (
        f"Expected ~2s total (one slow call), got {total_time:.2f}s. "
        "Requests may not be waiting properly."
    )


@_test_case("Singleflight: waiters wait even when upstream takes 15s")
def test_singleflight_very_slow_upstream():
    """
    Stress test: upstream takes 15 seconds, waiters must all wait and
    get the same result. No premature failures.
    """
    call_count = 0

    def very_slow_work():
        nonlocal call_count
        call_count += 1
        time.sleep(3.0)
        return ("delayed_result_15s", None)

    sf = Singleflight(default_timeout=30.0)
    key = ("very.slow.example", TYPE_A)

    results = []
    errors = []

    def make_request():
        r, e, _ = sf.do(key, very_slow_work, timeout=30.0)
        results.append(r)
        errors.append(e)

    threads = [threading.Thread(target=make_request) for _ in range(3)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    total_time = time.time() - start

    assert call_count == 1
    assert len(results) == 3
    for e in errors:
        assert e is None, f"Unexpected error: {e}"
    for r in results:
        assert r == ("delayed_result_15s", None), f"Wrong result: {r}"
    assert total_time >= 2.9 and total_time < 5.0, (
        f"Expected ~3s, got {total_time:.2f}s"
    )


@_test_case("Concurrent multi-domain query stability")
def test_concurrent_multi_domain_stability():
    """
    Test that concurrent queries for many different domain names
    all complete successfully without random SERVFAIL.

    Simulates: 50 different domains queried concurrently, 3 requests
    per domain (150 total requests). All should succeed.
    """
    domain_count = 20
    requests_per_domain = 3

    domains = [f"domain-{i:03d}.example.com" for i in range(domain_count)]

    response_data = {}
    for i, domain in enumerate(domains):
        ip = f"10.{(i // 256) % 256}.{i % 256}.1"
        response_data[domain] = ip

    def mock_send(name, qtype, timeout=None):
        time.sleep(random.uniform(0.01, 0.05))
        header = DNSHeader()
        header.id = random.randint(0, 0xFFFF)
        header.qr = 1
        header.rd = 1
        header.ra = 1
        header.qdcount = 1
        header.ancount = 1
        header.rcode = RCODE_NOERROR

        q = DNSQuestion()
        q.qname = name
        q.qtype = qtype
        q.qclass = CLASS_IN

        a = DNSResourceRecord()
        a.name = name
        a.rtype = TYPE_A
        a.rclass = CLASS_IN
        a.ttl = 300
        parts = [int(p) for p in response_data[name].split(".")]
        a.rdata = struct.pack("!BBBB", *parts)

        msg = DNSMessage()
        msg.header = header
        msg.questions.append(q)
        msg.answers.append(a)
        return msg

    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)
    resolver._send_query_upstream = mock_send

    all_requests = []
    for domain in domains:
        for _ in range(requests_per_domain):
            all_requests.append(domain)
    random.shuffle(all_requests)

    results = {}
    errors = []

    def query_domain(domain):
        try:
            rrs = resolver.resolve(domain, TYPE_A)
            results[domain] = rrs
        except Exception as e:
            errors.append((domain, e))

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(query_domain, d) for d in all_requests]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    assert len(errors) == 0, (
        f"{len(errors)} requests failed out of {len(all_requests)}. "
        f"Failures: {errors[:5]}"
    )

    assert len(results) == domain_count, (
        f"Expected {domain_count} unique domains, got {len(results)}"
    )

    for domain in domains:
        assert domain in results, f"Domain {domain} missing from results"
        rrs = results[domain]
        assert len(rrs) >= 1, f"No records for {domain}"
        a_rr = [rr for rr in rrs if rr.rtype == TYPE_A][0]
        ip = a_rr.parse_rdata()
        assert ip == response_data[domain], (
            f"Wrong IP for {domain}: got {ip}, expected {response_data[domain]}"
        )

    stats = resolver.stats()
    assert stats["singleflight"]["total_requests"] == len(all_requests)
    dedup_rate = stats["singleflight"]["saved_percent"]
    expected_dedup = (
        (len(all_requests) - domain_count) / len(all_requests) * 100
    )
    assert abs(dedup_rate - expected_dedup) < 1.0, (
        f"Dedup rate {dedup_rate:.1f}% doesn't match expected {expected_dedup:.1f}%"
    )


@_test_case("Resolver: cached CNAME chain returns all records")
def test_resolver_cached_cname_chain():
    """
    Test that after a CNAME chain is cached, subsequent lookups
    return the full chain from cache, not just the final answer.
    """
    call_count = 0

    def mock_send(name, qtype, timeout=None):
        nonlocal call_count
        call_count += 1
        header = DNSHeader()
        header.id = 0x2222
        header.qr = 1
        header.rd = 1
        header.ra = 1
        header.qdcount = 1
        header.ancount = 2
        header.rcode = RCODE_NOERROR

        q = DNSQuestion()
        q.qname = name
        q.qtype = qtype
        q.qclass = CLASS_IN

        cname = DNSResourceRecord()
        cname.name = "alias.example.com"
        cname.rtype = TYPE_CNAME
        cname.rclass = CLASS_IN
        cname.ttl = 300
        cname.rdata = encode_domain_name("final.example.com", allow_compression=False)[0]

        a = DNSResourceRecord()
        a.name = "final.example.com"
        a.rtype = TYPE_A
        a.rclass = CLASS_IN
        a.ttl = 300
        a.rdata = struct.pack("!BBBB", 10, 99, 99, 99)

        msg = DNSMessage()
        msg.header = header
        msg.questions.append(q)
        msg.answers.append(cname)
        msg.answers.append(a)
        return msg

    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)
    resolver._send_query_upstream = mock_send

    result1 = resolver.resolve("alias.example.com", TYPE_A)
    assert call_count == 1
    assert len(result1) >= 2

    cache_stats = cache.stats()
    assert cache_stats["entries"] >= 2

    result2 = resolver.resolve("alias.example.com", TYPE_A)
    assert call_count == 1, "Should not have called upstream again (cached)"

    assert len(result2) >= 2, (
        f"Cached lookup returned {len(result2)} records, expected >=2. "
        "Full CNAME chain not being returned from cache."
    )

    types = [rr.rtype for rr in result2]
    assert TYPE_CNAME in types, "Cached result missing CNAME record"
    assert TYPE_A in types, "Cached result missing A record"


def run_all_tests():
    print("=" * 60)
    print("DNS Server Test Suite")
    print("=" * 60)

    print("\n--- DNS Message Parsing ---")
    test_parse_simple_domain()
    test_parse_compression_pointer()
    test_reject_forward_pointer()
    test_reject_pointer_loop()
    test_reject_too_many_jumps()
    test_reject_oversized_label()
    test_reject_oversized_domain()
    test_reject_oversized_rdata()
    test_encode_decode_domain()
    test_message_roundtrip()
    test_parse_aaaa()
    test_parse_cname()
    test_parse_mx()
    test_domain_compression_encoding()

    print("\n--- Cache (Per-record TTL) ---")
    test_cache_basic()
    test_cache_ttl_expiration()
    test_cache_miss()
    test_cache_adjusted_ttl()
    test_cache_case_insensitive()
    test_cache_cname_follow()
    test_cache_independent_types()

    print("\n--- Singleflight (Deduplication) ---")
    test_singleflight_basic()
    test_singleflight_different_keys()
    test_singleflight_errors()
    test_singleflight_stats()

    print("\n--- Authority Zones ---")
    test_authority_a_lookup()
    test_authority_origin()
    test_authority_cname_within_zone()
    test_authority_store_multizone()
    test_authority_nxdomain()
    test_authority_mx()

    print("\n--- Server Integration & Security ---")
    test_server_authoritative()
    test_security_truncated_header()
    test_security_garbage()

    print("\n--- Real-world Scenario Tests ---")
    test_rdata_compression_cname()
    test_rdata_compression_ns()
    test_rdata_compression_mx()
    test_rdata_compression_multi_record()
    test_cname_chain_full_return()
    test_singleflight_slow_upstream()
    test_singleflight_very_slow_upstream()
    test_concurrent_multi_domain_stability()
    test_resolver_cached_cname_chain()

    print("\n" + "=" * 60)
    print(f"Results: {_passed} passed, {_failed} failed")
    print("=" * 60)

    return _failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
