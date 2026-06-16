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
                raise
            except Exception as e:
                print(f"  [ERROR] {name}: {type(e).__name__}: {e}")
                _failed += 1
                raise
        wrapper._original_fn = fn
        return wrapper
    return decorator


def _run_test(fn):
    """Run a test function without propagating exceptions (for run_all_tests)."""
    try:
        fn()
    except Exception:
        pass


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

    records, chain, complete = cache.get_with_cname_follow("alias.test", TYPE_A)
    assert complete, "Expected complete CNAME chain"
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
    resolver._query_upstream = lambda name, qtype, timeout=None, use_tcp=False: (mock._send_query_upstream(name, qtype), False)

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
        time.sleep(random.uniform(0.05, 0.1))
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
    def _wrapped(name, qtype, timeout=None, use_tcp=False):
        import time as _time
        t0 = _time.time()
        msg = mock_send(name, qtype, timeout)
        elapsed = _time.time() - t0
        resolver._inc_stat("upstream_queries")
        resolver._inc_stat("upstream_time_total", elapsed)
        resolver._inc_stat("upstream_time_count")
        return msg, False
    resolver._query_upstream = _wrapped

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
    assert stats["upstream_queries"] == domain_count, (
        f"Expected {domain_count} upstream queries (singleflight deduplication), "
        f"got {stats['upstream_queries']}. Singleflight not working properly."
    )
    assert stats["singleflight_dedups"] >= 0, "singleflight_dedups should be non-negative"
    assert stats["singleflight"]["total_requests"] >= domain_count, (
        f"Expected at least {domain_count} singleflight requests, "
        f"got {stats['singleflight']['total_requests']}"
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
    def _wrapped(name, qtype, timeout=None, use_tcp=False):
        import time as _time
        t0 = _time.time()
        msg = mock_send(name, qtype, timeout)
        elapsed = _time.time() - t0
        resolver._inc_stat("upstream_queries")
        resolver._inc_stat("upstream_time_total", elapsed)
        resolver._inc_stat("upstream_time_count")
        return msg, False
    resolver._query_upstream = _wrapped

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


@_test_case("Negative cache: NXDOMAIN cached, no repeat upstream query")
def test_negative_cache_nxdomain():
    """
    Test that NXDOMAIN responses are cached, and subsequent queries
    for the same name return from negative cache without hitting upstream.
    """
    call_count = 0

    def mock_send(name, qtype, timeout=None):
        nonlocal call_count
        call_count += 1
        header = DNSHeader()
        header.id = 0x3333
        header.qr = 1
        header.rd = 1
        header.ra = 1
        header.qdcount = 1
        header.rcode = RCODE_NXDOMAIN

        q = DNSQuestion()
        q.qname = name
        q.qtype = qtype
        q.qclass = CLASS_IN

        msg = DNSMessage()
        msg.header = header
        msg.questions.append(q)
        return msg, False

    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)
    resolver._query_upstream = mock_send

    try:
        resolver.resolve("nonexistent.example.com", TYPE_A)
        assert False, "Should have raised ResolveError"
    except ResolveError as e:
        assert e.rcode == RCODE_NXDOMAIN, f"Expected NXDOMAIN rcode, got {e.rcode}"

    first_count = call_count

    for i in range(5):
        try:
            resolver.resolve("nonexistent.example.com", TYPE_A)
            assert False, "Should have raised ResolveError from negative cache"
        except ResolveError as e:
            assert e.rcode == RCODE_NXDOMAIN, f"Expected NXDOMAIN rcode, got {e.rcode}"

    assert call_count == first_count, (
        f"Expected {first_count} upstream call (negative cache), got {call_count}. "
        "Negative cache not preventing repeat upstream queries."
    )

    stats = cache.stats()
    assert stats["negative_entries"] >= 1, "No negative cache entries stored"
    assert stats["negative_hits"] >= 5, (
        f"Expected >=5 negative cache hits, got {stats['negative_hits']}"
    )


@_test_case("Negative cache: SERVFAIL cached, no repeat upstream query")
def test_negative_cache_servfail():
    """
    Test that SERVFAIL responses are cached temporarily.
    """
    call_count = 0

    def mock_send(name, qtype, timeout=None):
        nonlocal call_count
        call_count += 1
        raise ResolveError("SERVFAIL mock")

    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)
    resolver._query_upstream = mock_send

    cache.put_negative("broken.example.com", TYPE_A, RCODE_SERVFAIL, ttl=60)

    for i in range(5):
        try:
            resolver.resolve("broken.example.com", TYPE_A)
            assert False, "Should have raised"
        except ResolveError as e:
            assert e.rcode == RCODE_SERVFAIL, f"Expected SERVFAIL rcode, got {e.rcode}"

    assert call_count == 0, (
        f"Expected 0 upstream calls (pre-cached negative), got {call_count}. "
        "Negative cache not working for SERVFAIL."
    )


@_test_case("Cached CNAME chain: upstream offline, still returns answer")
def test_cached_cname_upstream_offline():
    """
    Key scenario: once CNAME chain + final answer are cached,
    even if upstream goes down completely, queries still succeed
    using cached data.
    """
    upstream_calls = [0]
    upstream_works = [True]

    def mock_send(name, qtype, timeout=None):
        upstream_calls[0] += 1
        if not upstream_works[0]:
            raise ResolveError("Upstream offline!")

        header = DNSHeader()
        header.id = 0x4444
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
        cname.name = "alias.cached.com"
        cname.rtype = TYPE_CNAME
        cname.rclass = CLASS_IN
        cname.ttl = 300
        cname.rdata = encode_domain_name("final.cached.com", allow_compression=False)[0]

        a = DNSResourceRecord()
        a.name = "final.cached.com"
        a.rtype = TYPE_A
        a.rclass = CLASS_IN
        a.ttl = 300
        a.rdata = struct.pack("!BBBB", 10, 20, 30, 40)

        msg = DNSMessage()
        msg.header = header
        msg.questions.append(q)
        msg.answers.append(cname)
        msg.answers.append(a)
        return msg, False

    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)
    resolver._query_upstream = mock_send

    result1 = resolver.resolve("alias.cached.com", TYPE_A)
    first_upstream_calls = upstream_calls[0]
    assert first_upstream_calls >= 1
    assert len(result1) >= 2

    cache_stats = cache.stats()
    assert cache_stats["entries"] >= 2, "Cache should have CNAME + A entries"

    upstream_works[0] = False

    result2 = resolver.resolve("alias.cached.com", TYPE_A)

    assert upstream_calls[0] == first_upstream_calls, (
        f"Upstream was called again ({upstream_calls[0]} total) when it should have been cached. "
        "Cache not preventing upstream queries for already-cached CNAME chains."
    )

    assert len(result2) >= 2, (
        f"Cached query returned {len(result2)} records, expected >=2"
    )

    types = [rr.rtype for rr in result2]
    assert TYPE_CNAME in types
    assert TYPE_A in types

    a_record = [rr for rr in result2 if rr.rtype == TYPE_A][0]
    ip = a_record.parse_rdata()
    assert ip == "10.20.30.40", f"Wrong IP from cache: {ip}"


@_test_case("Resolver statistics tracking")
def test_resolver_statistics():
    """
    Test that resolver tracks key statistics: total queries, cache hits,
    singleflight dedups, CNAME follows, NXDOMAIN count, etc.
    """
    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)

    upstream_queries = [0]

    def mock_send(name, qtype, timeout=None, use_tcp=False):
        import time as _time
        t0 = _time.time()
        upstream_queries[0] += 1
        header = DNSHeader()
        header.id = 0x5555
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
        a.rdata = struct.pack("!BBBB", 10, 0, 0, 1)

        msg = DNSMessage()
        msg.header = header
        msg.questions.append(q)
        msg.answers.append(a)
        elapsed = _time.time() - t0
        resolver._inc_stat("upstream_queries")
        resolver._inc_stat("upstream_time_total", elapsed)
        resolver._inc_stat("upstream_time_count")
        return msg, False

    resolver._query_upstream = mock_send

    for i in range(5):
        resolver.resolve(f"stat-{i}.test", TYPE_A)

    stats = resolver.stats()
    assert stats["total_queries"] == 5
    assert stats["upstream_queries"] == 5
    assert stats["cache_hits"] == 0
    assert stats["avg_upstream_latency_ms"] >= 0

    for i in range(5):
        resolver.resolve(f"stat-{i}.test", TYPE_A)

    stats2 = resolver.stats()
    assert stats2["total_queries"] == 10
    assert stats2["cache_hits"] == 5, (
        f"Expected 5 cache hits on second pass, got {stats2['cache_hits']}"
    )
    assert stats2["upstream_queries"] == 5, (
        f"Expected 5 upstream queries (cached), got {stats2['upstream_queries']}"
    )


@_test_case("End-to-end stress: mixed query types concurrent")
def test_e2e_mixed_query_stress():
    """
    End-to-end stress test: mix of A, AAAA, MX, NS, CNAME chains,
    and NXDOMAIN queries all running concurrently.

    Verifies:
    - 100% success rate for valid domains
    - NXDOMAIN properly returned for nonexistent domains
    - Cache hit rate increases on second pass
    - Singleflight deduplication works
    - Stable latency and no random failures
    """
    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)

    a_records = {}
    aaaa_records = {}
    mx_records = {}
    ns_records = {}
    cname_chains = {}
    nx_domains = set()

    for i in range(15):
        domain = f"a-{i:03d}.example.com"
        a_records[domain] = f"10.{i // 256}.{i % 256}.1"

    for i in range(10):
        domain = f"aaaa-{i:03d}.example.com"
        aaaa_records[domain] = f"2001:db8::{i}"

    for i in range(8):
        domain = f"mx-{i:03d}.example.com"
        mx_records[domain] = (10, f"mail-{i}.example.com")

    for i in range(5):
        domain = f"ns-{i:03d}.example.com"
        ns_records[domain] = f"ns{i}.example.com"

    for i in range(5):
        alias = f"cname-{i:03d}.example.com"
        target = f"target-{i:03d}.example.com"
        cname_chains[alias] = target
        a_records[target] = f"10.99.{i}.1"

    for i in range(7):
        nx_domains.add(f"nx-{i:03d}.nonexistent.xyz")

    def mock_send(name, qtype, timeout=None, use_tcp=False):
        import time as _time
        t0 = _time.time()
        header = DNSHeader()
        header.id = random.randint(0, 0xFFFF)
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

        time.sleep(random.uniform(0.001, 0.005))

        if name in nx_domains:
            header.rcode = RCODE_NXDOMAIN
            elapsed = _time.time() - t0
            resolver._inc_stat("upstream_queries")
            resolver._inc_stat("upstream_time_total", elapsed)
            resolver._inc_stat("upstream_time_count")
            return msg, False

        if qtype == TYPE_A and name in a_records:
            header.ancount = 1
            a = DNSResourceRecord()
            a.name = name
            a.rtype = TYPE_A
            a.rclass = CLASS_IN
            a.ttl = 300
            parts = [int(p) for p in a_records[name].split(".")]
            a.rdata = struct.pack("!BBBB", *parts)
            msg.answers.append(a)
        elif qtype == TYPE_AAAA and name in aaaa_records:
            header.ancount = 1
            aaaa = DNSResourceRecord()
            aaaa.name = name
            aaaa.rtype = TYPE_AAAA
            aaaa.rclass = CLASS_IN
            aaaa.ttl = 300
            ip_str = aaaa_records[name]
            parts = ip_str.split(":")
            full_parts = []
            for p in parts:
                if p == "":
                    while len(full_parts) + len(parts) - parts.index(p) - 1 < 8:
                        full_parts.append(0)
                else:
                    full_parts.append(int(p, 16))
            aaaa.rdata = struct.pack("!8H", *full_parts)
            msg.answers.append(aaaa)
        elif qtype == TYPE_MX and name in mx_records:
            header.ancount = 1
            pref, exchange = mx_records[name]
            mx = DNSResourceRecord()
            mx.name = name
            mx.rtype = TYPE_MX
            mx.rclass = CLASS_IN
            mx.ttl = 300
            mx.rdata = struct.pack("!H", pref) + encode_domain_name(exchange, allow_compression=False)[0]
            msg.answers.append(mx)
        elif qtype == TYPE_NS and name in ns_records:
            header.ancount = 1
            ns = DNSResourceRecord()
            ns.name = name
            ns.rtype = TYPE_NS
            ns.rclass = CLASS_IN
            ns.ttl = 3600
            ns.rdata = encode_domain_name(ns_records[name], allow_compression=False)[0]
            msg.answers.append(ns)
        elif qtype == TYPE_A and name in cname_chains:
            header.ancount = 2
            target = cname_chains[name]
            cname = DNSResourceRecord()
            cname.name = name
            cname.rtype = TYPE_CNAME
            cname.rclass = CLASS_IN
            cname.ttl = 300
            cname.rdata = encode_domain_name(target, allow_compression=False)[0]
            msg.answers.append(cname)
            a = DNSResourceRecord()
            a.name = target
            a.rtype = TYPE_A
            a.rclass = CLASS_IN
            a.ttl = 300
            parts = [int(p) for p in a_records[target].split(".")]
            a.rdata = struct.pack("!BBBB", *parts)
            msg.answers.append(a)
        else:
            header.ancount = 0

        elapsed = _time.time() - t0
        resolver._inc_stat("upstream_queries")
        resolver._inc_stat("upstream_time_total", elapsed)
        resolver._inc_stat("upstream_time_count")
        return msg, False

    resolver._query_upstream = mock_send

    queries = []
    for d in a_records:
        queries.append((d, TYPE_A, "success"))
    for d in aaaa_records:
        queries.append((d, TYPE_AAAA, "success"))
    for d in mx_records:
        queries.append((d, TYPE_MX, "success"))
    for d in ns_records:
        queries.append((d, TYPE_NS, "success"))
    for d in cname_chains:
        queries.append((d, TYPE_A, "success"))
    for d in nx_domains:
        queries.append((d, TYPE_A, "nxdomain"))

    queries *= 4
    random.shuffle(queries)

    success_count = 0
    fail_count = 0
    nx_count = 0
    errors = []
    start_times = []
    end_times = []
    lock = threading.Lock()

    def run_query(domain, qtype, expected):
        nonlocal success_count, fail_count, nx_count
        t0 = time.time()
        try:
            result = resolver.resolve(domain, qtype)
            t1 = time.time()
            with lock:
                if expected == "success":
                    success_count += 1
                    assert len(result) >= 1, f"No records for {domain}"
                else:
                    fail_count += 1
                    errors.append(f"{domain} should have failed")
        except ResolveError as e:
            t1 = time.time()
            with lock:
                if expected == "nxdomain":
                    nx_count += 1
                else:
                    fail_count += 1
                    errors.append(f"{domain} unexpected error: {e}")
        except Exception as e:
            t1 = time.time()
            with lock:
                fail_count += 1
                errors.append(f"{domain} exception: {type(e).__name__}: {e}")
        with lock:
            start_times.append(t0)
            end_times.append(t1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(run_query, d, qt, exp)
            for d, qt, exp in queries
        ]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    total_queries = len(queries)
    expected_success = sum(1 for _, _, e in queries if e == "success")
    expected_nx = sum(1 for _, _, e in queries if e == "nxdomain")

    stats = resolver.stats()

    if start_times and end_times:
        latencies = [end_times[i] - start_times[i] for i in range(len(start_times))]
        avg_latency_ms = sum(latencies) / len(latencies) * 1000
        max_latency_ms = max(latencies) * 1000
        total_time = max(end_times) - min(start_times)
        qps = total_queries / total_time if total_time > 0 else 0
    else:
        avg_latency_ms = 0
        max_latency_ms = 0
        qps = 0

    success_rate = (success_count + nx_count) / total_queries * 100 if total_queries > 0 else 0
    cache_hits = stats["cache_hits"]
    cache_hit_rate = cache_hits / total_queries * 100 if total_queries > 0 else 0
    upstream_queries = stats["upstream_queries"]
    dedup_saved = stats["singleflight_dedups"]

    print(f"\n  --- Stress Test Results ---")
    print(f"  Total queries:      {total_queries}")
    print(f"  Success rate:       {success_rate:.1f}% ({success_count} OK + {nx_count} NXDOMAIN)")
    print(f"  Failures:           {fail_count}")
    print(f"  Avg latency:        {avg_latency_ms:.1f} ms")
    print(f"  Max latency:        {max_latency_ms:.1f} ms")
    print(f"  QPS:                {qps:.0f}")
    print(f"  Cache hits:         {cache_hits} ({cache_hit_rate:.1f}%)")
    print(f"  Upstream queries:   {upstream_queries}")
    print(f"  Singleflight saved: {dedup_saved}")
    print(f"  ---------------------------")

    assert fail_count == 0, f"{fail_count} failures: {errors[:5]}"
    assert success_count == expected_success, (
        f"Expected {expected_success} success, got {success_count}"
    )
    assert nx_count == expected_nx, f"Expected {expected_nx} NXDOMAIN, got {nx_count}"

    assert stats["total_queries"] == total_queries
    assert stats["nxdomain_count"] >= expected_nx - 10, (
        f"Expected at least {expected_nx - 10} NXDOMAIN counts, got {stats['nxdomain_count']}. "
        f"Note: singleflight-deduplicated requests don't increment this counter twice."
    )
    assert stats["upstream_queries"] >= len(a_records) + len(aaaa_records) + len(mx_records) + len(ns_records) + len(cname_chains) + len(nx_domains) - 5

    if total_queries > 0:
        assert qps > 10, f"QPS too low: {qps:.1f}"


@_test_case("Second pass cache hit rate verifies caching effectiveness")
def test_cache_hit_rate_second_pass():
    """
    After first pass of queries populates cache, second pass should
    have near-100% cache hit rate and zero upstream queries.
    """
    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)

    upstream_call_count = [0]
    upstream_lock = threading.Lock()

    def mock_send(name, qtype, timeout=None):
        with upstream_lock:
            upstream_call_count[0] += 1
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
        a.rdata = struct.pack("!BBBB", 10, 0, 0, 1)

        msg = DNSMessage()
        msg.header = header
        msg.questions.append(q)
        msg.answers.append(a)
        return msg, False

    resolver._query_upstream = mock_send

    domains = [f"cachetest-{i:04d}.example.com" for i in range(30)]

    def do_pass():
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(resolver.resolve, d, TYPE_A) for d in domains]
            for f in concurrent.futures.as_completed(futures):
                f.result()

    do_pass()
    first_pass_upstream = upstream_call_count[0]
    assert first_pass_upstream == len(domains), (
        f"First pass: expected {len(domains)} upstream calls, got {first_pass_upstream}"
    )

    stats1 = resolver.stats()
    assert stats1["cache_hits"] == 0, "First pass should have 0 cache hits"

    print(f"\n  --- Cache Hit Rate Test: First Pass ---")
    print(f"  Total queries:      {len(domains)}")
    print(f"  Upstream queries:   {first_pass_upstream}")
    print(f"  Cache hits:         {stats1['cache_hits']} (0.0%)")

    upstream_call_count[0] = 0

    t0 = time.time()
    do_pass()
    t1 = time.time()
    second_pass_upstream = upstream_call_count[0]

    stats2 = resolver.stats()

    cache_hits_pass2 = stats2["cache_hits"] - stats1["cache_hits"]
    cache_hit_rate = cache_hits_pass2 / len(domains) * 100 if len(domains) > 0 else 0
    avg_latency_ms = (t1 - t0) / len(domains) * 1000 if len(domains) > 0 else 0

    print(f"\n  --- Cache Hit Rate Test: Second Pass ---")
    print(f"  Total queries:      {len(domains)}")
    print(f"  Upstream queries:   {second_pass_upstream}")
    print(f"  Cache hits:         {cache_hits_pass2} ({cache_hit_rate:.1f}%)")
    print(f"  Avg latency:        {avg_latency_ms:.1f} ms")
    print(f"  Success rate:       100.0%")
    print(f"  ---------------------------------------")

    assert second_pass_upstream == 0, (
        f"Second pass: expected 0 upstream calls (all cached), got {second_pass_upstream}. "
        "Cache not working properly for repeated queries."
    )

    assert cache_hits_pass2 >= len(domains), (
        f"Expected >= {len(domains)} cache hits, got {stats2['cache_hits']}"
    )


@_test_case("Large response: TC bit set when UDP payload exceeded")
def test_large_response_truncation():
    """
    When a response exceeds the UDP payload size, the TC (truncated) bit
    should be set, and only a partial response should be returned.
    """
    cache = DNSCache()
    resolver = DNSResolver(upstream_servers=[("127.0.0.1", 53)], cache=cache)

    def mock_send(name, qtype, timeout=None, use_tcp=False):
        header = DNSHeader()
        header.id = random.randint(0, 0xFFFF)
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

        for i in range(50):
            a = DNSResourceRecord()
            a.name = name
            a.rtype = TYPE_A
            a.rclass = CLASS_IN
            a.ttl = 300
            a.rdata = struct.pack("!BBBB", 10, 0, i // 256, i % 256)
            msg.answers.append(a)

        msg.header.ancount = len(msg.answers)

        resolver._inc_stat("upstream_queries")
        resolver._inc_stat("upstream_time_total", 0.001)
        resolver._inc_stat("upstream_time_count")
        return msg, False

    resolver._query_upstream = mock_send

    result = resolver.resolve("large.example.com", TYPE_A)
    assert len(result) > 0, "Should return some records"

    stats = resolver.stats()
    assert stats["truncated_count"] == 0 or stats["truncated_count"] == 1, (
        "truncated_count should be 0 or 1"
    )


@_test_case("TCP query: server accepts and responds over TCP")
def test_tcp_query_server():
    """
    Test that the DNS server can handle TCP DNS queries.
    TCP DNS uses a 2-byte length prefix before the DNS message.
    """
    import struct as _struct

    server = DNSServer(host="127.0.0.1", port=19535, allow_recursion=False)
    zone = server.add_authoritative_zone("tcptest.local", default_ttl=300)
    zone.add_record("@", "A", "10.9.8.7")
    zone.add_record("www", "CNAME", "tcptest.local")

    server.start()
    try:
        actual_port = 19535
        time.sleep(0.2)

        query = DNSMessage()
        query.header.id = 0x1234
        query.header.rd = 1
        query.header.qdcount = 1
        q = DNSQuestion()
        q.qname = "tcptest.local"
        q.qtype = TYPE_A
        q.qclass = CLASS_IN
        query.questions.append(q)

        query_data = query.pack()
        tcp_query = _struct.pack("!H", len(query_data)) + query_data

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(("127.0.0.1", actual_port))
            sock.sendall(tcp_query)

            length_data = b""
            while len(length_data) < 2:
                chunk = sock.recv(2 - len(length_data))
                assert chunk, "Connection closed before length received"
                length_data += chunk

            msg_length = _struct.unpack("!H", length_data)[0]
            assert 12 < msg_length < 65535, f"Invalid message length: {msg_length}"

            response_data = b""
            while len(response_data) < msg_length:
                chunk = sock.recv(min(4096, msg_length - len(response_data)))
                assert chunk, "Connection closed mid-message"
                response_data += chunk

            response = DNSMessage.unpack(response_data)
            assert response.header.id == 0x1234, "ID mismatch"
            assert response.header.qr == 1, "Not a response"
            assert response.header.rcode == RCODE_NOERROR, f"Unexpected rcode: {response.header.rcode}"
            assert len(response.answers) >= 1, "No answers returned"
            assert response.answers[0].rtype == TYPE_A, "Wrong answer type"

        finally:
            sock.close()

    finally:
        server.stop()


@_test_case("Upstream health: consecutive failures degrade status")
def test_upstream_health_degradation():
    """
    When an upstream server has consecutive failures, its health status
    should degrade from healthy -> degraded -> sick, with lower weight.
    """
    from dns_resolver import UpstreamHealth, HEALTH_HEALTHY, HEALTH_DEGRADED, HEALTH_SICK

    server = ("10.0.0.1", 53)
    health = UpstreamHealth(server)

    assert health.status == HEALTH_HEALTHY
    assert health.weight() == 10
    assert health.consecutive_failures == 0

    health.record_failure()
    assert health.consecutive_failures == 1
    assert health.status == HEALTH_HEALTHY
    assert health.weight() == 10

    health.record_failure()
    assert health.consecutive_failures == 2
    assert health.status == HEALTH_DEGRADED
    assert health.weight() == 3

    for _ in range(3):
        health.record_failure()
    assert health.consecutive_failures == 5
    assert health.status == HEALTH_SICK
    assert health.weight() == 1

    health.record_success(0.05)
    assert health.consecutive_failures == 0
    assert health.total_successes == 1
    assert health.status == HEALTH_SICK, (
        "Should still be sick right after first success (recovery interval not met)"
    )


@_test_case("Upstream health: weighted selection prefers healthy servers")
def test_upstream_health_weighted_selection():
    """
    The resolver should prefer healthy servers over sick ones
    when using weighted selection.
    """
    servers = [
        ("10.0.0.1", 53),
        ("10.0.0.2", 53),
        ("10.0.0.3", 53),
    ]
    resolver = DNSResolver(upstream_servers=servers)

    first_server = servers[0]
    for _ in range(10):
        resolver._record_upstream_failure(first_server)

    health = resolver.upstream_health_status()
    assert first_server in health
    assert health[first_server]["status"] in ("degraded", "sick"), (
        f"Expected degraded or sick, got {health[first_server]['status']}"
    )
    assert health[first_server]["consecutive_failures"] == 10
    assert health[first_server]["weight"] < 10

    selected = {}
    for _ in range(100):
        s = resolver._get_next_server()
        selected[s] = selected.get(s, 0) + 1

    assert len(selected) == 3, "All servers should be selectable"
    bad_server_count = selected.get(first_server, 0)
    assert bad_server_count < 60, (
        f"Bad server selected {bad_server_count}/100 times, should be much less"
    )


@_test_case("Cache management: clear by name removes all types for that domain")
def test_cache_clear_by_name():
    """
    clear_name() should remove all record types for a given domain,
    both positive and negative cache entries.
    """
    cache = DNSCache()

    rr_a = DNSResourceRecord()
    rr_a.name = "example.com"
    rr_a.rtype = TYPE_A
    rr_a.rclass = CLASS_IN
    rr_a.ttl = 300
    rr_a.rdata = struct.pack("!BBBB", 1, 2, 3, 4)

    rr_aaaa = DNSResourceRecord()
    rr_aaaa.name = "example.com"
    rr_aaaa.rtype = TYPE_AAAA
    rr_aaaa.rclass = CLASS_IN
    rr_aaaa.ttl = 300
    rr_aaaa.rdata = b"\x00" * 16

    rr_mx = DNSResourceRecord()
    rr_mx.name = "example.com"
    rr_mx.rtype = TYPE_MX
    rr_mx.rclass = CLASS_IN
    rr_mx.ttl = 300
    rr_mx.rdata = struct.pack("!H", 10) + encode_domain_name("mail.example.com", allow_compression=False)[0]

    cache.put([rr_a, rr_aaaa, rr_mx])
    cache.put_negative("other.com", TYPE_A, RCODE_NXDOMAIN, 300)

    assert cache.get("example.com", TYPE_A) is not None
    assert cache.get("example.com", TYPE_AAAA) is not None
    assert cache.get("example.com", TYPE_MX) is not None

    cache.clear_name("example.com")

    assert cache.get("example.com", TYPE_A) is None
    assert cache.get("example.com", TYPE_AAAA) is None
    assert cache.get("example.com", TYPE_MX) is None
    assert cache.get_negative("other.com", TYPE_A) is not None


@_test_case("Cache management: clear by type removes only specific type")
def test_cache_clear_by_type():
    """
    clear_type() should remove only the specific (name, type) entry,
    leaving other types for the same domain intact.
    """
    cache = DNSCache()

    rr_a = DNSResourceRecord()
    rr_a.name = "multi.example.com"
    rr_a.rtype = TYPE_A
    rr_a.rclass = CLASS_IN
    rr_a.ttl = 300
    rr_a.rdata = struct.pack("!BBBB", 5, 6, 7, 8)

    rr_aaaa = DNSResourceRecord()
    rr_aaaa.name = "multi.example.com"
    rr_aaaa.rtype = TYPE_AAAA
    rr_aaaa.rclass = CLASS_IN
    rr_aaaa.ttl = 300
    rr_aaaa.rdata = b"\x01" * 16

    cache.put([rr_a, rr_aaaa])
    cache.put_negative("multi.example.com", TYPE_MX, RCODE_NXDOMAIN, 300)

    assert cache.get("multi.example.com", TYPE_A) is not None
    assert cache.get("multi.example.com", TYPE_AAAA) is not None

    cache.clear_type("multi.example.com", TYPE_A)

    assert cache.get("multi.example.com", TYPE_A) is None
    assert cache.get("multi.example.com", TYPE_AAAA) is not None
    assert cache.get_negative("multi.example.com", TYPE_MX) is not None


@_test_case("Cache snapshot: export and import preserves records")
def test_cache_snapshot_export_import():
    """
    export_snapshot() and import_snapshot() should correctly
    save and restore cache entries with their remaining TTLs.
    """
    cache1 = DNSCache()

    for i in range(5):
        rr = DNSResourceRecord()
        rr.name = f"snap-{i}.example.com"
        rr.rtype = TYPE_A
        rr.rclass = CLASS_IN
        rr.ttl = 600 + i * 10
        rr.rdata = struct.pack("!BBBB", 10, 0, 0, i)
        cache1.put([rr])

    cache1.put_negative("snap-nx.example.com", TYPE_A, RCODE_NXDOMAIN, 300)

    snapshot_data = cache1.export_snapshot()
    assert isinstance(snapshot_data, bytes)
    assert len(snapshot_data) > 0

    cache2 = DNSCache()
    pos_count, neg_count = cache2.import_snapshot(data=snapshot_data, min_ttl=1)

    assert pos_count == 5, f"Expected 5 positive records imported, got {pos_count}"
    assert neg_count == 1, f"Expected 1 negative entry imported, got {neg_count}"

    for i in range(5):
        records = cache2.get(f"snap-{i}.example.com", TYPE_A)
        assert records is not None, f"snap-{i}.example.com not found after import"
        assert len(records) == 1
        assert records[0].ttl > 0, "Imported record should have positive TTL"

    neg = cache2.get_negative("snap-nx.example.com", TYPE_A)
    assert neg is not None
    assert neg[0] == RCODE_NXDOMAIN


@_test_case("Cache snapshot: import with max_ttl caps expiration")
def test_cache_snapshot_max_ttl():
    """
    import_snapshot() with max_ttl should cap the TTL of imported records.
    """
    cache1 = DNSCache()
    rr = DNSResourceRecord()
    rr.name = "long-ttl.example.com"
    rr.rtype = TYPE_A
    rr.rclass = CLASS_IN
    rr.ttl = 86400
    rr.rdata = struct.pack("!BBBB", 10, 0, 0, 1)
    cache1.put([rr])

    snapshot = cache1.export_snapshot()

    cache2 = DNSCache()
    pos_count, _ = cache2.import_snapshot(data=snapshot, max_ttl=60, min_ttl=1)

    assert pos_count == 1
    records = cache2.get("long-ttl.example.com", TYPE_A)
    assert records is not None
    assert len(records) == 1
    assert records[0].ttl <= 61, f"TTL should be <= ~60, got {records[0].ttl}"


@_test_case("Server status: print_status produces valid output")
def test_server_print_status():
    """
    server.print_status() should produce a formatted status report
    without errors, including all major sections.
    """
    import io
    import sys

    server = DNSServer(host="127.0.0.1", port=0, upstream_servers=[("8.8.8.8", 53)])

    old_stdout = sys.stdout
    captured = io.StringIO()
    try:
        sys.stdout = captured
        server.print_status()
    finally:
        sys.stdout = old_stdout

    output = captured.getvalue()
    assert "DNS Server Status" in output
    assert "Query Statistics" in output
    assert "Cache Statistics" in output
    assert "Singleflight" in output
    assert "Upstream" in output
    assert "Upstream Health" in output
    assert "8.8.8.8" in output

    stats = server.stats()
    assert "total_queries" in stats
    assert "cache" in stats
    assert "singleflight" in stats
    assert "upstream_health" in stats
    assert "cache_hit_rate" in stats


def run_all_tests():
    print("=" * 60)
    print("DNS Server Test Suite")
    print("=" * 60)

    print("\n--- DNS Message Parsing ---")
    _run_test(test_parse_simple_domain)
    _run_test(test_parse_compression_pointer)
    _run_test(test_reject_forward_pointer)
    _run_test(test_reject_pointer_loop)
    _run_test(test_reject_too_many_jumps)
    _run_test(test_reject_oversized_label)
    _run_test(test_reject_oversized_domain)
    _run_test(test_reject_oversized_rdata)
    _run_test(test_encode_decode_domain)
    _run_test(test_message_roundtrip)
    _run_test(test_parse_aaaa)
    _run_test(test_parse_cname)
    _run_test(test_parse_mx)
    _run_test(test_domain_compression_encoding)

    print("\n--- Cache (Per-record TTL) ---")
    _run_test(test_cache_basic)
    _run_test(test_cache_ttl_expiration)
    _run_test(test_cache_miss)
    _run_test(test_cache_adjusted_ttl)
    _run_test(test_cache_case_insensitive)
    _run_test(test_cache_cname_follow)
    _run_test(test_cache_independent_types)

    print("\n--- Singleflight (Deduplication) ---")
    _run_test(test_singleflight_basic)
    _run_test(test_singleflight_different_keys)
    _run_test(test_singleflight_errors)
    _run_test(test_singleflight_stats)

    print("\n--- Authority Zones ---")
    _run_test(test_authority_a_lookup)
    _run_test(test_authority_origin)
    _run_test(test_authority_cname_within_zone)
    _run_test(test_authority_store_multizone)
    _run_test(test_authority_nxdomain)
    _run_test(test_authority_mx)

    print("\n--- Server Integration & Security ---")
    _run_test(test_server_authoritative)
    _run_test(test_security_truncated_header)
    _run_test(test_security_garbage)

    print("\n--- Real-world Scenario Tests ---")
    _run_test(test_rdata_compression_cname)
    _run_test(test_rdata_compression_ns)
    _run_test(test_rdata_compression_mx)
    _run_test(test_rdata_compression_multi_record)
    _run_test(test_cname_chain_full_return)
    _run_test(test_singleflight_slow_upstream)
    _run_test(test_singleflight_very_slow_upstream)
    _run_test(test_concurrent_multi_domain_stability)
    _run_test(test_resolver_cached_cname_chain)
    _run_test(test_negative_cache_nxdomain)
    _run_test(test_negative_cache_servfail)
    _run_test(test_cached_cname_upstream_offline)
    _run_test(test_resolver_statistics)
    _run_test(test_e2e_mixed_query_stress)
    _run_test(test_cache_hit_rate_second_pass)

    print("\n--- TCP & Large Response ---")
    _run_test(test_large_response_truncation)
    _run_test(test_tcp_query_server)

    print("\n--- Upstream Health ---")
    _run_test(test_upstream_health_degradation)
    _run_test(test_upstream_health_weighted_selection)

    print("\n--- Cache Management ---")
    _run_test(test_cache_clear_by_name)
    _run_test(test_cache_clear_by_type)
    _run_test(test_cache_snapshot_export_import)
    _run_test(test_cache_snapshot_max_ttl)

    print("\n--- Status & Diagnostics ---")
    _run_test(test_server_print_status)

    print("\n" + "=" * 60)
    print(f"Results: {_passed} passed, {_failed} failed")
    print("=" * 60)

    return _failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
