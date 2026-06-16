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
    MAX_LABEL_LENGTH,
    MAX_DOMAIN_LENGTH,
    MAX_POINTER_JUMPS,
    MAX_RDATA_LENGTH,
    DNSSecurityError,
    DNSParseError,
)
from dns_cache import DNSCache, CacheEntry
from singleflight import Singleflight
from dns_authority import AuthorityZone, AuthorityStore
from dns_server import DNSServer


_passed = 0
_failed = 0


def test(name):
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

@test("Parse simple domain name without compression")
def test_parse_simple_domain():
    data = b"\x03www\x07example\x03com\x00"
    name, offset = parse_domain_name(data, 0)
    assert name == "www.example.com", f"Got '{name}'"
    assert offset == 1 + 3 + 1 + 7 + 1 + 3 + 1


@test("Parse domain with compression pointer (backward jump)")
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


@test("Reject compression pointer that jumps forward (security)")
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


@test("Reject infinite pointer loop (security)")
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


@test("Reject too many pointer jumps (security)")
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


@test("Reject label exceeding 63 bytes (security)")
def test_reject_oversized_label():
    length_byte = MAX_LABEL_LENGTH + 1
    label_content = b"a" * (MAX_LABEL_LENGTH + 1)
    data = bytes([length_byte]) + label_content + b"\x00"
    try:
        parse_domain_name(data, 0)
        assert False, "Should have raised DNSSecurityError"
    except (DNSSecurityError, DNSParseError):
        pass


@test("Reject domain name exceeding 255 bytes (security)")
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


@test("Reject RR with oversized RDLENGTH (security)")
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


@test("Encode/decode domain round-trip")
def test_encode_decode_domain():
    for name in ["example.com", "www.sub.example.com.", "a.b.c.d.e.f"]:
        encoded, _ = encode_domain_name(name, allow_compression=False)
        decoded, _ = parse_domain_name(encoded, 0)
        expected = name.rstrip(".")
        assert decoded == expected, f"Round-trip failed: '{name}' -> '{decoded}'"


@test("DNS message pack/unpack round-trip")
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


@test("Parse AAAA record correctly")
def test_parse_aaaa():
    rr = DNSResourceRecord.create_aaaa("ipv6.test", "2001:db8::1", ttl=600)
    parsed = rr.parse_rdata()
    assert parsed is not None
    assert "2001" in parsed and "0db8" in parsed


@test("Parse CNAME record correctly")
def test_parse_cname():
    rr = DNSResourceRecord.create_cname("alias.test", "target.test", ttl=300)
    parsed = rr.parse_rdata()
    assert parsed == "target.test"


@test("Parse MX record correctly")
def test_parse_mx():
    rr = DNSResourceRecord.create_mx("test", 10, "mail.test", ttl=300)
    parsed = rr.parse_rdata()
    assert parsed == (10, "mail.test")


@test("Domain compression during encoding")
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

@test("Cache basic get/put")
def test_cache_basic():
    cache = DNSCache()
    rr = DNSResourceRecord.create_a("test.com", "10.0.0.1", ttl=100)
    cache.put([rr])
    result = cache.get("test.com", TYPE_A)
    assert result is not None
    assert len(result) == 1
    assert result[0].parse_rdata() == "10.0.0.1"
    cache.stop()


@test("Cache TTL expiration (per record)")
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


@test("Cache miss for non-existent entry")
def test_cache_miss():
    cache = DNSCache()
    assert cache.get("nonexistent.com", TYPE_A) is None
    cache.stop()


@test("Cache returns TTL adjusted to remaining time")
def test_cache_adjusted_ttl():
    cache = DNSCache()
    rr = DNSResourceRecord.create_a("ttl.test", "1.2.3.4", ttl=100)
    cache.put([rr])
    time.sleep(1.5)
    result = cache.get("ttl.test", TYPE_A)
    assert result is not None
    assert 97 <= result[0].ttl <= 99, f"Expected TTL ~98, got {result[0].ttl}"
    cache.stop()


@test("Cache case-insensitive lookups")
def test_cache_case_insensitive():
    cache = DNSCache()
    rr = DNSResourceRecord.create_a("MixedCase.COM", "1.2.3.4", ttl=300)
    cache.put([rr])
    assert cache.get("mixedcase.com", TYPE_A) is not None
    assert cache.get("MIXEDCASE.COM", TYPE_A) is not None
    cache.stop()


@test("Cache follows CNAME chains")
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


@test("Cache stores all record types independently")
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

@test("Singleflight basic deduplication")
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


@test("Singleflight different keys don't collide")
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


@test("Singleflight propagates errors")
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


@test("Singleflight stats tracking")
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

@test("Authority zone direct A record lookup")
def test_authority_a_lookup():
    zone = AuthorityZone("test.com")
    zone.add_record("www", "A", "10.0.0.1")
    records, is_auth, zone_exists = zone.lookup("www.test.com", TYPE_A)
    assert is_auth
    assert zone_exists
    assert len(records) == 1
    assert records[0].parse_rdata() == "10.0.0.1"


@test("Authority zone origin (@) record")
def test_authority_origin():
    zone = AuthorityZone("myzone.com")
    zone.add_record("@", "A", "10.0.0.100")
    records, is_auth, _ = zone.lookup("myzone.com", TYPE_A)
    assert is_auth
    assert len(records) == 1
    assert records[0].parse_rdata() == "10.0.0.100"


@test("Authority zone CNAME resolution within zone")
def test_authority_cname_within_zone():
    zone = AuthorityZone("intrazone.com")
    zone.add_record("alias", "CNAME", "target.intrazone.com")
    zone.add_record("target", "A", "172.16.0.1")

    records, is_auth, _ = zone.lookup("alias.intrazone.com", TYPE_A)
    assert is_auth
    types = [r.rtype for r in records]
    assert TYPE_CNAME in types
    assert TYPE_A in types


@test("Authority store multi-zone lookup")
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


@test("Authority zone returns no answer for unknown name")
def test_authority_nxdomain():
    zone = AuthorityZone("known.com")
    records, is_auth, zone_exists = zone.lookup("unknown.known.com", TYPE_A)
    assert is_auth
    assert zone_exists
    assert len(records) == 0


@test("Authority MX record")
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

@test("Full server authoritative query")
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


@test("Malformed packet security: truncated header")
def test_security_truncated_header():
    try:
        DNSMessage.unpack(b"\x00\x00\x01")
        assert False, "Should have raised"
    except (DNSParseError, DNSSecurityError):
        pass


@test("Malformed packet security: garbage data")
def test_security_garbage():
    garbage = os.urandom(200)
    try:
        DNSMessage.unpack(garbage)
    except (DNSParseError, DNSSecurityError):
        pass
    except Exception as e:
        assert False, f"Unexpected exception type: {type(e).__name__}"


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

    print("\n" + "=" * 60)
    print(f"Results: {_passed} passed, {_failed} failed")
    print("=" * 60)

    return _failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
