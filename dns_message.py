import struct
import io

# DNS Record Types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_OPT = 41
TYPE_ANY = 255

# DNS Classes
CLASS_IN = 1
CLASS_CH = 3
CLASS_HS = 4
CLASS_ANY = 255

# Response Codes
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

# Security limits
MAX_DOMAIN_LENGTH = 255
MAX_LABEL_LENGTH = 63
MAX_POINTER_JUMPS = 20
MAX_MESSAGE_SIZE = 65535
MAX_UDP_PAYLOAD = 512
MAX_EDNS_PAYLOAD = 4096
MAX_RDATA_LENGTH = 65500


class DNSSecurityError(Exception):
    pass


class DNSParseError(Exception):
    pass


def type_to_str(t):
    mapping = {
        TYPE_A: "A",
        TYPE_NS: "NS",
        TYPE_CNAME: "CNAME",
        TYPE_SOA: "SOA",
        TYPE_MX: "MX",
        TYPE_TXT: "TXT",
        TYPE_AAAA: "AAAA",
        TYPE_SRV: "SRV",
        TYPE_OPT: "OPT",
        TYPE_ANY: "ANY",
    }
    return mapping.get(t, f"TYPE{t}")


def str_to_type(s):
    mapping = {
        "A": TYPE_A,
        "NS": TYPE_NS,
        "CNAME": TYPE_CNAME,
        "SOA": TYPE_SOA,
        "MX": TYPE_MX,
        "TXT": TYPE_TXT,
        "AAAA": TYPE_AAAA,
        "SRV": TYPE_SRV,
        "OPT": TYPE_OPT,
        "ANY": TYPE_ANY,
    }
    return mapping.get(s.upper())


def class_to_str(c):
    mapping = {CLASS_IN: "IN", CLASS_CH: "CH", CLASS_HS: "HS", CLASS_ANY: "ANY"}
    return mapping.get(c, f"CLASS{c}")


class DNSHeader:
    FORMAT = "!HHHHHH"

    def __init__(self):
        self.id = 0
        self.qr = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 0
        self.ra = 0
        self.z = 0
        self.rcode = 0
        self.qdcount = 0
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

    def pack(self):
        flags = (
            (self.qr & 1) << 15
            | (self.opcode & 0xF) << 11
            | (self.aa & 1) << 10
            | (self.tc & 1) << 9
            | (self.rd & 1) << 8
            | (self.ra & 1) << 7
            | (self.z & 7) << 4
            | (self.rcode & 0xF)
        )
        return struct.pack(
            self.FORMAT,
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def unpack(cls, data, offset=0):
        h = cls()
        if len(data) < offset + 12:
            raise DNSParseError("DNS header truncated")
        h.id, flags, h.qdcount, h.ancount, h.nscount, h.arcount = struct.unpack_from(
            cls.FORMAT, data, offset
        )
        h.qr = (flags >> 15) & 1
        h.opcode = (flags >> 11) & 0xF
        h.aa = (flags >> 10) & 1
        h.tc = (flags >> 9) & 1
        h.rd = (flags >> 8) & 1
        h.ra = (flags >> 7) & 1
        h.z = (flags >> 4) & 7
        h.rcode = flags & 0xF
        return h, offset + 12


def parse_domain_name(data, offset, jumps=0):
    """
    Parse a DNS domain name with proper compression pointer handling.

    Security:
    - Limit pointer jumps to MAX_POINTER_JUMPS to prevent infinite loops
    - Ensure pointers only jump backward (to earlier offsets) to prevent forward-reference loops
    - Validate each label length and total domain length
    """
    if jumps > MAX_POINTER_JUMPS:
        raise DNSSecurityError("Too many compression pointer jumps, possible infinite loop")

    labels = []
    original_offset = offset
    jumped = False
    name_end_offset = None

    while True:
        if offset >= len(data):
            raise DNSParseError("Domain name parsing ran past end of message")

        length = data[offset]

        if length == 0:
            offset += 1
            if not jumped:
                name_end_offset = offset
            break

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise DNSParseError("Compression pointer truncated")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer >= original_offset:
                raise DNSSecurityError(
                    f"Compression pointer jumps forward ({pointer} >= {original_offset}), possible attack"
                )
            if not jumped:
                name_end_offset = offset + 2
            jumped = True
            offset = pointer
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise DNSSecurityError(
                    "Too many compression pointer jumps, possible infinite loop"
                )
            continue

        if (length & 0xC0) != 0:
            raise DNSParseError(f"Invalid label length byte: 0x{length:02x}")

        if length > MAX_LABEL_LENGTH:
            raise DNSSecurityError(
                f"Label too long: {length} bytes (max {MAX_LABEL_LENGTH})"
            )

        offset += 1
        if offset + length > len(data):
            raise DNSParseError("Label data truncated")

        label = data[offset : offset + length]
        labels.append(label.decode("ascii", errors="replace"))
        offset += length

        total = sum(len(l) for l in labels) + len(labels)
        if total > MAX_DOMAIN_LENGTH:
            raise DNSSecurityError(
                f"Domain name too long: {total} bytes (max {MAX_DOMAIN_LENGTH})"
            )

    if name_end_offset is None:
        name_end_offset = offset

    return ".".join(labels), name_end_offset


def encode_domain_name(name, allow_compression=True, compression_map=None, offset=0):
    """
    Encode a domain name, optionally using compression pointers.

    Security:
    - Validates label lengths and total length before encoding
    """
    if not name:
        return b"\x00", offset + 1

    if name.endswith("."):
        name = name[:-1]

    labels = name.split(".")
    for label in labels:
        if len(label) == 0:
            raise DNSSecurityError("Empty label in domain name")
        if len(label) > MAX_LABEL_LENGTH:
            raise DNSSecurityError(
                f"Label too long: '{label}' ({len(label)} bytes)"
            )

    total = sum(len(l) for l in labels) + len(labels) + 1
    if total > MAX_DOMAIN_LENGTH:
        raise DNSSecurityError(f"Domain name too long: {total} bytes")

    result = bytearray()
    current_offset = offset

    for i, label in enumerate(labels):
        suffix = ".".join(labels[i:])

        if (
            allow_compression
            and compression_map is not None
            and suffix in compression_map
        ):
            ptr = compression_map[suffix]
            pointer_val = 0xC000 | ptr
            result.extend(struct.pack("!H", pointer_val))
            current_offset += 2
            return bytes(result), current_offset

        if compression_map is not None and suffix not in compression_map:
            compression_map[suffix] = current_offset

        label_bytes = label.encode("ascii")
        result.append(len(label_bytes))
        result.extend(label_bytes)
        current_offset += 1 + len(label_bytes)

    result.append(0)
    current_offset += 1
    return bytes(result), current_offset


class DNSQuestion:
    def __init__(self):
        self.qname = ""
        self.qtype = TYPE_A
        self.qclass = CLASS_IN

    def pack(self, compression_map=None, offset=0):
        name_data, offset = encode_domain_name(
            self.qname, allow_compression=False, compression_map=None, offset=offset
        )
        data = name_data + struct.pack("!HH", self.qtype, self.qclass)
        return data, offset + 4

    @classmethod
    def unpack(cls, data, offset):
        q = cls()
        q.qname, offset = parse_domain_name(data, offset)
        if offset + 4 > len(data):
            raise DNSParseError("Question section truncated")
        q.qtype, q.qclass = struct.unpack_from("!HH", data, offset)
        return q, offset + 4


class DNSResourceRecord:
    def __init__(self):
        self.name = ""
        self.rtype = TYPE_A
        self.rclass = CLASS_IN
        self.ttl = 0
        self.rdata = b""
        self._message_context = None
        self._rdata_offset = 0

    @property
    def rdlength(self):
        return len(self.rdata)

    def pack(self, compression_map=None, offset=0):
        name_data, offset = encode_domain_name(
            self.name,
            allow_compression=True,
            compression_map=compression_map,
            offset=offset,
        )
        header = struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, self.rdlength)
        return name_data + header + self.rdata, offset + 10 + self.rdlength

    @classmethod
    def unpack(cls, data, offset):
        rr = cls()
        rr.name, offset = parse_domain_name(data, offset)
        if offset + 10 > len(data):
            raise DNSParseError("RR header truncated")
        rr.rtype, rr.rclass, rr.ttl, rdlen = struct.unpack_from("!HHIH", data, offset)
        offset += 10

        if rdlen > MAX_RDATA_LENGTH:
            raise DNSSecurityError(
                f"RDLENGTH too large: {rdlen} (max {MAX_RDATA_LENGTH})"
            )
        if rdlen < 0:
            raise DNSSecurityError("Negative RDLENGTH")
        if offset + rdlen > len(data):
            raise DNSParseError("RR RDATA truncated")

        rr.rdata = bytes(data[offset : offset + rdlen])
        rr._message_context = data
        rr._rdata_offset = offset
        offset += rdlen

        return rr, offset

    def parse_rdata(self, data=None):
        """
        Parse RDATA into a human-readable format based on record type.

        Uses the full message context (if available) to properly resolve
        compression pointers in RDATA for CNAME, NS, MX records.
        """
        has_context = self._message_context is not None
        full_msg = self._message_context if has_context else None
        rdata_off = self._rdata_offset if has_context else 0

        if self.rtype == TYPE_A:
            d = data if data is not None else self.rdata
            if len(d) != 4:
                return None
            return ".".join(str(b) for b in d)
        elif self.rtype == TYPE_AAAA:
            d = data if data is not None else self.rdata
            if len(d) != 16:
                return None
            parts = []
            for i in range(0, 16, 2):
                parts.append(f"{d[i]:02x}{d[i+1]:02x}")
            return ":".join(parts)
        elif self.rtype == TYPE_CNAME or self.rtype == TYPE_NS:
            try:
                if has_context:
                    name, _ = parse_domain_name(full_msg, rdata_off)
                else:
                    d = data if data is not None else self.rdata
                    name, _ = parse_domain_name(d, 0)
                return name
            except (DNSParseError, DNSSecurityError):
                return None
        elif self.rtype == TYPE_MX:
            try:
                if has_context:
                    if self._rdata_offset + 2 > len(full_msg):
                        return None
                    preference = struct.unpack_from("!H", full_msg, self._rdata_offset)[0]
                    exchange, _ = parse_domain_name(full_msg, self._rdata_offset + 2)
                else:
                    d = data if data is not None else self.rdata
                    if len(d) < 3:
                        return None
                    preference = struct.unpack_from("!H", d, 0)[0]
                    exchange, _ = parse_domain_name(d, 2)
                return (preference, exchange)
            except (DNSParseError, DNSSecurityError):
                return None
        elif self.rtype == TYPE_TXT:
            d = data if data is not None else self.rdata
            strings = []
            pos = 0
            while pos < len(d):
                slen = d[pos]
                pos += 1
                if pos + slen > len(d):
                    break
                strings.append(d[pos : pos + slen].decode("utf-8", errors="replace"))
                pos += slen
            return strings
        elif self.rtype == TYPE_SOA:
            try:
                if has_context:
                    mname, next_off = parse_domain_name(full_msg, self._rdata_offset)
                    rname, next_off = parse_domain_name(full_msg, next_off)
                    serial, refresh, retry, expire, minimum = struct.unpack_from(
                        "!IIIII", full_msg, next_off)
                else:
                    d = data if data is not None else self.rdata
                    mname, next_off = parse_domain_name(d, 0)
                    rname, next_off = parse_domain_name(d, next_off)
                    serial, refresh, retry, expire, minimum = struct.unpack_from(
                        "!IIIII", d, next_off)
                return {
                    "mname": mname,
                    "rname": rname,
                    "serial": serial,
                    "refresh": refresh,
                    "retry": retry,
                    "expire": expire,
                    "minimum": minimum,
                }
            except Exception:
                return None
        else:
            d = data if data is not None else self.rdata
            return d.hex()

    @classmethod
    def create_a(cls, name, ip, ttl=300):
        rr = cls()
        rr.name = name
        rr.rtype = TYPE_A
        rr.rclass = CLASS_IN
        rr.ttl = ttl
        parts = [int(p) for p in ip.split(".")]
        rr.rdata = bytes(parts)
        return rr

    @classmethod
    def create_aaaa(cls, name, ip, ttl=300):
        rr = cls()
        rr.name = name
        rr.rtype = TYPE_AAAA
        rr.rclass = CLASS_IN
        rr.ttl = ttl
        parts = ip.split(":")
        expanded = []
        for p in parts:
            if p == "":
                zeros_needed = 8 - len(parts) + 1
                expanded.extend(["0000"] * zeros_needed)
            else:
                expanded.append(p.zfill(4))
        rr.rdata = b"".join(bytes.fromhex(p) for p in expanded)
        return rr

    @classmethod
    def create_cname(cls, name, target, ttl=300):
        rr = cls()
        rr.name = name
        rr.rtype = TYPE_CNAME
        rr.rclass = CLASS_IN
        rr.ttl = ttl
        rr.rdata, _ = encode_domain_name(target)
        return rr

    @classmethod
    def create_mx(cls, name, preference, exchange, ttl=300):
        rr = cls()
        rr.name = name
        rr.rtype = TYPE_MX
        rr.rclass = CLASS_IN
        rr.ttl = ttl
        pref_bytes = struct.pack("!H", preference)
        exch_bytes, _ = encode_domain_name(exchange)
        rr.rdata = pref_bytes + exch_bytes
        return rr


class DNSMessage:
    def __init__(self):
        self.header = DNSHeader()
        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

    def pack(self, max_size=MAX_UDP_PAYLOAD):
        """
        Pack the DNS message, respecting size limits.
        If message would exceed max_size, truncate additional sections and set TC flag.
        Always updates header counts to match actual records packed.
        """
        compression_map = {}

        self.header.qdcount = len(self.questions)

        actual_answers = 0
        actual_authorities = 0
        actual_additionals = 0

        header_data = self.header.pack()
        result = bytearray(header_data)
        offset = len(header_data)

        for q in self.questions:
            q_data, offset = q.pack(compression_map=None, offset=offset)
            result.extend(q_data)

        sections = [
            (self.answers, "answers"),
            (self.authorities, "authorities"),
            (self.additionals, "additionals"),
        ]
        counters = [0, 0, 0]

        truncated = False
        for sidx, (records, _name) in enumerate(sections):
            for rr in records:
                rr_data, new_offset = rr.pack(
                    compression_map=compression_map, offset=offset
                )
                if len(result) + len(rr_data) > max_size:
                    truncated = True
                    break
                result.extend(rr_data)
                offset = new_offset
                counters[sidx] += 1
            if truncated:
                break

        actual_answers, actual_authorities, actual_additionals = counters

        self.header.ancount = actual_answers
        self.header.nscount = actual_authorities
        self.header.arcount = actual_additionals

        if truncated:
            self.header.tc = 1

        self.header.qdcount = len(self.questions)
        result[0:12] = self.header.pack()

        return bytes(result)

    @classmethod
    def unpack(cls, data):
        """
        Parse a complete DNS message.

        Security:
        - Validates message size
        - Section counts are validated during parsing
        - Each record's RDLENGTH is checked against MAX_RDATA_LENGTH
        """
        if len(data) > MAX_MESSAGE_SIZE:
            raise DNSSecurityError(
                f"DNS message too large: {len(data)} bytes (max {MAX_MESSAGE_SIZE})"
            )
        if len(data) < 12:
            raise DNSParseError("DNS message too short")

        msg = cls()
        msg.header, offset = DNSHeader.unpack(data, 0)

        for _ in range(msg.header.qdcount):
            q, offset = DNSQuestion.unpack(data, offset)
            msg.questions.append(q)

        for _ in range(msg.header.ancount):
            rr, offset = DNSResourceRecord.unpack(data, offset)
            msg.answers.append(rr)

        for _ in range(msg.header.nscount):
            rr, offset = DNSResourceRecord.unpack(data, offset)
            msg.authorities.append(rr)

        for _ in range(msg.header.arcount):
            rr, offset = DNSResourceRecord.unpack(data, offset)
            msg.additionals.append(rr)

        return msg

    def make_response(self):
        """Create a response message based on this query."""
        resp = DNSMessage()
        resp.header.id = self.header.id
        resp.header.qr = 1
        resp.header.opcode = self.header.opcode
        resp.header.rd = self.header.rd
        resp.header.ra = 1
        resp.header.rcode = RCODE_NOERROR
        resp.questions = list(self.questions)
        return resp

    def get_question(self):
        if self.questions:
            return self.questions[0]
        return None
