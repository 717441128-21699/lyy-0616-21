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
    CLASS_IN,
    str_to_type,
)


class AuthorityZone:
    """
    Stores authoritative DNS records for a specific zone.
    Thread-safe.
    """

    def __init__(self, origin, default_ttl=3600):
        self.origin = origin.rstrip(".").lower()
        self.default_ttl = default_ttl
        self._records = {}
        self._lock = threading.RLock()

    def _full_name(self, name):
        name = name.rstrip(".").lower()
        if name == "" or name == "@":
            return self.origin
        if not name.endswith(self.origin):
            return f"{name}.{self.origin}"
        return name

    def add_record(self, name, rtype_str, rdata, ttl=None):
        if ttl is None:
            ttl = self.default_ttl
        qtype = str_to_type(rtype_str)
        if qtype is None:
            raise ValueError(f"Unknown record type: {rtype_str}")

        full_name = self._full_name(name)

        if qtype == TYPE_A:
            rr = DNSResourceRecord.create_a(full_name, rdata, ttl)
        elif qtype == TYPE_AAAA:
            rr = DNSResourceRecord.create_aaaa(full_name, rdata, ttl)
        elif qtype == TYPE_CNAME:
            rr = DNSResourceRecord.create_cname(full_name, rdata, ttl)
        elif qtype == TYPE_MX:
            pref, exchange = rdata
            rr = DNSResourceRecord.create_mx(full_name, pref, exchange, ttl)
        elif qtype == TYPE_NS:
            rr = DNSResourceRecord()
            rr.name = full_name
            rr.rtype = TYPE_NS
            rr.rclass = CLASS_IN
            rr.ttl = ttl
            from dns_message import encode_domain_name
            rr.rdata, _ = encode_domain_name(rdata)
        elif qtype == TYPE_TXT:
            rr = DNSResourceRecord()
            rr.name = full_name
            rr.rtype = TYPE_TXT
            rr.rclass = CLASS_IN
            rr.ttl = ttl
            txt_bytes = rdata.encode("utf-8")
            rr.rdata = bytes([len(txt_bytes)]) + txt_bytes
        elif qtype == TYPE_SOA:
            rr = DNSResourceRecord()
            rr.name = full_name
            rr.rtype = TYPE_SOA
            rr.rclass = CLASS_IN
            rr.ttl = ttl
            from dns_message import encode_domain_name
            import struct
            mname, _ = encode_domain_name(rdata["mname"])
            rname, _ = encode_domain_name(rdata["rname"])
            soa_data = mname + rname + struct.pack(
                "!IIIII",
                rdata.get("serial", 1),
                rdata.get("refresh", 3600),
                rdata.get("retry", 600),
                rdata.get("expire", 86400),
                rdata.get("minimum", 300),
            )
            rr.rdata = soa_data
        else:
            raise ValueError(f"Unsupported record type for adding: {rtype_str}")

        key = (full_name, qtype)
        with self._lock:
            if key not in self._records:
                self._records[key] = []
            self._records[key].append(rr)

    def lookup(self, name, qtype):
        """
        Look up authoritative records.

        Returns (records, is_authoritative, zone_exists)
        - records: list of matching DNSResourceRecord
        - is_authoritative: True if this zone is authoritative for the name
        - zone_exists: True if the queried name is within this zone
        """
        name_lower = name.rstrip(".").lower()

        if not (name_lower == self.origin or name_lower.endswith("." + self.origin)):
            return [], False, False

        zone_exists = True

        if qtype == TYPE_CNAME:
            key = (name_lower, TYPE_CNAME)
            with self._lock:
                records = list(self._records.get(key, []))
            if records:
                return records, True, zone_exists
            return [], True, zone_exists

        cname_key = (name_lower, TYPE_CNAME)
        with self._lock:
            cname_records = list(self._records.get(cname_key, []))
            direct_key = (name_lower, qtype)
            direct_records = list(self._records.get(direct_key, []))

        if cname_records:
            cname_target = cname_records[0].parse_rdata()
            if cname_target and cname_target.lower().rstrip(".") == name_lower:
                return [], True, zone_exists

            all_records = list(cname_records)
            if cname_target:
                target_lower = cname_target.rstrip(".").lower()
                if target_lower == self.origin or target_lower.endswith("." + self.origin):
                    target_key = (target_lower, qtype)
                    with self._lock:
                        target_records = list(self._records.get(target_key, []))
                    all_records.extend(target_records)
            return all_records, True, zone_exists

        if direct_records:
            return direct_records, True, zone_exists

        return [], True, zone_exists


class AuthorityStore:
    """
    Manages multiple authoritative zones.
    """

    def __init__(self):
        self._zones = {}
        self._lock = threading.RLock()

    def add_zone(self, zone):
        with self._lock:
            self._zones[zone.origin] = zone

    def create_zone(self, origin, default_ttl=3600):
        zone = AuthorityZone(origin, default_ttl)
        self.add_zone(zone)
        return zone

    def lookup(self, name, qtype):
        """
        Look up records across all zones.
        Returns (records, is_authoritative_for_zone, matched_zone_origin_or_None)
        """
        name_lower = name.rstrip(".").lower()

        with self._lock:
            zones = list(self._zones.values())

        best_zone = None
        best_match_len = -1

        for zone in zones:
            if name_lower == zone.origin:
                if len(zone.origin) > best_match_len:
                    best_zone = zone
                    best_match_len = len(zone.origin)
            elif name_lower.endswith("." + zone.origin):
                if len(zone.origin) > best_match_len:
                    best_zone = zone
                    best_match_len = len(zone.origin)

        if best_zone is None:
            return [], False, None

        records, is_auth, _ = best_zone.lookup(name, qtype)
        return records, is_auth, best_zone.origin
