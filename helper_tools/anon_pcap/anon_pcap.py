#!/usr/bin/env python3
"""
anon_pcap.py - Anonymize PCAP captures with bijective IP mapping and protocol integrity.

Key Features:
- Bijective, consistent IP mapping (1-to-1, collision-free, reversible).
- Application payload is preserved untouched.
- Automatic recalculation of IP and TCP checksums (including pseudo-headers).
- Multiple IP anonymization modes:
  * Table-based RFC 1918 sequential pool (default, human-readable).
  * Prefix-preserving anonymization (CryptoPAn-style).
  * 32-bit keyed format-preserving permutation (Feistel cipher).
- Optional link-layer MAC anonymization (bijective locally administered MACs).
- Optional relative timestamp normalization (starts at t0 = 0.0s, keeps delta-t).
- Optional ephemeral port remapping (preserves service/well-known ports).
- Optional TCP Initial Sequence Number (ISN) flow-based offset.
- Export and import of bijective mapping tables (JSON) for de-anonymization (--reverse).
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Bijective IP Mappers
# ---------------------------------------------------------------------------


class TableIPMapper:
    """
    Bijective table-based IP mapper.
    Maps unique IPs to an address space (e.g. 10.0.0.0/8 for IPv4, fd00::/8 for IPv6).
    Guarantees 1-to-1 injective and surjective mapping on observed IPs.
    """

    ip_mode = "table"

    def __init__(
        self,
        ipv4_base: str = "10.0.0.0/8",
        ipv6_base: str = "fd00::/8",
        forward_map: dict[str, str] | None = None,
        reverse_map: dict[str, str] | None = None,
    ):
        self.ipv4_network = ipaddress.IPv4Network(ipv4_base, strict=False)
        self.ipv6_network = ipaddress.IPv6Network(ipv6_base, strict=False)

        self.forward_map: dict[str, str] = forward_map or {}
        self.reverse_map: dict[str, str] = reverse_map or {}

        # Initialize counters based on existing mappings to avoid collisions
        self._ipv4_counter = 1
        self._ipv6_counter = 1
        self._recompute_counters()

    def _recompute_counters(self) -> None:
        for mapped in self.forward_map.values():
            try:
                addr = ipaddress.ip_address(mapped)
                if addr.version == 4 and addr in self.ipv4_network:
                    offset = int(addr) - int(self.ipv4_network.network_address)
                    if offset >= self._ipv4_counter:
                        self._ipv4_counter = offset + 1
                elif addr.version == 6 and addr in self.ipv6_network:
                    offset = int(addr) - int(self.ipv6_network.network_address)
                    if offset >= self._ipv6_counter:
                        self._ipv6_counter = offset + 1
            except ValueError:
                continue

    def anonymize(self, ip_str: str) -> str:
        if ip_str in self.forward_map:
            return self.forward_map[ip_str]

        orig_addr = ipaddress.ip_address(ip_str)
        if orig_addr.version == 4:
            while True:
                candidate = str(self.ipv4_network.network_address + self._ipv4_counter)
                self._ipv4_counter += 1
                if candidate not in self.reverse_map:
                    break
        else:
            while True:
                candidate = str(self.ipv6_network.network_address + self._ipv6_counter)
                self._ipv6_counter += 1
                if candidate not in self.reverse_map:
                    break

        self.forward_map[ip_str] = candidate
        self.reverse_map[candidate] = ip_str
        return candidate

    def deanonymize(self, mapped_ip: str) -> str:
        return self.reverse_map.get(mapped_ip, mapped_ip)


class FeistelIPMapper:
    """
    Keyed 32-bit format-preserving Feistel permutation.
    Mathematically strictly bijective on the 32-bit integer space.
    """

    ip_mode = "feistel"

    def __init__(self, key: bytes):
        self.key = key
        self._round_keys = [hmac.new(self.key, f"rnd_{i}".encode(), hashlib.sha256).digest() for i in range(4)]
        self.forward_cache: dict[str, str] = {}
        self.reverse_cache: dict[str, str] = {}

    def _feistel_round(self, half: int, round_key: bytes) -> int:
        h = hmac.new(round_key, struct.pack(">H", half), hashlib.sha256).digest()
        return struct.unpack(">H", h[:2])[0]

    def _permute(self, val32: int) -> int:
        left = (val32 >> 16) & 0xFFFF
        right = val32 & 0xFFFF
        for rk in self._round_keys:
            left, right = right, left ^ self._feistel_round(right, rk)
        return (left << 16) | right

    def _inverse_permute(self, val32: int) -> int:
        left = (val32 >> 16) & 0xFFFF
        right = val32 & 0xFFFF
        for rk in reversed(self._round_keys):
            right, left = left, right ^ self._feistel_round(left, rk)
        return (left << 16) | right

    def anonymize(self, ip_str: str) -> str:
        if ip_str in self.forward_cache:
            return self.forward_cache[ip_str]

        orig_addr = ipaddress.ip_address(ip_str)
        if orig_addr.version == 4:
            val = int(orig_addr)
            mapped_val = self._permute(val)
            mapped_ip = str(ipaddress.IPv4Address(mapped_val))
        else:
            # Fallback for IPv6: Hash 128-bit into fd00:: range consistently
            h = hmac.new(self.key, orig_addr.packed, hashlib.sha256).digest()
            mapped_ip = str(
                ipaddress.IPv6Address(int(ipaddress.IPv6Address("fd00::")) | (int.from_bytes(h[:16], "big") & 0xFFFFFFFFFFFFFFFF))
            )

        self.forward_cache[ip_str] = mapped_ip
        self.reverse_cache[mapped_ip] = ip_str
        return mapped_ip

    def deanonymize(self, mapped_ip: str) -> str:
        if mapped_ip in self.reverse_cache:
            return self.reverse_cache[mapped_ip]

        addr = ipaddress.ip_address(mapped_ip)
        if addr.version == 4:
            orig_val = self._inverse_permute(int(addr))
            orig_ip = str(ipaddress.IPv4Address(orig_val))
            self.reverse_cache[mapped_ip] = orig_ip
            self.forward_cache[orig_ip] = mapped_ip
            return orig_ip
        return self.reverse_cache.get(mapped_ip, mapped_ip)


class CryptoPAnIPMapper:
    """
    CryptoPAn prefix-preserving pseudorandom permutation.
    If two IPs share an N-bit prefix, their anonymized IPs share the same N-bit prefix.
    Strictly bijective on 32-bit IPv4 addresses.
    """

    ip_mode = "cryptopan"

    def __init__(self, key: bytes):
        self.key = key
        self._prf_cache: dict[tuple[int, int], int] = {}
        self.forward_cache: dict[str, str] = {}
        self.reverse_cache: dict[str, str] = {}

    def _prf(self, prefix_bits: int, length: int) -> int:
        state = (prefix_bits, length)
        cached = self._prf_cache.get(state)
        if cached is not None:
            return cached
        msg = struct.pack(">IB", prefix_bits, length)
        h = hmac.new(self.key, msg, hashlib.sha256).digest()
        bit = h[0] & 1
        self._prf_cache[state] = bit
        return bit

    def _anonymize_int(self, ip_int: int) -> int:
        result = 0
        prefix = 0
        for i in range(32):
            bit = (ip_int >> (31 - i)) & 1
            flip = self._prf(prefix, i)
            anon_bit = bit ^ flip
            result = (result << 1) | anon_bit
            prefix = (prefix << 1) | bit
        return result

    def _deanonymize_int(self, anon_int: int) -> int:
        result = 0
        prefix = 0
        for i in range(32):
            anon_bit = (anon_int >> (31 - i)) & 1
            flip = self._prf(prefix, i)
            bit = anon_bit ^ flip
            result = (result << 1) | bit
            prefix = (prefix << 1) | bit
        return result

    def anonymize(self, ip_str: str) -> str:
        if ip_str in self.forward_cache:
            return self.forward_cache[ip_str]

        orig_addr = ipaddress.ip_address(ip_str)
        if orig_addr.version == 4:
            mapped_val = self._anonymize_int(int(orig_addr))
            mapped_ip = str(ipaddress.IPv4Address(mapped_val))
        else:
            mapped_ip = str(orig_addr)  # CryptoPAn is specifically defined for 32-bit IPv4

        self.forward_cache[ip_str] = mapped_ip
        self.reverse_cache[mapped_ip] = ip_str
        return mapped_ip

    def deanonymize(self, mapped_ip: str) -> str:
        if mapped_ip in self.reverse_cache:
            return self.reverse_cache[mapped_ip]

        addr = ipaddress.ip_address(mapped_ip)
        if addr.version == 4:
            orig_val = self._deanonymize_int(int(addr))
            orig_ip = str(ipaddress.IPv4Address(orig_val))
            self.reverse_cache[mapped_ip] = orig_ip
            self.forward_cache[orig_ip] = mapped_ip
            return orig_ip
        return self.reverse_cache.get(mapped_ip, mapped_ip)


# ---------------------------------------------------------------------------
# MAC & Port Mappers
# ---------------------------------------------------------------------------


class BijectiveMACMapper:
    """
    Bijective MAC address mapper.
    Maps MACs to locally administered unicast addresses (02:00:00:xx:xx:xx).
    """

    def __init__(
        self,
        forward_map: dict[str, str] | None = None,
        reverse_map: dict[str, str] | None = None,
    ):
        self.forward_map: dict[str, str] = forward_map or {}
        self.reverse_map: dict[str, str] = reverse_map or {}
        self._counter = len(self.forward_map) + 1

    def anonymize(self, mac_str: str) -> str:
        mac_lower = mac_str.lower()
        if mac_lower in self.forward_map:
            return self.forward_map[mac_lower]

        while True:
            # Generate locally administered unicast MAC: 02:00:00:XX:XX:XX
            b3 = (self._counter >> 16) & 0xFF
            b4 = (self._counter >> 8) & 0xFF
            b5 = self._counter & 0xFF
            candidate = f"02:00:00:{b3:02x}:{b4:02x}:{b5:02x}"
            self._counter += 1
            if candidate not in self.reverse_map:
                break

        self.forward_map[mac_lower] = candidate
        self.reverse_map[candidate] = mac_lower
        return candidate

    def deanonymize(self, mapped_mac: str) -> str:
        return self.reverse_map.get(mapped_mac.lower(), mapped_mac)


class BijectivePortMapper:
    """
    Bijective ephemeral port mapper.
    Preserves well-known service ports (< 1024 or explicit list),
    and bijectively remaps ephemeral ports (>= 1024).
    """

    WELL_KNOWN_PORTS = {80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995, 3306, 5432, 8080, 8443}

    def __init__(
        self,
        preserve_well_known: bool = True,
        forward_map: dict[str, int] | None = None,
        reverse_map: dict[str, int] | None = None,
    ):
        self.preserve_well_known = preserve_well_known
        self.forward_map: dict[str, int] = forward_map or {}
        self.reverse_map: dict[str, int] = reverse_map or {}
        self._counter = 49152

    def anonymize(self, port: int) -> int:
        if self.preserve_well_known and (port < 1024 or port in self.WELL_KNOWN_PORTS):
            return port

        port_key = str(port)
        if port_key in self.forward_map:
            return self.forward_map[port_key]

        while True:
            candidate = self._counter
            self._counter = 49152 + ((self._counter - 49152 + 1) % 16383)
            candidate_key = str(candidate)
            if candidate_key not in self.reverse_map and candidate not in self.WELL_KNOWN_PORTS:
                break

        self.forward_map[port_key] = candidate
        self.reverse_map[candidate_key] = port
        return candidate

    def deanonymize(self, mapped_port: int) -> int:
        port_key = str(mapped_port)
        return self.reverse_map.get(port_key, mapped_port)


# ---------------------------------------------------------------------------
# TCP Stream Tracking & ISN Offsets
# ---------------------------------------------------------------------------


class TCPStreamTracker:
    """
    Applies a consistent random offset to TCP sequence/ack numbers per 4-tuple stream.
    Preserves relative sequence progress and retransmission detection.
    """

    def __init__(self, seed: bytes | None = None):
        self.seed = seed or os.urandom(16)
        self._flow_offsets: dict[tuple[str, str, int, int], tuple[int, int]] = {}

    def _get_flow_key(self, src: str, dst: str, sport: int, dport: int) -> tuple[tuple[str, str, int, int], bool]:
        if (src, sport) <= (dst, dport):
            return (src, dst, sport, dport), True
        return (dst, src, dport, sport), False

    def get_offsets(self, src: str, dst: str, sport: int, dport: int) -> tuple[int, int]:
        canonical_key, is_forward = self._get_flow_key(src, dst, sport, dport)
        if canonical_key not in self._flow_offsets:
            key_bytes = f"{canonical_key}".encode()
            h = hmac.new(self.seed, key_bytes, hashlib.sha256).digest()
            fwd_offset = struct.unpack(">I", h[:4])[0]
            rev_offset = struct.unpack(">I", h[4:8])[0]
            self._flow_offsets[canonical_key] = (fwd_offset, rev_offset)

        fwd_off, rev_off = self._flow_offsets[canonical_key]
        if is_forward:
            return fwd_off, rev_off
        return rev_off, fwd_off


# ---------------------------------------------------------------------------
# File Mapping Persistence (JSON)
# ---------------------------------------------------------------------------


def save_mapping(
    filepath: str,
    ip_mapper,
    mac_mapper: BijectiveMACMapper | None,
    port_mapper: BijectivePortMapper | None,
    metadata: dict | None = None,
) -> None:
    data = {
        "metadata": metadata or {},
        "ip": {
            "forward": getattr(ip_mapper, "forward_map", getattr(ip_mapper, "forward_cache", {})),
            "reverse": getattr(ip_mapper, "reverse_map", getattr(ip_mapper, "reverse_cache", {})),
        },
    }
    if mac_mapper:
        data["mac"] = {
            "forward": mac_mapper.forward_map,
            "reverse": mac_mapper.reverse_map,
        }
    if port_mapper:
        data["port"] = {
            "forward": port_mapper.forward_map,
            "reverse": port_mapper.reverse_map,
        }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_mapping(filepath: str) -> dict:
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# CLI Argument Parser & Entry Point
# ---------------------------------------------------------------------------


def parse_args():
    parser = argparse.ArgumentParser(description="Anonymize PCAP captures with bijective IP mapping and protocol integrity.")
    parser.add_argument("-i", "--input", nargs="*", required=True, help="Input PCAP or PCAPNG file path(s)")
    parser.add_argument("-o", "--output", nargs="*", required=False, help="Output anonymized PCAP file path(s)")
    parser.add_argument(
        "--inplace",
        action="store_true",
        default=False,
        help="If set, edit the input files inplace",
    )
    parser.add_argument(
        "--ip-mode",
        choices=["table", "cryptopan", "feistel"],
        default="table",
        help="Bijective IP anonymization algorithm (default: table)",
    )
    parser.add_argument(
        "--ip-subnet",
        default="10.0.0.0/8",
        help="Target IPv4 private subnet for 'table' mode (default: 10.0.0.0/8)",
    )
    parser.add_argument(
        "--key",
        default=None,
        help="Secret key/passphrase for 'cryptopan' or 'feistel' modes (auto-generated if omitted)",
    )
    parser.add_argument(
        "--save-mapping",
        help="Path to save bijective mapping table (JSON) for de-anonymization",
    )
    parser.add_argument(
        "--load-mapping",
        help="Path to load existing bijective mapping table (JSON)",
    )
    parser.add_argument(
        "--reverse",
        action="store_true",
        help="Reverse anonymization (de-anonymize) using loaded mapping table or key",
    )
    parser.add_argument(
        "--anonymize-mac",
        action="store_true",
        help="Bijectively anonymize Ethernet MAC addresses (OUI masked to 02:xx:xx:...)",
    )
    parser.add_argument(
        "--relative-time",
        action="store_true",
        help="Shift timestamps so first packet is at t0 = 0.0s (preserves delta-t)",
    )
    parser.add_argument(
        "--anonymize-ephemeral-ports",
        action="store_true",
        help="Bijectively remap ephemeral TCP ports (preserves well-known service ports)",
    )
    parser.add_argument(
        "--mask-isn",
        action="store_true",
        help="Apply consistent random offset to TCP Initial Sequence Numbers per flow",
    )
    parser.add_argument(
        "--strip-ip-options",
        action="store_true",
        help="Strip IP header options (e.g. Record Route, Timestamp)",
    )

    return parser.parse_args()


# --------------------------------------------------------------------------
# Header layouts: byte offsets are relative to the start of each header
# --------------------------------------------------------------------------
# IPv4 header
IP4_VER_IHL = 0  # version (high nibble) | header length in 32-bit words (low nibble)
IP4_TOTAL_LEN = 2  # header + payload, in bytes
IP4_FLAGS_FRAG = 6  # 3 flag bits | 13-bit fragment offset (in 8-byte units)
IP4_TTL = 8
IP4_PROTOCOL = 9
IP4_CHECKSUM = 10
IP4_SRC = 12
IP4_DST = 16
IP4_ADDR_LEN = 4
IP4_ADDRS_END = IP4_DST + IP4_ADDR_LEN  # src and dst are contiguous: bytes 12..20
IP4_MIN_HDR_LEN = 20  # header length without options
IP4_IHL_UNIT = 4  # IHL counts 32-bit words
IP4_VER_IHL_NO_OPTIONS = (4 << 4) | (IP4_MIN_HDR_LEN // IP4_IHL_UNIT)  # 0x45
IP4_FLAG_MF = 0x2000  # "more fragments"
IP4_FRAG_OFFSET_MASK = 0x1FFF

# IPv6 header
IP6_PAYLOAD_LEN = 4  # everything after the 40-byte header (incl. extension headers)
IP6_NEXT_HEADER = 6
IP6_HOP_LIMIT = 7
IP6_SRC = 8
IP6_DST = 24
IP6_ADDR_LEN = 16
IP6_HDR_LEN = 40  # src and dst end exactly here: addresses are bytes 8..40

# IPv6 extension headers (all start with next-header, then a length byte)
EXT_NEXT_HEADER = 0
EXT_LEN = 1
EXT_LEN_UNIT = 8  # hop-by-hop / routing / dest-options: (len + 1) * 8 bytes
AH_LEN_UNIT = 4  # authentication header:              (len + 2) * 4 bytes
FRAG_HDR_LEN = 8
FRAG_OFFSET_FLAGS = 2  # fragment header: 13-bit offset | 2 reserved bits | M flag
FRAG_OFFSET_SHIFT = 3
FRAG_FLAG_MF = 0x0001

# IP protocol / next-header numbers
PROTO_HOPOPT = 0
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_IPV6_ROUTE = 43
PROTO_IPV6_FRAG = 44
PROTO_AH = 51
PROTO_ICMPV6 = 58
PROTO_IPV6_DSTOPTS = 60
_IP6_EXT_HEADERS = {PROTO_HOPOPT, PROTO_IPV6_ROUTE, PROTO_IPV6_FRAG, PROTO_AH, PROTO_IPV6_DSTOPTS}

# TCP header
TCP_SPORT = 0
TCP_DPORT = 2
TCP_SEQ = 4
TCP_ACK = 8
TCP_FLAGS = 13
TCP_CHECKSUM = 16
TCP_MIN_HDR_LEN = 20
TCP_FLAG_ACK = 0x10
_TCP_PORTS_SEQ_ACK = struct.Struct("!HHII")  # the 12 bytes at TCP_SPORT..TCP_SEQ+ACK
TCP_PORTS_SEQ_ACK_LEN = _TCP_PORTS_SEQ_ACK.size

# UDP and ICMPv6 headers
UDP_CHECKSUM = 6
UDP_HDR_LEN = 8
ICMPV6_CHECKSUM = 2
ICMPV6_MIN_LEN = 4  # type, code, checksum

U16 = struct.Struct("!H")
M32 = 0xFFFFFFFF

# Checksum pseudo-headers (RFC 793 / RFC 8200): addresses + these fields
PSEUDO4_TAIL = struct.Struct("!BBH")  # zero, protocol, L4 length
PSEUDO6_TAIL = struct.Struct("!I3xB")  # L4 length, 3 zero bytes, next header

# --------------------------------------------------------------------------
# pcap file layout
# --------------------------------------------------------------------------
PCAP_GLOBAL_HDR_LEN = 24
PCAP_LINKTYPE_OFFSET = 20  # last 4 bytes of the global header
PCAP_RECORD_HDR_LEN = 16  # ts_sec, ts_frac, incl_len, orig_len

# magic bytes as found in the file -> (struct byte order, ticks per second)
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 10**6),  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 10**6),  # big-endian,    microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 10**9),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 10**9),  # big-endian,    nanoseconds
}
RAW_LINKTYPES = {101, 228, 229, 12, 14}  # LINKTYPE_RAW / IPV4 / IPV6 / BSD DLT_RAW
ETHERNET_LINKTYPE = 1


# --------------------------------------------------------------------------
# Internet checksum helpers
# --------------------------------------------------------------------------
def _fold(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def _sum16(data):
    """
    One's-complement sum of big-endian 16-bit words, folded to 16 bits.
    Trick: 65536 == 1 (mod 65535), so the sum of the words equals the whole
    buffer read as one big integer, mod 65535. Python does that in C.
    """
    if len(data) & 1:
        data = bytes(data) + b"\0"  # odd length: pad with a zero byte
    n = int.from_bytes(data, "big")
    return n % 65535 or (0xFFFF if n else 0)


def _adjust(ck, old, new):
    """RFC 1624 incremental update: replace bytes `old` by `new` in checksum `ck`."""
    s = (~ck & 0xFFFF) + (~_sum16(old) & 0xFFFF) + _sum16(new)
    return ~_fold(s) & 0xFFFF


class Lazy(dict):
    """dict that fills itself on first miss using fn(key)."""

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def __missing__(self, key):
        val = self[key] = self.fn(key)
        return val


# --------------------------------------------------------------------------
# Packet processor
# --------------------------------------------------------------------------
class PCAPAnonymizer:
    def __init__(
        self,
        ip_mapper,
        mac_mapper: BijectiveMACMapper | None = None,
        port_mapper: BijectivePortMapper | None = None,
        tcp_tracker: TCPStreamTracker | None = None,
        relative_time: bool = False,
        strip_ip_options: bool = False,
        reverse_mode: bool = False,
        ttl=64,
    ):
        self.ip_mapper = ip_mapper
        self.port_mapper = port_mapper
        self.mac_mapper = mac_mapper
        self.relative_time = relative_time

        self.reverse_mode = reverse_mode
        self.strip_opts = strip_ip_options
        self.ttl = ttl
        self.tcp_tracker = tcp_tracker

        map_ip = self.ip_mapper.deanonymize if reverse_mode else self.ip_mapper.anonymize
        # packed address -> packed mapped address
        self._m4 = Lazy(lambda b: socket.inet_pton(socket.AF_INET, map_ip(socket.inet_ntop(socket.AF_INET, b))))
        self._m6 = Lazy(lambda b: socket.inet_pton(socket.AF_INET6, map_ip(socket.inet_ntop(socket.AF_INET6, b))))
        # packed address -> str (for the tcp tracker)
        self.ipv4_bytes_to_str = Lazy(lambda b: socket.inet_ntop(socket.AF_INET, b))
        self.ipv6_bytes_to_str = Lazy(lambda b: socket.inet_ntop(socket.AF_INET6, b))

        if self.port_mapper is not None:
            map_port = self.port_mapper.deanonymize if reverse_mode else self.port_mapper.anonymize
            self.map_port: Lazy | None = Lazy(map_port)
        else:
            self.map_port = None

        self.map_mac = lambda b: b
        if self.mac_mapper:
            if not reverse_mode:
                self.map_mac = self.mac_mapper.anonymize
            else:
                self.map_mac = self.mac_mapper.deanonymize

        self.skipped = 0  # non-IP or malformed packets, passed through unchanged

    # ---- entry point ------------------------------------------------------
    def process_packet(self, data):
        """Takes the raw bytes of one packet, returns the modified bytes."""
        if not data:
            return data
        version = data[0] >> 4  # first nibble is the IP version for both v4 and v6
        if version == 4:
            return self._ip4(bytearray(data))
        if version == 6:
            return self._ip6(bytearray(data))
        self.skipped += 1
        return data

    # ---- IPv4 -------------------------------------------------------------
    def _ip4(self, buf):
        n = len(buf)
        ihl = (buf[IP4_VER_IHL] & 0x0F) * IP4_IHL_UNIT  # header length in bytes
        if n < IP4_MIN_HDR_LEN or ihl < IP4_MIN_HDR_LEN or n < ihl:
            self.skipped += 1
            return buf

        total_len = U16.unpack_from(buf, IP4_TOTAL_LEN)[0]
        flags_frag = U16.unpack_from(buf, IP4_FLAGS_FRAG)[0]
        proto = buf[IP4_PROTOCOL]

        # remap src+dst (they are adjacent, so handle them as one 8-byte blob)
        old_addrs = bytes(buf[IP4_SRC:IP4_ADDRS_END])
        new_addrs = self._m4[old_addrs[:IP4_ADDR_LEN]] + self._m4[old_addrs[IP4_ADDR_LEN:]]
        buf[IP4_SRC:IP4_ADDRS_END] = new_addrs
        buf[IP4_TTL] = self.ttl

        # The L4 header is only present in the first (or only) fragment
        if not flags_frag & IP4_FRAG_OFFSET_MASK:
            has_total_len = total_len >= ihl  # total_len == 0 happens with TSO captures
            l4_end = min(total_len, n) if has_total_len else n
            whole_datagram = has_total_len and total_len <= n and not flags_frag & IP4_FLAG_MF
            self._l4(buf, False, proto, ihl, l4_end, old_addrs, new_addrs, whole_datagram)

        if self.strip_opts and ihl > IP4_MIN_HDR_LEN:
            removed = ihl - IP4_MIN_HDR_LEN
            buf = buf[:IP4_MIN_HDR_LEN] + buf[ihl:]  # drop the option bytes
            buf[IP4_VER_IHL] = IP4_VER_IHL_NO_OPTIONS
            if total_len >= ihl:
                U16.pack_into(buf, IP4_TOTAL_LEN, total_len - removed)
            ihl = IP4_MIN_HDR_LEN

        # header checksum: zero the field, sum the header, store the complement
        U16.pack_into(buf, IP4_CHECKSUM, 0)
        U16.pack_into(buf, IP4_CHECKSUM, ~_fold(_sum16(buf[:ihl])) & 0xFFFF)
        return buf

    # ---- IPv6 -------------------------------------------------------------
    def _ip6(self, buf):
        n = len(buf)
        if n < IP6_HDR_LEN:
            self.skipped += 1
            return buf

        payload_len = U16.unpack_from(buf, IP6_PAYLOAD_LEN)[0]
        next_header = buf[IP6_NEXT_HEADER]

        old_addrs = bytes(buf[IP6_SRC:IP6_HDR_LEN])
        new_addrs = self._m6[old_addrs[:IP6_ADDR_LEN]] + self._m6[old_addrs[IP6_ADDR_LEN:]]
        buf[IP6_SRC:IP6_HDR_LEN] = new_addrs
        buf[IP6_HOP_LIMIT] = self.ttl

        # Walk the extension headers to find where the upper-layer header starts
        l4_off = IP6_HDR_LEN
        frag_offset, more_fragments = 0, False
        while next_header in _IP6_EXT_HEADERS:
            if n < l4_off + FRAG_HDR_LEN:  # extension header is cut off
                return buf
            following = buf[l4_off + EXT_NEXT_HEADER]
            if next_header == PROTO_IPV6_FRAG:
                off_flags = U16.unpack_from(buf, l4_off + FRAG_OFFSET_FLAGS)[0]
                frag_offset = off_flags >> FRAG_OFFSET_SHIFT
                more_fragments = bool(off_flags & FRAG_FLAG_MF)
                l4_off += FRAG_HDR_LEN
            elif next_header == PROTO_AH:
                l4_off += (buf[l4_off + EXT_LEN] + 2) * AH_LEN_UNIT
            else:  # hop-by-hop, routing, destination options
                l4_off += (buf[l4_off + EXT_LEN] + 1) * EXT_LEN_UNIT
            next_header = following

        if not frag_offset:  # only the first fragment carries the L4 header
            has_payload_len = payload_len != 0  # 0 = jumbogram / offload
            l4_end = min(IP6_HDR_LEN + payload_len, n) if has_payload_len else n
            whole_datagram = has_payload_len and IP6_HDR_LEN + payload_len <= n and not more_fragments
            self._l4(buf, True, next_header, l4_off, l4_end, old_addrs, new_addrs, whole_datagram)
        return buf

    # ---- layer 4 ----------------------------------------------------------
    def _l4(self, buf, v6, proto, l4_off, l4_end, old_addrs, new_addrs, whole_datagram):
        """
        Remap TCP ports / ISN and fix the L4 checksum.
        l4_off..l4_end is the captured part of the L4 segment.
        old_addrs / new_addrs: src+dst before / after remapping.
        """
        if proto == PROTO_TCP:
            if l4_end - l4_off < TCP_MIN_HDR_LEN:
                return
            ck_pos = l4_off + TCP_CHECKSUM
            fields_end = l4_off + TCP_PORTS_SEQ_ACK_LEN
            old_fields = bytes(buf[l4_off:fields_end])  # ports, seq, ack
            self._tcp(buf, l4_off, v6, new_addrs)
            # everything the checksum covers that we changed, before and after
            old_changed = old_addrs + old_fields
            new_changed = new_addrs + bytes(buf[l4_off:fields_end])
        elif proto == PROTO_UDP:
            if l4_end - l4_off < UDP_HDR_LEN:
                return
            ck_pos = l4_off + UDP_CHECKSUM
            if not v6 and U16.unpack_from(buf, ck_pos)[0] == 0:
                return  # IPv4 UDP checksum 0 means "no checksum": leave it
            old_changed, new_changed = old_addrs, new_addrs
        elif proto == PROTO_ICMPV6 and v6:  # checksum covers the IPv6 pseudo-header
            if l4_end - l4_off < ICMPV6_MIN_LEN:
                return
            ck_pos = l4_off + ICMPV6_CHECKSUM
            old_changed, new_changed = old_addrs, new_addrs
        else:
            return  # ICMPv4 etc.: checksum doesn't cover the addresses

        if whole_datagram:
            # entire segment captured: recompute from scratch (like Scapy does)
            U16.pack_into(buf, ck_pos, 0)
            l4_len = l4_end - l4_off
            if v6:
                pseudo = new_addrs + PSEUDO6_TAIL.pack(l4_len, proto)
            else:
                pseudo = new_addrs + PSEUDO4_TAIL.pack(0, proto, l4_len)
            segment = memoryview(buf)[l4_off:l4_end]
            checksum = ~_fold(_sum16(pseudo) + _sum16(segment)) & 0xFFFF
        else:
            # truncated capture or fragment: the payload is incomplete, so patch
            # the existing checksum incrementally instead
            old_ck = U16.unpack_from(buf, ck_pos)[0]
            checksum = _adjust(old_ck, old_changed, new_changed)
        if checksum == 0 and proto == PROTO_UDP:
            checksum = 0xFFFF  # 0 would mean "no checksum" for UDP
        U16.pack_into(buf, ck_pos, checksum)

    def _tcp(self, buf, tcp_off, v6, new_addrs):
        """Remap ports and apply ISN/ACK offsets, in place."""
        if self.map_port is None and self.tcp_tracker is None:
            return
        sport, dport, seq, ack = _TCP_PORTS_SEQ_ACK.unpack_from(buf, tcp_off)
        if self.map_port is not None:
            sport, dport = self.map_port[sport], self.map_port[dport]
        if self.tcp_tracker is not None:
            addr_len = IP6_ADDR_LEN if v6 else IP4_ADDR_LEN
            to_str = self.ipv6_bytes_to_str if v6 else self.ipv4_bytes_to_str
            src_str = to_str[new_addrs[:addr_len]]
            dst_str = to_str[new_addrs[addr_len:]]
            # same as before: called with the already-remapped addresses/ports
            seq_off, ack_off = self.tcp_tracker.get_offsets(src_str, dst_str, sport, dport)
            if self.reverse_mode:
                seq_off, ack_off = -seq_off, -ack_off
            seq = (seq + seq_off) & M32
            if buf[tcp_off + TCP_FLAGS] & TCP_FLAG_ACK:
                ack = (ack + ack_off) & M32
        _TCP_PORTS_SEQ_ACK.pack_into(buf, tcp_off, sport, dport, seq, ack)


def read_pcap_header(file):
    hdr = file.read(PCAP_GLOBAL_HDR_LEN)
    if len(hdr) < PCAP_GLOBAL_HDR_LEN:
        raise ValueError("file too short to be a pcap file")
    try:
        endian, ticks_per_sec = _PCAP_MAGIC[hdr[:4]]
    except KeyError:
        raise ValueError("not a classic pcap file (pcapng? convert with " "`editcap -F pcap in.pcapng out.pcap`)") from None
    linktype = struct.unpack_from(endian + "I", hdr, PCAP_LINKTYPE_OFFSET)[0]
    if linktype not in RAW_LINKTYPES and linktype != ETHERNET_LINKTYPE:
        print(f"error: link type {linktype} is not a raw-IP type or ethernet", file=sys.stderr)
        sys.exit(1)

    return hdr, linktype, endian, ticks_per_sec


# --------------------------------------------------------------------------
# File driver
# --------------------------------------------------------------------------
def anonymize_pcap_file(processor: PCAPAnonymizer, path_in: str, path_out: str, t0=None, progress=True):
    start_time = time.time()
    count = 0

    inplace = False
    if path_out == path_in:
        inplace = True
        temp = tempfile.NamedTemporaryFile(delete=False)
        path_out = temp.name

    with open(path_in, "rb", buffering=1 << 20) as fin, open(path_out, "wb", buffering=1 << 20) as fout:
        hdr, linktype, endian, ticks_per_sec = read_pcap_header(fin)
        fout.write(hdr)

        record = struct.Struct(endian + "IIII")  # ts_sec, ts_frac, incl_len, orig_len
        while True:
            record_header = fin.read(PCAP_RECORD_HDR_LEN)
            if len(record_header) < PCAP_RECORD_HDR_LEN:
                break
            ts_sec, ts_frac, incl_len, orig_len = record.unpack(record_header)
            data = fin.read(incl_len)
            if len(data) < incl_len:
                break  # truncated file

            if processor.relative_time:
                ticks = ts_sec * ticks_per_sec + ts_frac
                if t0 is None:
                    t0 = ticks
                # clamp: out-of-order packets would otherwise go negative
                ts_sec, ts_frac = divmod(max(ticks - t0, 0), ticks_per_sec)

            # --- MODIFIED: Parse Ethernet header and isolate network bytes ---
            if linktype == ETHERNET_LINKTYPE and len(data) >= 14:
                # Check the EtherType (bytes 12 and 13). Network byte order is big-endian ("!H").
                ethertype = struct.unpack("!H", data[12:14])[0]

                # If 802.1Q VLAN tagged, the header is 18 bytes instead of 14
                eth_hdr_len = 18 if ethertype == 0x8100 else 14

                if len(data) >= eth_hdr_len:
                    eth_hdr = data[:eth_hdr_len]

                    dst_str = eth_hdr[0:6].hex(":")
                    src_str = eth_hdr[6:12].hex(":")

                    new_src_str = processor.map_mac(src_str)
                    new_dst_str = processor.map_mac(dst_str)

                    new_dst_bytes = bytes.fromhex(new_dst_str.replace(":", ""))
                    new_src_bytes = bytes.fromhex(new_src_str.replace(":", ""))
                    eth_hdr = new_dst_bytes + new_src_bytes + eth_hdr[12:]

                    network_bytes = data[eth_hdr_len:]

                    # Pass only the IP/network layer payload to the processor
                    processed_net = processor.process_packet(network_bytes)

                    # Reassemble the frame: Original Ethernet Header + Processed Payload
                    out = eth_hdr + processed_net
                else:
                    out = data  # Malformed packet (too short for its tags)
            elif linktype == ETHERNET_LINKTYPE:
                out = data  # Malformed packet (under 14 bytes)
            else:
                # If it's a raw IP PCAP, pass the whole frame
                out = processor.process_packet(data)

            removed = len(data) - len(out)  # non-zero only if IP options were stripped
            fout.write(record.pack(ts_sec, ts_frac, incl_len - removed, max(orig_len - removed, 0)))
            fout.write(out)

            count += 1
            if progress and count % 100000 == 0:
                print(f"    Processed {count} packets...", end="\r", flush=True)

    if inplace:
        shutil.move(path_out, path_in)
        path_out = path_in

    elapsed = time.time() - start_time
    rate = count / elapsed if elapsed > 0 else 0
    print(f"\n[+] Successfully processed {count} packets in {elapsed:.2f}s ({rate:.0f} pkts/s).")

    meta = {
        "input": os.path.basename(path_in),
        "output": os.path.basename(path_out),
        "ip_mode": processor.ip_mapper.ip_mode,
        "packets": count,
        "timestamp": time.time(),
    }

    return meta


# --------------------------------------------------------------------------
# File driver (PCAPNG Version)
# --------------------------------------------------------------------------
def anonymize_pcapng_file(processor, path_in: str, path_out: str, t0=None, progress=True):
    start_time = time.time()
    count = 0

    inplace = False
    if path_out == path_in:
        inplace = True
        temp = tempfile.NamedTemporaryFile(delete=False)
        path_out = temp.name

    # PCAPNG Block Types
    SHB_TYPE_BYTES = b"\x0a\x0d\x0d\x0a"  # Section Header Block (endian-independent)
    IDB_TYPE = 1  # Interface Description Block
    SPB_TYPE = 3  # Simple Packet Block
    EPB_TYPE = 6  # Enhanced Packet Block
    ETHERNET_LINKTYPE = 1  # Standard Ethernet linktype

    endian = "<"  # Default endianness, updated when SHB is encountered
    interfaces: dict[int, str] = {}

    # --- Helper to isolate and map MAC/Network bytes ---
    def _process_payload(linktype, packet_data):
        if linktype == ETHERNET_LINKTYPE and len(packet_data) >= 14:
            # Check the EtherType (bytes 12 and 13). Network byte order is big-endian ("!H").
            ethertype = struct.unpack("!H", packet_data[12:14])[0]
            eth_hdr_len = 18 if ethertype == 0x8100 else 14

            if len(packet_data) >= eth_hdr_len:
                eth_hdr = packet_data[:eth_hdr_len]
                dst_str = eth_hdr[0:6].hex(":")
                src_str = eth_hdr[6:12].hex(":")

                new_src_str = processor.map_mac(src_str)
                new_dst_str = processor.map_mac(dst_str)

                new_dst_bytes = bytes.fromhex(new_dst_str.replace(":", ""))
                new_src_bytes = bytes.fromhex(new_src_str.replace(":", ""))
                eth_hdr = new_dst_bytes + new_src_bytes + eth_hdr[12:]

                network_bytes = packet_data[eth_hdr_len:]

                # Pass only the IP/network layer payload to the processor
                processed_net = processor.process_packet(network_bytes)
                return eth_hdr + processed_net
            return packet_data
        elif linktype == ETHERNET_LINKTYPE:
            return packet_data  # Malformed packet (under 14 bytes)
        else:
            # If it's a raw IP PCAP, pass the whole frame
            return processor.process_packet(packet_data)

    # --- Main Block Processing Loop ---
    with open(path_in, "rb", buffering=1 << 20) as fin, open(path_out, "wb", buffering=1 << 20) as fout:

        while True:
            # Read block type and length
            b_type_bytes = fin.read(4)
            if not b_type_bytes or len(b_type_bytes) < 4:
                break

            b_len_bytes = fin.read(4)
            if len(b_len_bytes) < 4:
                break

            # 1. Section Header Block (SHB) - Dictates Endianness
            if b_type_bytes == SHB_TYPE_BYTES:
                magic_bytes = fin.read(4)
                if len(magic_bytes) < 4:
                    break

                if magic_bytes == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                elif magic_bytes == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                else:
                    raise ValueError(f"{path_in}: invalid pcapng byte-order magic.")

                b_len = struct.unpack(endian + "I", b_len_bytes)[0]

                # Read remainder of block (Type(4) + Len(4) + Magic(4) = 12 bytes read)
                read_size = b_len - 16
                body_remainder = fin.read(read_size)
                footer = fin.read(4)

                fout.write(b_type_bytes + b_len_bytes + magic_bytes + body_remainder + footer)
                interfaces = {}  # Reset interface ID mappings for new section
                continue

            # Standard block processing with established endianness
            b_type = struct.unpack(endian + "I", b_type_bytes)[0]
            b_len = struct.unpack(endian + "I", b_len_bytes)[0]

            read_size = b_len - 12  # Subtract Type(4), Len(4), and Footer(4)
            if read_size < 0:
                break

            body = fin.read(read_size)
            footer = fin.read(4)
            if len(body) < read_size or len(footer) < 4:
                break

            # 2. Interface Description Block (IDB)
            if b_type == IDB_TYPE:
                linktype = struct.unpack(endian + "H", body[0:2])[0]
                iface_id = len(interfaces)
                interfaces[iface_id] = linktype
                fout.write(b_type_bytes + b_len_bytes + body + footer)

            # 3. Enhanced Packet Block (EPB)
            elif b_type == EPB_TYPE:
                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
                packet_data = body[20 : 20 + cap_len]

                # Identify optional tags that might follow the packet padding
                pad_len = (4 - (cap_len % 4)) % 4
                options = body[20 + cap_len + pad_len :]

                linktype = interfaces.get(iface_id, ETHERNET_LINKTYPE)

                # Relative time processing (64-bit integer tick subtraction)
                if processor.relative_time:
                    ticks = (ts_high << 32) | ts_low
                    if t0 is None:
                        t0 = ticks
                    new_ticks = max(ticks - t0, 0)
                    ts_high = new_ticks >> 32
                    ts_low = new_ticks & 0xFFFFFFFF

                # Process Payload
                out = _process_payload(linktype, packet_data)

                removed = len(packet_data) - len(out)
                new_cap_len = cap_len - removed
                new_orig_len = max(0, orig_len - removed)

                # PCAPNG requires packet data to be padded to a 32-bit boundary
                new_pad_len = (4 - (new_cap_len % 4)) % 4
                new_padding = b"\x00" * new_pad_len

                new_body_header = struct.pack(endian + "IIIII", iface_id, ts_high, ts_low, new_cap_len, new_orig_len)
                new_body = new_body_header + out + new_padding + options

                new_b_len = 12 + len(new_body)

                fout.write(b_type_bytes)
                fout.write(struct.pack(endian + "I", new_b_len))
                fout.write(new_body)
                fout.write(struct.pack(endian + "I", new_b_len))

                count += 1
                if progress and count % 100000 == 0:
                    print(f"    Processed {count} packets...", end="\r", flush=True)

            # 4. Simple Packet Block (SPB)
            elif b_type == SPB_TYPE:
                orig_len = struct.unpack(endian + "I", body[:4])[0]
                cap_len = min(orig_len, len(body) - 4)  # Approximate capture length
                packet_data = body[4 : 4 + cap_len]

                linktype = interfaces.get(0, ETHERNET_LINKTYPE)
                out = _process_payload(linktype, packet_data)

                removed = len(packet_data) - len(out)
                new_orig_len = max(0, orig_len - removed)
                new_cap_len = cap_len - removed

                new_pad_len = (4 - (new_cap_len % 4)) % 4
                new_padding = b"\x00" * new_pad_len

                new_body = struct.pack(endian + "I", new_orig_len) + out + new_padding
                new_b_len = 12 + len(new_body)

                fout.write(b_type_bytes)
                fout.write(struct.pack(endian + "I", new_b_len))
                fout.write(new_body)
                fout.write(struct.pack(endian + "I", new_b_len))

                count += 1
                if progress and count % 100000 == 0:
                    print(f"    Processed {count} packets...", end="\r", flush=True)

            # 5. Other blocks (Name Resolution, Statistics, etc.)
            else:
                # Write completely unmodified
                fout.write(b_type_bytes + b_len_bytes + body + footer)

    if inplace:
        shutil.move(path_out, path_in)
        path_out = path_in

    elapsed = time.time() - start_time
    rate = count / elapsed if elapsed > 0 else 0
    print(f"\n[+] Successfully processed {count} packets in {elapsed:.2f}s ({rate:.0f} pkts/s).")

    meta = {
        "input": os.path.basename(path_in),
        "output": os.path.basename(path_out),
        "ip_mode": processor.ip_mapper.ip_mode,
        "packets": count,
        "timestamp": time.time(),
    }

    return meta


def main():
    args = parse_args()

    for path in args.input:
        if not os.path.isfile(path):
            print(f"Error: Input file '{path}' does not exist.", file=sys.stderr)
            sys.exit(1)

    if not args.inplace and (args.output is None or len(args.output) != len(args.input)):
        print("The amount of input files must equal to the amount of output files")
        sys.exit(1)

    if args.inplace and (args.output is not None and len(args.output) > 0):
        print("Output files can't be specified when --inplace flag is set")
        sys.exit(1)

    if args.inplace:
        args.output = args.input

    if args.reverse and not args.load_mapping and args.ip_mode == "table":
        print(
            "Error: --reverse in 'table' mode requires --load-mapping <file.json> to restore original IPs.",
            file=sys.stderr,
        )
        sys.exit(1)

    loaded_data = load_mapping(args.load_mapping) if args.load_mapping else {}

    # Initialize IP mapper
    ip_fwd = loaded_data.get("ip", {}).get("forward", {})
    ip_rev = loaded_data.get("ip", {}).get("reverse", {})

    if args.ip_mode == "table":
        ip_mapper = TableIPMapper(
            ipv4_base=args.ip_subnet,
            forward_map=ip_fwd,
            reverse_map=ip_rev,
        )
    elif args.ip_mode == "cryptopan":
        key_bytes = args.key.encode() if args.key else b"default_secret_key_cryptopan_32!"
        ip_mapper = CryptoPAnIPMapper(key=key_bytes)
        ip_mapper.forward_cache.update(ip_fwd)
        ip_mapper.reverse_cache.update(ip_rev)
    elif args.ip_mode == "feistel":
        key_bytes = args.key.encode() if args.key else b"default_secret_key_feistel_rnd32"
        ip_mapper = FeistelIPMapper(key=key_bytes)
        ip_mapper.forward_cache.update(ip_fwd)
        ip_mapper.reverse_cache.update(ip_rev)
    else:
        raise ValueError(f"Unknown IP mode: {args.ip_mode}")

    # Initialize MAC mapper
    mac_mapper = None
    if args.anonymize_mac or "mac" in loaded_data:
        mac_fwd = loaded_data.get("mac", {}).get("forward", {})
        mac_rev = loaded_data.get("mac", {}).get("reverse", {})
        mac_mapper = BijectiveMACMapper(forward_map=mac_fwd, reverse_map=mac_rev)

    # Initialize Port mapper
    port_mapper = None
    if args.anonymize_ephemeral_ports or "port" in loaded_data:
        port_fwd = loaded_data.get("port", {}).get("forward", {})
        port_rev = loaded_data.get("port", {}).get("reverse", {})
        port_mapper = BijectivePortMapper(forward_map=port_fwd, reverse_map=port_rev)

    # Initialize TCP stream tracker
    tcp_tracker = TCPStreamTracker() if args.mask_isn else None

    # Initialize processor
    processor = PCAPAnonymizer(
        ip_mapper=ip_mapper,
        mac_mapper=mac_mapper,
        port_mapper=port_mapper,
        tcp_tracker=tcp_tracker,
        relative_time=args.relative_time,
        strip_ip_options=args.strip_ip_options,
        reverse_mode=args.reverse,
    )

    action_label = "De-anonymizing" if args.reverse else "Anonymizing"
    if args.output is not None and len(args.output) > 0:
        print(f"[*] {action_label} '{args.input}' -> '{args.output}'")
    else:
        print(f"[*] {action_label} '{args.input}'")
    print(f"[*] IP Mode: {args.ip_mode} (Bijective mapping)")
    print("[*] Application Payload: PRESERVED UNTOUCHED")

    meta_list = []
    for path_in, path_out in zip(args.input, args.output, strict=True):
        meta = anonymize_pcapng_file(processor, path_in, path_out)
        meta_list.append(meta)

    # Save mapping table if requested
    if args.save_mapping:
        save_mapping(args.save_mapping, ip_mapper, mac_mapper, port_mapper, metadata=meta_list)
        print(f"[+] Saved bijective mapping table to '{args.save_mapping}'")

    print("[+] Done.")


if __name__ == "__main__":
    main()
