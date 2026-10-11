#!/usr/bin/env python
"""Bounded, offline and redacted analysis of a user-provided PCAPNG file.

This script never prints or writes packet payloads, client IP addresses, or
unapproved JSON fields. It reads PCAPNG per interface because dpkt 1.9.8's
Reader exposes one datalink and one timestamp resolution for the whole file.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
import zlib
from collections import Counter, OrderedDict
from pathlib import Path
from urllib.parse import unquote, urlsplit

if __package__:
    from .current_schema_match import (
        CurrentSchema,
        MAX_PROTO_FIELDS,
        SchemaLoadError,
        unmatched_result,
    )
else:
    _SCHEMA_PATH = Path(__file__).with_name("current_schema_match.py")
    _SCHEMA_SPEC = importlib.util.spec_from_file_location(
        "_ag_local_evidence_current_schema_match", _SCHEMA_PATH)
    if _SCHEMA_SPEC is None or _SCHEMA_SPEC.loader is None:
        raise RuntimeError("evidence schema matcher unavailable")
    _SCHEMA_MODULE = importlib.util.module_from_spec(_SCHEMA_SPEC)
    _SCHEMA_SPEC.loader.exec_module(_SCHEMA_MODULE)
    CurrentSchema = _SCHEMA_MODULE.CurrentSchema
    MAX_PROTO_FIELDS = _SCHEMA_MODULE.MAX_PROTO_FIELDS
    SchemaLoadError = _SCHEMA_MODULE.SchemaLoadError
    unmatched_result = _SCHEMA_MODULE.unmatched_result


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROVENANCE_PATH = REPOSITORY_ROOT / "tools" / "validation" / "provenance.py"
_PROVENANCE_SPEC = importlib.util.spec_from_file_location(
    "_ag_local_evidence_provenance", PROVENANCE_PATH)
if _PROVENANCE_SPEC is None or _PROVENANCE_SPEC.loader is None:
    raise RuntimeError("repository provenance helper unavailable")
_PROVENANCE_MODULE = importlib.util.module_from_spec(_PROVENANCE_SPEC)
_PROVENANCE_SPEC.loader.exec_module(_PROVENANCE_MODULE)

MAX_BLOCK = 16 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 512 * 1024 * 1024
MAX_INTERFACES = 256
MAX_TCP_FLOWS = 100_000
MAX_SCAN_ERROR_EXAMPLES = 64
MAX_TEST_REPORT_BYTES = 4 * 1024 * 1024
MAX_SAMPLE = 4096
MAX_PROTOCOL_PROBE_SEGMENTS = 8
MAX_PROTOCOL_PROBE_SEGMENT_BYTES = 64
MAX_PROTOCOL_PROBE_BYTES = MAX_PROTOCOL_PROBE_SEGMENTS * MAX_PROTOCOL_PROBE_SEGMENT_BYTES
DUPLICATE_WINDOW_NS = 2_000_000
DUPLICATE_CACHE = 250_000
FLOW_CAP = 32 * 1024 * 1024
TOTAL_REASSEMBLY_CAP = 64 * 1024 * 1024
HTTP_FLOW_CAP = 2 * 1024 * 1024
MAX_HTTP_HEADER = 64 * 1024
MAX_HTTP_JSON = 256 * 1024
MAX_FRAME = 4 * 1024 * 1024
MAX_INFLATED = 1024 * 1024
MAX_INFLATED_PER_FLOW = 4 * 1024 * 1024
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"PATCH ", b"DELETE ", b"OPTIONS ")
LINK_NAMES = {
    0: "NULL/loopback",
    1: "Ethernet",
    12: "raw-IP-alt",
    101: "raw-IP",
    108: "raw-IP-alt2",
    113: "Linux-cooked-v1",
    228: "IPv4",
    229: "IPv6",
    276: "Linux-cooked-v2",
}
BLOCK_NAMES = {
    0x0A0D0D0A: "SHB",
    1: "IDB",
    2: "PB",
    3: "SPB",
    4: "NRB",
    5: "ISB",
    6: "EPB",
}


class CaptureError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_options(raw: bytes, endian: str):
    options = []
    pos = 0
    malformed = False
    while pos < len(raw):
        if len(raw) - pos < 4:
            malformed = any(raw[pos:])
            break
        code, length = struct.unpack_from(endian + "HH", raw, pos)
        pos += 4
        if code == 0 and length == 0:
            if any(raw[pos:]):
                malformed = True
            break
        padded = (length + 3) & ~3
        if length > len(raw) - pos or padded > len(raw) - pos:
            malformed = True
            break
        options.append((code, raw[pos:pos + length]))
        pos += padded
    return options, malformed


class PcapNGScanner:
    def __init__(self, path: Path):
        self.path = path
        self.file_size = path.stat().st_size
        if self.file_size > MAX_CAPTURE_FILE_BYTES:
            raise CaptureError("capture-byte-cap")
        self.blocks = {}
        self.sections = 0
        self.interfaces = []
        self.interface_stats = {}
        self.packet_records = 0
        self.truncated_records = 0
        self.timestamp_unknown_records = 0
        self.option_errors = 0
        self.errors = []
        self.error_counts = Counter()
        self.complete = False
        self.bytes_scanned = 0
        self.min_timestamp_ns = None
        self.max_timestamp_ns = None
        self._if_by_key = {}

    def _block_count(self, block_type):
        name = BLOCK_NAMES.get(block_type, "OTHER")
        self.blocks[name] = self.blocks.get(name, 0) + 1

    def _record_error(self, reason):
        self.error_counts[reason] += 1
        if len(self.errors) < MAX_SCAN_ERROR_EXAMPLES:
            self.errors.append(reason)

    def scan(self, callback=None):
        endian = None
        current_interfaces = []
        with self.path.open("rb") as stream:
            while True:
                block_offset = stream.tell()
                header = stream.read(8)
                if not header:
                    self.bytes_scanned = stream.tell()
                    self.complete = self.bytes_scanned == self.file_size
                    break
                if len(header) != 8:
                    self._record_error("trailing-short-block-header")
                    self.bytes_scanned = stream.tell()
                    break

                if header[:4] == b"\x0a\x0d\x0d\x0a":
                    bom = stream.read(4)
                    if len(bom) != 4:
                        self._record_error("short-section-byte-order-magic")
                        self.bytes_scanned = stream.tell()
                        break
                    if bom == b"\x4d\x3c\x2b\x1a":
                        endian = "<"
                    elif bom == b"\x1a\x2b\x3c\x4d":
                        endian = ">"
                    else:
                        self._record_error("invalid-section-byte-order-magic")
                        self.bytes_scanned = stream.tell()
                        break
                    block_len = struct.unpack(endian + "I", header[4:8])[0]
                    if block_len < 28 or block_len % 4 or block_len > MAX_BLOCK:
                        self._record_error("invalid-section-block-length")
                        self.bytes_scanned = stream.tell()
                        break
                    rest = stream.read(block_len - 12)
                    if len(rest) != block_len - 12:
                        self._record_error("truncated-section-block")
                        self.bytes_scanned = stream.tell()
                        break
                    block = header + bom + rest
                    if struct.unpack_from(endian + "I", block, block_len - 4)[0] != block_len:
                        self._record_error("section-trailer-length-mismatch")
                        self.bytes_scanned = stream.tell()
                        break
                    self._block_count(0x0A0D0D0A)
                    self.sections += 1
                    major, minor = struct.unpack_from(endian + "HH", block, 12)
                    section_length = struct.unpack_from(endian + "q", block, 16)[0]
                    current_interfaces = []
                    self._current_section = self.sections - 1
                    self._current_section_info = {
                        "major": major,
                        "minor": minor,
                        "section_length": section_length,
                        "start_offset": block_offset,
                    }
                    option_raw = block[24:-4]
                    _, bad_options = parse_options(option_raw, endian)
                    if bad_options:
                        self.option_errors += 1
                    continue

                if endian is None:
                    self._record_error("block-before-section-header")
                    self.bytes_scanned = stream.tell()
                    break
                block_type, block_len = struct.unpack(endian + "II", header)
                if block_len < 12 or block_len % 4 or block_len > MAX_BLOCK:
                    self._record_error("invalid-block-length")
                    self.bytes_scanned = stream.tell()
                    break
                rest = stream.read(block_len - 8)
                if len(rest) != block_len - 8:
                    self._record_error("truncated-block")
                    self.bytes_scanned = stream.tell()
                    break
                if struct.unpack_from(endian + "I", rest, len(rest) - 4)[0] != block_len:
                    self._record_error("block-trailer-length-mismatch")
                    self.bytes_scanned = stream.tell()
                    break
                self._block_count(block_type)
                body = rest[:-4]
                if block_type == 1:
                    if len(body) < 8:
                        self._record_error("short-interface-block")
                        continue
                    if len(self.interfaces) >= MAX_INTERFACES:
                        self._record_error("interface-count-cap")
                        continue
                    linktype, _, snaplen = struct.unpack_from(endian + "HHI", body, 0)
                    iface = {
                        "section": self.sections - 1,
                        "local_id": len(current_interfaces),
                        "linktype": linktype,
                        "snaplen": snaplen,
                        "ts_num": 1,
                        "ts_den": 1_000_000,
                        "ts_offset": 0,
                        "stats": {},
                        "packets": 0,
                        "captured_bytes": 0,
                        "wire_bytes": 0,
                        "truncated": 0,
                        "timestamp_unknown": 0,
                    }
                    options, bad_options = parse_options(body[8:], endian)
                    if bad_options:
                        self.option_errors += 1
                    for code, value in options:
                        if code == 9 and len(value) == 1:
                            raw_res = value[0]
                            if raw_res & 0x80:
                                iface["ts_den"] = 1 << (raw_res & 0x7F)
                            else:
                                iface["ts_den"] = 10 ** raw_res
                        elif code == 14 and len(value) == 8:
                            iface["ts_offset"] = struct.unpack(endian + "q", value)[0]
                    current_interfaces.append(iface)
                    self.interfaces.append(iface)
                    self._if_by_key[(iface["section"], iface["local_id"])] = iface
                elif block_type == 6:
                    if len(body) < 20:
                        self._record_error("short-enhanced-packet-block")
                        continue
                    if_id, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(endian + "IIIII", body, 0)
                    self._packet_block(current_interfaces, if_id, (ts_hi << 32) | ts_lo,
                                       caplen, wirelen, body[20:], endian, callback, "EPB")
                elif block_type == 2:
                    if len(body) < 20:
                        self._record_error("short-packet-block")
                        continue
                    if_id, _, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(endian + "HHIIII", body, 0)
                    self._packet_block(current_interfaces, if_id, (ts_hi << 32) | ts_lo,
                                       caplen, wirelen, body[20:], endian, callback, "PB")
                elif block_type == 3:
                    if len(body) < 4:
                        self._record_error("short-simple-packet-block")
                        continue
                    wirelen = struct.unpack_from(endian + "I", body, 0)[0]
                    if not current_interfaces:
                        self._record_error("simple-packet-without-interface")
                        continue
                    iface = current_interfaces[0]
                    caplen = min(wirelen, iface["snaplen"]) if iface["snaplen"] else wirelen
                    data = body[4:4 + caplen]
                    self._packet_record(iface, None, caplen, wirelen, data, callback, "SPB")
                elif block_type == 5:
                    if len(body) < 12:
                        self._record_error("short-interface-statistics-block")
                        continue
                    if_id, _, _ = struct.unpack_from(endian + "III", body, 0)
                    if if_id >= len(current_interfaces):
                        self._record_error("statistics-interface-out-of-range")
                        continue
                    options, bad_options = parse_options(body[12:], endian)
                    if bad_options:
                        self.option_errors += 1
                    counters = {4: "received", 5: "ifdrop", 6: "filteraccept",
                                7: "osdrop", 8: "usrdeliv"}
                    for code, value in options:
                        if code in counters and len(value) == 8:
                            current_interfaces[if_id]["stats"][counters[code]] = struct.unpack(endian + "Q", value)[0]
                else:
                    if block_type in (4,):
                        # Name-resolution records may include sensitive hostnames.
                        pass
                self.bytes_scanned = stream.tell()

        for iface in self.interfaces:
            if iface.get("stats") is None:
                iface["stats"] = {}
        return self

    def _packet_block(self, interfaces, if_id, ticks, caplen, wirelen, data, endian, callback, kind):
        if if_id >= len(interfaces):
            self._record_error("packet-interface-out-of-range")
            return
        if caplen > len(data):
            self._record_error("packet-capture-length-overruns-block")
            return
        iface = interfaces[if_id]
        if iface["ts_den"]:
            timestamp_ns = ((ticks * 1_000_000_000 * iface["ts_num"]) // iface["ts_den"]
                            + iface["ts_offset"] * 1_000_000_000)
        else:
            timestamp_ns = None
        self._packet_record(iface, timestamp_ns, caplen, wirelen, data[:caplen], callback, kind)

    def _packet_record(self, iface, timestamp_ns, caplen, wirelen, data, callback, kind):
        self.packet_records += 1
        iface["packets"] += 1
        iface["captured_bytes"] += caplen
        iface["wire_bytes"] += wirelen
        if caplen < wirelen:
            self.truncated_records += 1
            iface["truncated"] += 1
        if timestamp_ns is None:
            self.timestamp_unknown_records += 1
            iface["timestamp_unknown"] += 1
        else:
            if self.min_timestamp_ns is None or timestamp_ns < self.min_timestamp_ns:
                self.min_timestamp_ns = timestamp_ns
            if self.max_timestamp_ns is None or timestamp_ns > self.max_timestamp_ns:
                self.max_timestamp_ns = timestamp_ns
        if callback is not None:
            callback({
                "section": iface["section"],
                "if_id": iface["local_id"],
                "linktype": iface["linktype"],
                "snaplen": iface["snaplen"],
                "timestamp_ns": timestamp_ns,
                "caplen": caplen,
                "wirelen": wirelen,
                "data": data,
                "block_kind": kind,
            })


def decode_tcp(record):
    data = record["data"]
    linktype = record["linktype"]
    offset = 0
    ether_type = None
    if linktype == 1:
        if len(data) < 14:
            return None, "short-link-header"
        ether_type = struct.unpack_from(">H", data, 12)[0]
        offset = 14
        vlan_count = 0
        while ether_type in (0x8100, 0x88A8, 0x9100) and vlan_count < 4:
            if len(data) < offset + 4:
                return None, "short-vlan-header"
            ether_type = struct.unpack_from(">H", data, offset + 2)[0]
            offset += 4
            vlan_count += 1
    elif linktype == 113:
        if len(data) < 16:
            return None, "short-sll-header"
        ether_type = struct.unpack_from(">H", data, 14)[0]
        offset = 16
    elif linktype == 276:
        if len(data) < 20:
            return None, "short-sll2-header"
        ether_type = struct.unpack_from(">H", data, 0)[0]
        offset = 20
    elif linktype in (0, 12, 101, 108):
        if linktype in (0, 108):
            if len(data) < 4:
                return None, "short-loopback-header"
            offset = 4
        if len(data) <= offset:
            return None, "short-raw-ip-header"
        version = data[offset] >> 4
        ether_type = 0x0800 if version == 4 else (0x86DD if version == 6 else None)
    elif linktype == 228:
        ether_type = 0x0800
    elif linktype == 229:
        ether_type = 0x86DD
    else:
        return None, "unsupported-linktype"

    if ether_type == 0x0800:
        if len(data) < offset + 20:
            return None, "short-ipv4-header"
        first = data[offset]
        if first >> 4 != 4:
            return None, "invalid-ipv4-version"
        ihl = (first & 0x0F) * 4
        if ihl < 20 or len(data) < offset + ihl:
            return None, "invalid-ipv4-ihl"
        total_len = struct.unpack_from(">H", data, offset + 2)[0]
        if total_len < ihl:
            return None, "invalid-ipv4-length"
        frag = struct.unpack_from(">H", data, offset + 6)[0]
        proto = data[offset + 9]
        src = data[offset + 12:offset + 16]
        dst = data[offset + 16:offset + 20]
        if proto != 6:
            return None, "not-tcp"
        if (frag & 0x1FFF) != 0:
            return {"fragment": True, "src": src, "dst": dst}, "fragment"
        fragment_more = bool(frag & 0x2000)
        l4_offset = offset + ihl
        declared_end = offset + total_len
        fragmented = fragment_more
    elif ether_type == 0x86DD:
        if len(data) < offset + 40:
            return None, "short-ipv6-header"
        if data[offset] >> 4 != 6:
            return None, "invalid-ipv6-version"
        payload_len = struct.unpack_from(">H", data, offset + 4)[0]
        next_header = data[offset + 6]
        src = data[offset + 8:offset + 24]
        dst = data[offset + 24:offset + 40]
        l4_offset = offset + 40
        declared_end = l4_offset + payload_len
        fragmented = False
        ext_count = 0
        while next_header in (0, 43, 44, 60, 51, 135) and ext_count < 8:
            if len(data) < l4_offset + 2:
                return None, "short-ipv6-extension"
            ext_type = next_header
            next_header = data[l4_offset]
            if ext_type == 44:
                if len(data) < l4_offset + 8:
                    return None, "short-ipv6-fragment"
                fragment_word = struct.unpack_from(">H", data, l4_offset + 2)[0]
                if (fragment_word & 0xFFF8) != 0:
                    return {"fragment": True, "src": src, "dst": dst}, "fragment"
                fragmented = bool(fragment_word & 1)
                ext_len = 8
            elif ext_type == 51:
                ext_len = (data[l4_offset + 1] + 2) * 4
            else:
                ext_len = (data[l4_offset + 1] + 1) * 8
            if ext_len < 8 or len(data) < l4_offset + ext_len:
                return None, "short-ipv6-extension"
            l4_offset += ext_len
            ext_count += 1
        if next_header != 6:
            return None, "not-tcp"
    else:
        return None, "not-ip"

    if len(data) < l4_offset + 20:
        return None, "short-tcp-header"
    sport, dport, seq, ack = struct.unpack_from(">HHII", data, l4_offset)
    data_offset = (data[l4_offset + 12] >> 4) * 4
    if data_offset < 20 or len(data) < l4_offset + data_offset:
        return None, "invalid-tcp-offset"
    flags = data[l4_offset + 13]
    captured_end = min(len(data), declared_end)
    payload_start = l4_offset + data_offset
    captured_payload = data[payload_start:captured_end] if captured_end > payload_start else b""
    declared_payload = max(0, declared_end - payload_start)
    payload_truncated = len(captured_payload) < declared_payload or record["caplen"] < record["wirelen"]
    return {
        "version": 4 if ether_type == 0x0800 else 6,
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack,
        "flags": flags,
        "payload": captured_payload,
        "payload_declared": declared_payload,
        "payload_truncated": payload_truncated,
        "fragmented": fragmented,
    }, None


def flow_key_for(packet):
    left = (packet["src"], packet["sport"])
    right = (packet["dst"], packet["dport"])
    ordered = tuple(sorted((left, right)))
    direction = 0 if left == ordered[0] else 1
    key = (packet["version"], ordered[0], ordered[1])
    return key, direction


def seq_delta(seq, base):
    return ((seq - base + 0x80000000) & 0xFFFFFFFF) - 0x80000000


class CrossInterfaceDeduper:
    def __init__(self):
        self.cache = OrderedDict()
        self.suppressed = 0

    def duplicate(self, signature, timestamp_ns, interface_key):
        if timestamp_ns is None:
            return False
        previous = self.cache.get(signature)
        if previous is not None:
            old_ns, old_if = previous
            if old_if != interface_key and abs(timestamp_ns - old_ns) <= DUPLICATE_WINDOW_NS:
                self.suppressed += 1
                return True
        self.cache[signature] = (timestamp_ns, interface_key)
        self.cache.move_to_end(signature)
        while len(self.cache) > DUPLICATE_CACHE:
            self.cache.popitem(last=False)
        return False


class Flow:
    def __init__(self, key):
        self.key = key
        self.first_ts = None
        self.last_ts = None
        self.initiator_dir = None
        self.initiator_ts = None
        self.dirs = []
        for _ in range(2):
            self.dirs.append({
                "packets": 0,
                "payload_bytes": 0,
                "payload_declared": 0,
                "syn": 0,
                "synack": 0,
                "fin": 0,
                "rst": 0,
                "truncated": 0,
                "truncated_declared_bytes": 0,
                "fragmented": 0,
                "fragmented_payload_bytes": 0,
                "base_seq": None,
                "sample": None,
                "sample_seq": None,
                "sample_ts": None,
                "protocol_probe_segments": [],
                "protocol_probe_segments_skipped": 0,
                "protocol_probe_segments_skipped_by_reason": {},
                "highest_end": None,
                "sequence_regressions": 0,
                "segments": [],
            })
        self.cross_iface_dups = 0
        self.id = None
        self.hint = "unknown"
        self.http = False
        self.protocol_candidate = False
        self.protocol_probe_reason = "not-probed"
        self.retained_bytes = 0
        self.cap_hit = False
        self.reassembly = {}
        self.selection_kind = None
        self.selection_reason = "not-selected"
        self.second_pass_dups = 0
        self.has_fragmented_tcp = any(d["fragmented"] for d in self.dirs)

    @property
    def total_payload(self):
        return sum(d["payload_bytes"] for d in self.dirs)

    @property
    def server_endpoint(self):
        if self.initiator_dir is None:
            return None
        return self.key[1 + (1 - self.initiator_dir)]


def packet_signature(flow_key, direction, packet):
    payload = packet["payload"]
    digest = hashlib.blake2s(payload, digest_size=12).digest()
    return (flow_key, direction, packet["seq"], packet["ack"], packet["flags"],
            len(payload), digest)


def scan_flows(scanner):
    flows = {}
    deduper = CrossInterfaceDeduper()
    stats = {
        "tcp_decode_rejections": {},
        "decoded_tcp_packet_records": 0,
        "flow_count_cap_packets": 0,
        "tcp_packets": 0,
        "tcp_payload_packets": 0,
        "tcp_payload_bytes": 0,
        "tcp_payload_declared_bytes": 0,
        "tcp_truncated_packets": 0,
        "tcp_truncated_declared_bytes": 0,
        "tcp_fragment_packets": 0,
        "tcp_fragment_payload_bytes": 0,
        "nonfirst_fragments": 0,
        "unsupported_link_packets": 0,
    }

    def count_rejection(reason):
        rejections = stats["tcp_decode_rejections"]
        rejections[reason] = rejections.get(reason, 0) + 1

    def handle(record):
        packet, error = decode_tcp(record)
        if error is not None:
            count_rejection(error)
            if error == "unsupported-linktype":
                stats["unsupported_link_packets"] += 1
            elif error == "fragment":
                stats["nonfirst_fragments"] += 1
            return
        stats["decoded_tcp_packet_records"] += 1
        key, direction = flow_key_for(packet)
        flow = flows.get(key)
        if flow is None:
            if len(flows) >= MAX_TCP_FLOWS:
                stats["flow_count_cap_packets"] += 1
                count_rejection("tcp-flow-count-cap")
                return
            flow = Flow(key)
            flows[key] = flow
        timestamp_ns = record["timestamp_ns"]
        if timestamp_ns is not None:
            if flow.first_ts is None or timestamp_ns < flow.first_ts:
                flow.first_ts = timestamp_ns
            if flow.last_ts is None or timestamp_ns > flow.last_ts:
                flow.last_ts = timestamp_ns
        d = flow.dirs[direction]
        flags = packet["flags"]
        if flags & 0x02:
            d["syn"] += 1
            if flags & 0x10:
                d["synack"] += 1
            elif flow.initiator_dir is None or timestamp_ns is not None and timestamp_ns < (flow.initiator_ts or timestamp_ns + 1):
                flow.initiator_dir = direction
                flow.initiator_ts = timestamp_ns
            if d["base_seq"] is None:
                d["base_seq"] = (packet["seq"] + 1) & 0xFFFFFFFF
        if flags & 0x01:
            d["fin"] += 1
        if flags & 0x04:
            d["rst"] += 1
        if packet["fragmented"]:
            d["fragmented"] += 1
            d["fragmented_payload_bytes"] += len(packet["payload"])
            stats["tcp_fragment_packets"] += 1
            stats["tcp_fragment_payload_bytes"] += len(packet["payload"])
        sig = packet_signature(key, direction, packet)
        iface_key = (record["section"], record["if_id"])
        if deduper.duplicate(sig, timestamp_ns, iface_key):
            flow.cross_iface_dups += 1
            return
        stats["tcp_packets"] += 1
        d["packets"] += 1
        if packet["payload"]:
            stats["tcp_payload_packets"] += 1
            stats["tcp_payload_bytes"] += len(packet["payload"])
            stats["tcp_payload_declared_bytes"] += packet["payload_declared"]
            d["payload_bytes"] += len(packet["payload"])
            d["payload_declared"] += packet["payload_declared"]
            if packet["payload_truncated"]:
                d["truncated"] += 1
                missing_bytes = max(0, packet["payload_declared"] - len(packet["payload"]))
                d["truncated_declared_bytes"] += missing_bytes
                stats["tcp_truncated_packets"] += 1
                stats["tcp_truncated_declared_bytes"] += missing_bytes
            base = d["base_seq"]
            sample_offset = seq_delta(packet["seq"], base) if base is not None else None
            old_offset = seq_delta(d["sample_seq"], base) if base is not None and d["sample_seq"] is not None else None
            better = d["sample"] is None
            if not better and sample_offset is not None and old_offset is not None:
                better = sample_offset < old_offset
            if not better and sample_offset is None and d["sample_ts"] is not None and timestamp_ns is not None:
                better = timestamp_ns < d["sample_ts"]
            if better:
                d["sample"] = packet["payload"][:MAX_SAMPLE]
                d["sample_seq"] = packet["seq"]
                d["sample_ts"] = timestamp_ns
            if base is not None:
                segment_offset = seq_delta(packet["seq"], base)
                if 0 <= segment_offset < MAX_PROTOCOL_PROBE_BYTES:
                    if len(d["protocol_probe_segments"]) < MAX_PROTOCOL_PROBE_SEGMENTS:
                        d["protocol_probe_segments"].append((
                            packet["seq"], packet["payload"][:MAX_PROTOCOL_PROBE_SEGMENT_BYTES]))
                    else:
                        d["protocol_probe_segments_skipped"] += 1
                        reasons = d["protocol_probe_segments_skipped_by_reason"]
                        reasons["protocol-probe-segment-count-cap"] = (
                            reasons.get("protocol-probe-segment-count-cap", 0) + 1)
                elif segment_offset >= MAX_PROTOCOL_PROBE_BYTES:
                    d["protocol_probe_segments_skipped"] += 1
                    reasons = d["protocol_probe_segments_skipped_by_reason"]
                    reasons["protocol-probe-prefix-cap"] = (
                        reasons.get("protocol-probe-prefix-cap", 0) + 1)
                end = segment_offset + len(packet["payload"])
                if d["highest_end"] is not None and segment_offset < d["highest_end"]:
                    d["sequence_regressions"] += 1
                d["highest_end"] = max(d["highest_end"] if d["highest_end"] is not None else end, end)
        if packet["fragmented"]:
            d["truncated"] += 1

    scanner.scan(handle)
    stats["cross_interface_duplicates_suppressed"] = deduper.suppressed
    stats["tcp_flow_count"] = len(flows)
    return flows, stats


def is_tls_record(data):
    return bool(data and len(data) >= 3 and data[0] in (20, 21, 22, 23)
                and data[1] == 3 and data[2] <= 4)


def http_hint(data):
    if not data:
        return False
    return data.startswith(HTTP_METHODS) or data.startswith(b"HTTP/1.")


def _mapped_frame_prefix(sample, direction, schema_matcher):
    if schema_matcher is None or not sample:
        return False
    if direction == "client_to_server":
        if len(sample) < 13:
            return False
        length = struct.unpack_from("<I", sample, 0)[0]
        if length < 9 or length + 4 > MAX_FRAME:
            return False
        command_a = struct.unpack_from("<I", sample, 5)[0]
        command_b = struct.unpack_from("<H", sample, 11)[0]
        return (schema_matcher.resolve(direction, command_a)[0] == "mapped"
                or schema_matcher.resolve(direction, command_b)[0] == "mapped")
    if direction == "server_to_client":
        if len(sample) < 11:
            return False
        size = struct.unpack_from(">H", sample, 0)[0]
        if size < 9 or size + 2 > MAX_FRAME:
            return False
        compress_flag = sample[2]
        high_flag = sample[4]
        if compress_flag not in (0, 1) or high_flag not in (0, 1):
            return False
        low_command = struct.unpack_from(">H", sample, 5)[0]
        command = low_command + (0x10000 if high_flag else 0)
        return schema_matcher.resolve(direction, command)[0] == "mapped"
    return False


def _protocol_probe_prefix(direction_data):
    """Build a bounded, SYN-origin prefix from TCP segments captured in either order."""
    base = direction_data.get("base_seq")
    if base is None:
        return b"", "syn-origin-unobserved"
    segments = direction_data.get("protocol_probe_segments", ())
    if not segments:
        return b"", "probe-segments-unavailable"
    data = bytearray(MAX_PROTOCOL_PROBE_BYTES)
    present = bytearray(MAX_PROTOCOL_PROBE_BYTES)
    conflict = False
    for seq, payload in sorted(segments, key=lambda row: seq_delta(row[0], base)):
        offset = seq_delta(seq, base)
        if offset < 0 or offset >= MAX_PROTOCOL_PROBE_BYTES:
            continue
        sample = payload[:MAX_PROTOCOL_PROBE_SEGMENT_BYTES]
        take = min(len(sample), MAX_PROTOCOL_PROBE_BYTES - offset)
        for index in range(take):
            target = offset + index
            if present[target]:
                if data[target] != sample[index]:
                    conflict = True
            else:
                data[target] = sample[index]
                present[target] = 1
    prefix_end = 0
    while prefix_end < MAX_PROTOCOL_PROBE_BYTES and present[prefix_end]:
        prefix_end += 1
    prefix = bytes(data[:prefix_end])
    if conflict:
        return prefix, "conflicting-probe-overlap"
    if prefix_end == 0:
        return prefix, "probe-prefix-gap"
    return prefix, "probe-prefix-contiguous"


def _mapped_protocol_prefix(flow, schema_matcher):
    if flow.initiator_dir is None:
        return False, "initiator-direction-unobserved"
    client_prefix, client_probe = _protocol_probe_prefix(flow.dirs[flow.initiator_dir])
    server_prefix, server_probe = _protocol_probe_prefix(flow.dirs[1 - flow.initiator_dir])
    if (client_probe != "conflicting-probe-overlap"
            and _mapped_frame_prefix(client_prefix, "client_to_server", schema_matcher)):
        return True, "mapped-client-frame-prefix"
    if (server_probe != "conflicting-probe-overlap"
            and _mapped_frame_prefix(server_prefix, "server_to_client", schema_matcher)):
        return True, "mapped-server-frame-prefix"
    if "conflicting-probe-overlap" in (client_probe, server_probe):
        return False, "conflicting-probe-overlap"
    if "probe-prefix-contiguous" not in (client_probe, server_probe):
        return False, "protocol-probe-prefix-incomplete"
    return False, "no-mapped-frame-prefix"


def classify_flows(flows, schema_matcher=None):
    ordered = sorted(flows.values(), key=lambda f: (f.first_ts or 0, f.key))
    for index, flow in enumerate(ordered, 1):
        flow.id = "F%03d" % index
        dirs = flow.dirs
        samples = [d["sample"] or b"" for d in dirs]
        tls = any(is_tls_record(sample) for sample in samples)
        if tls:
            flow.hint = "tls-count-only"
        elif any(http_hint(x) for x in samples):
            flow.http = True
            flow.hint = "http-cleartext"
        elif flow.total_payload:
            flow.protocol_candidate, flow.protocol_probe_reason = _mapped_protocol_prefix(
                flow, schema_matcher)
            flow.hint = ("mapped-protocol-candidate" if flow.protocol_candidate
                         else "opaque-tcp-candidate")
    return ordered


def select_reassembly_flows(ordered):
    selected = {}
    total_budget = 0
    for flow in ordered:
        if flow.hint == "tls-count-only":
            flow.selection_reason = "tls-count-only"
            continue
        if flow.http:
            if flow.total_payload > HTTP_FLOW_CAP:
                flow.selection_reason = "http-flow-cap"
                continue
            kind = "http"
        elif flow.protocol_candidate:
            kind = "protocol"
        else:
            flow.selection_reason = flow.protocol_probe_reason
            continue
        cap = HTTP_FLOW_CAP if kind == "http" else FLOW_CAP
        if flow.total_payload > cap:
            flow.selection_reason = "per-flow-reassembly-cap"
            flow.cap_hit = True
            continue
        if total_budget + flow.total_payload > TOTAL_REASSEMBLY_CAP:
            flow.selection_reason = "aggregate-reassembly-cap"
            flow.cap_hit = True
            continue
        flow.selection_kind = kind
        flow.selection_reason = "selected-http" if kind == "http" else flow.protocol_probe_reason
        flow.reassembly = {
            0: {"segments": [], "truncated": 0, "truncated_bytes": 0,
                "fragmented": 0, "fragmented_bytes": 0, "cap_skipped": 0,
                "cap_skipped_by_reason": {}},
            1: {"segments": [], "truncated": 0, "truncated_bytes": 0,
                "fragmented": 0, "fragmented_bytes": 0, "cap_skipped": 0,
                "cap_skipped_by_reason": {}},
        }
        selected[flow.key] = flow
        total_budget += flow.total_payload
    return selected, total_budget


def collect_selected_streams(path, selected):
    scanner = PcapNGScanner(path)
    deduper = CrossInterfaceDeduper()
    stored_total = 0
    per_flow_limit = FLOW_CAP
    aggregate_limit = TOTAL_REASSEMBLY_CAP
    decode_rejections = {}
    selected_packet_records = 0
    truncated_declared_bytes = 0
    fragmented_captured_bytes = 0

    def count_rejection(reason):
        decode_rejections[reason] = decode_rejections.get(reason, 0) + 1

    def count_cap_skip(stream, reason, amount):
        stream["cap_skipped"] += amount
        by_reason = stream["cap_skipped_by_reason"]
        by_reason[reason] = by_reason.get(reason, 0) + amount

    def handle(record):
        nonlocal stored_total, selected_packet_records
        nonlocal truncated_declared_bytes, fragmented_captured_bytes
        packet, error = decode_tcp(record)
        if error is not None:
            count_rejection(error)
            return
        if not packet:
            return
        key, direction = flow_key_for(packet)
        flow = selected.get(key)
        if flow is None:
            return
        selected_packet_records += 1
        d = flow.reassembly[direction]
        if packet["fragmented"]:
            d["fragmented"] += 1
            d["fragmented_bytes"] += len(packet["payload"])
            fragmented_captured_bytes += len(packet["payload"])
            flow.has_fragmented_tcp = True
            count_rejection("fragmented-tcp-payload-skipped")
            return
        if packet["payload_truncated"]:
            d["truncated"] += 1
            missing_bytes = max(0, packet["payload_declared"] - len(packet["payload"]))
            d["truncated_bytes"] += missing_bytes
            truncated_declared_bytes += missing_bytes
        if not packet["payload"]:
            return
        sig = packet_signature(key, direction, packet)
        if deduper.duplicate(sig, record["timestamp_ns"], (record["section"], record["if_id"])):
            flow.second_pass_dups += 1
            return
        payload_len = len(packet["payload"])
        if flow.retained_bytes + payload_len > per_flow_limit:
            count_cap_skip(d, "per-flow-reassembly-cap", payload_len)
            flow.cap_hit = True
            return
        if stored_total + payload_len > aggregate_limit:
            count_cap_skip(d, "aggregate-reassembly-cap", payload_len)
            flow.cap_hit = True
            return
        d["segments"].append((packet["seq"], packet["payload"], record["timestamp_ns"]))
        flow.retained_bytes += payload_len
        stored_total += payload_len

    scanner.scan(handle)
    return scanner, stored_total, deduper.suppressed, {
        "decode_rejections": decode_rejections,
        "selected_packet_records": selected_packet_records,
        "truncated_declared_bytes": truncated_declared_bytes,
        "fragmented_captured_bytes": fragmented_captured_bytes,
    }


def reassemble_direction(flow, direction):
    stream_info = flow.reassembly.get(direction)
    if not stream_info:
        return {
            "data": b"", "complete": False, "captured_span_contiguous": False,
            "origin_known": flow.dirs[direction]["base_seq"] is not None,
            "close_observed": bool(flow.dirs[direction]["fin"] or flow.dirs[direction]["rst"]),
            "reason": "not-selected", "chunks": [], "segments": 0,
            "contiguous_bytes": 0, "after_gap_bytes": 0, "gap": None,
            "exact_overlap_bytes": 0, "conflict_bytes": 0,
            "negative_offset_bytes": 0, "out_of_bounds_bytes": 0,
            "cap_skipped": 0, "cap_skipped_by_reason": {}, "truncated_packets": 0,
            "truncated_declared_bytes": 0, "fragmented_packets": 0,
            "fragmented_captured_bytes": 0,
        }
    segments = stream_info["segments"]
    if not segments:
        direction_data = flow.dirs[direction]
        return {
            "data": b"", "complete": False, "captured_span_contiguous": False,
            "origin_known": direction_data["base_seq"] is not None,
            "close_observed": bool(direction_data["fin"] or direction_data["rst"]),
            "reason": "no-payload-segments", "chunks": [], "segments": 0,
            "contiguous_bytes": 0, "after_gap_bytes": 0, "gap": None,
            "exact_overlap_bytes": 0, "conflict_bytes": 0,
            "negative_offset_bytes": 0, "out_of_bounds_bytes": 0,
            "cap_skipped": stream_info.get("cap_skipped", 0),
            "cap_skipped_by_reason": dict(stream_info.get("cap_skipped_by_reason", {})),
            "truncated_packets": stream_info.get("truncated", 0),
            "truncated_declared_bytes": stream_info.get("truncated_bytes", 0),
            "fragmented_packets": stream_info.get("fragmented", 0),
            "fragmented_captured_bytes": stream_info.get("fragmented_bytes", 0),
        }
    d = flow.dirs[direction]
    base = d["base_seq"]
    origin_known = base is not None
    if base is None:
        first = min(segments, key=lambda item: (item[2] is None, item[2] or 0))
        base = first[0]
        offsets = [seq_delta(item[0], base) for item in segments]
        min_offset = min(offsets)
        if min_offset < 0:
            base = (base + min_offset) & 0xFFFFFFFF
    rows = []
    segment_timestamps = [item[2] for item in segments if item[2] is not None]
    negative_offset_segments = 0
    negative_offset_bytes = 0
    out_of_bounds_segments = 0
    out_of_bounds_bytes = 0
    for seq, payload, timestamp_ns in segments:
        offset = seq_delta(seq, base)
        if offset < 0:
            negative_offset_segments += 1
            negative_offset_bytes += len(payload)
            continue
        if offset > FLOW_CAP or offset + len(payload) > FLOW_CAP:
            out_of_bounds_segments += 1
            out_of_bounds_bytes += len(payload)
            continue
        rows.append((offset, timestamp_ns or 0, payload, timestamp_ns))
    rows.sort(key=lambda item: (item[0], item[1]))

    data = bytearray()
    time_chunks = []
    exact_overlap_bytes = 0
    conflict_bytes = 0
    gap = None
    after_gap_segments = 0
    after_gap_bytes = 0
    total_covered_bound = 0
    for offset, _, payload, timestamp_ns in rows:
        end = offset + len(payload)
        total_covered_bound = max(total_covered_bound, end)
        if gap is not None:
            after_gap_segments += 1
            after_gap_bytes += len(payload)
            continue
        current_end = len(data)
        if offset > current_end:
            gap = (current_end, offset)
            after_gap_segments += 1
            after_gap_bytes += len(payload)
            continue
        overlap = max(0, min(current_end - offset, len(payload)))
        if overlap:
            existing_start = max(0, offset)
            source_start = existing_start - offset
            existing_end = existing_start + overlap
            if data[existing_start:existing_end] == payload[source_start:source_start + overlap]:
                exact_overlap_bytes += overlap
            else:
                common = min(overlap, len(payload))
                a = data[existing_start:existing_start + common]
                b = payload[source_start:source_start + common]
                conflict_bytes += sum(1 for left, right in zip(a, b) if left != right)
        append_from = max(0, current_end - offset)
        if append_from < len(payload):
            start = len(data)
            data.extend(payload[append_from:])
            time_chunks.append((start, len(data), timestamp_ns))

    span_reasons = []
    direction_reasons = []
    if not origin_known:
        direction_reasons.append("SYN not observed; stream start is unknown")
    if gap is not None:
        span_reasons.append("sequence gap %d..%d (%d missing bytes); later segments not parsed" % (
            gap[0], gap[1], gap[1] - gap[0]))
    if negative_offset_segments:
        span_reasons.append("negative sequence offsets skipped: %d segments / %d bytes" % (
            negative_offset_segments, negative_offset_bytes))
    if out_of_bounds_segments:
        span_reasons.append("out-of-cap sequence offsets skipped: %d segments / %d bytes" % (
            out_of_bounds_segments, out_of_bounds_bytes))
    if conflict_bytes:
        span_reasons.append("conflicting overlap bytes=%d" % conflict_bytes)
    if stream_info.get("truncated"):
        span_reasons.append("capture/IP payload truncations=%d" % stream_info["truncated"])
    if stream_info.get("fragmented"):
        span_reasons.append("IP-fragmented TCP packets=%d skipped" % stream_info["fragmented"])
    if stream_info.get("cap_skipped"):
        span_reasons.append("reassembly-budget skipped bytes=%d" % stream_info["cap_skipped"])
    close_observed = bool(d["fin"] or d["rst"])
    if not close_observed:
        direction_reasons.append("FIN/RST not observed in this direction")
    captured_span_contiguous = not span_reasons
    direction_session_complete = captured_span_contiguous and origin_known and close_observed
    reasons = span_reasons + direction_reasons
    result = {
        "data": bytes(data),
        "complete": direction_session_complete,
        "captured_span_contiguous": captured_span_contiguous,
        "origin_known": origin_known,
        "close_observed": close_observed,
        "reason": "; ".join(reasons) if reasons else "captured span contiguous; FIN/RST observed",
        "chunks": time_chunks,
        "segments": len(segments),
        "contiguous_bytes": len(data),
        "highest_sequence_offset": total_covered_bound,
        "gap": gap,
        "after_gap_segments": after_gap_segments,
        "after_gap_bytes": after_gap_bytes,
        "exact_overlap_bytes": exact_overlap_bytes,
        "conflict_bytes": conflict_bytes,
        "negative_offset_segments": negative_offset_segments,
        "negative_offset_bytes": negative_offset_bytes,
        "out_of_bounds_segments": out_of_bounds_segments,
        "out_of_bounds_bytes": out_of_bounds_bytes,
        "cap_skipped": stream_info.get("cap_skipped", 0),
        "cap_skipped_by_reason": dict(stream_info.get("cap_skipped_by_reason", {})),
        "truncated_packets": stream_info.get("truncated", 0),
        "truncated_declared_bytes": stream_info.get("truncated_bytes", 0),
        "fragmented_packets": stream_info.get("fragmented", 0),
        "fragmented_captured_bytes": stream_info.get("fragmented_bytes", 0),
        "sequence_regressions": d["sequence_regressions"],
        "stream_sha256": hashlib.sha256(data).hexdigest() if data else "",
        "first_segment_timestamp_ns": min(segment_timestamps) if segment_timestamps else None,
        "last_segment_timestamp_ns": max(segment_timestamps) if segment_timestamps else None,
    }
    return result


def timestamp_at(chunks, offset):
    for start, end, timestamp_ns in chunks:
        if start <= offset < end:
            return timestamp_ns
    return None


def timestamp_for_range(chunks, offset, length):
    """Return the last timestamp only when every byte in a range is timestamped."""
    if length <= 0:
        return None
    end_offset = offset + length
    cursor = offset
    latest = None
    for start, end, timestamp_ns in chunks:
        if end <= cursor:
            continue
        if start > cursor:
            break
        overlap_end = min(end, end_offset)
        if overlap_end <= cursor:
            continue
        if timestamp_ns is None:
            return None
        latest = timestamp_ns if latest is None else max(latest, timestamp_ns)
        cursor = overlap_end
        if cursor >= end_offset:
            return latest
    return None


def is_zlib_header(payload):
    if len(payload) < 2:
        return False
    cmf, flg = payload[0], payload[1]
    return (cmf & 0x0F) == 8 and (cmf >> 4) <= 7 and ((cmf << 8) + flg) % 31 == 0


def inflate_bounded(payload, output_cap=MAX_INFLATED):
    if not is_zlib_header(payload):
        return {"attempted": False, "ok": False, "data": b"", "reason": "not-zlib"}
    output_cap = max(0, min(MAX_INFLATED, output_cap))
    try:
        decoder = zlib.decompressobj()
        output = decoder.decompress(payload, output_cap + 1)
        if len(output) > output_cap or decoder.unconsumed_tail:
            return {"attempted": True, "ok": False, "data": b"", "reason": "output-cap"}
        tail = decoder.flush(output_cap + 1 - len(output))
        output += tail
        if len(output) > output_cap:
            return {"attempted": True, "ok": False, "data": b"", "reason": "output-cap"}
        if not decoder.eof or decoder.unused_data:
            return {"attempted": True, "ok": False, "data": b"", "reason": "truncated-or-trailing-zlib"}
        if len(output) > max(1, len(payload)) * 64:
            return {"attempted": True, "ok": False, "data": b"", "reason": "ratio-cap"}
        return {"attempted": True, "ok": True, "data": output, "reason": "ok"}
    except zlib.error:
        return {"attempted": True, "ok": False, "data": b"", "reason": "invalid-zlib"}


def read_protobuf_varint(data, position):
    value = 0
    for index in range(10):
        if position >= len(data):
            return None, position
        byte = data[position]
        position += 1
        if index == 9 and byte > 1:
            return None, position
        value |= (byte & 0x7F) << (index * 7)
        if byte < 0x80:
            return value, position
    return None, position


def protobuf_wire_shape(data, max_fields=MAX_PROTO_FIELDS):
    if len(data) > MAX_INFLATED:
        return False, 0
    if not data:
        return True, 0
    pos = 0
    fields = 0
    while pos < len(data) and fields < max_fields:
        tag, pos = read_protobuf_varint(data, pos)
        field_number = tag >> 3 if tag is not None else 0
        if tag is None or field_number == 0 or field_number > 536870911:
            return False, fields
        wire_type = tag & 7
        if wire_type == 0:
            value, pos = read_protobuf_varint(data, pos)
            if value is None:
                return False, fields
        elif wire_type == 1:
            if len(data) - pos < 8:
                return False, fields
            pos += 8
        elif wire_type == 2:
            length, pos = read_protobuf_varint(data, pos)
            if length is None or length > len(data) - pos:
                return False, fields
            pos += length
        elif wire_type == 5:
            if len(data) - pos < 4:
                return False, fields
            pos += 4
        else:
            return False, fields
        if pos > len(data):
            return False, fields
        fields += 1
    return pos == len(data) and fields > 0, fields


def analyze_body(body, compress_flag=None, inflated_used=0, honor_compress_flag=False):
    remaining_inflate_budget = max(0, MAX_INFLATED_PER_FLOW - inflated_used)
    zlib_info = inflate_bounded(body, remaining_inflate_budget)
    raw_valid, raw_fields = protobuf_wire_shape(body)
    base = {
        "zlib_header_detected": zlib_info["attempted"],
        "inflate_attempted": zlib_info["attempted"],
        "inflate_ok": zlib_info["ok"] if zlib_info["attempted"] else None,
        "inflate_reason": zlib_info["reason"],
        "protobuf_wire_valid_raw": raw_valid,
        "protobuf_fields_raw": raw_fields,
        "protobuf_wire_valid_inflated": None,
        "protobuf_fields_inflated": None,
        "protobuf_wire_valid": False,
        "protobuf_fields": 0,
        "protobuf_view": "undetermined",
        "payload_len": len(body),
        "expanded_len": len(zlib_info["data"]) if zlib_info["ok"] else 0,
        "compression_probe_relation": "unknown",
    }
    if honor_compress_flag:
        if compress_flag == 0:
            # A protobuf varint may begin with bytes that resemble a zlib header.
            # The observed zero flag selects the raw body; inflation remains diagnostic only.
            payload = body
            use_inflated = False
            base["protobuf_view"] = "raw-compress-flag-0"
            base["compression_probe_relation"] = (
                "flag-0-with-zlib-signature-candidate" if zlib_info["attempted"]
                else "flag-0-without-zlib-signature-candidate")
        elif compress_flag == 1:
            base["protobuf_view"] = "inflated-compress-flag-1"
            base["compression_probe_relation"] = (
                "flag-1-with-zlib-signature-candidate" if zlib_info["attempted"]
                else "flag-1-without-zlib-signature-candidate")
            if not zlib_info["attempted"]:
                base["wire_reason"] = "compress-flag-1-without-zlib-signature"
                return base
            if not zlib_info["ok"]:
                base["wire_reason"] = "compress-flag-1-zlib-decode-failed-" + zlib_info["reason"]
                return base
            payload = zlib_info["data"]
            use_inflated = True
        else:
            # Other flag values have unknown protocol semantics; record raw wire shape
            # without inferring either a compression mode or a command interpretation.
            payload = body
            use_inflated = False
            base["protobuf_view"] = "raw-compression-flag-unknown"
            base["compression_probe_relation"] = "unclassified-compress-flag"
    else:
        # Uplink has no observed compression flag in this parser. A zlib-looking
        # prefix is diagnostic only; it must never select a different wire body.
        base["protobuf_view"] = "raw-no-explicit-compression-flag"
        base["compression_probe_relation"] = (
            "unflagged-zlib-signature-diagnostic" if zlib_info["attempted"]
            else "unflagged-no-zlib-signature")
        payload = body
        use_inflated = False

    if len(payload) > MAX_INFLATED:
        base["wire_reason"] = "protobuf-input-cap"
        return base
    valid, fields = protobuf_wire_shape(payload)
    if use_inflated:
        base["protobuf_wire_valid_inflated"] = valid
        base["protobuf_fields_inflated"] = fields
    base.update({
        "protobuf_wire_valid": valid,
        "protobuf_fields": fields,
        "wire_reason": "complete-wire-shape" if valid else "invalid-or-incomplete-wire-shape",
    })
    return base


def bounded_body_payload(body):
    # This is used for uplink 10042 inspection. Compression is not selected by
    # a zlib-looking prefix when no explicit flag is available.
    if len(body) > MAX_INFLATED:
        return None, "protobuf-input-cap"
    return body, None


def schema_payload_for_body(body, body_info, remaining_inflate_budget):
    if not body_info.get("protobuf_wire_valid"):
        return None, "protobuf-wire-shape-invalid"
    view = body_info.get("protobuf_view")
    if view in ("raw-compress-flag-0", "raw-no-explicit-compression-flag"):
        return body, None
    if view == "inflated-compress-flag-1":
        info = inflate_bounded(body, remaining_inflate_budget)
        if not info["ok"]:
            return None, "bounded-inflate-" + info["reason"]
        return info["data"], None
    if view == "raw-compression-flag-unknown":
        return None, "compression-mode-unknown"
    return None, "protobuf-view-unknown"


def schema_match_for_body(schema_matcher, direction, command, body, body_info,
                          remaining_inflate_budget, stream_verified):
    if schema_matcher is None:
        return unmatched_result("current-schema-not-loaded")
    if not stream_verified:
        return schema_matcher.match(direction, command, b"", stream_verified=False)
    payload, reason = schema_payload_for_body(body, body_info, remaining_inflate_budget)
    if payload is None:
        return schema_matcher.unparsed(direction, command, reason, stream_verified=True)
    return schema_matcher.match(direction, command, payload, stream_verified=True)


def parse_up_frames(stream_data, variant, time_chunks, allow_proto_fields=False,
                    schema_matcher=None, schema_direction=None, allow_schema_match=False):
    frames = []
    pos = 0
    error = None
    inflated_used = 0
    while pos + 4 <= len(stream_data):
        length = struct.unpack_from("<I", stream_data, pos)[0]
        if length < 9 or length > MAX_FRAME - 4:
            error = "invalid-length-at-offset-%d" % pos
            break
        total = length + 4
        if total > len(stream_data) - pos:
            error = "partial-frame-at-offset-%d" % pos
            break
        frame = stream_data[pos:pos + total]
        if variant == "A":
            command = struct.unpack_from("<I", frame, 5)[0]
            server_index = struct.unpack_from("<H", frame, 11)[0]
        else:
            server_index = struct.unpack_from("<I", frame, 5)[0]
            command = struct.unpack_from("<H", frame, 11)[0]
        body = frame[13:]
        remaining_inflate_budget = max(0, MAX_INFLATED_PER_FLOW - inflated_used)
        body_info = analyze_body(body, None, inflated_used)
        schema_info = None
        if variant == "A" and schema_matcher is not None:
            schema_info = schema_match_for_body(
                schema_matcher, schema_direction, command, body, body_info,
                remaining_inflate_budget, allow_schema_match)
        if body_info["inflate_ok"]:
            inflated_used += body_info["expanded_len"]
        version_info = None
        if variant == "A" and command == 10042:
            if not allow_proto_fields:
                version_info = {"status": "stream-origin-or-prefix-not-verified", "matches": []}
            else:
                decoded_body, decode_reason = bounded_body_payload(body)
                if decoded_body is None:
                    version_info = {"status": decode_reason, "matches": []}
                else:
                    version_info = extract_cs10042_versions(decoded_body)
        frames.append({
            "frame_index": len(frames),
            "offset": pos,
            "timestamp_ns": timestamp_at(time_chunks, pos),
            "complete_timestamp_ns": timestamp_for_range(time_chunks, pos, total),
            "length": total,
            "command": command,
            "body_len": len(body),
            "body_info": body_info,
            "current_schema_match": schema_info,
            "cs10042_versions": version_info,
            "server_index_small": server_index <= 65535,
            "version_byte": frame[4],
        })
        pos += total
    if pos < len(stream_data) and error is None:
        error = "short-header-tail-at-offset-%d" % pos
    parsed = {"variant": variant, "frames": frames, "parsed_bytes": pos,
              "tail_bytes": len(stream_data) - pos, "error": error}
    parsed["trace_sha256"] = trace_hash(frames, variant, "up")
    parsed["boundary_sha256"] = frame_boundary_hash(frames)
    return parsed


def parse_down_frames(stream_data, time_chunks, schema_matcher=None,
                      allow_schema_match=False):
    frames = []
    pos = 0
    error = None
    inflated_used = 0
    while pos + 2 <= len(stream_data):
        size = struct.unpack_from(">H", stream_data, pos)[0]
        if size < 9:
            error = "invalid-size-at-offset-%d" % pos
            break
        total = size + 2
        if total > len(stream_data) - pos:
            error = "partial-frame-at-offset-%d" % pos
            break
        frame = stream_data[pos:pos + total]
        compress_flag = frame[2]
        reserved_byte = frame[3]
        high_flag = frame[4]
        low_command = struct.unpack_from(">H", frame, 5)[0]
        if high_flag == 0:
            command = low_command
        elif high_flag == 1:
            command = low_command + 0x10000
        else:
            command = None
        body = frame[11:]
        remaining_inflate_budget = max(0, MAX_INFLATED_PER_FLOW - inflated_used)
        body_info = analyze_body(body, compress_flag, inflated_used, honor_compress_flag=True)
        schema_info = None
        if schema_matcher is not None:
            schema_info = schema_match_for_body(
                schema_matcher, "server_to_client", command, body, body_info,
                remaining_inflate_budget, allow_schema_match)
        if body_info["inflate_ok"]:
            inflated_used += body_info["expanded_len"]
        frames.append({
            "frame_index": len(frames),
            "offset": pos,
            "timestamp_ns": timestamp_at(time_chunks, pos),
            "complete_timestamp_ns": timestamp_for_range(time_chunks, pos, total),
            "length": total,
            "command": command,
            "low_command": low_command,
            "body_len": len(body),
            "body_info": body_info,
            "current_schema_match": schema_info,
            "compress_flag": compress_flag,
            "reserved_byte": reserved_byte,
            "high_flag": high_flag,
        })
        pos += total
    if pos < len(stream_data) and error is None:
        error = "short-header-tail-at-offset-%d" % pos
    parsed = {"variant": "down-11B", "frames": frames, "parsed_bytes": pos,
              "tail_bytes": len(stream_data) - pos, "error": error}
    parsed["trace_sha256"] = trace_hash(frames, "down-11B", "down")
    parsed["boundary_sha256"] = frame_boundary_hash(frames)
    return parsed


def trace_hash(frames, variant, direction):
    digest = hashlib.sha256()
    for frame in frames:
        body_info = frame["body_info"]
        command = frame.get("command")
        command_text = "unknown" if command is None else str(command)
        row = "%s|%s|%d|%d|%s|%d|%d|%s|%s|%s|%s|%s|%s\n" % (
            direction, variant, frame["offset"], frame["length"], command_text,
            frame["body_len"], int(body_info["zlib_header_detected"]),
            int(body_info["protobuf_wire_valid"]), body_info["inflate_reason"],
            frame.get("low_command", ""), frame.get("compress_flag", ""),
            frame.get("reserved_byte", ""), frame.get("high_flag", ""))
        digest.update(row.encode("ascii"))
    return digest.hexdigest()


def frame_boundary_hash(frames):
    digest = hashlib.sha256()
    for frame in frames:
        digest.update(("%d|%d|%d\n" % (
            frame["offset"], frame["length"], frame["body_len"])).encode("ascii"))
    return digest.hexdigest()


def command_counts(frames):
    counts = {}
    for frame in frames:
        command = frame.get("command")
        value = "unknown-high-flag" if command is None else str(command)
        counts[value] = counts.get(value, 0) + 1
    return counts


def variant_score(parsed):
    frames = parsed["frames"]
    if not frames:
        return {"plausible_command_fraction": 0.0, "framing_complete": False}
    plausible = sum(1000 <= frame["command"] <= 5_000_000 for frame in frames)
    return {
        "plausible_command_fraction": plausible / len(frames),
        "framing_complete": parsed["error"] is None and parsed["tail_bytes"] == 0,
    }


def normalize_http_host(raw):
    if not raw or len(raw) > 512:
        return None
    try:
        candidate = urlsplit("//" + raw.strip()).hostname
    except ValueError:
        return None
    if not candidate:
        return None
    candidate = candidate.encode("idna").decode("ascii").lower()
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", candidate):
        return None
    return candidate


def safe_http_path(target):
    if not target or len(target) > 4096:
        return "/{redacted}"
    try:
        parsed = urlsplit(target)
        raw_path = parsed.path or "/"
    except ValueError:
        return "/{redacted}"
    if len(raw_path) > 2048:
        return "/{redacted}"
    output = []
    static_words = {
        "api", "sdk", "game", "server", "client", "resource", "version", "config",
        "login", "logout", "init", "startup", "bootstrap", "manifest", "notice",
        "update", "check", "service", "gateway", "auth", "info", "list", "query",
        "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
    }
    for segment in raw_path.split("/"):
        decoded = unquote(segment)
        folded = decoded.casefold()
        if not decoded:
            output.append("")
        elif folded in static_words:
            output.append(folded)
        elif re.fullmatch(r"v[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}", folded):
            output.append(folded)
        else:
            output.append("{redacted}")
    result = "/".join(output)
    return result if result.startswith("/") else "/" + result


VERSION_KEYS = {
    "appversion": "appVersion",
    "clientversion": "clientVersion",
    "resourceversion": "resourceVersion",
    "version": "version",
    "versioncode": "versionCode",
}
VERSION_VALUE_RE = re.compile(r"(?i)v?[0-9]{1,5}(?:[._-][0-9]{1,5}){0,4}\Z")


def extract_cs10042_versions(data):
    wire_valid, field_count = protobuf_wire_shape(data)
    result = {"status": "wire-shape-check-failed", "matches": [],
              "current_schema_match": "unknown"}
    if not wire_valid:
        return result
    if field_count == 0:
        result["status"] = "empty-wire-message-no-version-fields"
        return result
    occurrences = {10: [], 21: []}
    pos = 0
    while pos < len(data):
        tag, pos = read_protobuf_varint(data, pos)
        if tag is None:
            return result
        number = tag >> 3
        wire_type = tag & 7
        if wire_type == 0:
            _, pos = read_protobuf_varint(data, pos)
            if number in occurrences:
                occurrences[number].append((wire_type, None))
        elif wire_type == 1:
            if number in occurrences:
                occurrences[number].append((wire_type, None))
            pos += 8
        elif wire_type == 2:
            length, pos = read_protobuf_varint(data, pos)
            value_end = pos + length
            if number in occurrences:
                occurrences[number].append((wire_type, data[pos:value_end]))
            pos = value_end
        elif wire_type == 5:
            if number in occurrences:
                occurrences[number].append((wire_type, None))
            pos += 4
        else:
            return result
    labels = {10: "client_vs", 21: "resource_vs"}
    issues = []
    for number, label in labels.items():
        items = occurrences[number]
        if not items:
            issues.append(label + ":absent")
            continue
        if len(items) != 1:
            issues.append(label + ":ambiguous-occurrences")
            continue
        wire_type, raw_value = items[0]
        if wire_type != 2 or raw_value is None or len(raw_value) > 128:
            issues.append(label + ":type-or-length-mismatch")
            continue
        try:
            value = raw_value.decode("ascii")
        except UnicodeDecodeError:
            issues.append(label + ":non-ascii-value")
            continue
        if not VERSION_VALUE_RE.fullmatch(value):
            issues.append(label + ":not-version-pattern")
            continue
        result["matches"].append({"field": label, "value": value})
    result["status"] = "complete-wire-shape-target-fields-checked"
    result["issues"] = issues
    return result
def extract_allowlisted_versions(value):
    found = []
    visited = 0

    def walk(item, depth):
        nonlocal visited
        if depth > 10 or visited >= 10000:
            return
        visited += 1
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    continue
                normalized = key.casefold()
                label = VERSION_KEYS.get(normalized)
                if label is not None:
                    if isinstance(child, (str, int)) and not isinstance(child, bool):
                        text = str(child)
                        if len(text) <= 128 and VERSION_VALUE_RE.fullmatch(text):
                            found.append((label, text))
                if isinstance(child, (dict, list)):
                    walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item[:1000]:
                walk(child, depth + 1)

    walk(value, 0)
    unique = sorted(set(found))
    return unique


def parse_chunked_body(data, pos, cap):
    output = bytearray()
    cursor = pos
    while cursor < len(data):
        line_end = data.find(b"\r\n", cursor, min(len(data), cursor + 128))
        if line_end < 0:
            return None, cursor, False
        size_token = data[cursor:line_end].split(b";", 1)[0].strip()
        if not size_token or len(size_token) > 16:
            return None, cursor, False
        try:
            size = int(size_token, 16)
        except ValueError:
            return None, cursor, False
        cursor = line_end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n\r\n", cursor, min(len(data), cursor + MAX_HTTP_HEADER))
            if trailer_end >= 0:
                return bytes(output), trailer_end + 4, True
            if data[cursor:cursor + 2] == b"\r\n":
                return bytes(output), cursor + 2, True
            return None, cursor, False
        if size > cap - len(output) or cursor + size + 2 > len(data):
            return None, cursor, False
        output.extend(data[cursor:cursor + size])
        cursor += size
        if data[cursor:cursor + 2] != b"\r\n":
            return None, cursor, False
        cursor += 2
    return None, cursor, False


def parse_http_messages(data, flow_id, direction, chunks, allow_json=True, max_messages=20):
    events = []
    pos = 0
    for _ in range(max_messages):
        header_end = data.find(b"\r\n\r\n", pos, min(len(data), pos + MAX_HTTP_HEADER))
        if header_end < 0:
            break
        header_blob = data[pos:header_end]
        lines = header_blob.split(b"\r\n")
        if not lines:
            break
        first = lines[0].decode("ascii", "ignore")
        request_match = re.match(r"^([A-Z]{3,10})\s+(\S{1,4096})\s+HTTP/1\.[01]$", first)
        response_match = re.match(r"^HTTP/1\.[01]\s+([0-9]{3})(?:\s|$)", first)
        if request_match:
            method = request_match.group(1)
            target = request_match.group(2)
            parsed_type = "request"
        elif response_match:
            method = "HTTP-response"
            target = ""
            parsed_type = "response"
        else:
            break
        headers = {}
        for header_line in lines[1:]:
            if b":" not in header_line:
                continue
            name, value = header_line.split(b":", 1)
            name = name.strip().lower()
            if name in (b"host", b"content-length", b"content-type", b"transfer-encoding"):
                headers[name.decode("ascii")] = value.strip().decode("ascii", "ignore")[:512]
        body_start = header_end + 4
        body = None
        consumed = body_start
        body_complete = False
        json_allowed = False
        transfer = headers.get("transfer-encoding", "").lower()
        content_type = headers.get("content-type", "").lower()
        if "chunked" in transfer:
            body, consumed, body_complete = parse_chunked_body(data, body_start, MAX_HTTP_JSON)
            json_allowed = bool(allow_json and "application/json" in content_type and body_complete)
        elif "content-length" in headers:
            try:
                body_len = int(headers["content-length"])
            except ValueError:
                body_len = MAX_HTTP_JSON + 1
            if body_len <= MAX_HTTP_JSON and body_start + body_len <= len(data):
                body = data[body_start:body_start + body_len]
                consumed = body_start + body_len
                body_complete = True
                json_allowed = bool(allow_json and "application/json" in content_type)
            else:
                consumed = len(data)
        elif parsed_type == "request" and method in ("GET", "HEAD", "OPTIONS", "DELETE"):
            body = b""
            body_complete = True
        else:
            consumed = len(data)
        versions = []
        if json_allowed and body is not None:
            try:
                versions = extract_allowlisted_versions(json.loads(body.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                versions = []
        host = normalize_http_host(headers.get("host"))
        event = {
            "flow": flow_id,
            "direction": direction,
            "kind": parsed_type,
            "method": method,
            "status": response_match.group(1) if response_match else None,
            "host": host,
            "path": safe_http_path(target) if target else None,
            "timestamp_ns": timestamp_at(chunks, pos),
            "message_complete_timestamp_ns": timestamp_for_range(chunks, pos, consumed - pos)
            if body_complete else None,
            "observed_prefix_end_timestamp_ns": timestamp_for_range(chunks, pos, consumed - pos),
            "body_complete": body_complete,
            "versions": versions,
            "json_inspected": json_allowed,
        }
        events.append(event)
        if consumed <= pos:
            break
        if not body_complete and parsed_type == "response" and "content-length" not in headers and "chunked" not in transfer:
            break
        pos = consumed
        if pos >= len(data):
            break
    return events


def analyze_selected_flows(ordered, path, schema_matcher=None):
    selected, budget = select_reassembly_flows(ordered)
    second_scan, stored_total, second_duplicates, second_scan_stats = collect_selected_streams(
        path, selected)
    http_events = []
    frame_summaries = []
    timeline = []
    protocol_totals = {"A_frames": 0, "B_frames": 0, "down_frames": 0,
                       "zlib_signature_candidates": 0,
                       "zlib_inflate_diagnostic_successes": 0,
                       "compress_flag_1_downlink_inflate_successes": 0,
                       "protobuf_wire_valid": 0, "protobuf_wire_invalid": 0,
                       "compression_probe_relations": {},
                       "down_compress_flag_values": {},
                       "down_reserved_byte_values": {},
                       "down_high_flag_values": {},
                       "up_version_byte_values": {}}

    def count_value(counter, value):
        key = str(value)
        counter[key] = counter.get(key, 0) + 1

    def add_body_stats(info):
        protocol_totals["zlib_signature_candidates"] += int(info["zlib_header_detected"])
        protocol_totals["zlib_inflate_diagnostic_successes"] += int(info["inflate_ok"] is True)
        protocol_totals["compress_flag_1_downlink_inflate_successes"] += int(
            info["protobuf_view"] == "inflated-compress-flag-1"
            and info["inflate_ok"] is True)
        protocol_totals["protobuf_wire_valid"] += int(info["protobuf_wire_valid"])
        protocol_totals["protobuf_wire_invalid"] += int(not info["protobuf_wire_valid"])
        relation = info["compression_probe_relation"]
        protocol_totals["compression_probe_relations"][relation] = (
            protocol_totals["compression_probe_relations"].get(relation, 0) + 1)

    for flow in ordered:
        if flow.selection_kind is None and flow.http:
            for direction, d in enumerate(flow.dirs):
                if d["sample"]:
                    direction_label = "direction-%d (orientation unknown)" % direction
                    if flow.initiator_dir is not None:
                        direction_label = "client-to-server" if direction == flow.initiator_dir else "server-to-client"
                    sample_events = parse_http_messages(
                        d["sample"], flow.id, direction_label, [], allow_json=False)
                    for event in sample_events:
                        event["metadata_source"] = "single-segment-header-only"
                        event["observed_prefix_end_timestamp_ns"] = d["sample_ts"]
                        http_events.append(event)
                        timeline.append({
                            "timestamp_ns": event["observed_prefix_end_timestamp_ns"],
                            "kind": "http", "flow": flow.id,
                            "direction": direction_label, "event": event})
            continue
        if flow.selection_kind is None:
            continue
        direction_data = {}
        for direction in (0, 1):
            result = reassemble_direction(flow, direction)
            direction_data[direction] = result
            if flow.selection_kind == "http" and result["data"]:
                direction_label = "direction-%d (orientation unknown)" % direction
                if flow.initiator_dir is not None:
                    direction_label = "client-to-server" if direction == flow.initiator_dir else "server-to-client"
                allow_http_json = result["origin_known"] and result["captured_span_contiguous"]
                events = parse_http_messages(result["data"], flow.id, direction_label,
                                             result["chunks"], allow_json=allow_http_json)
                for event in events:
                    event["metadata_source"] = "contiguous-stream-prefix"
                    http_events.append(event)
                    event_time = (event["message_complete_timestamp_ns"]
                                  or event["observed_prefix_end_timestamp_ns"])
                    timeline.append({"timestamp_ns": event_time, "kind": "http",
                                     "flow": flow.id, "direction": direction_label,
                                     "event": event})

        if flow.selection_kind != "protocol":
            flow.reassembly_result = direction_data
            continue

        if flow.initiator_dir is None:
            client_dir = None
        else:
            client_dir = flow.initiator_dir
        dirs_to_parse = []
        if client_dir is None:
            dirs_to_parse = [(0, "direction-0"), (1, "direction-1")]
        else:
            dirs_to_parse = [(client_dir, "client-to-server"), (1 - client_dir, "server-to-client")]
        variants = {}
        for direction, label in dirs_to_parse:
            stream = direction_data[direction]
            if label == "server-to-client":
                parsed = parse_down_frames(
                    stream["data"], stream["chunks"], schema_matcher=schema_matcher,
                    allow_schema_match=bool(
                        schema_matcher is not None and stream["origin_known"]
                        and stream["captured_span_contiguous"]))
                variants[(direction, "down")] = parsed
                protocol_totals["down_frames"] += len(parsed["frames"])
                frame_summaries.append({
                    "flow": flow.id,
                    "direction": label,
                    "variant": "down-11B",
                    "frames": parsed["frames"],
                    "trace_sha256": parsed["trace_sha256"],
                    "boundary_sha256": parsed["boundary_sha256"],
                    "parsed_bytes": parsed["parsed_bytes"],
                    "framing_error": parsed["error"],
                    "tail_bytes": parsed["tail_bytes"],
                    "stream": stream,
                })
                for frame in parsed["frames"]:
                    info = frame["body_info"]
                    add_body_stats(info)
                    count_value(protocol_totals["down_compress_flag_values"], frame["compress_flag"])
                    count_value(protocol_totals["down_reserved_byte_values"], frame["reserved_byte"])
                    count_value(protocol_totals["down_high_flag_values"], frame["high_flag"])
                    timeline.append({
                        "timestamp_ns": frame["complete_timestamp_ns"],
                        "kind": "frame", "flow": flow.id, "direction": label,
                        "variant": "down-11B", "frame_index": frame["frame_index"],
                        "offset": frame["offset"], "command": frame["command"],
                        "low_command": frame["low_command"], "high_flag": frame["high_flag"],
                        "compress_flag": frame["compress_flag"],
                        "reserved_byte": frame["reserved_byte"],
                        "length": frame["length"],
                        "protobuf_wire_valid": info["protobuf_wire_valid"],
                        "body_info": info,
                    })
            else:
                schema_direction = "client_to_server" if label == "client-to-server" else None
                for variant in ("A", "B"):
                    allow_proto_fields = bool(
                        variant == "A" and stream["origin_known"]
                        and stream["captured_span_contiguous"])
                    parsed = parse_up_frames(stream["data"], variant, stream["chunks"],
                                             allow_proto_fields=allow_proto_fields,
                                             schema_matcher=schema_matcher,
                                             schema_direction=schema_direction,
                                             allow_schema_match=bool(
                                                 variant == "A" and schema_direction
                                                 and stream["origin_known"]
                                                 and stream["captured_span_contiguous"]))
                    variants[(direction, variant)] = parsed
                    protocol_totals[variant + "_frames"] += len(parsed["frames"])
                    frame_summaries.append({
                        "flow": flow.id,
                        "direction": label,
                        "variant": variant,
                        "frames": parsed["frames"],
                        "trace_sha256": parsed["trace_sha256"],
                        "boundary_sha256": parsed["boundary_sha256"],
                        "parsed_bytes": parsed["parsed_bytes"],
                        "framing_error": parsed["error"],
                        "tail_bytes": parsed["tail_bytes"],
                        "stream": stream,
                    })
                    if variant == "A":
                        for frame in parsed["frames"]:
                            info = frame["body_info"]
                            add_body_stats(info)
                            count_value(protocol_totals["up_version_byte_values"], frame["version_byte"])
                            if frame["cs10042_versions"] is not None:
                                versions = frame["cs10042_versions"].get("matches", [])
                            else:
                                versions = []
                            timeline.append({
                                "timestamp_ns": frame["complete_timestamp_ns"],
                                "kind": "frame", "flow": flow.id,
                                "direction": label, "variant": "up-A-shared-boundaries",
                                "frame_index": frame["frame_index"], "offset": frame["offset"],
                                "command": frame["command"], "length": frame["length"],
                                "protobuf_wire_valid": info["protobuf_wire_valid"],
                                "body_info": info,
                                "cs10042_versions": versions,
                            })
        a_summary = variants.get((client_dir, "A")) if client_dir is not None else None
        b_summary = variants.get((client_dir, "B")) if client_dir is not None else None
        score_a = variant_score(a_summary) if a_summary else None
        score_b = variant_score(b_summary) if b_summary else None
        flow.reassembly_result = direction_data
        flow.variant_result = {
            "A": a_summary,
            "B": b_summary,
            "down": variants.get((1 - client_dir, "down")) if client_dir is not None else None,
            "A_score": score_a,
            "B_score": score_b,
            "client_dir": client_dir,
            "server_dir": 1 - client_dir if client_dir is not None else None,
        }
    timeline.sort(key=lambda item: (
        item.get("timestamp_ns") is None,
        item.get("timestamp_ns") or 0,
        item.get("flow", ""), item.get("direction", ""),
        item.get("offset", 0), item.get("frame_index", 0)))
    return {
        "selected": selected,
        "budget": budget,
        "stored_total": stored_total,
        "second_scan": second_scan,
        "second_scan_stats": second_scan_stats,
        "second_duplicates": second_duplicates,
        "http_events": http_events,
        "frame_summaries": frame_summaries,
        "timeline": timeline,
        "protocol_totals": protocol_totals,
    }


def equivalent_protocol_flow_groups(flow_analysis):
    groups = OrderedDict()
    for flow in flow_analysis["selected"].values():
        if flow.selection_kind != "protocol" or flow.initiator_dir is None:
            continue
        client_dir = flow.initiator_dir
        server_dir = 1 - client_dir
        c2s = flow.reassembly_result[client_dir]
        s2c = flow.reassembly_result[server_dir]
        if not c2s["data"] or not s2c["data"]:
            continue
        up = flow.variant_result.get("A")
        down = flow.variant_result.get("down")
        signature = (
            len(c2s["data"]), c2s["stream_sha256"], c2s["captured_span_contiguous"],
            bool(up and up["error"] is None and up["tail_bytes"] == 0),
            up["boundary_sha256"] if up else "",
            len(s2c["data"]), s2c["stream_sha256"], s2c["captured_span_contiguous"],
            bool(down and down["error"] is None and down["tail_bytes"] == 0),
            down["boundary_sha256"] if down else "",
        )
        groups.setdefault(signature, []).append(flow)
    return [group for group in groups.values() if len(group) > 1]


def schema_match_summary(flow_analysis):
    protocol_flows = [flow for flow in flow_analysis["selected"].values()
                      if flow.selection_kind == "protocol"]
    equivalent_groups = equivalent_protocol_flow_groups(flow_analysis)
    grouped_ids = {flow.id for group in equivalent_groups for flow in group}
    representatives = [group[0] for group in equivalent_groups]
    representatives.extend(flow for flow in protocol_flows if flow.id not in grouped_ids)
    representative_ids = {flow.id for flow in representatives}
    rows = {}
    totals = Counter()
    for summary in flow_analysis["frame_summaries"]:
        if summary["flow"] not in representative_ids or summary["variant"] not in ("A", "down-11B"):
            continue
        for frame in summary["frames"]:
            info = frame.get("current_schema_match") or unmatched_result("current-schema-not-loaded")
            totals["protocol_events"] += 1
            if summary["variant"] == "A":
                totals["deduplicated_upstream_frames"] += 1
            else:
                totals["deduplicated_downstream_frames"] += 1
                if frame.get("compress_flag") == 1:
                    totals["deduplicated_downlink_flag_1_frames"] += 1
                    if frame.get("body_info", {}).get("inflate_ok") is True:
                        totals["deduplicated_downlink_flag_1_zlib_inflate_successes"] += 1
            if info.get("message_name"):
                totals["mapped_events"] += 1
            if info.get("wire_match") is True:
                totals["wire_match_events"] += 1
            if info.get("wire_mismatch_count", 0):
                totals["wire_mismatch_events"] += 1
            if info.get("unknown_field_occurrences", 0):
                totals["unknown_field_events"] += 1
            if info.get("required_omission_count", 0):
                totals["required_omission_events"] += 1
            merge_sites = info.get("singular_message_merge_sites", 0)
            if merge_sites:
                totals["frames_with_singular_message_merges"] += 1
            totals["singular_message_merge_sites"] += merge_sites
            totals["singular_message_merge_extra_occurrences"] += info.get(
                "singular_message_merge_extra_occurrences", 0)
            if not info.get("parse_complete", False) and info.get("message_name"):
                totals["incomplete_mapped_events"] += 1
            key = (summary["direction"], frame.get("command"),
                   info.get("message_name") or "", info.get("status", "unknown"))
            row = rows.setdefault(key, {
                "direction": summary["direction"],
                "command": frame.get("command"),
                "message_name": info.get("message_name"),
                "frames": 0,
                "statuses": Counter(),
                "wire_match_frames": 0,
                "unknown_paths": Counter(),
                "wire_mismatches": Counter(),
                "required_omissions": Counter(),
            })
            row["frames"] += 1
            row["statuses"][info.get("status", "unknown")] += 1
            row["wire_match_frames"] += int(info.get("wire_match") is True)
            for unknown in info.get("unknown_field_paths", []):
                path = unknown.get("path", []) if isinstance(unknown, dict) else unknown
                count = unknown.get("count", 1) if isinstance(unknown, dict) else 1
                row["unknown_paths"][tuple(path)] += count
            for mismatch in info.get("wire_mismatches", []):
                key2 = (tuple(mismatch.get("path", [])), mismatch.get("observed_wire_type"),
                        tuple(mismatch.get("expected_wire_types", [])))
                row["wire_mismatches"][key2] += mismatch.get("count", 1)
            for omission in info.get("required_omissions", []):
                row["required_omissions"][tuple(omission.get("path", []))] += omission.get("count", 1)

    output_rows = []
    for _, row in sorted(rows.items(), key=lambda item: (
            item[1]["direction"], item[1]["command"] is None,
            item[1]["command"] if item[1]["command"] is not None else 0,
            item[1]["message_name"] or "", item[0][3])):
        output_rows.append({
            "direction": row["direction"],
            "command": row["command"],
            "message_name": row["message_name"],
            "frames": row["frames"],
            "wire_match_frames": row["wire_match_frames"],
            "statuses": dict(sorted(row["statuses"].items())),
            "unknown_field_numbers": sorted({path[-1] for path in row["unknown_paths"] if path}),
            "unknown_field_paths": [
                {"path": list(path), "occurrences": count}
                for path, count in sorted(row["unknown_paths"].items())
            ],
            "wire_mismatches": [
                {"path": list(path), "observed_wire_type": observed,
                 "expected_wire_types": list(expected), "occurrences": count}
                for (path, observed, expected), count in sorted(row["wire_mismatches"].items())
            ],
            "required_omissions": [
                {"path": list(path), "count": count}
                for path, count in sorted(row["required_omissions"].items())
            ],
        })
    totals["message_rows"] = len(output_rows)
    for name in ("protocol_events", "mapped_events", "wire_match_events",
                 "wire_mismatch_events", "unknown_field_events",
                 "required_omission_events", "incomplete_mapped_events",
                 "frames_with_singular_message_merges", "singular_message_merge_sites",
                 "singular_message_merge_extra_occurrences",
                 "deduplicated_upstream_frames", "deduplicated_downstream_frames",
                 "deduplicated_downlink_flag_1_frames",
                 "deduplicated_downlink_flag_1_zlib_inflate_successes"):
        totals.setdefault(name, 0)
    return {"totals": dict(totals), "rows": output_rows}


def _counter_dict(counter):
    return {str(key): int(value) for key, value in sorted(counter.items(), key=lambda item: str(item[0]))}


def _reason_code(error):
    if not error:
        return None
    return re.sub(r"-at-offset-[0-9]+$", "", str(error))


def _execution_sources():
    paths = (Path(__file__).resolve(), Path(__file__).with_name("current_schema_match.py").resolve(),
             PROVENANCE_PATH.resolve())
    return {
        path.relative_to(REPOSITORY_ROOT).as_posix(): sha256_file(path)
        for path in paths
    }


def _stream_integrity(flow_analysis):
    totals = Counter()
    issue_counts = Counter()
    auxiliary_http_totals = Counter()
    auxiliary_http_issues = Counter()
    cap_skip_reasons = Counter()
    auxiliary_http_cap_skip_reasons = Counter()
    framing_errors = Counter()
    parser_tail_bytes = 0
    primary_frame_count = 0
    frame_statuses = Counter()
    for flow in flow_analysis["selected"].values():
        if flow.selection_kind == "protocol":
            scope_totals = totals
            scope_issues = issue_counts
            scope_cap_skip_reasons = cap_skip_reasons
        elif flow.selection_kind == "http":
            scope_totals = auxiliary_http_totals
            scope_issues = auxiliary_http_issues
            scope_cap_skip_reasons = auxiliary_http_cap_skip_reasons
        else:
            continue
        streams = getattr(flow, "reassembly_result", {})
        for direction, stream in streams.items():
            packet_direction = flow.dirs[direction]
            has_observed_payload = bool(packet_direction["payload_bytes"] or packet_direction["payload_declared"])
            if not has_observed_payload and not stream.get("segments"):
                continue
            scope_totals["selected_stream_directions"] += 1
            scope_totals["captured_contiguous_bytes"] += stream.get("contiguous_bytes", 0)
            scope_totals["post_gap_segment_bytes"] += stream.get("after_gap_bytes", 0)
            scope_totals["gap_missing_bytes"] += ((stream.get("gap") or (0, 0))[1]
                                                    - (stream.get("gap") or (0, 0))[0])
            scope_totals["exact_overlap_bytes"] += stream.get("exact_overlap_bytes", 0)
            scope_totals["conflicting_overlap_bytes"] += stream.get("conflict_bytes", 0)
            scope_totals["negative_offset_bytes"] += stream.get("negative_offset_bytes", 0)
            scope_totals["out_of_bounds_bytes"] += stream.get("out_of_bounds_bytes", 0)
            scope_totals["truncated_declared_bytes"] += stream.get("truncated_declared_bytes", 0)
            scope_totals["fragmented_captured_bytes"] += stream.get("fragmented_captured_bytes", 0)
            scope_totals["reassembly_cap_skipped_bytes"] += stream.get("cap_skipped", 0)
            scope_totals["truncated_packets"] += stream.get("truncated_packets", 0)
            scope_totals["fragmented_packets"] += stream.get("fragmented_packets", 0)
            scope_totals["session_close_observed_directions"] += int(stream.get("close_observed", False))
            scope_totals["session_close_unobserved_directions"] += int(not stream.get("close_observed", False))
            if flow.selection_kind == "http" and not stream.get("close_observed", False):
                scope_issues["session-close-not-observed"] += 1
            for reason, amount in stream.get("cap_skipped_by_reason", {}).items():
                scope_cap_skip_reasons[reason] += amount
            if stream.get("segments"):
                scope_totals["directions_with_reassembled_segments"] += 1
            else:
                scope_issues["payload-without-reassembled-segments"] += 1
            if not stream.get("origin_known", False):
                scope_issues["syn-origin-unverified"] += 1
            if stream.get("gap") is not None:
                scope_issues["sequence-gap"] += 1
            if stream.get("conflict_bytes", 0):
                scope_issues["conflicting-overlap"] += 1
            if stream.get("truncated_packets", 0) or stream.get("truncated_declared_bytes", 0):
                scope_issues["truncated-tcp-payload"] += 1
            if stream.get("fragmented_packets", 0) or stream.get("fragmented_captured_bytes", 0):
                scope_issues["fragmented-tcp-payload"] += 1
            if stream.get("cap_skipped", 0):
                scope_issues["reassembly-cap-skipped-payload"] += 1
            if stream.get("negative_offset_bytes", 0):
                scope_issues["negative-sequence-offset"] += 1
            if stream.get("out_of_bounds_bytes", 0):
                scope_issues["sequence-offset-out-of-bounds"] += 1

    for summary in flow_analysis["frame_summaries"]:
        if summary["variant"] not in ("A", "down-11B"):
            continue
        primary_frame_count += len(summary["frames"])
        parser_tail_bytes += summary["tail_bytes"]
        if summary["framing_error"]:
            framing_errors[_reason_code(summary["framing_error"])] += 1
        for frame in summary["frames"]:
            info = frame.get("current_schema_match") or unmatched_result("current-schema-not-loaded")
            frame_statuses[info.get("status", "unknown")] += 1
    totals["primary_protocol_frames_observed"] = primary_frame_count
    totals["frame_parser_tail_bytes"] = parser_tail_bytes
    totals["unparsed_bytes_total"] = (parser_tail_bytes + totals["post_gap_segment_bytes"]
                                      + totals["reassembly_cap_skipped_bytes"])
    auxiliary_http_totals["unparsed_bytes_total"] = (
        auxiliary_http_totals["post_gap_segment_bytes"]
        + auxiliary_http_totals["reassembly_cap_skipped_bytes"])
    if parser_tail_bytes:
        issue_counts["protocol-frame-tail-bytes"] += 1
    if framing_errors:
        issue_counts["protocol-frame-framing-error"] += sum(framing_errors.values())
    return (totals, issue_counts, auxiliary_http_totals, auxiliary_http_issues,
            cap_skip_reasons, auxiliary_http_cap_skip_reasons, framing_errors, frame_statuses)


def run_capture_analysis(input_path, digest, schema_matcher, expected_input_sha256=None,
                         expected_schema_sha256=None):
    """Analyze one capture and return a count-only, privacy-allowlisted evidence document."""
    input_path = Path(input_path).resolve()
    stat_before_obj = input_path.stat()
    stat_before = (stat_before_obj.st_size, stat_before_obj.st_mtime_ns)
    source_hashes_before = _execution_sources()
    scanner = PcapNGScanner(input_path)
    flows, flow_stats = scan_flows(scanner)
    ordered = classify_flows(flows, schema_matcher=schema_matcher)
    flow_analysis = analyze_selected_flows(ordered, input_path, schema_matcher=schema_matcher)
    stat_after_obj = input_path.stat()
    stat_after = (stat_after_obj.st_size, stat_after_obj.st_mtime_ns)
    digest_after = sha256_file(input_path)
    input_stable = stat_before == stat_after and digest == digest_after
    schema_stable = True
    if schema_matcher.path.is_file():
        schema_stable = sha256_file(schema_matcher.path) == schema_matcher.sha256
    source_hashes_after = _execution_sources()
    sources_stable = source_hashes_before == source_hashes_after

    second_scan = flow_analysis["second_scan"]
    second_stats = flow_analysis["second_scan_stats"]
    (integrity_totals, integrity_issues, auxiliary_http_totals,
     auxiliary_http_issues, cap_skip_reasons, auxiliary_http_cap_skip_reasons,
     framing_errors, frame_statuses) = _stream_integrity(flow_analysis)
    schema_summary = schema_match_summary(flow_analysis)["totals"]
    if scanner.error_counts:
        integrity_issues["pcap-block-validation-error"] += sum(scanner.error_counts.values())
    if second_scan.error_counts:
        integrity_issues["selected-pass-block-validation-error"] += sum(second_scan.error_counts.values())
    if scanner.truncated_records:
        integrity_issues["capture-truncated-record"] += scanner.truncated_records
    if flow_stats["tcp_decode_rejections"].get("fragment", 0):
        integrity_issues["nonfirst-ip-fragment-rejected"] += flow_stats["tcp_decode_rejections"]["fragment"]
    if not scanner.complete or not second_scan.complete:
        integrity_issues["pcap-block-scan-incomplete"] += 1
    if not input_stable:
        integrity_issues["capture-changed-during-analysis"] += 1
    if not schema_stable:
        integrity_issues["schema-changed-during-analysis"] += 1
    if not sources_stable:
        integrity_issues["executed-source-changed-during-analysis"] += 1
    if expected_input_sha256 and digest.lower() != expected_input_sha256.lower():
        integrity_issues["capture-expected-hash-mismatch"] += 1
    if expected_schema_sha256 and schema_matcher.sha256.lower() != expected_schema_sha256.lower():
        integrity_issues["schema-expected-hash-mismatch"] += 1
    if schema_summary.get("protocol_events", 0) == 0:
        integrity_issues["no-current-schema-protocol-frames"] += 1
    if schema_summary.get("protocol_events", 0) != schema_summary.get("wire_match_events", 0):
        integrity_issues["current-schema-wire-match-incomplete"] += 1
    if schema_summary.get("required_omission_events", 0):
        integrity_issues["required-fields-omitted"] += schema_summary["required_omission_events"]
    probe_reasons = Counter()
    selection_reasons = Counter()
    hints = Counter()
    probe_segments_retained = 0
    probe_segments_skipped = 0
    probe_skip_reasons = Counter()
    auxiliary_http_flow_count = 0
    auxiliary_http_reassembled_flow_count = 0
    auxiliary_http_unselected_reasons = Counter()
    protocol_candidate_unselected_reasons = Counter()
    for flow in ordered:
        hints[flow.hint] += 1
        selection_reasons[flow.selection_reason] += 1
        if flow.http:
            auxiliary_http_flow_count += 1
            if flow.selection_kind == "http":
                auxiliary_http_reassembled_flow_count += 1
            else:
                auxiliary_http_unselected_reasons[flow.selection_reason] += 1
        if flow.total_payload:
            probe_reasons[flow.protocol_probe_reason] += 1
        if flow.protocol_candidate and flow.selection_kind is None:
            protocol_candidate_unselected_reasons[flow.selection_reason] += 1
            if flow.selection_reason == "per-flow-reassembly-cap":
                integrity_issues["target-protocol-per-flow-reassembly-cap"] += 1
            elif flow.selection_reason == "aggregate-reassembly-cap":
                integrity_issues["target-protocol-aggregate-reassembly-cap"] += 1
        for direction in flow.dirs:
            probe_segments_retained += len(direction["protocol_probe_segments"])
            probe_segments_skipped += direction["protocol_probe_segments_skipped"]
            probe_skip_reasons.update(direction["protocol_probe_segments_skipped_by_reason"])

    protocol = flow_analysis["protocol_totals"]
    source_report = _PROVENANCE_MODULE.provenance(source_hashes_before)
    schema_binding = schema_matcher.binding()
    safe_schema_binding = {
        key: schema_binding[key]
        for key in ("size_bytes", "sha256", "load_status", "message_count", "field_count",
                    "mapped_command_count", "ambiguous_command_count", "json_depth_limit",
                    "schema_byte_limit", "protobuf_recursion_depth_limit",
                    "protobuf_field_limit_per_frame", "protobuf_input_limit_per_frame",
                    "enum_field_count", "enum_domain_validation", "packed_option_metadata",
                    "required_presence_semantics", "scalar_value_domains_checked",
                    "defaults_used_for_matching")
    }
    tcp_rejections = {
        "first_pass": _counter_dict(Counter(flow_stats["tcp_decode_rejections"])),
        "selected_pass": _counter_dict(Counter(second_stats["decode_rejections"])),
        "first_pass_payload_conditions": {
            "capture_truncated_payload_packets": int(flow_stats["tcp_truncated_packets"]),
            "capture_truncated_declared_payload_bytes": int(flow_stats["tcp_truncated_declared_bytes"]),
            "first_ip_fragment_packets": int(flow_stats["tcp_fragment_packets"]),
            "first_ip_fragment_captured_payload_bytes": int(flow_stats["tcp_fragment_payload_bytes"]),
        },
    }
    tcp_rejections["first_pass_flow_limit"] = int(flow_stats["flow_count_cap_packets"])
    tcp_rejections["selected_pass_scan_errors"] = _counter_dict(Counter(second_scan.error_counts))
    tcp_rejections["first_pass_scan_errors"] = _counter_dict(Counter(scanner.error_counts))
    tcp_rejections["flow_selection_reasons"] = _counter_dict(selection_reasons)
    tcp_rejections["protocol_candidate_not_reassembled_reasons"] = _counter_dict(
        protocol_candidate_unselected_reasons)
    tcp_rejections["protocol_probe_segment_skips"] = _counter_dict(probe_skip_reasons)
    tcp_rejections["reassembly_cap_skipped_bytes_by_scope"] = {
        "target_protocol": _counter_dict(cap_skip_reasons),
        "auxiliary_http": _counter_dict(auxiliary_http_cap_skip_reasons),
    }

    blockers = _counter_dict(integrity_issues)
    complete = not blockers
    return {
        "format": "ag-local-offline-evidence-v1",
        "passed": complete,
        "complete": complete,
        "incomplete_reasons": blockers,
        "provenance": source_report,
        "execution_sources_sha256": source_hashes_before,
        "inputs": {
            "capture_sha256": digest,
            "capture_expected_sha256": expected_input_sha256,
            "capture_hash_verified": (expected_input_sha256 is None
                                       or digest.lower() == expected_input_sha256.lower()),
            "capture_size_bytes": scanner.file_size,
            "capture_sha256_stable_after_scan": input_stable,
            "schema_sha256": schema_matcher.sha256,
            "schema_expected_sha256": expected_schema_sha256,
            "schema_hash_verified": (expected_schema_sha256 is None
                                      or schema_matcher.sha256.lower() == expected_schema_sha256.lower()),
            "schema_sha256_stable_after_scan": schema_stable,
            "schema_binding": safe_schema_binding,
        },
        "method": {
            "offline_only": True,
            "dependencies_profile": (
                "Analyzer uses Python standard library only; provenance records runtime and lock hashes "
                "plus installed metadata versions, but does not verify installed packages against the lock."),
            "completeness_scope": (
                "passed/complete cover current-schema validation only for target protocol flows selected "
                "from bounded mapped-frame prefixes, plus input/source integrity. They do not assert that "
                "every TCP flow or application message in the capture was identified."),
            "auxiliary_http_scope": (
                "Cleartext HTTP-hinted streams are auxiliary diagnostics; their integrity and selection "
                "limits are reported separately and do not block target protocol validation."),
            "tls_scope": "TLS-hinted flows are counted only; payloads are not decrypted or validated.",
            "payloads_or_field_values_emitted": False,
            "privacy_allowlist": ["counts", "status codes", "hashes", "bounded parser reasons", "schema field numbers"],
            "file_and_interface_limits": {
                "capture_bytes": MAX_CAPTURE_FILE_BYTES,
                "pcap_block_bytes": MAX_BLOCK,
                "interface_count": MAX_INTERFACES,
                "block_error_examples": MAX_SCAN_ERROR_EXAMPLES,
            },
            "tcp_limits": {
                "flow_count": MAX_TCP_FLOWS,
                "per_flow_reassembly_bytes": FLOW_CAP,
                "aggregate_reassembly_bytes": TOTAL_REASSEMBLY_CAP,
                "probe_segments_per_direction": MAX_PROTOCOL_PROBE_SEGMENTS,
                "probe_bytes_per_segment": MAX_PROTOCOL_PROBE_SEGMENT_BYTES,
                "probe_prefix_bytes_per_direction": MAX_PROTOCOL_PROBE_BYTES,
                "probe_segments_retained": probe_segments_retained,
                "probe_segments_skipped": probe_segments_skipped,
                "duplicate_window_ns": DUPLICATE_WINDOW_NS,
                "duplicate_cache_entries": DUPLICATE_CACHE,
                "duplicate_rule": "cross-interface only; same flow direction, sequence, acknowledgement, flags, payload length and BLAKE2s-96 payload digest within the bounded timestamp window",
            },
            "frame_and_compression_limits": {
                "frame_bytes": MAX_FRAME,
                "protobuf_bytes": MAX_INFLATED,
                "inflate_bytes_per_flow": MAX_INFLATED_PER_FLOW,
                "inflate_ratio": 64,
                "compression_selection": "Downlink flag 0 selects raw; flag 1 requires bounded complete zlib; unknown flags do not select a schema payload. Uplink has no observed explicit compression flag, so raw bytes are used for protobuf/schema and 10042 version parsing; bounded zlib-signature checks are diagnostic only and never select inflated bytes.",
            },
            "tcp_prefix_selection": "At most eight SYN-origin TCP payload segments per direction, retaining at most 64 bytes from each and assembling only a contiguous 512-byte prefix; conflicting probe overlaps are rejected.",
            "synthetic_tests": {
                "executed_by_capture_command": False,
                "status": "not-run",
                "reason": "Run the isolated repository Python test runner separately; capture analysis does not execute test suites.",
            },
        },
        "results": {
            "pcap": {
                "block_scan_complete": scanner.complete and not scanner.error_counts,
                "bytes_scanned": scanner.bytes_scanned,
                "block_counts": _counter_dict(Counter(scanner.blocks)),
                "block_rejection_reasons": _counter_dict(Counter(scanner.error_counts)),
                "section_count": scanner.sections,
                "interface_count": len(scanner.interfaces),
                "packet_records": scanner.packet_records,
                "capture_truncated_records": scanner.truncated_records,
                "unknown_timestamp_records": scanner.timestamp_unknown_records,
                "malformed_option_lists": scanner.option_errors,
                "file_stable_during_two_pass_scan": input_stable,
            },
            "tcp": {
                "flow_count": len(ordered),
                "flow_hints": _counter_dict(hints),
                "flow_selection_reasons": _counter_dict(selection_reasons),
                "protocol_probe_reasons": _counter_dict(probe_reasons),
                "payload_packets": flow_stats["tcp_payload_packets"],
                "captured_payload_bytes": flow_stats["tcp_payload_bytes"],
                "declared_payload_bytes": flow_stats["tcp_payload_declared_bytes"],
                "cross_interface_duplicates_suppressed_first_pass": flow_stats["cross_interface_duplicates_suppressed"],
                "cross_interface_duplicates_suppressed_selected_pass": flow_analysis["second_duplicates"],
                "all_rejection_and_drop_reasons": tcp_rejections,
            },
            "selected_stream_integrity": {
                "scope": "selected-target-protocol-flows-only",
                **_counter_dict(integrity_totals),
                "issue_counts": blockers,
                "framing_rejection_reasons": _counter_dict(framing_errors),
            },
            "auxiliary_http_stream_integrity": {
                "scope": "diagnostic-only; does-not-affect-target-protocol-pass",
                **_counter_dict(auxiliary_http_totals),
                "issue_counts": _counter_dict(auxiliary_http_issues),
                "reassembly_cap_skipped_bytes_by_reason": _counter_dict(
                    auxiliary_http_cap_skip_reasons),
                "flow_selection": {
                    "http_hint_flows": auxiliary_http_flow_count,
                    "reassembled_flows": auxiliary_http_reassembled_flow_count,
                    "not_reassembled_flows_by_reason": _counter_dict(
                        auxiliary_http_unselected_reasons),
                },
            },
            "protocol": {
                "upstream_a_frames_observed": protocol["A_frames"],
                "upstream_b_diagnostic_frames_observed": protocol["B_frames"],
                "downstream_frames_observed": protocol["down_frames"],
                "zlib_signature_candidates": protocol["zlib_signature_candidates"],
                "zlib_inflate_diagnostic_successes_across_selected_flow_views": protocol[
                    "zlib_inflate_diagnostic_successes"],
                "observed_compress_flag_1_downlink_inflate_successes": protocol[
                    "compress_flag_1_downlink_inflate_successes"],
                "compression_probe_relations": _counter_dict(
                    Counter(protocol["compression_probe_relations"])),
                "deduplicated_direction_frame_counts": {
                    "upstream": schema_summary["deduplicated_upstream_frames"],
                    "downstream": schema_summary["deduplicated_downstream_frames"],
                    "total": (schema_summary["deduplicated_upstream_frames"]
                              + schema_summary["deduplicated_downstream_frames"]),
                },
                "deduplicated_downlink_compress_flag_1_frames": schema_summary[
                    "deduplicated_downlink_flag_1_frames"],
                "deduplicated_downlink_compress_flag_1_zlib_inflate_successes": schema_summary[
                    "deduplicated_downlink_flag_1_zlib_inflate_successes"],
                "protobuf_wire_valid_bodies": protocol["protobuf_wire_valid"],
                "protobuf_wire_invalid_bodies": protocol["protobuf_wire_invalid"],
                "deduplicated_schema_match_totals": _counter_dict(Counter(schema_summary)),
                "schema_match_trust": {
                    "status": "trusted" if complete else "untrusted-incomplete-evidence",
                    "trusted_wire_match_events": (
                        schema_summary["wire_match_events"] if complete else 0),
                },
                "observed_schema_match_statuses": _counter_dict(frame_statuses),
            },
        },
    }


def _valid_sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def _path_has_reparse_component(path):
    junction_check = getattr(Path, "is_junction", None)
    for component in (path, *path.parents):
        if component.is_symlink():
            return True
        if junction_check is not None and junction_check(component):
            return True
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze one explicitly hash-pinned PCAPNG capture offline")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--schema-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if not _valid_sha256(args.input_sha256) or not _valid_sha256(args.schema_sha256):
        parser.error("input and schema SHA-256 values must each contain 64 hexadecimal characters")
    input_path = args.input.resolve()
    schema_path = args.schema.resolve()
    output_lexical_path = Path(os.path.abspath(str(args.output_dir)))
    if _path_has_reparse_component(output_lexical_path):
        parser.error("output path must not contain a symlink or junction")
    output_path = output_lexical_path.resolve()
    if output_path == input_path or output_path == schema_path:
        parser.error("output directory cannot replace an input file")
    if output_path.exists():
        parser.error("output directory already exists; existing evidence is never overwritten")
    if not input_path.is_file() or not schema_path.is_file():
        parser.error("capture and schema inputs must be existing files")
    try:
        actual_input_sha256 = sha256_file(input_path)
        if actual_input_sha256.lower() != args.input_sha256.lower():
            parser.error("capture SHA-256 does not match the explicitly supplied expected hash")
        schema_matcher = CurrentSchema.load(schema_path, expected_sha256=args.schema_sha256)
        report = run_capture_analysis(
            input_path, actual_input_sha256, schema_matcher,
            expected_input_sha256=args.input_sha256,
            expected_schema_sha256=args.schema_sha256)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.mkdir()
        output_file = output_path / "analysis.json"
        with output_file.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=True, indent=2, sort_keys=True)
            stream.write("\n")
    except SchemaLoadError as exc:
        parser.error("schema rejected by bounded loader: %s" % str(exc))
    except CaptureError as exc:
        parser.error("capture rejected by bounded parser: %s" % str(exc))
    except OSError:
        parser.error("capture analysis could not read an input or create the new output")
    print("Offline metadata-only analysis complete; a new report was written.")
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CaptureError:
        print("Capture analysis stopped by a bounded parser check.", file=sys.stderr)
        raise SystemExit(2)
