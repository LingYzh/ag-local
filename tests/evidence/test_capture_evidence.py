"""End-to-end synthetic PCAPNG tests for the bounded evidence CLI."""

from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.evidence import analyze_official_startup as capture
from tools.evidence.current_schema_match import CurrentSchema


CLIENT_IP = bytes((10, 1, 2, 3))
SERVER_IP = bytes((10, 4, 5, 6))
CLIENT_PORT = 12001
SERVER_PORT = 40123
CLIENT_ISN = 1000


def _field(number, logical_type, label, raw_type, raw_label):
    return {
        "number": number,
        "name": "field_%d" % number,
        "type": logical_type,
        "label": label,
        "ref": None,
        "metadata": {"descriptor": {"raw_type_code": raw_type, "raw_label_code": raw_label}},
    }


def schema_document():
    fields = [
        _field(1, "uint32", "required", 13, 2),
        _field(2, "string", "optional", 9, 1),
        _field(4, "string", "optional", 9, 1),
        _field(15, "uint32", "optional", 13, 1),
    ]
    return {
        "messages": [
            {
                "name": "synthetic.RootRequest",
                "fields": fields,
                "metadata": {"command_mapping": {"direction": "client_to_server", "command_id": 99}},
            },
            {
                "name": "synthetic.RootResponse",
                "fields": fields,
                "metadata": {"command_mapping": {"direction": "server_to_client", "command_id": 100}},
            },
        ],
    }


def matcher():
    return CurrentSchema(schema_document(), "0" * 64, 0, Path("synthetic-schema.json"))


def varint(value):
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def length_field(number, payload):
    return varint((number << 3) | 2) + varint(len(payload)) + payload


def upstream_frame(body=b"\x08\x01"):
    frame_length = 9 + len(body)
    return (struct.pack("<I", frame_length) + b"\x01" + struct.pack("<I", 99)
            + b"\x00\x00" + struct.pack("<H", 1) + body)


def tcp_packet(payload=b"", seq=CLIENT_ISN, flags=0x18, src=CLIENT_IP, dst=SERVER_IP,
               sport=CLIENT_PORT, dport=SERVER_PORT, fragment_word=0, ip_payload_extra=0):
    ip_total_length = 20 + 20 + len(payload) + ip_payload_extra
    ip_header = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, ip_total_length, 1, fragment_word, 64, 6, 0, src, dst)
    tcp_header = struct.pack(
        ">HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, 0, (5 << 12) | flags, 65535, 0, 0)
    return b"\x00" * 12 + b"\x08\x00" + ip_header + tcp_header + payload


def _block(block_type, body):
    if len(body) % 4:
        raise ValueError("pcapng block bodies in this fixture must already be padded")
    total_length = 8 + len(body) + 4
    return struct.pack("<II", block_type, total_length) + body + struct.pack("<I", total_length)


def section_header():
    return _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))


def interface_block(linktype=1, snaplen=65535):
    return _block(1, struct.pack("<HHI", linktype, 0, snaplen))


def enhanced_packet(packet, timestamp=1, interface_id=0, wire_extra=0, caplen_override=None):
    caplen = len(packet) if caplen_override is None else caplen_override
    wirelen = len(packet) + wire_extra
    padded_packet = packet + b"\x00" * ((-len(packet)) % 4)
    body = struct.pack("<IIIII", interface_id, 0, timestamp, caplen, wirelen) + padded_packet
    return _block(6, body)


def capture_bytes(records, interface_count=1):
    return (section_header() + b"".join(interface_block() for _ in range(interface_count))
            + b"".join(records))


def run_report(pcap_bytes):
    with tempfile.TemporaryDirectory(prefix="ag-capture-test-") as directory:
        path = Path(directory) / "synthetic.pcapng"
        path.write_bytes(pcap_bytes)
        digest = hashlib.sha256(pcap_bytes).hexdigest()
        return capture.run_capture_analysis(path, digest, matcher(), expected_input_sha256=digest)


class PcapNGBoundaryTests(unittest.TestCase):
    def test_repeated_local_interface_id_across_sections_is_scoped(self):
        packet = tcp_packet(flags=0x02)
        raw = (section_header() + interface_block() + enhanced_packet(packet, timestamp=1)
               + section_header() + interface_block() + enhanced_packet(packet, timestamp=2))
        scanner = capture.PcapNGScanner(_write_temp_capture(self, raw))
        scanner.scan()
        self.assertTrue(scanner.complete)
        self.assertEqual(scanner.sections, 2)
        self.assertEqual([item["local_id"] for item in scanner.interfaces], [0, 0])
        self.assertEqual(scanner.packet_records, 2)
        self.assertEqual(dict(scanner.error_counts), {})

    def test_packet_interface_out_of_range_is_counted(self):
        raw = capture_bytes([enhanced_packet(tcp_packet(flags=0x02), interface_id=1)])
        scanner = capture.PcapNGScanner(_write_temp_capture(self, raw))
        scanner.scan()
        self.assertEqual(scanner.packet_records, 0)
        self.assertEqual(scanner.error_counts["packet-interface-out-of-range"], 1)

    def test_invalid_block_length_and_truncated_block_are_rejected(self):
        invalid_length = capture_bytes([]) + struct.pack("<II", 6, 10)
        scanner = capture.PcapNGScanner(_write_temp_capture(self, invalid_length))
        scanner.scan()
        self.assertEqual(scanner.error_counts["invalid-block-length"], 1)
        self.assertFalse(scanner.complete)

        truncated = capture_bytes([]) + struct.pack("<II", 6, 24) + b"\x00" * 8
        scanner = capture.PcapNGScanner(_write_temp_capture(self, truncated))
        scanner.scan()
        self.assertEqual(scanner.error_counts["truncated-block"], 1)
        self.assertFalse(scanner.complete)

    def test_packet_capture_length_overrun_is_rejected(self):
        packet = tcp_packet(flags=0x02)
        padded_length = len(packet) + ((-len(packet)) % 4)
        raw = capture_bytes([enhanced_packet(packet, caplen_override=padded_length + 4)])
        scanner = capture.PcapNGScanner(_write_temp_capture(self, raw))
        scanner.scan()
        self.assertEqual(scanner.error_counts["packet-capture-length-overruns-block"], 1)


def _write_temp_capture(test_case, raw):
    if not hasattr(test_case, "_capture_temp"):
        test_case._capture_temp = tempfile.TemporaryDirectory(prefix="ag-pcapng-scan-")
        test_case.addCleanup(test_case._capture_temp.cleanup)
    path = Path(test_case._capture_temp.name) / ("scan-%d.pcapng" % len(list(Path(test_case._capture_temp.name).glob("*.pcapng"))))
    path.write_bytes(raw)
    return path


class SyntheticCaptureIntegrationTests(unittest.TestCase):
    def test_zlib_looking_unflagged_protobuf_remains_raw_and_schema_matches(self):
        body = b"\x78\x9c\x01\x08\x01"
        frame = upstream_frame(body)
        raw = capture_bytes([
            enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
            enhanced_packet(tcp_packet(frame, seq=CLIENT_ISN + 1), timestamp=2),
        ])

        report = run_report(raw)
        protocol = report["results"]["protocol"]
        self.assertTrue(report["passed"], report["incomplete_reasons"])
        self.assertEqual(protocol["upstream_a_frames_observed"], 1)
        self.assertEqual(protocol["deduplicated_schema_match_totals"]["wire_match_events"], 1)
        self.assertEqual(protocol["zlib_signature_candidates"], 1)
        self.assertEqual(protocol["zlib_inflate_diagnostic_successes_across_selected_flow_views"], 0)
        self.assertEqual(
            protocol["compression_probe_relations"],
            {"unflagged-zlib-signature-diagnostic": 1},
        )

    def test_protocol_header_split_across_out_of_order_tcp_segments_is_selected(self):
        frame = upstream_frame()
        records = [
            enhanced_packet(tcp_packet(seq=CLIENT_ISN, flags=0x02), timestamp=1),
            enhanced_packet(tcp_packet(frame[5:], seq=CLIENT_ISN + 1 + 5), timestamp=2),
            enhanced_packet(tcp_packet(frame[:5], seq=CLIENT_ISN + 1), timestamp=3),
        ]
        report = run_report(capture_bytes(records))
        results = report["results"]
        self.assertTrue(report["passed"], report["incomplete_reasons"])
        self.assertEqual(results["tcp"]["flow_selection_reasons"], {"mapped-client-frame-prefix": 1})
        self.assertEqual(results["protocol"]["upstream_a_frames_observed"], 1)
        self.assertEqual(results["protocol"]["deduplicated_schema_match_totals"]["wire_match_events"], 1)

    def test_cross_interface_tcp_retransmission_is_deduplicated(self):
        frame = upstream_frame()
        packet = tcp_packet(frame, seq=CLIENT_ISN + 1)
        raw = capture_bytes(
            [
                enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
                enhanced_packet(packet, timestamp=2, interface_id=0),
                enhanced_packet(packet, timestamp=3, interface_id=1),
            ],
            interface_count=2,
        )
        report = run_report(raw)
        self.assertEqual(report["results"]["tcp"]["cross_interface_duplicates_suppressed_first_pass"], 1)
        self.assertEqual(report["results"]["tcp"]["cross_interface_duplicates_suppressed_selected_pass"], 1)
        self.assertEqual(report["results"]["protocol"]["upstream_a_frames_observed"], 1)

    def test_conflicting_late_overlap_keeps_candidate_but_fails_completeness(self):
        body = b"\x08\x01" + length_field(2, b"a" * 60)
        frame = upstream_frame(body)
        changed = frame[:-1] + b"b"
        raw = capture_bytes([
            enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
            enhanced_packet(tcp_packet(frame, seq=CLIENT_ISN + 1), timestamp=2),
            enhanced_packet(tcp_packet(changed, seq=CLIENT_ISN + 1), timestamp=3),
        ])
        report = run_report(raw)
        integrity = report["results"]["selected_stream_integrity"]
        protocol = report["results"]["protocol"]
        self.assertEqual(protocol["upstream_a_frames_observed"], 1)
        self.assertEqual(protocol["deduplicated_schema_match_totals"]["wire_match_events"], 0)
        self.assertEqual(protocol["schema_match_trust"]["trusted_wire_match_events"], 0)
        self.assertEqual(protocol["schema_match_trust"]["status"], "untrusted-incomplete-evidence")
        self.assertGreater(integrity["conflicting_overlap_bytes"], 0)
        self.assertFalse(report["passed"])
        self.assertFalse(report["complete"])
        self.assertIn("conflicting-overlap", report["incomplete_reasons"])

    def test_auxiliary_http_overlap_is_reported_without_blocking_protocol_validation(self):
        frame = upstream_frame()
        http_request = b"GET /startup HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
        changed_http_request = http_request[:-4] + b"x\r\n\r\n"
        http_client_ip = bytes((10, 9, 8, 7))
        http_server_ip = bytes((10, 6, 5, 4))
        http_client_port = 12002
        http_server_port = 8080
        raw = capture_bytes([
            enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
            enhanced_packet(tcp_packet(frame, seq=CLIENT_ISN + 1), timestamp=2),
            enhanced_packet(tcp_packet(
                flags=0x02, src=http_client_ip, dst=http_server_ip,
                sport=http_client_port, dport=http_server_port), timestamp=3),
            enhanced_packet(tcp_packet(
                http_request, seq=CLIENT_ISN + 1, src=http_client_ip, dst=http_server_ip,
                sport=http_client_port, dport=http_server_port), timestamp=4),
            enhanced_packet(tcp_packet(
                changed_http_request, seq=CLIENT_ISN + 1, src=http_client_ip, dst=http_server_ip,
                sport=http_client_port, dport=http_server_port), timestamp=5),
        ])

        report = run_report(raw)

        protocol = report["results"]["protocol"]
        integrity = report["results"]["selected_stream_integrity"]
        auxiliary = report["results"]["auxiliary_http_stream_integrity"]
        self.assertEqual(protocol["deduplicated_schema_match_totals"]["wire_match_events"], 1)
        self.assertEqual(protocol["schema_match_trust"]["status"], "trusted")
        self.assertEqual(protocol["schema_match_trust"]["trusted_wire_match_events"], 1)
        self.assertTrue(report["passed"], report["incomplete_reasons"])
        self.assertTrue(report["complete"], report["incomplete_reasons"])
        self.assertNotIn("conflicting-overlap", report["incomplete_reasons"])
        self.assertEqual(integrity["conflicting_overlap_bytes"], 0)
        self.assertGreater(
            auxiliary["conflicting_overlap_bytes"], 0)
        self.assertIn(
            "conflicting-overlap", auxiliary["issue_counts"])
        self.assertIn("session-close-not-observed", auxiliary["issue_counts"])
        self.assertEqual(auxiliary["flow_selection"]["http_hint_flows"], 1)

    def test_protocol_candidate_reassembly_caps_block_otherwise_matching_report(self):
        second_body = b"\x08\x02" + length_field(2, b"candidate-over-cap")
        second_frame = upstream_frame(second_body)
        packets = [
            enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
            enhanced_packet(tcp_packet(upstream_frame(), seq=CLIENT_ISN + 1), timestamp=2),
            enhanced_packet(tcp_packet(flags=0x02, sport=CLIENT_PORT + 1), timestamp=3),
            enhanced_packet(tcp_packet(
                second_frame, seq=CLIENT_ISN + 1, sport=CLIENT_PORT + 1), timestamp=4),
        ]
        raw = capture_bytes(packets)

        with mock.patch.object(capture, "FLOW_CAP", len(upstream_frame())):
            per_flow_report = run_report(raw)
        self.assertFalse(per_flow_report["complete"])
        self.assertIn(
            "target-protocol-per-flow-reassembly-cap",
            per_flow_report["incomplete_reasons"])
        self.assertEqual(
            per_flow_report["results"]["protocol"]["schema_match_trust"][
                "trusted_wire_match_events"], 0)
        self.assertEqual(
            per_flow_report["results"]["tcp"]["all_rejection_and_drop_reasons"][
                "protocol_candidate_not_reassembled_reasons"],
            {"per-flow-reassembly-cap": 1})

        with mock.patch.object(capture, "TOTAL_REASSEMBLY_CAP", len(upstream_frame())):
            aggregate_report = run_report(raw)
        self.assertFalse(aggregate_report["complete"])
        self.assertIn(
            "target-protocol-aggregate-reassembly-cap",
            aggregate_report["incomplete_reasons"])
        self.assertEqual(
            aggregate_report["results"]["tcp"]["all_rejection_and_drop_reasons"][
                "protocol_candidate_not_reassembled_reasons"],
            {"aggregate-reassembly-cap": 1})

    def test_capture_truncation_invalidates_otherwise_matching_frame(self):
        frame = upstream_frame()
        packet = tcp_packet(frame, seq=CLIENT_ISN + 1, ip_payload_extra=3)
        raw = capture_bytes([
            enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
            enhanced_packet(packet, timestamp=2, wire_extra=3),
        ])
        report = run_report(raw)
        protocol = report["results"]["protocol"]
        self.assertEqual(protocol["upstream_a_frames_observed"], 1)
        self.assertEqual(protocol["deduplicated_schema_match_totals"]["wire_match_events"], 0)
        self.assertEqual(report["results"]["selected_stream_integrity"]["truncated_declared_bytes"], 3)
        self.assertFalse(report["passed"])
        self.assertFalse(report["complete"])
        self.assertIn("truncated-tcp-payload", report["incomplete_reasons"])

    def test_sequence_gap_retains_candidate_and_reports_remaining_bytes(self):
        frame = upstream_frame()
        tail = b"\x08\x02"
        first = tcp_packet(frame, seq=CLIENT_ISN + 1)
        after_gap = tcp_packet(tail, seq=CLIENT_ISN + 1 + len(frame) + 5)
        raw = capture_bytes([
            enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
            enhanced_packet(first, timestamp=2),
            enhanced_packet(after_gap, timestamp=3),
        ])
        report = run_report(raw)
        integrity = report["results"]["selected_stream_integrity"]
        protocol = report["results"]["protocol"]
        self.assertEqual(protocol["upstream_a_frames_observed"], 1)
        self.assertEqual(protocol["deduplicated_schema_match_totals"]["wire_match_events"], 0)
        self.assertEqual(integrity["post_gap_segment_bytes"], len(tail))
        self.assertEqual(integrity["gap_missing_bytes"], 5)
        self.assertGreater(integrity["unparsed_bytes_total"], 0)
        self.assertFalse(report["passed"])
        self.assertFalse(report["complete"])

    def test_ip_fragment_is_counted_as_rejected_and_cannot_pass(self):
        frame = upstream_frame()
        raw = capture_bytes([
            enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
            enhanced_packet(tcp_packet(frame, seq=CLIENT_ISN + 1, fragment_word=0x2000), timestamp=2),
        ])
        report = run_report(raw)
        rejections = report["results"]["tcp"]["all_rejection_and_drop_reasons"]
        self.assertEqual(rejections["first_pass_payload_conditions"]["first_ip_fragment_packets"], 1)
        self.assertGreater(rejections["selected_pass"].get("fragmented-tcp-payload-skipped", 0), 0)
        self.assertFalse(report["complete"])
        self.assertTrue(report["incomplete_reasons"])

    def test_cli_requires_hashes_and_writes_only_metadata_to_new_directory(self):
        frame = upstream_frame()
        raw = capture_bytes([
            enhanced_packet(tcp_packet(flags=0x02), timestamp=1),
            enhanced_packet(tcp_packet(frame, seq=CLIENT_ISN + 1), timestamp=2),
        ])
        with tempfile.TemporaryDirectory(prefix="ag-evidence-cli-") as directory:
            root = Path(directory)
            pcap_path = root / "private-name.pcapng"
            schema_path = root / "synthetic-schema.json"
            output_path = root / "new-output"
            pcap_path.write_bytes(raw)
            schema_bytes = json.dumps(schema_document(), separators=(",", ":")).encode("utf-8")
            schema_path.write_bytes(schema_bytes)
            args = [
                "--input", str(pcap_path), "--input-sha256", hashlib.sha256(raw).hexdigest(),
                "--schema", str(schema_path), "--schema-sha256", hashlib.sha256(schema_bytes).hexdigest(),
                "--output-dir", str(output_path),
            ]
            self.assertEqual(capture.main(args), 0)
            report_path = output_path / "analysis.json"
            raw_report = report_path.read_text(encoding="utf-8")
            report = json.loads(raw_report)
            self.assertTrue(report["passed"])
            self.assertNotIn("private-name.pcapng", raw_report)
            self.assertNotIn(str(pcap_path), raw_report)
            self.assertNotIn("10.1.2.3", raw_report)
            self.assertNotIn("10.4.5.6", raw_report)
            self.assertNotIn("user_reported_context", raw_report)
            with self.assertRaises(SystemExit):
                capture.main(args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
