#!/usr/bin/env python
"""Synthetic boundary tests for current-schema protobuf matching."""

from __future__ import annotations

import unittest
import struct
import zlib
from pathlib import Path

from tools.evidence import analyze_official_startup as capture
from tools.evidence.current_schema_match import (
    CurrentSchema,
    EXPECTED_SCHEMA_SHA256,
    MAX_JSON_DEPTH,
    SchemaLoadError,
    _read_schema_document,
)


def make_field(number, logical_type, label, raw_type, raw_label, ref=None):
    return {
        "number": number,
        "name": "field_%d" % number,
        "type": logical_type,
        "label": label,
        "ref": ref,
        "default_value": "ignored-test-default",
        "metadata": {
            "descriptor": {
                "raw_type_code": raw_type,
                "raw_label_code": raw_label,
            },
        },
    }


def make_schema():
    document = {
        "messages": [
            {
                "name": "test_pb.root",
                "fields": [
                    make_field(1, "uint32", "required", 13, 2),
                    make_field(2, "message", "repeated", 11, 3, "test_pb.child"),
                    make_field(3, "uint32", "repeated", 13, 3),
                    make_field(4, "string", "optional", 9, 1),
                ],
                "metadata": {
                    "command_mapping": {
                        "direction": "client_to_server",
                        "command_id": 99,
                        "evidence": "ignored-test-evidence",
                        "prefix": "ignored-test-prefix",
                    },
                },
            },
            {
                "name": "test_pb.child",
                "fields": [make_field(1, "uint32", "required", 13, 2)],
                "metadata": {},
            },
        ],
    }
    return CurrentSchema(document, "0" * 64, 0, Path("synthetic-schema.json"))


def make_required_nested_schema(parent_label):
    document = {
        "messages": [
            {
                "name": "test_pb.root",
                "fields": [make_field(1, "message", parent_label, 11,
                                      3 if parent_label == "repeated" else 1,
                                      "test_pb.child")],
                "metadata": {
                    "command_mapping": {
                        "direction": "client_to_server",
                        "command_id": 99,
                    },
                },
            },
            {
                "name": "test_pb.child",
                "fields": [
                    make_field(1, "uint32", "required", 13, 2),
                    make_field(2, "uint32", "required", 13, 2),
                ],
                "metadata": {},
            },
        ],
    }
    return CurrentSchema(document, "0" * 64, 0, Path("synthetic-required-nested-schema.json"))


def encode_varint(value):
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def length_field(number, payload):
    return encode_varint((number << 3) | 2) + encode_varint(len(payload)) + payload


class CurrentSchemaMatchTests(unittest.TestCase):
    def setUp(self):
        self.schema = make_schema()

    def test_recursive_nested_and_packed_repeated_fields(self):
        child = b"\x08\x01"
        payload = (
            b"\x08\x07"
            + length_field(2, child)
            + length_field(3, b"\x02\x03")
            + length_field(4, b"a")
        )
        result = self.schema.match("client_to_server", 99, payload)
        self.assertTrue(result["parse_complete"])
        self.assertTrue(result["wire_match"])
        self.assertTrue(result["required_fields_complete"])
        self.assertEqual(result["field_occurrences"], 5)
        self.assertEqual(result["packed_field_occurrences"], 1)
        self.assertEqual(result["unknown_field_numbers"], [])
        self.assertEqual(result["wire_mismatches"], [])

    def test_repeated_packable_unpacked_form_is_accepted(self):
        payload = b"\x08\x01\x18\x02\x18\x03"
        result = self.schema.match("client_to_server", 99, payload)
        self.assertTrue(result["wire_match"])
        self.assertEqual(result["packed_field_occurrences"], 0)

    def test_repeated_singular_message_occurrences_merge_required_presence(self):
        schema = make_required_nested_schema("optional")
        payload = length_field(1, b"\x08\x01") + length_field(1, b"\x10\x02")
        result = schema.match("client_to_server", 99, payload)
        self.assertTrue(result["parse_complete"])
        self.assertTrue(result["wire_match"])
        self.assertTrue(result["required_fields_complete"])
        self.assertEqual(result["required_omissions"], [])
        self.assertEqual(result["singular_message_merge_sites"], 1)
        self.assertEqual(result["singular_message_merge_extra_occurrences"], 1)

    def test_repeated_message_instances_keep_required_presence_separate(self):
        schema = make_required_nested_schema("repeated")
        payload = length_field(1, b"\x08\x01") + length_field(1, b"\x10\x02")
        result = schema.match("client_to_server", 99, payload)
        self.assertTrue(result["parse_complete"])
        self.assertEqual(result["status"], "wire-match-with-required-omissions")
        self.assertEqual(
            result["required_omissions"],
            [{"path": [1, 1], "count": 1}, {"path": [1, 2], "count": 1}],
        )
        self.assertEqual(result["singular_message_merge_sites"], 0)
        self.assertEqual(result["singular_message_merge_extra_occurrences"], 0)

    def test_wire_shape_accepts_more_than_legacy_ten_thousand_field_gate(self):
        valid, field_count = capture.protobuf_wire_shape(b"\x08\x01" * 12000)
        self.assertTrue(valid)
        self.assertEqual(field_count, 12000)

    def test_wire_shape_stops_at_shared_hundred_thousand_field_cap(self):
        over_cap = b"\x08\x01" * (capture.MAX_PROTO_FIELDS + 1)
        valid, field_count = capture.protobuf_wire_shape(over_cap)
        self.assertFalse(valid)
        self.assertEqual(field_count, capture.MAX_PROTO_FIELDS)

    def test_empty_body_is_not_promoted_past_required_omissions(self):
        result = self.schema.match("client_to_server", 99, b"")
        self.assertTrue(result["parse_complete"])
        self.assertTrue(result["wire_match"])
        self.assertFalse(result["required_fields_complete"])
        self.assertEqual(result["status"], "wire-match-with-required-omissions")
        self.assertEqual(result["required_omissions"], [{"path": [1], "count": 1}])

    def test_wire_mismatch_and_required_omission_are_separate(self):
        payload = length_field(1, b"")
        result = self.schema.match("client_to_server", 99, payload)
        self.assertEqual(result["wire_mismatch_count"], 1)
        self.assertEqual(result["wire_mismatches"][0]["path"], [1])
        self.assertEqual(result["required_omissions"], [{"path": [1], "count": 1}])
        self.assertFalse(result["wire_match"])

    def test_unknown_field_number_is_preserved_without_value(self):
        result = self.schema.match("client_to_server", 99, b"\x08\x01\x98\x06\x05")
        self.assertEqual(result["unknown_field_numbers"], [99])
        self.assertEqual(result["unknown_field_paths"], [{"path": [99], "count": 1}])
        self.assertTrue(result["required_fields_complete"])

    def test_invalid_utf8_schema_string_is_rejected(self):
        result = self.schema.match("client_to_server", 99, length_field(4, b"\xff"))
        self.assertFalse(result["wire_match"])
        self.assertIn("string-utf8-invalid", result["validation_errors"])

    def test_schema_loader_rejects_invalid_utf8(self):
        with self.assertRaisesRegex(SchemaLoadError, "schema-utf8-invalid"):
            _read_schema_document(b"\xff", 32, 8)

    def test_recursive_depth_cap(self):
        recursive = CurrentSchema({
            "messages": [{
                "name": "test_pb.node",
                "fields": [make_field(1, "message", "optional", 11, 1, "test_pb.node")],
                "metadata": {"command_mapping": {"direction": "client_to_server", "command_id": 1}},
            }],
        }, "0" * 64, 0, Path("synthetic-recursive-schema.json"))
        payload = b""
        for _ in range(34):
            payload = length_field(1, payload)
        result = recursive.match("client_to_server", 1, payload)
        self.assertFalse(result["parse_complete"])
        self.assertIn("protobuf-recursion-depth-cap", result["validation_errors"])

    def test_per_frame_field_cap(self):
        payload = b"\x08\x01" + (b"\x18\x02" * 100000)
        result = self.schema.match("client_to_server", 99, payload)
        self.assertFalse(result["parse_complete"])
        self.assertIn("protobuf-field-count-cap", result["validation_errors"])

    def test_per_frame_input_byte_cap(self):
        result = self.schema.match("client_to_server", 99, b"\x00" * (1024 * 1024 + 1))
        self.assertFalse(result["parse_complete"])
        self.assertEqual(result["status"], "protobuf-input-byte-cap")
        self.assertIn("protobuf-input-byte-cap", result["validation_errors"])

    def test_schema_loader_rejects_duplicate_keys_depth_and_size(self):
        with self.assertRaisesRegex(SchemaLoadError, "duplicate-json-key"):
            _read_schema_document(b'{"a":1,"a":2}', 32, 8)
        deep = b"[" * (MAX_JSON_DEPTH + 1) + b"]" * (MAX_JSON_DEPTH + 1)
        with self.assertRaisesRegex(SchemaLoadError, "json-depth-cap"):
            _read_schema_document(deep, len(deep), MAX_JSON_DEPTH)
        with self.assertRaisesRegex(SchemaLoadError, "schema-byte-cap"):
            _read_schema_document(b"{}", 1, 8)

    def test_compression_flag_controls_body_view_without_fallback(self):
        raw = b"\x08\x07"
        compressed = zlib.compress(raw)
        info = capture.analyze_body(compressed, 1, honor_compress_flag=True)
        selected, reason = capture.schema_payload_for_body(compressed, info, 1024)
        self.assertIsNone(reason)
        self.assertEqual(selected, raw)

        zlib_like_protobuf = b"\x78\x01"
        raw_info = capture.analyze_body(zlib_like_protobuf, 0, honor_compress_flag=True)
        selected_raw, raw_reason = capture.schema_payload_for_body(zlib_like_protobuf, raw_info, 1024)
        self.assertIsNone(raw_reason)
        self.assertEqual(selected_raw, zlib_like_protobuf)

        unflagged_info = capture.analyze_body(zlib_like_protobuf, None)
        self.assertEqual(unflagged_info["protobuf_view"], "raw-no-explicit-compression-flag")
        self.assertEqual(
            unflagged_info["compression_probe_relation"],
            "unflagged-zlib-signature-diagnostic",
        )
        unflagged_payload, unflagged_reason = capture.schema_payload_for_body(
            zlib_like_protobuf, unflagged_info, 1024)
        self.assertIsNone(unflagged_reason)
        self.assertEqual(unflagged_payload, zlib_like_protobuf)

    def test_10042_versions_parse_raw_body_even_with_zlib_looking_prefix(self):
        body = (b"\x78\x9c\x01" + length_field(10, b"v1.2.3")
                + length_field(21, b"v4.5.6"))
        frame_length = 9 + len(body)
        frame = (struct.pack("<I", frame_length) + b"\x01" + struct.pack("<I", 10042)
                 + b"\x00\x00" + struct.pack("<H", 1) + body)

        parsed = capture.parse_up_frames(frame, "A", [], allow_proto_fields=True)
        observed = parsed["frames"][0]
        self.assertTrue(observed["body_info"]["zlib_header_detected"])
        self.assertFalse(observed["body_info"]["inflate_ok"])
        self.assertEqual(observed["body_info"]["protobuf_view"], "raw-no-explicit-compression-flag")
        self.assertEqual(
            observed["cs10042_versions"]["matches"],
            [
                {"field": "client_vs", "value": "v1.2.3"},
                {"field": "resource_vs", "value": "v4.5.6"},
            ],
        )

    def test_bounded_zlib_rejects_expansion_bomb_and_trailing_data(self):
        bomb = zlib.compress(b"Z" * 16384)
        bomb_result = capture.inflate_bounded(bomb, output_cap=256)
        self.assertFalse(bomb_result["ok"])
        self.assertEqual(bomb_result["reason"], "output-cap")

        trailing_result = capture.inflate_bounded(zlib.compress(b"\x08\x01") + b"trailing")
        self.assertFalse(trailing_result["ok"])
        self.assertEqual(trailing_result["reason"], "truncated-or-trailing-zlib")

    def test_real_schema_hash_and_limits(self):
        schema_path = Path(__file__).resolve().parents[2] / "v5_server/artifacts/app307-resource321-static/schema.json"
        schema = CurrentSchema.load(schema_path)
        binding = schema.binding()
        self.assertEqual(binding["sha256"], EXPECTED_SCHEMA_SHA256)
        self.assertEqual(binding["message_count"], 3061)
        self.assertEqual(binding["field_count"], 6889)
        self.assertEqual(binding["mapped_command_count"], 2317)
        self.assertEqual(binding["ambiguous_command_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
