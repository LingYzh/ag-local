#!/usr/bin/env python
"""Bounded, value-redacting protobuf matcher for the current static schema IR."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


MAX_SCHEMA_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_SCHEMA_MESSAGES = 10000
MAX_SCHEMA_FIELDS = 100000
MAX_PROTO_DEPTH = 32
MAX_PROTO_FIELDS = 100000
MAX_PROTO_BYTES = 1024 * 1024
MAX_DETAIL_ITEMS = 256
EXPECTED_SCHEMA_SHA256 = "917010c2bc0cf4e4bfb21dfdf66c77128cff61d9a47c848a30f0a1c1d4a842b0"

WIRE_TYPES = {
    "double": (1, True),
    "float": (5, True),
    "int64": (0, True),
    "uint64": (0, True),
    "int32": (0, True),
    "bool": (0, True),
    "string": (2, False),
    "message": (2, False),
    "bytes": (2, False),
    "uint32": (0, True),
    "sint32": (0, True),
    "fixed64": (1, True),
    "sfixed64": (1, True),
    "fixed32": (5, True),
    "sfixed32": (5, True),
    "sint64": (0, True),
}

RAW_TYPE_CODES = {
    1: "double",
    2: "float",
    3: "int64",
    4: "uint64",
    5: "int32",
    6: "fixed64",
    7: "fixed32",
    8: "bool",
    9: "string",
    11: "message",
    12: "bytes",
    13: "uint32",
    14: "enum",
    15: "sfixed32",
    16: "sfixed64",
    17: "sint32",
    18: "sint64",
}

RAW_LABEL_CODES = {1: "optional", 2: "required", 3: "repeated"}


class SchemaLoadError(Exception):
    """A non-sensitive reason code for rejecting a schema artifact."""


class _DuplicateKeyError(Exception):
    pass


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError()
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise SchemaLoadError("non-finite-json-constant")


def _check_json_depth(raw: bytes, max_depth: int) -> int:
    depth = 0
    maximum = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > max_depth:
                raise SchemaLoadError("json-depth-cap")
            maximum = max(maximum, depth)
        elif byte in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                raise SchemaLoadError("json-structure-invalid")
    if in_string or depth != 0:
        raise SchemaLoadError("json-structure-invalid")
    return maximum


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_field(field, message_name):
    if not isinstance(field, dict):
        raise SchemaLoadError("field-record-invalid")
    number = field.get("number")
    logical_type = field.get("type")
    label = field.get("label")
    ref = field.get("ref")
    if not _is_int(number) or number < 1 or number > 536870911:
        raise SchemaLoadError("field-number-invalid")
    if logical_type not in WIRE_TYPES:
        raise SchemaLoadError("field-type-unsupported")
    if label not in RAW_LABEL_CODES.values():
        raise SchemaLoadError("field-label-invalid")
    metadata = field.get("metadata")
    descriptor = metadata.get("descriptor") if isinstance(metadata, dict) else None
    if not isinstance(descriptor, dict):
        raise SchemaLoadError("field-descriptor-missing")
    raw_type = descriptor.get("raw_type_code")
    raw_label = descriptor.get("raw_label_code")
    if not _is_int(raw_type) or not _is_int(raw_label):
        raise SchemaLoadError("field-descriptor-code-invalid")
    raw_name = RAW_TYPE_CODES.get(raw_type)
    if raw_name is None or RAW_LABEL_CODES.get(raw_label) != label:
        raise SchemaLoadError("field-descriptor-code-unsupported")
    is_enum = raw_name == "enum"
    if is_enum:
        if logical_type != "int32":
            raise SchemaLoadError("enum-logical-type-mismatch")
    elif raw_name != logical_type:
        raise SchemaLoadError("field-raw-type-mismatch")
    if logical_type == "message":
        if not isinstance(ref, str) or not ref:
            raise SchemaLoadError("message-reference-missing")
    elif ref is not None:
        raise SchemaLoadError("nonmessage-reference-present")
    base_wire, packable = WIRE_TYPES[logical_type]
    if is_enum:
        base_wire, packable = 0, True
    return {
        "number": number,
        "type": logical_type,
        "label": label,
        "ref": ref,
        "wire": base_wire,
        "packable": packable,
        "enum_domain_unknown": is_enum,
    }


def _read_schema_document(raw: bytes, max_bytes: int, max_depth: int):
    if len(raw) > max_bytes:
        raise SchemaLoadError("schema-byte-cap")
    _check_json_depth(raw, max_depth)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise SchemaLoadError("schema-utf8-invalid") from None
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError:
        raise SchemaLoadError("duplicate-json-key") from None
    except SchemaLoadError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise SchemaLoadError("schema-json-invalid") from None


class CurrentSchema:
    def __init__(self, document, raw_sha256: str, size_bytes: int, path: Path):
        self.sha256 = raw_sha256
        self.size_bytes = size_bytes
        self.path = path
        messages = document.get("messages") if isinstance(document, dict) else None
        if not isinstance(messages, list) or len(messages) > MAX_SCHEMA_MESSAGES:
            raise SchemaLoadError("message-list-invalid-or-over-cap")
        self.messages = {}
        total_fields = 0
        mapping_candidates = {}
        for message in messages:
            if not isinstance(message, dict):
                raise SchemaLoadError("message-record-invalid")
            name = message.get("name")
            fields_raw = message.get("fields")
            if not isinstance(name, str) or not name or name in self.messages:
                raise SchemaLoadError("message-name-invalid-or-duplicate")
            if not isinstance(fields_raw, list):
                raise SchemaLoadError("message-fields-invalid")
            fields = {}
            for field_raw in fields_raw:
                total_fields += 1
                if total_fields > MAX_SCHEMA_FIELDS:
                    raise SchemaLoadError("schema-field-count-cap")
                field = _validate_field(field_raw, name)
                number = field["number"]
                if number in fields:
                    raise SchemaLoadError("duplicate-field-number")
                fields[number] = field
            self.messages[name] = fields
            metadata = message.get("metadata")
            command_mapping = metadata.get("command_mapping") if isinstance(metadata, dict) else None
            if command_mapping is not None:
                if not isinstance(command_mapping, dict):
                    raise SchemaLoadError("command-mapping-invalid")
                direction = command_mapping.get("direction")
                command_id = command_mapping.get("command_id")
                if direction not in ("client_to_server", "server_to_client"):
                    raise SchemaLoadError("command-direction-invalid")
                if not _is_int(command_id) or command_id < 0 or command_id > 0xFFFFFFFF:
                    raise SchemaLoadError("command-id-invalid")
                mapping_candidates.setdefault((direction, command_id), []).append(name)
        self.total_fields = total_fields
        self.command_map = {}
        self.ambiguous_commands = {}
        for key, names in mapping_candidates.items():
            unique_names = sorted(set(names))
            if len(unique_names) == 1:
                self.command_map[key] = unique_names[0]
            else:
                self.ambiguous_commands[key] = unique_names
        for fields in self.messages.values():
            for field in fields.values():
                if field["type"] == "message" and field["ref"] not in self.messages:
                    raise SchemaLoadError("message-reference-unresolved")
        self.enum_field_count = sum(
            field["enum_domain_unknown"]
            for fields in self.messages.values()
            for field in fields.values()
        )
        self.packed_options_present = False

    @classmethod
    def load(cls, path: Path, expected_sha256: str = EXPECTED_SCHEMA_SHA256,
             max_bytes: int = MAX_SCHEMA_BYTES, max_depth: int = MAX_JSON_DEPTH):
        path = Path(path)
        try:
            before = path.stat()
        except OSError:
            raise SchemaLoadError("schema-file-unavailable") from None
        if before.st_size > max_bytes:
            raise SchemaLoadError("schema-byte-cap")
        try:
            with path.open("rb") as stream:
                raw = stream.read(max_bytes + 1)
            after = path.stat()
        except OSError:
            raise SchemaLoadError("schema-file-read-failed") from None
        if len(raw) > max_bytes:
            raise SchemaLoadError("schema-byte-cap")
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise SchemaLoadError("schema-changed-during-read")
        if len(raw) != after.st_size:
            raise SchemaLoadError("schema-size-changed-during-read")
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 and digest.lower() != expected_sha256.lower():
            raise SchemaLoadError("schema-sha256-mismatch")
        document = _read_schema_document(raw, max_bytes, max_depth)
        return cls(document, digest, len(raw), path.resolve())

    def binding(self):
        return {
            "artifact": self.path.name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "load_status": "validated",
            "message_count": len(self.messages),
            "field_count": self.total_fields,
            "mapped_command_count": len(self.command_map),
            "ambiguous_command_count": len(self.ambiguous_commands),
            "duplicate_json_keys_rejected": True,
            "json_depth_limit": MAX_JSON_DEPTH,
            "schema_byte_limit": MAX_SCHEMA_BYTES,
            "protobuf_recursion_depth_limit": MAX_PROTO_DEPTH,
            "protobuf_field_limit_per_frame": MAX_PROTO_FIELDS,
            "protobuf_input_limit_per_frame": MAX_PROTO_BYTES,
            "enum_field_count": self.enum_field_count,
            "enum_domain_validation": "unknown-no-domain-table-in-current-ir" if self.enum_field_count else "not-applicable-no-enum-fields-in-current-ir",
            "packed_option_metadata": "absent; repeated packable fields accept valid packed or unpacked wire forms",
            "required_presence_semantics": "singular embedded-message occurrences merge; repeated message instances are independent",
            "scalar_value_domains_checked": False,
            "defaults_used_for_matching": False,
        }

    def match(self, direction: str, command_id: int | None, payload: bytes | memoryview,
              stream_verified: bool = True):
        lookup_status, message_name = self.resolve(direction, command_id, stream_verified)
        if message_name is None:
            return _unmatched(lookup_status)
        return match_message(payload, message_name, self.messages)

    def resolve(self, direction: str, command_id: int | None, stream_verified: bool = True):
        if not stream_verified:
            return "stream-origin-or-prefix-unverified", None
        if direction not in ("client_to_server", "server_to_client"):
            return "stream-orientation-unverified", None
        if command_id is None:
            return "command-unknown", None
        key = (direction, command_id)
        if key in self.ambiguous_commands:
            return "ambiguous-command-mapping", None
        message_name = self.command_map.get(key)
        if message_name is None:
            return "unmapped-command", None
        return "mapped", message_name

    def unparsed(self, direction: str, command_id: int | None, status: str,
                 stream_verified: bool = True):
        lookup_status, message_name = self.resolve(direction, command_id, stream_verified)
        if message_name is None:
            return _unmatched(lookup_status)
        result = _unmatched(status)
        result["message_name"] = message_name
        return result


def _unmatched(status: str):
    return {
        "status": status,
        "message_name": None,
        "wire_match": None,
        "parse_complete": None,
        "field_occurrences": 0,
        "singular_message_merge_sites": 0,
        "singular_message_merge_extra_occurrences": 0,
        "unknown_field_occurrences": 0,
        "unknown_field_numbers": [],
        "unknown_field_paths": [],
        "wire_mismatch_count": 0,
        "wire_mismatches": [],
        "required_omission_count": 0,
        "required_omissions": [],
        "required_omissions_status": "not-evaluated",
        "required_fields_complete": None,
        "packed_field_occurrences": 0,
        "packed_field_paths": [],
        "enum_domain_unknown_paths": [],
        "validation_errors": [],
    }


def unmatched_result(status: str):
    return _unmatched(status)


def _read_varint(data, pos):
    value = 0
    for index in range(10):
        if pos >= len(data):
            return None, pos, "truncated-varint"
        byte = data[pos]
        pos += 1
        if index == 9 and byte > 1:
            return None, pos, "varint-overflow"
        value |= (byte & 0x7F) << (index * 7)
        if byte < 0x80:
            return value, pos, None
    return None, pos, "varint-overflow"


def _read_length(data, pos):
    length, pos, error = _read_varint(data, pos)
    if error:
        return None, None, pos, error
    if length > len(data) - pos:
        return None, None, pos, "length-overrun"
    end = pos + length
    return pos, end, end, None


def _skip_value(data, wire_type, pos):
    if wire_type == 0:
        _, new_pos, error = _read_varint(data, pos)
        return new_pos, error
    if wire_type == 1:
        if len(data) - pos < 8:
            return pos, "truncated-fixed64"
        return pos + 8, None
    if wire_type == 2:
        _, _, new_pos, error = _read_length(data, pos)
        return new_pos, error
    if wire_type == 5:
        if len(data) - pos < 4:
            return pos, "truncated-fixed32"
        return pos + 4, None
    return pos, "unsupported-wire-type"


class _MatchState:
    def __init__(self, schemas):
        self.schemas = schemas
        self.field_occurrences = 0
        self.message_instances = []
        self.unknown_occurrences = 0
        self.unknown_paths = {}
        self.mismatches = {}
        self.required_omissions = {}
        self.packed_occurrences = 0
        self.packed_paths = set()
        self.enum_paths = set()
        self.singular_message_merge_sites = 0
        self.singular_message_merge_extra_occurrences = 0
        self.errors = set()
        self.required_status_partial = False

    def add_error(self, code):
        self.errors.add(code)

    def add_unknown(self, path):
        self.unknown_occurrences += 1
        key = tuple(path)
        self.unknown_paths[key] = self.unknown_paths.get(key, 0) + 1

    def add_mismatch(self, path, observed, expected):
        key = (tuple(path), observed, tuple(sorted(expected)))
        self.mismatches[key] = self.mismatches.get(key, 0) + 1

    def add_required_omission(self, path):
        key = tuple(path)
        self.required_omissions[key] = self.required_omissions.get(key, 0) + 1

    def add_packed(self, path):
        self.packed_occurrences += 1
        self.packed_paths.add(tuple(path))

    def new_message_instance(self, message_name, path_prefix, occurrences=1):
        if len(self.message_instances) >= MAX_PROTO_FIELDS + 1:
            self.add_error("protobuf-message-instance-cap")
            self.required_status_partial = True
            return None
        fields = self.schemas.get(message_name)
        if fields is None:
            self.add_error("message-reference-unresolved")
            self.required_status_partial = True
            return None
        instance = _MessageInstance(message_name, path_prefix, fields, occurrences)
        self.message_instances.append(instance)
        return instance


class _MessageInstance:
    """Required-field presence for one logical protobuf message instance."""

    __slots__ = ("message_name", "path_prefix", "required_missing", "singular_children", "occurrences")

    def __init__(self, message_name, path_prefix, fields, occurrences=1):
        self.message_name = message_name
        self.path_prefix = path_prefix
        self.required_missing = {
            number for number, field in fields.items() if field["label"] == "required"
        }
        self.singular_children = {}
        self.occurrences = occurrences


def _parse_packed_values(data, wire_type):
    pos = 0
    if wire_type == 0:
        while pos < len(data):
            _, pos, error = _read_varint(data, pos)
            if error:
                return False, error
        return True, None
    if wire_type == 1:
        if len(data) % 8:
            return False, "packed-fixed64-length-not-multiple"
        return True, None
    if wire_type == 5:
        if len(data) % 4:
            return False, "packed-fixed32-length-not-multiple"
        return True, None
    return False, "packed-wire-type-unsupported"


def _parse_message(data, message_name, path_prefix, depth, state, instance):
    if depth > MAX_PROTO_DEPTH:
        state.add_error("protobuf-recursion-depth-cap")
        state.required_status_partial = True
        return False
    fields = state.schemas.get(message_name)
    if fields is None:
        state.add_error("message-reference-unresolved")
        state.required_status_partial = True
        return False
    pos = 0
    message_complete = True
    while pos < len(data):
        if state.field_occurrences >= MAX_PROTO_FIELDS:
            state.add_error("protobuf-field-count-cap")
            state.required_status_partial = True
            message_complete = False
            break
        tag, after_tag, error = _read_varint(data, pos)
        if error:
            state.add_error(error)
            state.required_status_partial = True
            message_complete = False
            break
        field_number = tag >> 3
        wire_type = tag & 7
        if field_number < 1 or field_number > 536870911:
            state.add_error("invalid-field-number")
            state.required_status_partial = True
            message_complete = False
            break
        if wire_type in (3, 4):
            state.add_error("unsupported-group-wire-type")
            state.required_status_partial = True
            message_complete = False
            break
        state.field_occurrences += 1
        path = path_prefix + (field_number,)
        field = fields.get(field_number)
        if field is None:
            state.add_unknown(path)
            pos, error = _skip_value(data, wire_type, after_tag)
            if error:
                state.add_error(error)
                state.required_status_partial = True
                message_complete = False
                break
            continue

        expected_wire = field["wire"]
        accepted_wires = {expected_wire}
        if field["label"] == "repeated" and field["packable"]:
            accepted_wires.add(2)
        if wire_type not in accepted_wires:
            state.add_mismatch(path, wire_type, accepted_wires)
            pos, error = _skip_value(data, wire_type, after_tag)
            if error:
                state.add_error(error)
                state.required_status_partial = True
                message_complete = False
                break
            continue

        if field["label"] == "required":
            instance.required_missing.discard(field_number)
        if field["enum_domain_unknown"]:
            state.enum_paths.add(path)

        if field["label"] == "repeated" and field["packable"] and wire_type == 2:
            packed_start, packed_end, new_pos, error = _read_length(data, after_tag)
            if error:
                state.add_error(error)
                state.required_status_partial = True
                message_complete = False
                break
            packed_data = data[packed_start:packed_end]
            packed_ok, packed_error = _parse_packed_values(packed_data, expected_wire)
            state.add_packed(path)
            if not packed_ok:
                state.add_error(packed_error or "packed-value-invalid")
                state.required_status_partial = True
                message_complete = False
            pos = new_pos
            continue

        if wire_type == 2:
            value_start, value_end, new_pos, error = _read_length(data, after_tag)
            if error:
                state.add_error(error)
                state.required_status_partial = True
                message_complete = False
                break
            value_view = data[value_start:value_end]
            if field["type"] == "message":
                if field["label"] == "repeated":
                    child_instance = state.new_message_instance(field["ref"], path)
                else:
                    child_instance = instance.singular_children.get(field_number)
                    if child_instance is None:
                        child_instance = state.new_message_instance(field["ref"], path)
                        if child_instance is not None:
                            instance.singular_children[field_number] = child_instance
                    else:
                        if child_instance.occurrences == 1:
                            state.singular_message_merge_sites += 1
                        child_instance.occurrences += 1
                        state.singular_message_merge_extra_occurrences += 1
                if child_instance is None:
                    nested_complete = False
                else:
                    nested_complete = _parse_message(
                        value_view, field["ref"], path, depth + 1, state, child_instance)
                if not nested_complete:
                    message_complete = False
            elif field["type"] == "string":
                try:
                    value_view.tobytes().decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    state.add_error("string-utf8-invalid")
                    message_complete = False
            pos = new_pos
            continue

        pos, error = _skip_value(data, wire_type, after_tag)
        if error:
            state.add_error(error)
            state.required_status_partial = True
            message_complete = False
            break

    if not message_complete:
        state.required_status_partial = True
    return message_complete


def _bounded_items(values, limit=MAX_DETAIL_ITEMS):
    items = sorted(values)
    return items[:limit], max(0, len(items) - limit)


def match_message(payload: bytes | memoryview, message_name: str, schemas: dict):
    view = payload if isinstance(payload, memoryview) else memoryview(payload)
    if len(view) > MAX_PROTO_BYTES:
        result = _unmatched("protobuf-input-byte-cap")
        result.update({
            "message_name": message_name,
            "wire_match": False,
            "parse_complete": False,
            "required_omissions_status": "partial",
            "validation_errors": ["protobuf-input-byte-cap"],
        })
        return result
    state = _MatchState(schemas)
    root_instance = state.new_message_instance(message_name, ())
    if root_instance is None:
        parse_complete = False
    else:
        parse_complete = _parse_message(view, message_name, (), 0, state, root_instance)
    for instance in state.message_instances:
        for field_number in instance.required_missing:
            state.add_required_omission(instance.path_prefix + (field_number,))
    unknown_paths, unknown_omitted = _bounded_items(state.unknown_paths.items())
    mismatch_items, mismatch_omitted = _bounded_items(state.mismatches.items())
    required_items, required_omitted = _bounded_items(state.required_omissions.items())
    packed_paths, packed_omitted = _bounded_items(state.packed_paths)
    enum_paths, enum_omitted = _bounded_items(state.enum_paths)
    mismatches = [
        {
            "path": list(path),
            "observed_wire_type": observed,
            "expected_wire_types": list(expected),
            "count": count,
        }
        for (path, observed, expected), count in mismatch_items
    ]
    unknown_path_details = [
        {"path": list(path), "count": count}
        for path, count in unknown_paths
    ]
    required = [
        {"path": list(path), "count": count}
        for path, count in required_items
    ]
    wire_match = parse_complete and not state.unknown_paths and not state.mismatches and not state.errors
    if not parse_complete:
        status = "protobuf-parse-incomplete"
    elif state.errors:
        status = "protobuf-schema-validation-error"
    elif state.mismatches:
        status = "wire-mismatch"
    elif state.unknown_paths:
        status = "unknown-fields"
    elif state.required_omissions:
        status = "wire-match-with-required-omissions"
    else:
        status = "wire-match"
    errors, error_omitted = _bounded_items(state.errors)
    return {
        "status": status,
        "message_name": message_name,
        "wire_match": wire_match,
        "parse_complete": parse_complete,
        "field_occurrences": state.field_occurrences,
        "singular_message_merge_sites": state.singular_message_merge_sites,
        "singular_message_merge_extra_occurrences": state.singular_message_merge_extra_occurrences,
        "unknown_field_occurrences": state.unknown_occurrences,
        "unknown_field_numbers": sorted({path[-1] for path in state.unknown_paths if path})[:MAX_DETAIL_ITEMS],
        "unknown_field_numbers_omitted": max(0, len({path[-1] for path in state.unknown_paths if path}) - MAX_DETAIL_ITEMS),
        "unknown_field_paths": unknown_path_details,
        "unknown_field_paths_omitted": unknown_omitted,
        "wire_mismatch_count": sum(state.mismatches.values()),
        "wire_mismatches": mismatches,
        "wire_mismatches_omitted": mismatch_omitted,
        "required_omission_count": sum(state.required_omissions.values()),
        "required_omissions": required,
        "required_omissions_omitted": required_omitted,
        "required_omissions_status": "partial" if state.required_status_partial else "complete",
        "required_fields_complete": parse_complete and not state.required_omissions,
        "packed_field_occurrences": state.packed_occurrences,
        "packed_field_paths": [list(path) for path in packed_paths],
        "packed_field_paths_omitted": packed_omitted,
        "enum_domain_unknown_paths": [list(path) for path in enum_paths],
        "enum_domain_unknown_paths_omitted": enum_omitted,
        "validation_errors": errors,
        "validation_errors_omitted": error_omitted,
    }
