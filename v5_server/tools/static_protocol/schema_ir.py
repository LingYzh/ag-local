"""Build a provenance-rich schema from statically recovered declarations.

This module does not execute Lua and does not read files itself. It accepts the
bounded bundle extraction result, verifies every declaration/reference, and
emits the desktop loader's schema shape plus deterministic source metadata.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import math
import re
from typing import Any, Mapping

from .bytecode import Limits
from .static_vm import (
    AnalysisResult,
    ExternalRef,
    MessageClass,
    StaticAnalysisError,
    StaticTable,
    Symbol,
    analyze_asset,
)


MAX_PROTOCOL_ASSETS = 4096
MAX_TOTAL_PROTOCOL_BYTES = 32 * 1024 * 1024
MAX_TOTAL_MESSAGES = 50_000
MAX_TOTAL_FIELDS = 250_000
MAX_TOTAL_STATIC_NODES = 1_000_000
MAX_TOTAL_INSTRUCTIONS = 4_000_000
MAX_LOCATION_STRING = 1024

FIELD_TYPE_NAMES = {
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
    15: "sfixed32",
    16: "sfixed64",
    17: "sint32",
    18: "sint64",
}
FIELD_LABEL_NAMES = {1: "optional", 2: "required", 3: "repeated"}

_ASSET_NAME = re.compile(r"^[A-Za-z0-9_]+_pb\.lua$")
_MODULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FULL_NAME = re.compile(r"^\.?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_COMMAND_NAME = re.compile(r"^(cs|sc)_([0-9]+)$", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_DESCRIPTOR_KEYS = {
    "enum_types", "extensions", "fields", "full_name", "is_extendable",
    "name", "nested_types",
}
_FIELD_DESCRIPTOR_KEYS = {
    "cpp_type", "default_value", "full_name", "has_default_value", "index",
    "label", "message_type", "name", "number", "type",
}


class SchemaRecoveryError(ValueError):
    """The bytecode declarations cannot be represented without guessing."""


@dataclass(frozen=True)
class _Asset:
    key: str
    canonical_name: str
    stem: str
    data: bytes
    asset_sha256: str
    location: dict[str, Any]
    analysis: AnalysisResult


@dataclass(frozen=True)
class _Message:
    asset: _Asset
    message_class: MessageClass
    descriptor: StaticTable
    export_name: str
    short_name: str
    raw_full_name: str
    output_name: str
    fields_table: StaticTable


def _read_member(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _location_value(value: Any, *, where: str, depth: int = 0) -> Any:
    if depth > 4:
        raise SchemaRecoveryError(f"{where}: asset location is nested too deeply")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SchemaRecoveryError(f"{where}: asset location contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > MAX_LOCATION_STRING:
            raise SchemaRecoveryError(f"{where}: asset location string exceeds its limit")
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
            raise SchemaRecoveryError(f"{where}: absolute paths are not emitted as source metadata")
        if any(part == ".." for part in normalized.split("/")):
            raise SchemaRecoveryError(f"{where}: parent traversal is not valid source metadata")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            if not isinstance(key, str) or len(key) > 128:
                raise SchemaRecoveryError(f"{where}: asset location has an invalid key")
            result[key] = _location_value(value[key], where=f"{where}.{key}", depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise SchemaRecoveryError(f"{where}: asset location list exceeds its limit")
        return [_location_value(item, where=where, depth=depth + 1) for item in value]
    raise SchemaRecoveryError(f"{where}: unsupported asset location value {type(value).__name__}")


def _clean_location(value: Any, *, asset_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaRecoveryError(f"{asset_name}: missing static asset location metadata")
    allowed = {
        "entry", "source_entry", "object", "path_id", "byte_start", "byte_size",
        "bundle_uncompressed_byte_start",
    }
    unexpected = sorted(str(key) for key in value if key not in allowed)
    if unexpected:
        raise SchemaRecoveryError(f"{asset_name}: unsupported asset location keys {unexpected}")

    entry_keys = [key for key in ("source_entry", "entry") if key in value]
    if not entry_keys:
        raise SchemaRecoveryError(f"{asset_name}: asset location is missing source_entry/entry")
    missing = sorted({"object", "path_id", "byte_start", "byte_size"} - set(value))
    if missing:
        raise SchemaRecoveryError(f"{asset_name}: asset location is missing required fields {missing}")
    clean_entries = {
        key: _location_value(value[key], where=f"{asset_name}.location.{key}")
        for key in entry_keys
    }
    if any(not isinstance(entry, str) or not entry.strip() for entry in clean_entries.values()):
        raise SchemaRecoveryError(f"{asset_name}: asset source entry must be a non-empty relative string")
    if len(set(clean_entries.values())) != 1:
        raise SchemaRecoveryError(f"{asset_name}: source_entry and entry identify different bundle entries")

    object_value = value.get("object")
    if object_value != "TextAsset":
        raise SchemaRecoveryError(f"{asset_name}: asset location object must be 'TextAsset'")

    required_integer_ranges = {
        "path_id": (-(2**63), (2**63) - 1),
        "byte_start": (0, (2**63) - 1),
        "byte_size": (1, (2**32) - 1),
    }
    for key, (minimum, maximum) in required_integer_ranges.items():
        number = value.get(key)
        if not isinstance(number, int) or isinstance(number, bool):
            raise SchemaRecoveryError(f"{asset_name}: asset location {key} must be an integer")
        if number < minimum or number > maximum:
            raise SchemaRecoveryError(
                f"{asset_name}: asset location {key} is outside {minimum}..{maximum}"
            )

    result = {
        "source_entry": clean_entries[entry_keys[0]],
        "object": "TextAsset",
    }
    result.update({key: value[key] for key in required_integer_ranges})
    if "bundle_uncompressed_byte_start" in value:
        uncompressed_start = value["bundle_uncompressed_byte_start"]
        if not isinstance(uncompressed_start, int) or isinstance(uncompressed_start, bool):
            raise SchemaRecoveryError(
                f"{asset_name}: asset location bundle_uncompressed_byte_start must be an integer"
            )
        if uncompressed_start < 0 or uncompressed_start > (2**63) - 1:
            raise SchemaRecoveryError(
                f"{asset_name}: asset location bundle_uncompressed_byte_start is outside 0..{(2**63) - 1}"
            )
        result["bundle_uncompressed_byte_start"] = uncompressed_start
    return result


def _canonical_asset_name(name: Any) -> tuple[str, str, str]:
    if not isinstance(name, str) or not name or len(name) > 512:
        raise SchemaRecoveryError("protocol asset name must be a bounded non-empty string")
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SchemaRecoveryError(f"{name!r}: unsafe protocol asset path")
    if len(parts) > 1 and parts[-2] != "protocol":
        raise SchemaRecoveryError(f"{name!r}: protocol assets must be bare filenames or under protocol/")
    basename = parts[-1]
    if not _ASSET_NAME.fullmatch(basename):
        raise SchemaRecoveryError(f"{name!r}: expected a *_pb.lua protocol TextAsset")
    stem = basename[:-4]
    if not _MODULE_NAME.fullmatch(stem):
        raise SchemaRecoveryError(f"{name!r}: invalid protocol module name")
    return name, basename, stem


def _get_location(locations: Any, key: str, canonical_name: str, stem: str) -> Any:
    if not isinstance(locations, Mapping):
        return None
    for candidate in (key, key.replace("\\", "/"), canonical_name, f"protocol/{canonical_name}", stem):
        if candidate in locations:
            return locations[candidate]
    return None


def _json_scalar(value: Any, *, where: str) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SchemaRecoveryError(f"{where}: non-finite value is outside the schema subset")
        return value
    raise SchemaRecoveryError(f"{where}: unsupported declaration value {type(value).__name__}")


def _require_value(table: StaticTable, key: str, *, where: str) -> Any:
    if key not in table.entries:
        raise SchemaRecoveryError(f"{where}: missing required static {table.kind}[{key!r}]")
    return table.entries[key]


def _validate_entry_keys(table: StaticTable, allowed: set[str], *, where: str) -> None:
    unexpected = sorted(str(key) for key in table.entries if key not in allowed)
    if unexpected:
        raise SchemaRecoveryError(f"{where}: unsupported declaration entries {unexpected}")


def _table_is_empty(value: Any, *, where: str) -> None:
    if not isinstance(value, StaticTable):
        raise SchemaRecoveryError(f"{where}: expected a statically constructed table")
    if value.entries:
        raise SchemaRecoveryError(f"{where}: non-empty declaration is outside the static schema subset")


def _offset_map(table: StaticTable) -> dict[str, int]:
    return {str(key): value for key, value in sorted(table.entry_offsets.items(), key=lambda item: str(item[0]))}


def _write_offset_map(table: StaticTable) -> dict[str, list[int]]:
    return {
        str(key): list(offsets)
        for key, offsets in sorted(table.write_offsets.items(), key=lambda item: str(item[0]))
    }


def _source_direction(short_name: str) -> dict[str, Any] | None:
    match = _COMMAND_NAME.fullmatch(short_name)
    if match is None:
        return None
    prefix = match.group(1).lower()
    return {
        "prefix": prefix,
        "direction": "client_to_server" if prefix == "cs" else "server_to_client",
        "command_id": int(match.group(2)),
        "evidence": "structural_name_prefix_only_not_runtime_traffic_evidence",
    }


def _asset_module(result: AnalysisResult, expected_stem: str) -> str:
    namespace = result.namespace
    if not isinstance(namespace, str) or not _MODULE_NAME.fullmatch(namespace):
        raise SchemaRecoveryError(f"{result.asset_name}: invalid static module namespace")
    if namespace.casefold() != expected_stem.casefold():
        raise SchemaRecoveryError(
            f"{result.asset_name}: module declaration {namespace!r} does not match source asset {expected_stem!r}"
        )
    return namespace


def _module_require_path(value: str, *, source_asset: str) -> str | None:
    if value == "protobuf":
        return None
    normalized = value.replace("\\", "/")
    if not re.fullmatch(r"protocol/[A-Za-z0-9_]+_pb", normalized):
        raise SchemaRecoveryError(f"{source_asset}: unsupported required module path {value!r}")
    return normalized


def _validate_return(result: AnalysisResult) -> None:
    expected = (Symbol("global", (result.namespace,)),)
    if result.return_values != expected:
        raise SchemaRecoveryError(
            f"{result.asset_name}: unsupported return value; only the exact root-module symbol is admitted"
        )


def _walk_supported_value(
    value: Any,
    *,
    where: str,
    local_tables: set[int],
    local_messages: set[int],
    visited: set[int],
    allow_external_ref: bool = False,
) -> None:
    if value is None or isinstance(value, (bool, int, float, str)):
        _json_scalar(value, where=where)
        return
    if isinstance(value, Symbol):
        raise SchemaRecoveryError(f"{where}: unresolved symbolic value {value.label()!r}")
    if isinstance(value, ExternalRef):
        if not allow_external_ref:
            raise SchemaRecoveryError(f"{where}: external reference appears outside FieldDescriptor.message_type")
        if not value.module or not value.name:
            raise SchemaRecoveryError(f"{where}: incomplete external reference")
        return
    if isinstance(value, MessageClass):
        if id(value) not in local_messages:
            raise SchemaRecoveryError(f"{where}: unregistered Message constructor result")
        if id(value) in visited:
            return
        visited.add(id(value))
        _walk_supported_value(
            value.descriptor,
            where=f"{where}.descriptor",
            local_tables=local_tables,
            local_messages=local_messages,
            visited=visited,
        )
        return
    if isinstance(value, StaticTable):
        if id(value) not in local_tables:
            raise SchemaRecoveryError(f"{where}: unregistered static table node")
        if id(value) in visited:
            return
        visited.add(id(value))
        for key, child in sorted(value.entries.items(), key=lambda item: str(item[0])):
            _walk_supported_value(
                child,
                where=f"{where}[{key!r}]",
                local_tables=local_tables,
                local_messages=local_messages,
                visited=visited,
                allow_external_ref=value.kind == "FieldDescriptor" and key == "message_type",
            )
        return
    raise SchemaRecoveryError(f"{where}: unsupported symbolic declaration value {type(value).__name__}")


def _table_key_order(key: str | int) -> tuple[str, str]:
    return type(key).__name__, str(key)


def _checked_offsets(
    offsets: Any,
    *,
    where: str,
    allow_empty: bool,
) -> list[int]:
    if not isinstance(offsets, (list, tuple)):
        raise SchemaRecoveryError(f"{where}: source offsets are not a list")
    if not allow_empty and not offsets:
        raise SchemaRecoveryError(f"{where}: required source read/write offsets are missing")
    result: list[int] = []
    for offset in offsets:
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > (2**63) - 1:
            raise SchemaRecoveryError(f"{where}: source offset is outside the supported integer range")
        result.append(offset)
    return result


def _validate_lookup_table_history(
    table: StaticTable,
    *,
    where: str,
    require_every_entry_read: bool,
) -> None:
    entry_keys = set(table.entries)
    if any(not isinstance(key, (str, int)) or isinstance(key, bool) for key in entry_keys):
        raise SchemaRecoveryError(f"{where}: lookup table has a non-static key")
    if set(table.entry_offsets) != entry_keys:
        raise SchemaRecoveryError(f"{where}: lookup entry offsets do not match its final entries")
    if set(table.write_offsets) != entry_keys:
        raise SchemaRecoveryError(f"{where}: lookup write history does not match its final entries")
    if not set(table.read_offsets).issubset(entry_keys):
        raise SchemaRecoveryError(f"{where}: lookup read history refers to a missing final entry")
    if require_every_entry_read and set(table.read_offsets) != entry_keys:
        raise SchemaRecoveryError(f"{where}: one or more non-empty lookup entries were not read")

    for key in sorted(entry_keys, key=_table_key_order):
        entry_offset = table.entry_offsets[key]
        if not isinstance(entry_offset, int) or isinstance(entry_offset, bool) or entry_offset < 0:
            raise SchemaRecoveryError(f"{where}[{key!r}]: invalid entry source offset")
        writes = _checked_offsets(
            table.write_offsets[key],
            where=f"{where}[{key!r}].write_offsets",
            allow_empty=False,
        )
        if len(writes) != 1 or writes[-1] != entry_offset:
            raise SchemaRecoveryError(f"{where}[{key!r}]: lookup entry has ambiguous write history")
        if key in table.read_offsets:
            _checked_offsets(
                table.read_offsets[key],
                where=f"{where}[{key!r}].read_offsets",
                allow_empty=False,
            )


def _unsupported_unreachable_table(
    asset: _Asset,
    node: StaticTable,
    reason: str,
) -> SchemaRecoveryError:
    return SchemaRecoveryError(
        f"{asset.key}: created static table node (kind={node.kind!r}) at byte {node.created_at} "
        f"is not reachable from module exports; unsupported helper graph: {reason}"
    )


def _classify_lookup_helpers(
    asset: _Asset,
    result: AnalysisResult,
    *,
    reachable: set[int],
    table_ids: set[int],
    field_ids: set[int],
) -> dict[str, Any]:
    """Admit only one source-read lookup container outside the export graph.

    The admitted shape is a single plain table whose entries point to unique,
    same-asset plain child tables. Non-empty children contain only unique local
    FieldDescriptor references, and every parent/leaf lookup is observed in
    the static read-offset trace. A child with no source entries or history may
    be retained as explicit unused_empty_lookup scaffolding only while its
    parent key is never read.
    """
    unreachable = [node for node in result.created_tables if id(node) not in reachable]
    unreachable_ids = {id(node) for node in unreachable}
    empty_report = {
        "counts": {
            "lookup_containers": 0,
            "field_lookup_tables": 0,
            "unused_empty_lookup": 0,
            "field_aliases": 0,
        },
        "lookup_containers": [],
    }
    if not unreachable:
        return empty_report

    parents: dict[int, list[tuple[StaticTable, str | int]]] = {id(node): [] for node in result.created_tables}
    for parent in result.created_tables:
        for key, value in parent.entries.items():
            if isinstance(value, StaticTable) and id(value) in table_ids:
                parents[id(value)].append((parent, key))

    roots = [node for node in unreachable if not parents[id(node)]]
    if len(roots) != 1:
        node = min(unreachable, key=lambda value: value.created_at)
        raise _unsupported_unreachable_table(asset, node, "unreachable nodes do not have one unique lookup root")
    container = roots[0]
    if container.kind != "table":
        raise _unsupported_unreachable_table(asset, container, "lookup root is not a plain table")
    if container.asset_name != asset.key:
        raise _unsupported_unreachable_table(asset, container, "lookup root was not constructed in this asset")
    if not container.entries:
        raise _unsupported_unreachable_table(asset, container, "standalone empty table")

    try:
        _validate_lookup_table_history(
            container,
            where=f"{asset.key}:lookup@{container.created_at}",
            require_every_entry_read=False,
        )
    except SchemaRecoveryError as exc:
        raise _unsupported_unreachable_table(asset, container, str(exc)) from exc

    children: list[dict[str, Any]] = []
    seen_child_ids: set[int] = set()
    seen_field_ids: set[int] = set()
    empty_count = 0
    field_table_count = 0
    field_alias_count = 0
    expected_unreachable = {id(container)}
    active_root_keys: set[str | int] = set()

    for parent_key, child in sorted(container.entries.items(), key=lambda item: _table_key_order(item[0])):
        where = f"{asset.key}:lookup@{container.created_at}[{parent_key!r}]"
        if not isinstance(child, StaticTable) or child.kind != "table":
            raise _unsupported_unreachable_table(asset, container, f"{where} is not a plain child lookup table")
        if id(child) in seen_child_ids:
            raise _unsupported_unreachable_table(asset, container, f"{where} aliases a child table more than once")
        seen_child_ids.add(id(child))
        expected_unreachable.add(id(child))
        if id(child) not in table_ids:
            raise _unsupported_unreachable_table(asset, container, f"{where} points to an unregistered child table")
        if id(child) not in unreachable_ids:
            raise _unsupported_unreachable_table(asset, container, f"{where} child is also reachable outside the lookup container")
        if child.asset_name != asset.key:
            raise _unsupported_unreachable_table(asset, container, f"{where} child was constructed in another asset")
        parent_edges = parents[id(child)]
        if len(parent_edges) != 1 or parent_edges[0][0] is not container or parent_edges[0][1] != parent_key:
            raise _unsupported_unreachable_table(asset, container, f"{where} does not have one unique container parent")

        parent_reads = container.read_offsets.get(parent_key, ())
        if not isinstance(parent_reads, (list, tuple)):
            raise _unsupported_unreachable_table(asset, container, f"{where} has invalid parent read provenance")
        if child.entries:
            if not parent_reads:
                raise _unsupported_unreachable_table(asset, container, f"{where} is a non-empty child whose container key was never read")
            active_root_keys.add(parent_key)
            try:
                _checked_offsets(parent_reads, where=f"{where}.container_read_offsets", allow_empty=False)
                _validate_lookup_table_history(child, where=where, require_every_entry_read=True)
            except SchemaRecoveryError as exc:
                raise _unsupported_unreachable_table(asset, container, str(exc)) from exc

            alias_records: list[dict[str, Any]] = []
            for alias_key, descriptor in sorted(child.entries.items(), key=lambda item: _table_key_order(item[0])):
                if not isinstance(descriptor, StaticTable) or descriptor.kind != "FieldDescriptor":
                    raise _unsupported_unreachable_table(asset, container, f"{where}[{alias_key!r}] is not a FieldDescriptor leaf")
                if id(descriptor) not in field_ids:
                    raise _unsupported_unreachable_table(asset, container, f"{where}[{alias_key!r}] points to an unregistered FieldDescriptor")
                if descriptor.asset_name != asset.key:
                    raise _unsupported_unreachable_table(asset, container, f"{where}[{alias_key!r}] FieldDescriptor belongs to another asset")
                if id(descriptor) in seen_field_ids:
                    raise _unsupported_unreachable_table(asset, container, f"{where}[{alias_key!r}] duplicates a FieldDescriptor identity")
                seen_field_ids.add(id(descriptor))
                alias_records.append({
                    "key": alias_key,
                    "field_descriptor_created_at": descriptor.created_at,
                    "entry_offset": child.entry_offsets[alias_key],
                    "write_offsets": list(child.write_offsets[alias_key]),
                    "read_offsets": list(child.read_offsets[alias_key]),
                })
            field_table_count += 1
            field_alias_count += len(alias_records)
            classification = "field_lookup"
        else:
            if child.entry_offsets or child.write_offsets or child.read_offsets:
                raise _unsupported_unreachable_table(
                    asset,
                    container,
                    f"{where} looks empty after writes or reads; nil erasure and pseudo-empty tables are unsupported",
                )
            if parent_reads:
                raise _unsupported_unreachable_table(asset, container, f"{where} empty child was read and is not unused scaffolding")
            alias_records = []
            empty_count += 1
            classification = "unused_empty_lookup"

        children.append({
            "key": parent_key,
            "classification": classification,
            "child_created_at": child.created_at,
            "container_entry_offset": container.entry_offsets[parent_key],
            "container_write_offsets": list(container.write_offsets[parent_key]),
            "container_read_offsets": list(parent_reads),
            "entry_count": len(child.entries),
            "entry_offsets": alias_records,
        })

    if set(container.read_offsets) != active_root_keys:
        raise _unsupported_unreachable_table(
            asset,
            container,
            "container read trace contains a missing, stale, or unused child key",
        )
    if expected_unreachable != unreachable_ids:
        extra = min(
            (node for node in unreachable if id(node) not in expected_unreachable),
            key=lambda value: value.created_at,
        )
        raise _unsupported_unreachable_table(asset, extra, "node is outside the single-level lookup-container shape")

    return {
        "counts": {
            "lookup_containers": 1,
            "field_lookup_tables": field_table_count,
            "unused_empty_lookup": empty_count,
            "field_aliases": field_alias_count,
        },
        "lookup_containers": [{
            "created_at": container.created_at,
            "asset_name": asset.key,
            "entry_count": len(container.entries),
            "entry_offsets": children,
        }],
    }


def _resolve_export_descriptor(value: Any, *, where: str) -> StaticTable:
    if isinstance(value, MessageClass):
        descriptor = value.descriptor
        if isinstance(descriptor, StaticTable) and descriptor.kind == "Descriptor":
            return descriptor
    elif isinstance(value, StaticTable) and value.kind == "Descriptor":
        return value
    raise SchemaRecoveryError(f"{where}: referenced export is not a known message descriptor")


def _parse_field(
    field_descriptor: StaticTable,
    *,
    asset: _Asset,
    message: _Message,
    slot: int,
    descriptor_ids: set[int],
    table_ids: set[int],
) -> tuple[dict[str, Any], StaticTable | ExternalRef | None]:
    where = f"{asset.key}:{message.raw_full_name}.fields[{slot}]"
    if field_descriptor.kind != "FieldDescriptor":
        raise SchemaRecoveryError(f"{where}: fields table contains a non-FieldDescriptor value")
    _validate_entry_keys(field_descriptor, _FIELD_DESCRIPTOR_KEYS, where=where)

    name = _require_value(field_descriptor, "name", where=where)
    number = _require_value(field_descriptor, "number", where=where)
    type_code = _require_value(field_descriptor, "type", where=where)
    label_code = _require_value(field_descriptor, "label", where=where)
    index = _require_value(field_descriptor, "index", where=where)
    full_name = _require_value(field_descriptor, "full_name", where=where)
    has_default_value = _require_value(field_descriptor, "has_default_value", where=where)

    if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
        raise SchemaRecoveryError(f"{where}: invalid field name")
    if not isinstance(number, int) or isinstance(number, bool):
        raise SchemaRecoveryError(f"{where}: field number is not an integer")
    if number < 1 or number > (2**29) - 1 or 19_000 <= number <= 19_999:
        raise SchemaRecoveryError(f"{where}: illegal protobuf field number {number}")
    if not isinstance(type_code, int) or isinstance(type_code, bool):
        raise SchemaRecoveryError(f"{where}: descriptor type is not an integer")
    type_name = FIELD_TYPE_NAMES.get(type_code)
    if type_name is None:
        raise SchemaRecoveryError(f"{where}: unsupported protobuf descriptor type code {type_code}")
    if not isinstance(label_code, int) or isinstance(label_code, bool):
        raise SchemaRecoveryError(f"{where}: descriptor label is not an integer")
    label_name = FIELD_LABEL_NAMES.get(label_code)
    if label_name is None:
        raise SchemaRecoveryError(f"{where}: unsupported protobuf descriptor label code {label_code}")
    if not isinstance(index, int) or isinstance(index, bool) or index != slot - 1:
        raise SchemaRecoveryError(f"{where}: FieldDescriptor.index does not match its one-based fields slot")
    if not isinstance(full_name, str) or not _FULL_NAME.fullmatch(full_name):
        raise SchemaRecoveryError(f"{where}: invalid field full_name")
    if not isinstance(has_default_value, bool):
        raise SchemaRecoveryError(f"{where}: has_default_value is not boolean")
    if has_default_value and "default_value" not in field_descriptor.entries:
        raise SchemaRecoveryError(f"{where}: explicit default is declared without a default_value")

    raw_ref = field_descriptor.entries.get("message_type")
    if type_name == "message":
        if raw_ref is None:
            raise SchemaRecoveryError(f"{where}: message field is missing its message_type reference")
        if isinstance(raw_ref, MessageClass):
            target_descriptor = raw_ref.descriptor
            if not isinstance(target_descriptor, StaticTable) or target_descriptor.kind != "Descriptor":
                raise SchemaRecoveryError(f"{where}: local MessageClass does not resolve to a Descriptor")
            if id(target_descriptor) not in descriptor_ids:
                raise SchemaRecoveryError(f"{where}: local message reference points outside the recovered descriptors")
            reference: StaticTable | ExternalRef = target_descriptor
            reference_metadata: dict[str, Any] = {"kind": "local_descriptor"}
        elif isinstance(raw_ref, StaticTable) and raw_ref.kind == "Descriptor":
            if id(raw_ref) not in descriptor_ids:
                raise SchemaRecoveryError(f"{where}: local message reference points outside the recovered descriptors")
            reference = raw_ref
            reference_metadata = {"kind": "local_descriptor"}
        elif isinstance(raw_ref, ExternalRef):
            reference = raw_ref
            reference_metadata = {
                "kind": "external_module_symbol",
                "module": raw_ref.module,
                "symbol": raw_ref.name,
            }
        else:
            raise SchemaRecoveryError(f"{where}: message_type is not a known descriptor reference")
    else:
        if "message_type" in field_descriptor.entries:
            raise SchemaRecoveryError(f"{where}: non-message field contains a message_type reference")
        reference = None
        reference_metadata = None

    default_present = "default_value" in field_descriptor.entries
    default_table: StaticTable | None = None
    if default_present:
        raw_default_value = field_descriptor.entries["default_value"]
        if isinstance(raw_default_value, StaticTable):
            default_table = raw_default_value
            if label_name != "repeated":
                raise SchemaRecoveryError(f"{where}: static Lua table defaults are supported only for repeated fields")
            if default_table.kind != "table":
                raise SchemaRecoveryError(f"{where}: static Lua table default is not a plain table")
            if id(default_table) not in table_ids or default_table.asset_name != asset.key:
                raise SchemaRecoveryError(f"{where}: static Lua table default is not registered to this asset")
            if (
                default_table.entries
                or default_table.entry_offsets
                or default_table.write_offsets
                or default_table.read_offsets
            ):
                raise SchemaRecoveryError(
                    f"{where}: only a source-proven empty Lua table default is supported; non-empty or erased tables are unknown"
                )
            if (
                not isinstance(default_table.created_at, int)
                or isinstance(default_table.created_at, bool)
                or default_table.created_at < 0
                or default_table.created_at > (2**63) - 1
            ):
                raise SchemaRecoveryError(f"{where}: Lua table default has an invalid creation source offset")
            default_value: Any = {"kind": "lua_table", "entries": []}
        else:
            default_value = _json_scalar(raw_default_value, where=f"{where}.default_value")
    else:
        default_value = None
    cpp_type = field_descriptor.entries.get("cpp_type")
    if cpp_type is not None and (not isinstance(cpp_type, int) or isinstance(cpp_type, bool)):
        raise SchemaRecoveryError(f"{where}: cpp_type is not an integer")

    source_metadata: dict[str, Any] = {
        "bundle_sha256": asset.location.get("bundle_sha256"),
        "asset_name": asset.key,
        "asset_sha256": asset.asset_sha256,
        "asset_location": asset.location.get("asset_location"),
        "module": asset.analysis.namespace,
        "message_full_name": message.raw_full_name,
        "message_descriptor_byte_offset": message.descriptor.created_at,
        "field_descriptor_byte_offset": field_descriptor.created_at,
        "code_start_offset": asset.analysis.code_offset,
        "entry_offsets": _offset_map(field_descriptor),
        "entry_write_offsets": _write_offset_map(field_descriptor),
    }
    if default_table is not None:
        source_metadata["default_value_table"] = {
            "kind": "lua_table",
            "created_at": default_table.created_at,
            "entry_offsets": [],
            "write_offsets": [],
            "read_offsets": [],
        }

    field: dict[str, Any] = {
        "number": number,
        "name": name,
        "type": type_name,
        "label": label_name,
        "ref": None,
        "has_default_value": has_default_value,
        "default_value_present": default_present,
        "metadata": {
            "descriptor": {
                "raw_type_code": type_code,
                "raw_label_code": label_code,
                "cpp_type": cpp_type,
                "index": index,
                "full_name": full_name,
                "default_value": {"present": default_present, "value": default_value},
                "default_value_encoding": (
                    "tagged_lua_table_literal" if default_table is not None
                    else "json_scalar" if default_present
                    else None
                ),
                "has_default_value": has_default_value,
                "message_type": reference_metadata,
            },
            "source": source_metadata,
        },
    }
    if default_present:
        field["default_value"] = default_value
    return field, reference


def _get_bundle_sha256(extracted: Any) -> str:
    value = _read_member(extracted, "bundle_sha256")
    if value is None:
        value = _read_member(_read_member(extracted, "metadata", {}), "bundle_sha256")
    if not isinstance(value, str) or not _SHA256.fullmatch(value.lower()):
        raise SchemaRecoveryError("extracted bundle has no valid SHA-256 source identity")
    return value.lower()


def _prepare_assets(extracted: Any, limits: Limits) -> tuple[str, list[_Asset]]:
    bundle_sha256 = _get_bundle_sha256(extracted)
    raw_assets = _read_member(extracted, "protocol_assets")
    locations = _read_member(extracted, "asset_locations", {})
    if not isinstance(raw_assets, Mapping) or not raw_assets:
        raise SchemaRecoveryError("extracted bundle has no protocol_assets mapping")
    if len(raw_assets) > MAX_PROTOCOL_ASSETS:
        raise SchemaRecoveryError(f"protocol asset count exceeds {MAX_PROTOCOL_ASSETS}")

    normalized_locations: dict[str, Any] = {}
    if isinstance(locations, Mapping):
        for key, value in locations.items():
            if not isinstance(key, str):
                raise SchemaRecoveryError("asset location key is not a string")
            normalized = key.replace("\\", "/")
            if normalized in normalized_locations:
                raise SchemaRecoveryError(f"duplicate normalized asset location key {normalized!r}")
            normalized_locations[normalized] = value

    prepared: list[_Asset] = []
    seen_canonical: set[str] = set()
    aggregate_counts = {
        "protocol_bytes": 0,
        "messages": 0,
        "fields": 0,
        "static_nodes": 0,
        "instructions": 0,
    }
    aggregate_limits = {
        "messages": MAX_TOTAL_MESSAGES,
        "fields": MAX_TOTAL_FIELDS,
        "static_nodes": MAX_TOTAL_STATIC_NODES,
        "instructions": MAX_TOTAL_INSTRUCTIONS,
    }
    for key, raw_data in raw_assets.items():
        raw_key, basename, stem = _canonical_asset_name(key)
        canonical_key = raw_key.replace("\\", "/")
        folded = canonical_key.casefold()
        if folded in seen_canonical:
            raise SchemaRecoveryError(f"duplicate normalized protocol asset {canonical_key!r}")
        seen_canonical.add(folded)
        if not isinstance(raw_data, (bytes, bytearray, memoryview)):
            raise SchemaRecoveryError(f"{raw_key}: protocol asset content is not bytes")
        raw_size = raw_data.nbytes if isinstance(raw_data, memoryview) else len(raw_data)
        if raw_size > limits.max_asset_bytes:
            raise SchemaRecoveryError(f"{raw_key}: protocol asset exceeds the bytecode asset limit")
        next_total_bytes = aggregate_counts["protocol_bytes"] + raw_size
        if next_total_bytes > MAX_TOTAL_PROTOCOL_BYTES:
            raise SchemaRecoveryError(
                "aggregate protocol bytes exceed "
                f"{MAX_TOTAL_PROTOCOL_BYTES}: {next_total_bytes} > {MAX_TOTAL_PROTOCOL_BYTES}"
            )
        data = bytes(raw_data)
        if len(data) != raw_size:
            raise SchemaRecoveryError(f"{raw_key}: protocol asset byte length changed during conversion")
        aggregate_counts["protocol_bytes"] = next_total_bytes
        location_value = _get_location(normalized_locations, canonical_key, basename, stem)
        location = _clean_location(location_value, asset_name=raw_key)
        location = {
            "bundle_sha256": bundle_sha256,
            "asset_location": location,
        }
        try:
            result = analyze_asset(raw_key, data, limits)
        except (StaticAnalysisError, ValueError) as exc:
            raise SchemaRecoveryError(str(exc)) from exc
        module = _asset_module(result, stem)
        if result.code_offset < 0 or result.code_offset >= len(data):
            raise SchemaRecoveryError(f"{raw_key}: invalid bytecode code offset")
        _validate_return(result)

        try:
            asset_metrics = {
                "messages": len(result.created_message_classes),
                "fields": len(result.created_field_descriptors),
                "static_nodes": result.static_nodes,
                "instructions": result.instruction_count,
            }
        except (AttributeError, TypeError) as exc:
            raise SchemaRecoveryError(f"{raw_key}: static analysis result has invalid aggregate counters") from exc
        for metric, count in asset_metrics.items():
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise SchemaRecoveryError(f"{raw_key}: static analysis {metric} count is invalid")
            aggregate_counts[metric] += count
            maximum = aggregate_limits[metric]
            if aggregate_counts[metric] > maximum:
                raise SchemaRecoveryError(
                    f"aggregate {metric.replace('_', ' ')} exceed {maximum}: "
                    f"{aggregate_counts[metric]} > {maximum} after {raw_key}"
                )
        prepared.append(
            _Asset(
                key=raw_key,
                canonical_name=basename,
                stem=stem,
                data=data,
                asset_sha256=hashlib.sha256(data).hexdigest(),
                location=location,
                analysis=result,
            )
        )

    prepared.sort(key=lambda asset: (asset.analysis.namespace.casefold(), asset.key.casefold()))
    if len({asset.analysis.namespace.casefold() for asset in prepared}) != len(prepared):
        raise SchemaRecoveryError("protocol module namespaces are not unique")
    return bundle_sha256, prepared


def _validate_import_closure(assets: list[_Asset]) -> dict[str, _Asset]:
    by_require_path: dict[str, _Asset] = {}
    for asset in assets:
        require_path = f"protocol/{asset.stem}"
        if require_path in by_require_path:
            raise SchemaRecoveryError(f"duplicate module require path {require_path!r}")
        by_require_path[require_path] = asset

    for asset in assets:
        required_paths: set[str] = set()
        for required in asset.analysis.required_modules:
            if not isinstance(required, str):
                raise SchemaRecoveryError(f"{asset.key}: required module path is not a string")
            normalized = _module_require_path(required, source_asset=asset.key)
            if normalized is None:
                continue
            required_paths.add(normalized)
            if normalized not in by_require_path:
                raise SchemaRecoveryError(f"{asset.key}: required protocol module {normalized!r} is absent")
        for descriptor in asset.analysis.created_field_descriptors:
            reference = descriptor.entries.get("message_type")
            if isinstance(reference, ExternalRef):
                normalized = _module_require_path(reference.module, source_asset=asset.key)
                if normalized is None or normalized not in required_paths:
                    raise SchemaRecoveryError(
                        f"{asset.key}: external message reference is not backed by a literal require"
                    )
    return by_require_path


def _validate_construction_graph(assets: list[_Asset]) -> dict[str, dict[str, Any]]:
    helper_reports: dict[str, dict[str, Any]] = {}
    for asset in assets:
        result = asset.analysis
        table_ids = {id(node) for node in result.created_tables}
        descriptor_ids = {id(node) for node in result.created_descriptors}
        field_ids = {id(node) for node in result.created_field_descriptors}
        message_ids = {id(node) for node in result.created_message_classes}
        registered_node_count = len(result.created_tables) + len(result.created_message_classes)
        if result.static_nodes != registered_node_count:
            raise SchemaRecoveryError(
                f"{asset.key}: static node registry accounts for {registered_node_count} nodes, "
                f"but analysis recorded {result.static_nodes}"
            )
        if len(table_ids) != len(result.created_tables):
            raise SchemaRecoveryError(f"{asset.key}: duplicate static table construction node registration")
        if not descriptor_ids.issubset(table_ids) or not field_ids.issubset(table_ids):
            raise SchemaRecoveryError(f"{asset.key}: Descriptor/FieldDescriptor is absent from the static table registry")
        if len(descriptor_ids) != len(result.created_descriptors):
            raise SchemaRecoveryError(f"{asset.key}: duplicate Descriptor construction node registration")
        if len(field_ids) != len(result.created_field_descriptors):
            raise SchemaRecoveryError(f"{asset.key}: duplicate FieldDescriptor construction node registration")
        if len(message_ids) != len(result.created_message_classes):
            raise SchemaRecoveryError(f"{asset.key}: duplicate Message construction node registration")
        if any(node.kind != "Descriptor" for node in result.created_descriptors):
            raise SchemaRecoveryError(f"{asset.key}: descriptor registry contains a non-Descriptor table")
        if any(node.kind != "FieldDescriptor" for node in result.created_field_descriptors):
            raise SchemaRecoveryError(f"{asset.key}: field registry contains a non-FieldDescriptor table")

        exported_messages = Counter(
            id(value) for value in result.exports.values() if isinstance(value, MessageClass)
        )
        for value in result.exports.values():
            if isinstance(value, MessageClass) and id(value) not in message_ids:
                raise SchemaRecoveryError(f"{asset.key}: module exports an unregistered Message constructor result")
            if isinstance(value, StaticTable) and value.kind in ("Descriptor", "FieldDescriptor"):
                if value.kind == "Descriptor" and id(value) not in descriptor_ids:
                    raise SchemaRecoveryError(f"{asset.key}: module exports an unregistered Descriptor node")
                if value.kind == "FieldDescriptor" and id(value) not in field_ids:
                    raise SchemaRecoveryError(f"{asset.key}: module exports an unregistered FieldDescriptor node")

        descriptor_owners: Counter[int] = Counter()
        for message_class in result.created_message_classes:
            if exported_messages[id(message_class)] != 1:
                raise SchemaRecoveryError(
                    f"{asset.key}: constructed Message is not exported exactly once; possible discarded CALL result"
                )
            descriptor = message_class.descriptor
            if not isinstance(descriptor, StaticTable) or descriptor.kind != "Descriptor":
                raise SchemaRecoveryError(f"{asset.key}: Message constructor does not reference a local Descriptor")
            if id(descriptor) not in descriptor_ids:
                raise SchemaRecoveryError(f"{asset.key}: Message constructor references an unregistered Descriptor")
            descriptor_owners[id(descriptor)] += 1
        if any(descriptor_owners[id(node)] != 1 for node in result.created_descriptors):
            raise SchemaRecoveryError(f"{asset.key}: every Descriptor must belong to exactly one Message")

        field_owners: Counter[int] = Counter()
        for descriptor in result.created_descriptors:
            fields = descriptor.entries.get("fields")
            if not isinstance(fields, StaticTable):
                raise SchemaRecoveryError(f"{asset.key}: Descriptor.fields is not a static table")
            for value in fields.entries.values():
                if not isinstance(value, StaticTable) or value.kind != "FieldDescriptor":
                    raise SchemaRecoveryError(f"{asset.key}: Descriptor.fields contains an unknown node")
                if id(value) not in field_ids:
                    raise SchemaRecoveryError(f"{asset.key}: Descriptor.fields references an unregistered field")
                field_owners[id(value)] += 1
        if any(field_owners[id(node)] != 1 for node in result.created_field_descriptors):
            raise SchemaRecoveryError(
                f"{asset.key}: every constructed FieldDescriptor must be owned by exactly one Descriptor.fields"
            )

        reachable: set[int] = set()
        for export_name, value in sorted(result.exports.items()):
            offsets = result.global_write_offsets.get(export_name)
            if not offsets:
                raise SchemaRecoveryError(f"{asset.key}: export {export_name!r} has no source write offset")
            _walk_supported_value(
                value,
                where=f"{asset.key}.exports[{export_name!r}]",
                local_tables=table_ids,
                local_messages=message_ids,
                visited=reachable,
            )
        helper_reports[asset.key] = _classify_lookup_helpers(
            asset,
            result,
            reachable=reachable,
            table_ids=table_ids,
            field_ids=field_ids,
        )
    return helper_reports


def _build_messages(assets: list[_Asset]) -> tuple[list[_Message], dict[int, _Message]]:
    messages: list[_Message] = []
    by_descriptor_id: dict[int, _Message] = {}
    by_output_name: set[str] = set()

    for asset in assets:
        result = asset.analysis
        for message_class in result.created_message_classes:
            descriptor = message_class.descriptor
            if not isinstance(descriptor, StaticTable) or descriptor.kind != "Descriptor":
                raise SchemaRecoveryError(f"{asset.key}: Message points to an unsupported Descriptor")
            _validate_entry_keys(descriptor, _DESCRIPTOR_KEYS, where=f"{asset.key}.Descriptor")
            short_name = _require_value(descriptor, "name", where=f"{asset.key}.Descriptor")
            raw_full_name = _require_value(descriptor, "full_name", where=f"{asset.key}.Descriptor")
            fields_table = _require_value(descriptor, "fields", where=f"{asset.key}.Descriptor")
            is_extendable = _require_value(descriptor, "is_extendable", where=f"{asset.key}.Descriptor")
            if not isinstance(short_name, str) or not _IDENTIFIER.fullmatch(short_name):
                raise SchemaRecoveryError(f"{asset.key}: Descriptor.name is not a valid identifier")
            if not isinstance(raw_full_name, str) or not _FULL_NAME.fullmatch(raw_full_name):
                raise SchemaRecoveryError(f"{asset.key}: Descriptor.full_name is invalid")
            if not isinstance(fields_table, StaticTable):
                raise SchemaRecoveryError(f"{asset.key}: Descriptor.fields is not a static table")
            if not isinstance(is_extendable, bool):
                raise SchemaRecoveryError(f"{asset.key}: Descriptor.is_extendable is not boolean")
            if is_extendable:
                raise SchemaRecoveryError(f"{asset.key}: extendable messages are outside the schema subset")
            for key in ("enum_types", "extensions", "nested_types"):
                _table_is_empty(_require_value(descriptor, key, where=f"{asset.key}.Descriptor"), where=f"{asset.key}.{raw_full_name}.{key}")

            output_name = f"{result.namespace.lower()}.{short_name.lower()}"
            if output_name in by_output_name:
                raise SchemaRecoveryError(f"duplicate canonical message name {output_name!r}")
            by_output_name.add(output_name)
            exports = [
                name for name, value in result.exports.items()
                if value is message_class
            ]
            if len(exports) != 1:
                raise SchemaRecoveryError(f"{asset.key}: Message export identity is not unique")
            message = _Message(
                asset=asset,
                message_class=message_class,
                descriptor=descriptor,
                export_name=exports[0],
                short_name=short_name,
                raw_full_name=raw_full_name,
                output_name=output_name,
                fields_table=fields_table,
            )
            if id(descriptor) in by_descriptor_id:
                raise SchemaRecoveryError(f"{asset.key}: one Descriptor maps to multiple output Messages")
            by_descriptor_id[id(descriptor)] = message
            messages.append(message)

    messages.sort(key=lambda item: item.output_name)
    return messages, by_descriptor_id


def _message_reference_target(
    reference: StaticTable | ExternalRef,
    *,
    source: _Asset,
    by_require_path: Mapping[str, _Asset],
    by_descriptor_id: Mapping[int, _Message],
) -> tuple[_Message, dict[str, Any]]:
    if isinstance(reference, StaticTable):
        target = by_descriptor_id.get(id(reference))
        if target is None:
            raise SchemaRecoveryError(f"{source.key}: local message reference is not in the recovered schema")
        return target, {
            "kind": "local_descriptor",
            "module": target.asset.analysis.namespace,
            "short_name": target.short_name,
            "full_name": target.raw_full_name,
        }

    require_path = _module_require_path(reference.module, source_asset=source.key)
    if require_path is None:
        raise SchemaRecoveryError(f"{source.key}: protobuf runtime symbol cannot be used as a message type")
    target_asset = by_require_path.get(require_path)
    if target_asset is None:
        raise SchemaRecoveryError(f"{source.key}: external message module {require_path!r} is unresolved")
    if reference.module not in source.analysis.required_modules:
        raise SchemaRecoveryError(f"{source.key}: external message symbol is not imported by a literal require")
    if reference.name not in target_asset.analysis.exports:
        raise SchemaRecoveryError(
            f"{source.key}: external message symbol {reference.name!r} is absent from {require_path!r}"
        )
    target_descriptor = _resolve_export_descriptor(
        target_asset.analysis.exports[reference.name],
        where=f"{source.key}:{reference.module}.{reference.name}",
    )
    target = by_descriptor_id.get(id(target_descriptor))
    if target is None:
        raise SchemaRecoveryError(f"{source.key}: external export resolves to an unregistered Descriptor")
    return target, {
        "kind": "external_module_symbol",
        "module": reference.module,
        "symbol": reference.name,
        "target_module": target.asset.analysis.namespace,
        "target_short_name": target.short_name,
        "target_full_name": target.raw_full_name,
    }


def build_schema(extracted: Any, limits: Limits = Limits()) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(schema, report)`` after a closed, deterministic static recovery.

    ``extracted`` must expose ``bundle_sha256``, ``protocol_assets`` and
    ``asset_locations``. No source paths or bytecode contents are emitted.
    """
    try:
        bundle_sha256, assets = _prepare_assets(extracted, limits)
        by_require_path = _validate_import_closure(assets)
        helper_reports = _validate_construction_graph(assets)
        messages, by_descriptor_id = _build_messages(assets)
        descriptor_ids = set(by_descriptor_id)
        table_ids_by_asset = {
            asset.key: {id(node) for node in asset.analysis.created_tables}
            for asset in assets
        }
        total_fields = 0
        message_documents: list[dict[str, Any]] = []
        pending_references: list[tuple[dict[str, Any], StaticTable | ExternalRef, _Asset]] = []
        message_reference_count = 0

        for message in messages:
            descriptor = message.descriptor
            asset = message.asset
            entries = message.fields_table.entries
            expected_slots = list(range(1, len(entries) + 1))
            actual_slots = sorted(entries)
            if actual_slots != expected_slots:
                raise SchemaRecoveryError(
                    f"{asset.key}:{message.raw_full_name}: fields table indices are not dense 1..N"
                )

            seen_names: set[str] = set()
            seen_numbers: set[int] = set()
            field_documents: list[dict[str, Any]] = []
            for slot in expected_slots:
                field_descriptor = entries[slot]
                field_document, reference = _parse_field(
                    field_descriptor,
                    asset=asset,
                    message=message,
                    slot=slot,
                    descriptor_ids=descriptor_ids,
                    table_ids=table_ids_by_asset[asset.key],
                )
                if field_document["name"] in seen_names:
                    raise SchemaRecoveryError(
                        f"{asset.key}:{message.raw_full_name}: duplicate field name {field_document['name']!r}"
                    )
                if field_document["number"] in seen_numbers:
                    raise SchemaRecoveryError(
                        f"{asset.key}:{message.raw_full_name}: duplicate field number {field_document['number']}"
                    )
                seen_names.add(field_document["name"])
                seen_numbers.add(field_document["number"])
                if reference is not None:
                    message_reference_count += 1
                    pending_references.append((field_document, reference, asset))
                field_documents.append(field_document)

            field_documents.sort(key=lambda field: (field["number"], field["name"]))
            total_fields += len(field_documents)
            direction = _source_direction(message.short_name)
            export_offsets = list(asset.analysis.global_write_offsets.get(message.export_name, ()))
            document = {
                "name": message.output_name,
                "fields": field_documents,
                "metadata": {
                    "source_module": asset.analysis.namespace,
                    "short_name": message.short_name,
                    "raw_full_name": message.raw_full_name,
                    "is_extendable": descriptor.entries["is_extendable"],
                    "enum_type_count": len(descriptor.entries["enum_types"].entries),
                    "extension_count": len(descriptor.entries["extensions"].entries),
                    "nested_type_count": len(descriptor.entries["nested_types"].entries),
                    "command_mapping": direction,
                },
                "source": {
                    "bundle_sha256": bundle_sha256,
                    "asset_name": asset.key,
                    "asset_sha256": asset.asset_sha256,
                    "asset_location": asset.location["asset_location"],
                    "module": asset.analysis.namespace,
                    "raw_full_name": message.raw_full_name,
                    "descriptor_byte_offset": descriptor.created_at,
                    "message_call_byte_offset": message.message_class.created_at,
                    "message_export_name": message.export_name,
                    "message_export_write_offsets": export_offsets,
                    "code_start_offset": asset.analysis.code_offset,
                    "descriptor_entry_offsets": _offset_map(descriptor),
                    "descriptor_entry_write_offsets": _write_offset_map(descriptor),
                    "fields_entry_offsets": _offset_map(message.fields_table),
                },
            }
            message_documents.append(document)

        for field_document, reference, source_asset in pending_references:
            target, reference_metadata = _message_reference_target(
                reference,
                source=source_asset,
                by_require_path=by_require_path,
                by_descriptor_id=by_descriptor_id,
            )
            field_document["ref"] = target.output_name
            field_document["metadata"]["descriptor"]["message_type"] = reference_metadata
            field_document["metadata"]["source"]["reference_target"] = {
                "module": target.asset.analysis.namespace,
                "short_name": target.short_name,
                "raw_full_name": target.raw_full_name,
                "schema_name": target.output_name,
            }

        # Validate the final core shape exactly as consumed by desktop/schema.ts.
        final_names: set[str] = set()
        final_targets: set[str] = {message["name"] for message in message_documents}
        for message in message_documents:
            name = message["name"]
            if not isinstance(name, str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name
            ):
                raise SchemaRecoveryError(f"invalid canonical schema message name {name!r}")
            normalized = name.strip().lstrip(".").lower()
            if normalized in final_names:
                raise SchemaRecoveryError(f"duplicate normalized schema message name {normalized!r}")
            final_names.add(normalized)
            for field in message["fields"]:
                if field["type"] == "message" and field["ref"] not in final_targets:
                    raise SchemaRecoveryError(
                        f"{name}.{field['name']} references missing schema message {field['ref']!r}"
                    )

        schema = {
            "metadata": {
                "format": "alpha-persei-static-protocol-schema-v1",
                "bundle_sha256": bundle_sha256,
                "protocol_asset_count": len(assets),
                "message_count": len(message_documents),
                "field_count": total_fields,
                "evidence": "static_luajit_declaration_recovery_only",
                "runtime_test_performed": False,
                "compatibility_admitted": False,
            },
            "messages": message_documents,
        }
        asset_report = []
        total_helper_counts = {
            "lookup_containers": 0,
            "field_lookup_tables": 0,
            "unused_empty_lookup": 0,
            "field_aliases": 0,
        }
        for asset in assets:
            result = asset.analysis
            construction_helpers = helper_reports[asset.key]
            for key in total_helper_counts:
                total_helper_counts[key] += construction_helpers["counts"][key]
            asset_report.append({
                "asset_name": asset.key,
                "module": result.namespace,
                "asset_sha256": asset.asset_sha256,
                "asset_location": asset.location["asset_location"],
                "required_modules": list(result.required_modules),
                "message_count": len(result.created_message_classes),
                "field_count": len(result.created_field_descriptors),
                "instruction_count": result.instruction_count,
                "code_start_offset": result.code_offset,
                "static_node_count": result.static_nodes,
                "static_table_entry_count": result.static_table_entries,
                "call_counts": result.call_counts,
                "construction_helpers": construction_helpers,
            })
        report = {
            "source": {
                "bundle_sha256": bundle_sha256,
                "protocol_asset_count": len(assets),
            },
            "assets": asset_report,
            "construction_helper_counts": total_helper_counts,
            "message_count": len(message_documents),
            "field_count": total_fields,
            "message_reference_count": message_reference_count,
            "resolved_message_reference_count": message_reference_count,
            "static_declaration_recovery": True,
            "runtime_test_performed": False,
            "compatibility_admitted": False,
        }
        return schema, report
    except SchemaRecoveryError:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, StaticAnalysisError) as exc:
        raise SchemaRecoveryError(f"schema recovery failed closed: {type(exc).__name__}: {exc}") from exc
