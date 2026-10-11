from __future__ import annotations

import hashlib
import json
import struct
import unittest
from dataclasses import replace
from unittest.mock import patch

from v5_server.tools.static_protocol import bytecode, schema_ir, static_vm
from v5_server.tools.static_protocol.bytecode import (
    BytecodeDump,
    BytecodeError,
    Instruction,
    KNum,
    Limits,
    Prototype,
    parse_dump,
)
from v5_server.tools.static_protocol.static_vm import (
    AnalysisResult,
    ExternalRef,
    MessageClass,
    StaticAnalysisError,
    StaticTable,
    Symbol,
    _AnalysisBudget,
    _AnalysisContext,
    analyze_asset,
)


def _uleb(value: int) -> bytes:
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _word(opcode: str, a: int = 0, b: int = 0, c: int = 0, d: int | None = None) -> int:
    op = bytecode.OPCODE_NAMES.index(opcode)
    if d is None:
        return op | (a << 8) | (c << 16) | (b << 24)
    return op | (a << 8) | ((d & 0xFFFF) << 16)


def _dump(
    words: list[int],
    *,
    strings: tuple[bytes, ...] = (),
    framesize: int = 8,
    dump_flags: int = 0x0A,
) -> bytes:
    proto = bytearray((0, 0, framesize, 0))
    proto.extend(_uleb(len(strings)))
    proto.extend(_uleb(0))
    proto.extend(_uleb(len(words)))
    for word in words:
        proto.extend(struct.pack("<I", word))
    for value in strings:
        proto.extend(_uleb(len(value) + 5))
        proto.extend(value)
    return b"\x1bLJ\x02" + _uleb(dump_flags) + _uleb(len(proto)) + bytes(proto) + b"\x00"


def _fake_result(
    asset_name: str,
    namespace: str,
    message_specs: list[dict[str, object]],
    *,
    required_modules: tuple[str, ...] = ("protobuf",),
    extra_exports: dict[str, object] | None = None,
    orphan_descriptors: int = 0,
    orphan_fields: int = 0,
    orphan_tables: int = 0,
) -> AnalysisResult:
    limits = Limits()
    context = _AnalysisContext(
        asset_name,
        limits,
        _AnalysisBudget(limits.max_static_nodes_per_asset, limits.max_static_table_entries_per_asset),
    )
    exports: dict[str, object] = {}
    assigned_globals: dict[str, object] = {}
    global_offsets: dict[str, tuple[int, ...]] = {}

    for message_index, spec in enumerate(message_specs):
        base = 10 + message_index * 100
        descriptor = context.new_table("Descriptor", base)
        fields = context.new_table("table", base + 1)
        empty_enum_types = context.new_table("table", base + 2)
        empty_extensions = context.new_table("table", base + 3)
        empty_nested = context.new_table("table", base + 4)
        descriptor.set("name", spec["name"], offset=base + 5)
        descriptor.set("full_name", spec.get("full_name", ".pkg." + str(spec["name"])), offset=base + 6)
        descriptor.set("fields", fields, offset=base + 7)
        descriptor.set("is_extendable", False, offset=base + 8)
        descriptor.set("enum_types", empty_enum_types, offset=base + 9)
        descriptor.set("extensions", empty_extensions, offset=base + 10)
        descriptor.set("nested_types", empty_nested, offset=base + 11)

        message_class = context.new_message_class(descriptor, base + 12)
        export_name = str(spec.get("export_name", spec["name"]))
        exports[export_name] = message_class
        assigned_globals[export_name] = message_class
        global_offsets[export_name] = (base + 13,)

        for slot, field_spec in enumerate(spec.get("fields", []), start=1):
            field_descriptor = context.new_table("FieldDescriptor", base + 20 + slot)
            field_name = str(field_spec["name"])
            field_number = int(field_spec["number"])
            field_type = int(field_spec.get("type", 13))
            field_label = int(field_spec.get("label", 1))
            field_descriptor.set("name", field_name, offset=base + 30 + slot)
            field_descriptor.set("number", field_number, offset=base + 31 + slot)
            field_descriptor.set("type", field_type, offset=base + 32 + slot)
            field_descriptor.set("label", field_label, offset=base + 33 + slot)
            field_descriptor.set("index", slot - 1, offset=base + 34 + slot)
            field_descriptor.set("full_name", f".pkg.{spec['name']}.{field_name}", offset=base + 35 + slot)
            field_descriptor.set("has_default_value", bool(field_spec.get("has_default_value", False)), offset=base + 36 + slot)
            field_descriptor.set("cpp_type", int(field_spec.get("cpp_type", 3)), offset=base + 37 + slot)
            if field_spec.get("default_present", True):
                field_descriptor.set("default_value", field_spec.get("default_value", 0), offset=base + 38 + slot)
            if "message_type" in field_spec:
                field_descriptor.set("message_type", field_spec["message_type"], offset=base + 39 + slot)
            fields.set(slot, field_descriptor, offset=base + 40 + slot)

    for index in range(orphan_descriptors):
        context.new_table("Descriptor", 50_000 + index)
    for index in range(orphan_fields):
        context.new_table("FieldDescriptor", 60_000 + index)
    for index in range(orphan_tables):
        context.new_table("table", 70_000 + index)

    if extra_exports:
        for key, value in extra_exports.items():
            exports[key] = value
            assigned_globals[key] = value
            global_offsets[key] = (90_000,)

    return AnalysisResult(
        asset_name=asset_name,
        namespace=namespace,
        code_offset=4,
        exports=exports,
        required_modules=required_modules,
        call_counts={"protobuf.Descriptor": len(message_specs)},
        instruction_count=30,
        assigned_globals=assigned_globals,
        global_write_offsets=global_offsets,
        created_tables=tuple(context.created_tables),
        created_descriptors=tuple(context.descriptors),
        created_field_descriptors=tuple(context.field_descriptors),
        created_message_classes=tuple(context.message_classes),
        return_values=(Symbol("global", (namespace,)),),
        static_nodes=context.budget.nodes,
        static_table_entries=context.budget.entries,
    )


def _extracted(
    assets: dict[str, bytes],
    results: dict[str, AnalysisResult],
    *,
    locations: dict[str, object] | None = None,
) -> dict[str, object]:
    location_map = locations or {
        name: {
            "source_entry": "scripts64|sample|1",
            "object": "TextAsset",
            "path_id": index + 101,
            "byte_start": index * 16,
            "byte_size": 16,
        }
        for index, name in enumerate(assets)
    }
    return {
        "bundle_sha256": "a" * 64,
        "protocol_assets": assets,
        "asset_locations": location_map,
        "metadata": {"source_kind": "unit-test"},
        "_results": results,
    }


def _attach_lookup_helper(
    result: AnalysisResult,
    child_specs: list[dict[str, object]],
    *,
    root_offset: int = 100_000,
) -> AnalysisResult:
    if not result.created_tables:
        raise AssertionError("lookup helper fixture requires at least one existing table")
    budget = result.created_tables[0].budget
    limits = result.created_tables[0].limits
    created: list[StaticTable] = []

    def new_table(offset: int) -> StaticTable:
        budget.add_node(result.asset_name, offset, "table")
        table = StaticTable("table", offset, result.asset_name, budget, limits)
        created.append(table)
        return table

    root = new_table(root_offset)
    built_children: list[StaticTable] = []
    for child_index, spec in enumerate(child_specs):
        key = str(spec.get("key", f"lookup_{child_index}"))
        parent_offset = root_offset + 1 + child_index
        if "value" in spec:
            root.set(key, spec["value"], offset=parent_offset)
            if spec.get("root_read", False):
                static_vm._get(root, key, asset=result.asset_name, offset=parent_offset + 50)
            continue

        if "reuse" in spec:
            child = built_children[int(spec["reuse"])]
        else:
            child = new_table(root_offset + 100 + child_index * 100)
            built_children.append(child)
            for entry_index, (alias, field_index) in enumerate(spec.get("fields", [])):
                entry_offset = root_offset + 110 + child_index * 100 + entry_index
                if field_index == "nested":
                    value = new_table(entry_offset + 50)
                else:
                    value = result.created_field_descriptors[int(field_index)]
                child.set(str(alias), value, offset=entry_offset)
                unread_aliases = set(spec.get("unread_aliases", set()))
                if str(alias) not in unread_aliases:
                    static_vm._get(child, str(alias), asset=result.asset_name, offset=entry_offset + 25)
            if spec.get("pseudoempty", False):
                child.set("discarded", None, offset=root_offset + 190 + child_index * 100)

        root.set(key, child, offset=parent_offset)
        default_root_read = bool(spec.get("fields"))
        if spec.get("root_read", default_root_read):
            static_vm._get(root, key, asset=result.asset_name, offset=parent_offset + 50)

    created_tables = (*result.created_tables, *created)
    return replace(
        result,
        created_tables=created_tables,
        static_nodes=budget.nodes,
        static_table_entries=budget.entries,
    )


def _attach_lua_table_default(
    result: AnalysisResult,
    *,
    field_index: int = 0,
    created_at: int = 200_000,
    nonempty: bool = False,
    pseudoempty: bool = False,
) -> tuple[AnalysisResult, StaticTable]:
    budget = result.created_tables[0].budget
    limits = result.created_tables[0].limits
    budget.add_node(result.asset_name, created_at, "table")
    table = StaticTable("table", created_at, result.asset_name, budget, limits)
    if nonempty:
        table.set("item", 1, offset=created_at + 1)
    elif pseudoempty:
        table.set("item", None, offset=created_at + 1)
    result.created_field_descriptors[field_index].set("default_value", table, offset=created_at + 2)
    return (
        replace(
            result,
            created_tables=(*result.created_tables, table),
            static_nodes=budget.nodes,
            static_table_entries=budget.entries,
        ),
        table,
    )


class BytecodeReaderTests(unittest.TestCase):
    def test_tagged_uleb33_masks_first_payload_and_reads_128(self) -> None:
        reader = bytecode._Reader(b"\x80\x02")
        self.assertEqual(reader.uleb33(), (False, 128))

    def test_constant_table_float_uses_two_ordinary_ulebs(self) -> None:
        reader = bytecode._Reader(_uleb(4) + _uleb(0) + _uleb(0x3FF80000))
        value = bytecode._read_ktab_value(reader, Limits(), bytecode._Budget())
        self.assertIsInstance(value, KNum)
        self.assertEqual(value.value, 1.5)

    def test_truncated_dump_is_rejected(self) -> None:
        with self.assertRaisesRegex(BytecodeError, "truncated"):
            parse_dump(b"\x1bLJ")

    def test_wrong_dump_flags_are_rejected(self) -> None:
        with self.assertRaisesRegex(BytecodeError, "unsupported dump flags"):
            parse_dump(_dump([_word("RET0")], dump_flags=0x02))

    def test_unknown_opcode_is_rejected(self) -> None:
        with self.assertRaisesRegex(BytecodeError, "unknown opcode number 255"):
            parse_dump(_dump([255]))

    def test_instruction_budget_is_checked_before_reading_code(self) -> None:
        with self.assertRaisesRegex(BytecodeError, "instruction count exceeds"):
            parse_dump(_dump([_word("RET0")]), limits=Limits(max_instructions_per_proto=0))


class StaticVmTests(unittest.TestCase):
    def test_tsetb_preserves_lua_integer_key(self) -> None:
        strings = (b"module", b"p10_pb", b"holder", b"_M")
        d = {value: len(strings) - 1 - index for index, value in enumerate(strings)}
        chunk = _dump(
            [
                _word("GGET", a=0, d=d[b"module"]),
                _word("KSTR", a=2, d=d[b"p10_pb"]),
                _word("CALL", a=0, b=2, c=2),
                _word("TNEW", a=3),
                _word("KSHORT", a=4, d=42),
                _word("TSETB", a=4, b=3, c=1),
                _word("GSET", a=3, d=d[b"holder"]),
                _word("GGET", a=5, d=d[b"p10_pb"]),
                _word("RET1", a=5),
            ],
            strings=strings,
            framesize=6,
        )
        result = analyze_asset("p10_pb.lua", chunk)
        holder = result.exports["holder"]
        self.assertIsInstance(holder, StaticTable)
        self.assertEqual(holder.entries, {1: 42})
        self.assertNotIn(0, holder.entries)
        self.assertNotIn(2, holder.entries)

    def test_gset_register_must_be_inside_frame(self) -> None:
        proto = Prototype(
            flags=0,
            numparams=0,
            framesize=3,
            upvalue_count=0,
            code_offset=7,
            instructions=(
                Instruction(0, 7, "GSET", 3, 0, 0, 0),
                Instruction(1, 11, "RET0", 0, 0, 0, 0),
            ),
            gc_constants=(b"name",),
            number_constants=(),
        )
        with patch.object(static_vm, "parse_dump", return_value=BytecodeDump(0x0A, (proto,))):
            with self.assertRaisesRegex(StaticAnalysisError, "register 3 is outside frame size 3"):
                analyze_asset("m_pb.lua", b"synthetic")

    def test_unknown_opcode_semantics_fail_closed(self) -> None:
        proto = Prototype(
            flags=0,
            numparams=0,
            framesize=1,
            upvalue_count=0,
            code_offset=7,
            instructions=(Instruction(0, 7, "TSETM", 0, 0, 0, 0),),
            gc_constants=(),
            number_constants=(),
        )
        with patch.object(static_vm, "parse_dump", return_value=BytecodeDump(0x0A, (proto,))):
            with self.assertRaisesRegex(StaticAnalysisError, "unsupported opcode TSETM"):
                analyze_asset("m_pb.lua", b"synthetic")

    def test_nil_table_assignment_removes_presence(self) -> None:
        limits = Limits()
        budget = _AnalysisBudget(limits.max_static_nodes_per_asset, limits.max_static_table_entries_per_asset)
        table = StaticTable("table", 0, "m_pb.lua", budget, limits)
        table.set("default_value", 0, offset=1)
        table.set("default_value", None, offset=2)
        self.assertNotIn("default_value", table.entries)
        self.assertNotIn("default_value", table.entry_offsets)
        self.assertEqual(table.write_offsets["default_value"], [1, 2])

    def test_static_table_reads_are_recorded_separately_from_writes(self) -> None:
        limits = Limits()
        budget = _AnalysisBudget(limits.max_static_nodes_per_asset, limits.max_static_table_entries_per_asset)
        table = StaticTable("table", 0, "m_pb.lua", budget, limits)
        table.set("key", 7, offset=1)
        self.assertEqual(static_vm._get(table, "key", asset="m_pb.lua", offset=2), 7)
        self.assertEqual(table.write_offsets["key"], [1])
        self.assertEqual(table.read_offsets["key"], [2])


class SchemaIrTests(unittest.TestCase):
    def _build(self, assets: dict[str, bytes], results: dict[str, AnalysisResult]):
        extracted = _extracted(assets, results)
        with patch.object(schema_ir, "analyze_asset", side_effect=lambda name, _data, _limits: results[name]):
            return schema_ir.build_schema(extracted)

    def test_all_message_names_are_module_qualified_and_defaults_are_preserved(self) -> None:
        name = "protocol/p10_pb.lua"
        result = _fake_result(
            name,
            "p10_pb",
            [{
                "name": "cs_10038",
                "fields": [{"name": "channel_id", "number": 1, "type": 13, "label": 2,
                            "has_default_value": False, "default_value": 0}],
            }],
        )
        schema, report = self._build({name: b"asset bytes"}, {name: result})
        message = schema["messages"][0]
        field = message["fields"][0]
        self.assertEqual(message["name"], "p10_pb.cs_10038")
        self.assertEqual(field["type"], "uint32")
        self.assertEqual(field["label"], "required")
        self.assertFalse(field["has_default_value"])
        self.assertTrue(field["default_value_present"])
        self.assertEqual(field["default_value"], 0)
        self.assertEqual(report["runtime_test_performed"], False)
        self.assertEqual(report["compatibility_admitted"], False)

    def test_repeated_empty_lua_table_default_is_tagged_and_source_located(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{
                "name": "items", "number": 1, "type": 13, "label": 3,
                "has_default_value": False, "default_present": False,
            }]}],
        )
        result, default_table = _attach_lua_table_default(result)

        schema, _ = self._build({name: b"bytes"}, {name: result})

        field = schema["messages"][0]["fields"][0]
        tagged_default = {"kind": "lua_table", "entries": []}
        self.assertEqual(field["default_value"], tagged_default)
        self.assertTrue(field["default_value_present"])
        self.assertFalse(field["has_default_value"])
        self.assertEqual(field["metadata"]["descriptor"]["default_value"]["value"], tagged_default)
        self.assertEqual(field["metadata"]["descriptor"]["default_value_encoding"], "tagged_lua_table_literal")
        self.assertEqual(field["metadata"]["source"]["default_value_table"], {
            "kind": "lua_table",
            "created_at": default_table.created_at,
            "entry_offsets": [],
            "write_offsets": [],
            "read_offsets": [],
        })

    def test_lua_table_default_must_be_empty_unerased_and_repeated(self) -> None:
        name = "protocol/a_pb.lua"
        for table_shape in ("nonempty", "pseudoempty"):
            with self.subTest(table_shape=table_shape):
                result = _fake_result(
                    name,
                    "a_pb",
                    [{"name": "one", "fields": [{
                        "name": "items", "number": 1, "type": 13, "label": 3,
                        "has_default_value": False, "default_present": False,
                    }]}],
                )
                result, _ = _attach_lua_table_default(
                    result,
                    nonempty=table_shape == "nonempty",
                    pseudoempty=table_shape == "pseudoempty",
                )
                with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "source-proven empty Lua table default"):
                    self._build({name: b"bytes"}, {name: result})

        optional_result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{
                "name": "item", "number": 1, "type": 13, "label": 1,
                "has_default_value": False, "default_present": False,
            }]}],
        )
        optional_result, _ = _attach_lua_table_default(optional_result)
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "only for repeated fields"):
            self._build({name: b"bytes"}, {name: optional_result})

    def test_external_reference_is_closed_and_uses_target_canonical_name(self) -> None:
        source_name = "protocol/a_pb.lua"
        target_name = "protocol/b_pb.lua"
        target = _fake_result(target_name, "b_pb", [{"name": "child", "export_name": "B_CHILD"}])
        source = _fake_result(
            source_name,
            "a_pb",
            [{
                "name": "parent",
                "fields": [{
                    "name": "child", "number": 1, "type": 11, "label": 1,
                    "message_type": ExternalRef("protocol/b_pb", "B_CHILD"),
                }],
            }],
            required_modules=("protobuf", "protocol/b_pb"),
        )
        schema, report = self._build(
            {source_name: b"source", target_name: b"target"},
            {source_name: source, target_name: target},
        )
        messages = {message["name"]: message for message in schema["messages"]}
        self.assertEqual(messages["a_pb.parent"]["fields"][0]["ref"], "b_pb.child")
        self.assertEqual(report["message_reference_count"], 1)
        self.assertEqual(report["resolved_message_reference_count"], 1)

    def test_duplicate_short_names_keep_module_identity(self) -> None:
        first_name = "protocol/a_pb.lua"
        second_name = "protocol/b_pb.lua"
        first = _fake_result(first_name, "a_pb", [{"name": "shared"}])
        second = _fake_result(second_name, "b_pb", [{"name": "shared"}])
        schema, _ = self._build(
            {first_name: b"a" * 8, second_name: b"b" * 8},
            {first_name: first, second_name: second},
        )
        self.assertEqual([message["name"] for message in schema["messages"]], ["a_pb.shared", "b_pb.shared"])

    def test_no_legacy_bare_alias_is_created(self) -> None:
        name = "protocol/p58_pb.lua"
        result = _fake_result(name, "p58_pb", [{"name": "crickets_round_score_net_rec"}])
        schema, _ = self._build({name: b"bytes"}, {name: result})
        self.assertEqual([item["name"] for item in schema["messages"]], ["p58_pb.crickets_round_score_net_rec"])

    def test_module_import_must_resolve(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "parent", "fields": [{
                "name": "child", "number": 1, "type": 11, "label": 1,
                "message_type": ExternalRef("protocol/missing_pb", "MISSING"),
            }]}],
            required_modules=("protobuf", "protocol/missing_pb"),
        )
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "required protocol module .* is absent"):
            self._build({name: b"bytes"}, {name: result})

    def test_constructed_orphan_descriptor_fails(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one"}], orphan_descriptors=1)
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "every Descriptor must belong to exactly one Message"):
            self._build({name: b"bytes"}, {name: result})

    def test_unreachable_plain_table_fails_closed(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one"}], orphan_tables=1)
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "created static table node \\(kind='table'\\) at byte 70000 is not reachable"):
            self._build({name: b"bytes"}, {name: result})

    def test_provably_unused_empty_lookup_child_is_reported_with_provenance(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "count", "number": 1}]}],
        )
        result = _attach_lookup_helper(result, [
            {"key": "used", "fields": [("count_alias", 0)]},
            {"key": "unused", "fields": []},
        ])

        schema, report = self._build({name: b"bytes"}, {name: result})

        expected_counts = {
            "lookup_containers": 1,
            "field_lookup_tables": 1,
            "unused_empty_lookup": 1,
            "field_aliases": 1,
        }
        self.assertEqual(report["construction_helper_counts"], expected_counts)
        helper = report["assets"][0]["construction_helpers"]
        self.assertEqual(helper["counts"], expected_counts)
        container = helper["lookup_containers"][0]
        self.assertEqual(container["created_at"], 100_000)
        self.assertEqual(container["asset_name"], name)
        unused = next(entry for entry in container["entry_offsets"] if entry["classification"] == "unused_empty_lookup")
        self.assertEqual(unused["key"], "unused")
        self.assertEqual(unused["container_read_offsets"], [])
        self.assertEqual(unused["entry_offsets"], [])
        used = next(entry for entry in container["entry_offsets"] if entry["classification"] == "field_lookup")
        self.assertEqual(used["entry_offsets"][0]["key"], "count_alias")
        self.assertEqual(used["entry_offsets"][0]["field_descriptor_created_at"], result.created_field_descriptors[0].created_at)
        self.assertNotIn("construction_helpers", schema["messages"][0])

    def test_nil_erased_pseudoempty_lookup_child_is_rejected(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one"}])
        result = _attach_lookup_helper(result, [{"key": "pseudo", "fields": [], "pseudoempty": True}])
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "nil erasure and pseudo-empty tables are unsupported"):
            self._build({name: b"bytes"}, {name: result})

    def test_unread_nonempty_lookup_entry_is_rejected(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "count", "number": 1}]}],
        )
        result = _attach_lookup_helper(result, [{"key": "unused", "fields": [("count_alias", 0)], "root_read": False}])
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "container key was never read"):
            self._build({name: b"bytes"}, {name: result})

    def test_unread_field_alias_entry_is_rejected(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "count", "number": 1}]}],
        )
        result = _attach_lookup_helper(result, [
            {"key": "used", "fields": [("count_alias", 0)], "unread_aliases": {"count_alias"}},
        ])
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "lookup entries were not read"):
            self._build({name: b"bytes"}, {name: result})

    def test_duplicate_field_descriptor_alias_is_rejected(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "count", "number": 1}]}],
        )
        result = _attach_lookup_helper(result, [
            {"key": "used", "fields": [("first", 0), ("second", 0)]},
        ])
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "duplicates a FieldDescriptor identity"):
            self._build({name: b"bytes"}, {name: result})

    def test_mixed_and_multilevel_lookup_helpers_are_rejected(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "count", "number": 1}]}],
        )
        mixed = _attach_lookup_helper(result, [{"key": "scalar", "value": "not a child table", "root_read": True}])
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "not a plain child lookup table"):
            self._build({name: b"bytes"}, {name: mixed})

        nested_result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "count", "number": 1}]}],
        )
        nested = _attach_lookup_helper(nested_result, [{"key": "used", "fields": [("nested", "nested")]}])
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "is not a FieldDescriptor leaf"):
            self._build({name: b"bytes"}, {name: nested})

    def test_lookup_child_must_have_a_unique_container_entry(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "count", "number": 1}]}],
        )
        result = _attach_lookup_helper(result, [
            {"key": "first", "fields": [("count_alias", 0)]},
            {"key": "second", "reuse": 0, "root_read": True},
        ])
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "one unique container parent"):
            self._build({name: b"bytes"}, {name: result})

    def test_all_static_table_nodes_must_be_registered(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one"}])
        broken = replace(result, created_tables=result.created_tables[:-1])
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "static node registry accounts for"):
            self._build({name: b"bytes"}, {name: broken})

    def test_unresolved_symbol_cannot_be_exported(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one"}],
            extra_exports={"unknown": Symbol("global", ("not_defined",))},
        )
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "unresolved symbolic value"):
            self._build({name: b"bytes"}, {name: result})

    def test_unknown_descriptor_type_fails_closed(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "mystery", "number": 1, "type": 99}]}],
        )
        with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "unsupported protobuf descriptor type code 99"):
            self._build({name: b"bytes"}, {name: result})

    def test_asset_location_must_not_leak_absolute_paths(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one"}])
        locations = {name: {
            "entry": r"D:\\secret\\scripts64",
            "object": "TextAsset",
            "path_id": 101,
            "byte_start": 0,
            "byte_size": 16,
        }}
        extracted = _extracted({name: b"bytes"}, {name: result}, locations=locations)
        with patch.object(schema_ir, "analyze_asset", side_effect=lambda asset, _data, _limits: result):
            with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "absolute paths"):
                schema_ir.build_schema(extracted)

    def test_asset_location_requires_complete_typed_source_identity(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one"}])
        incomplete = {name: {
            "source_entry": "scripts64|sample|1",
            "object": "TextAsset",
            "path_id": 101,
            "byte_size": 16,
        }}
        extracted = _extracted({name: b"bytes"}, {name: result}, locations=incomplete)
        with patch.object(schema_ir, "analyze_asset", side_effect=lambda asset, _data, _limits: result):
            with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, "missing required fields .*byte_start"):
                schema_ir.build_schema(extracted)

    def test_asset_location_entry_alias_is_emitted_as_source_entry(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one"}])
        locations = {name: {
            "entry": "scripts64|sample|1",
            "object": "TextAsset",
            "path_id": 101,
            "byte_start": 0,
            "byte_size": 16,
        }}
        extracted = _extracted({name: b"bytes"}, {name: result}, locations=locations)
        with patch.object(schema_ir, "analyze_asset", side_effect=lambda asset, _data, _limits: result):
            schema, _ = schema_ir.build_schema(extracted)
        asset_location = schema["messages"][0]["source"]["asset_location"]
        self.assertEqual(asset_location["source_entry"], "scripts64|sample|1")
        self.assertNotIn("entry", asset_location)

    def test_asset_location_numeric_types_and_ranges_are_checked(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one"}])
        base = {
            "source_entry": "scripts64|sample|1",
            "object": "TextAsset",
            "path_id": 101,
            "byte_start": 0,
            "byte_size": 16,
        }
        cases = (
            ({**base, "path_id": True}, "path_id must be an integer"),
            ({**base, "byte_start": -1}, "byte_start is outside"),
            ({**base, "byte_size": 0}, "byte_size is outside"),
            ({**base, "bundle_uncompressed_byte_start": -1}, "bundle_uncompressed_byte_start is outside"),
        )
        for location, message in cases:
            with self.subTest(message=message):
                extracted = _extracted({name: b"bytes"}, {name: result}, locations={name: location})
                with patch.object(schema_ir, "analyze_asset", side_effect=lambda asset, _data, _limits: result):
                    with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, message):
                        schema_ir.build_schema(extracted)

    def test_aggregate_budgets_fail_during_preparation(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(
            name,
            "a_pb",
            [{"name": "one", "fields": [{"name": "count", "number": 1}]}],
        )
        assets = {name: b"bytes"}
        aggregate_cases = (
            ("MAX_TOTAL_PROTOCOL_BYTES", 4, "aggregate protocol bytes exceed"),
            ("MAX_TOTAL_MESSAGES", 0, "aggregate messages exceed"),
            ("MAX_TOTAL_FIELDS", 0, "aggregate fields exceed"),
            ("MAX_TOTAL_STATIC_NODES", 0, "aggregate static nodes exceed"),
            ("MAX_TOTAL_INSTRUCTIONS", 0, "aggregate instructions exceed"),
        )
        for constant, limit, message in aggregate_cases:
            with self.subTest(constant=constant), patch.object(schema_ir, constant, limit):
                with patch.object(schema_ir, "analyze_asset", side_effect=lambda asset, _data, _limits: result):
                    with self.assertRaisesRegex(schema_ir.SchemaRecoveryError, message):
                        self._build(assets, {name: result})

    def test_output_is_deterministic(self) -> None:
        name = "protocol/a_pb.lua"
        result = _fake_result(name, "a_pb", [{"name": "one", "fields": [{"name": "count", "number": 2}]}])
        assets = {name: b"stable bytes"}
        extracted = _extracted(assets, {name: result})
        with patch.object(schema_ir, "analyze_asset", side_effect=lambda asset, _data, _limits: result):
            first = schema_ir.build_schema(extracted)
            second = schema_ir.build_schema(extracted)
        first_bytes = json.dumps(first, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        second_bytes = json.dumps(second, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        self.assertEqual(hashlib.sha256(first_bytes).hexdigest(), hashlib.sha256(second_bytes).hexdigest())


if __name__ == "__main__":
    unittest.main()
