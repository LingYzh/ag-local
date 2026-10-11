"""A deliberately small, non-executing interpreter for protobuf declarations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .bytecode import BytecodeError, BytecodeDump, KNum, KTable, Limits, Prototype, parse_dump


class StaticAnalysisError(ValueError):
    """The bytecode uses semantics outside the audited declaration subset."""


@dataclass
class _AnalysisBudget:
    max_nodes: int
    max_entries: int
    nodes: int = 0
    entries: int = 0

    def add_node(self, asset: str, offset: int, kind: str) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise StaticAnalysisError(
                f"{asset}: byte {offset}: static {kind} nodes exceed the per-asset limit {self.max_nodes}"
            )

    def add_entries(self, asset: str, offset: int, count: int) -> None:
        self.entries += count
        if self.entries > self.max_entries:
            raise StaticAnalysisError(
                f"{asset}: byte {offset}: cumulative static table entries exceed the per-asset limit {self.max_entries}"
            )


@dataclass(eq=False)
class StaticTable:
    kind: str
    created_at: int
    asset_name: str
    budget: _AnalysisBudget = field(repr=False)
    limits: Limits = field(repr=False)
    entries: dict[str | int, Any] = field(default_factory=dict)
    entry_offsets: dict[str | int, int] = field(default_factory=dict)
    write_offsets: dict[str | int, list[int]] = field(default_factory=dict)
    read_offsets: dict[str | int, list[int]] = field(default_factory=dict)

    def set(self, key: str | int, value: Any, *, offset: int) -> None:
        asset = self.asset_name
        if not isinstance(key, (str, int)) or isinstance(key, bool):
            raise StaticAnalysisError(f"{asset}: byte {offset}: table key is not a static string/integer")
        self.write_offsets.setdefault(key, []).append(offset)
        if value is None:
            self.entries.pop(key, None)
            self.entry_offsets.pop(key, None)
            return
        if key not in self.entries:
            if len(self.entries) >= self.limits.max_table_entries:
                raise StaticAnalysisError(
                    f"{asset}: byte {offset}: table exceeds {self.limits.max_table_entries} entries"
                )
            self.budget.add_entries(asset, offset, 1)
        self.entries[key] = value
        self.entry_offsets[key] = offset


@dataclass(frozen=True)
class Symbol:
    kind: str
    path: tuple[str, ...]

    def label(self) -> str:
        return ".".join(self.path)


@dataclass(frozen=True)
class ModuleValue:
    name: str


@dataclass(frozen=True)
class ExternalRef:
    module: str
    name: str


@dataclass(frozen=True)
class MessageClass:
    descriptor: Any
    created_at: int


@dataclass
class _AnalysisContext:
    asset_name: str
    limits: Limits
    budget: _AnalysisBudget
    created_tables: list[StaticTable] = field(default_factory=list)
    descriptors: list[StaticTable] = field(default_factory=list)
    field_descriptors: list[StaticTable] = field(default_factory=list)
    message_classes: list[MessageClass] = field(default_factory=list)

    def new_table(self, kind: str, offset: int) -> StaticTable:
        self.budget.add_node(self.asset_name, offset, kind)
        table = StaticTable(kind, offset, self.asset_name, self.budget, self.limits)
        self.created_tables.append(table)
        if kind == "Descriptor":
            self.descriptors.append(table)
        elif kind == "FieldDescriptor":
            self.field_descriptors.append(table)
        return table

    def new_message_class(self, descriptor: Any, offset: int) -> MessageClass:
        self.budget.add_node(self.asset_name, offset, "Message")
        value = MessageClass(descriptor, offset)
        self.message_classes.append(value)
        return value


@dataclass(frozen=True)
class AnalysisResult:
    asset_name: str
    namespace: str
    code_offset: int
    exports: dict[str, Any]
    required_modules: tuple[str, ...]
    call_counts: dict[str, int]
    instruction_count: int
    assigned_globals: dict[str, Any]
    global_write_offsets: dict[str, tuple[int, ...]]
    created_tables: tuple[StaticTable, ...]
    created_descriptors: tuple[StaticTable, ...]
    created_field_descriptors: tuple[StaticTable, ...]
    created_message_classes: tuple[MessageClass, ...]
    return_values: tuple[Any, ...]
    static_nodes: int
    static_table_entries: int


def _source_string(proto: Prototype, encoded_index: int, asset: str, offset: int) -> str:
    # LuaJIT 2.1 addresses GC constants backwards from KBASE. The on-disk pool
    # itself is stored in forward order, so D/C is len(pool)-1-index.
    index = len(proto.gc_constants) - 1 - encoded_index
    if index < 0 or index >= len(proto.gc_constants):
        raise StaticAnalysisError(f"{asset}: byte {offset}: GC string index {encoded_index} is out of range")
    value = proto.gc_constants[index]
    if not isinstance(value, bytes):
        raise StaticAnalysisError(f"{asset}: byte {offset}: GC constant {encoded_index} is not a string")
    try:
        return value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise StaticAnalysisError(f"{asset}: byte {offset}: identifier string is not valid UTF-8") from exc


def _constant_table(
    proto: Prototype,
    encoded_index: int,
    context: _AnalysisContext,
    offset: int,
) -> StaticTable:
    asset = context.asset_name
    limits = context.limits
    index = len(proto.gc_constants) - 1 - encoded_index
    if index < 0 or index >= len(proto.gc_constants):
        raise StaticAnalysisError(f"{asset}: byte {offset}: table constant index {encoded_index} is out of range")
    constant = proto.gc_constants[index]
    if not isinstance(constant, KTable):
        raise StaticAnalysisError(f"{asset}: byte {offset}: TDUP target is not a constant table")
    table = context.new_table("table", offset)
    # LuaJIT's constant-table array dump writes storage slots 0..n-1. Its
    # integer-key table array uses the Lua integer key as the slot index, so
    # slot 0 is key 0 and must not be shifted to key 1 here.
    for array_index, value in enumerate(constant.array):
        table.set(array_index, _plain_constant(value, asset, offset), offset=offset)
    for key, value in constant.hash_entries:
        converted_key = _plain_constant(key, asset, offset)
        if not isinstance(converted_key, (str, int)) or isinstance(converted_key, bool):
            raise StaticAnalysisError(f"{asset}: byte {offset}: TDUP has a non-static hash key")
        table.set(converted_key, _plain_constant(value, asset, offset), offset=offset)
    return table


def _plain_constant(value: Any, asset: str, offset: int) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise StaticAnalysisError(f"{asset}: byte {offset}: table string is not valid UTF-8") from exc
    if isinstance(value, KNum):
        return value.value
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise StaticAnalysisError(f"{asset}: byte {offset}: unsupported constant table value {type(value).__name__}")


def _get(value: Any, key: Any, *, asset: str, offset: int) -> Any:
    if isinstance(value, StaticTable):
        if not isinstance(key, (str, int)) or isinstance(key, bool):
            raise StaticAnalysisError(f"{asset}: byte {offset}: table read key is not a static string/integer")
        if key not in value.entries:
            raise StaticAnalysisError(f"{asset}: byte {offset}: missing static {value.kind}[{key!r}]")
        value.read_offsets.setdefault(key, []).append(offset)
        return value.entries[key]
    if isinstance(value, ModuleValue):
        if value.name == "protobuf":
            return Symbol("protobuf-callable", (value.name, str(key)))
        if value.name == "package":
            return Symbol("package-member", (value.name, str(key)))
        return ExternalRef(value.name, str(key))
    if isinstance(value, Symbol) and value.kind == "global":
        raise StaticAnalysisError(
            f"{asset}: byte {offset}: property read from unresolved global {value.label()}"
        )
    raise StaticAnalysisError(
        f"{asset}: byte {offset}: property read uses unsupported {type(value).__name__}"
    )


def _call_target(value: Any) -> str:
    if isinstance(value, Symbol):
        return value.label()
    return type(value).__name__


def _invoke_static(value: Any, args: list[Any], *, context: _AnalysisContext, offset: int) -> list[Any]:
    """Model only declarations/imports. No user or Lua function is invoked."""
    asset = context.asset_name
    if isinstance(value, Symbol) and value.kind == "global-callable":
        if value.path == ("require",):
            if len(args) != 1 or not isinstance(args[0], str) or not args[0]:
                raise StaticAnalysisError(f"{asset}: byte {offset}: require needs one literal module path")
            return [ModuleValue(args[0].replace("\\", "/"))]
        if value.path == ("module",):
            if len(args) not in (1, 2) or not isinstance(args[0], str) or not args[0]:
                raise StaticAnalysisError(f"{asset}: byte {offset}: unsupported module declaration")
            if len(args) == 2 and args[1] != Symbol("package-member", ("package", "seeall")):
                raise StaticAnalysisError(f"{asset}: byte {offset}: unsupported module option")
            return [ModuleValue(args[0].replace("\\", "/"))]
    if isinstance(value, Symbol) and value.kind == "protobuf-callable":
        if value.path == ("protobuf", "Descriptor") and not args:
            return [context.new_table("Descriptor", offset)]
        if value.path == ("protobuf", "FieldDescriptor") and not args:
            return [context.new_table("FieldDescriptor", offset)]
        if value.path == ("protobuf", "Message") and len(args) == 1:
            if isinstance(args[0], StaticTable) and args[0].kind == "Descriptor":
                return [context.new_message_class(args[0], offset)]
            if isinstance(args[0], ExternalRef):
                return [context.new_message_class(args[0], offset)]
    raise StaticAnalysisError(
        f"{asset}: byte {offset}: unsupported static CALL target {_call_target(value)} "
        f"with {len(args)} argument(s)"
    )


def analyze_asset(asset_name: str, asset_bytes: bytes, limits: Limits = Limits()) -> AnalysisResult:
    """Statically interpret one protocol asset's root declaration chunk."""
    try:
        dump = parse_dump(asset_bytes, asset_name, limits)
    except BytecodeError as exc:
        raise StaticAnalysisError(str(exc)) from exc
    if len(dump.prototypes) != 1:
        raise StaticAnalysisError(f"{asset_name}: expected one root prototype, found {len(dump.prototypes)}")
    proto = dump.prototypes[0]
    if proto.upvalue_count:
        raise StaticAnalysisError(f"{asset_name}: byte {proto.code_offset}: root prototype has upvalues")

    budget = _AnalysisBudget(
        limits.max_static_nodes_per_asset,
        limits.max_static_table_entries_per_asset,
    )
    context = _AnalysisContext(asset_name, limits, budget)
    registers: list[Any] = [None] * limits.max_registers
    globals_: dict[str, Any] = {
        "require": Symbol("global-callable", ("require",)),
        "module": Symbol("global-callable", ("module",)),
        "package": ModuleValue("package"),
    }
    namespace: str | None = None
    imports: list[str] = []
    assigned_globals: dict[str, Any] = {}
    global_write_offsets: dict[str, list[int]] = {}
    return_values: tuple[Any, ...] = ()
    call_counts: Counter[str] = Counter()
    returned = False

    def setreg(index: int, value: Any, instruction_offset: int) -> None:
        if index < 0 or index >= proto.framesize:
            raise StaticAnalysisError(
                f"{asset_name}: byte {instruction_offset}: register {index} is outside frame size {proto.framesize}"
            )
        registers[index] = value

    def getreg(index: int, instruction_offset: int) -> Any:
        if index < 0 or index >= proto.framesize:
            raise StaticAnalysisError(
                f"{asset_name}: byte {instruction_offset}: register {index} is outside frame size {proto.framesize}"
            )
        return registers[index]

    for instruction in proto.instructions:
        if returned:
            raise StaticAnalysisError(
                f"{asset_name}: byte {instruction.byte_offset}: instruction follows a terminal return"
            )
        op, a, b, c, d = instruction.opcode, instruction.a, instruction.b, instruction.c, instruction.d
        off = instruction.byte_offset

        if op == "GGET":
            key = _source_string(proto, d, asset_name, off)
            setreg(a, globals_.get(key, Symbol("global", (key,))), off)
        elif op == "GSET":
            key = _source_string(proto, d, asset_name, off)
            value = getreg(a, off)
            globals_[key] = value
            assigned_globals[key] = value
            global_write_offsets.setdefault(key, []).append(off)
        elif op == "KSTR":
            setreg(a, _source_string(proto, d, asset_name, off), off)
        elif op == "KSHORT":
            setreg(a, d - 0x10000 if d & 0x8000 else d, off)
        elif op == "KNUM":
            if d >= len(proto.number_constants):
                raise StaticAnalysisError(f"{asset_name}: byte {off}: KNUM index {d} is out of range")
            setreg(a, proto.number_constants[d].value, off)
        elif op == "KPRI":
            values = {0: None, 1: False, 2: True}
            if d not in values:
                raise StaticAnalysisError(f"{asset_name}: byte {off}: unsupported KPRI value {d}")
            setreg(a, values[d], off)
        elif op == "KNIL":
            if d < a:
                raise StaticAnalysisError(f"{asset_name}: byte {off}: invalid KNIL range")
            for index in range(a, d + 1):
                setreg(index, None, off)
        elif op == "MOV":
            # MOV is ABC: C names the source register; D is merely the packed
            # B/C word and must not be treated as a register index.
            setreg(a, getreg(c, off), off)
        elif op == "TNEW":
            setreg(a, context.new_table("table", off), off)
        elif op == "TDUP":
            setreg(a, _constant_table(proto, d, context, off), off)
        elif op == "TGETS":
            key = _source_string(proto, c, asset_name, off)
            setreg(a, _get(getreg(b, off), key, asset=asset_name, offset=off), off)
        elif op == "TGETB":
            setreg(a, _get(getreg(b, off), c, asset=asset_name, offset=off), off)
        elif op == "TGETV":
            setreg(a, _get(getreg(b, off), getreg(c, off), asset=asset_name, offset=off), off)
        elif op == "TSETS":
            target = getreg(b, off)
            if not isinstance(target, StaticTable):
                raise StaticAnalysisError(f"{asset_name}: byte {off}: TSETS target is not a static table")
            target.set(_source_string(proto, c, asset_name, off), getreg(a, off), offset=off)
        elif op == "TSETB":
            target = getreg(b, off)
            if not isinstance(target, StaticTable):
                raise StaticAnalysisError(f"{asset_name}: byte {off}: TSETB target is not a static table")
            # LuaJIT's TSETB.C is the source integer key itself (lj_parse.c
            # stores 256+k; the store emitter removes the 256 bias), and the
            # VM uses RC directly as the array offset. Do not add or subtract 1.
            target.set(c, getreg(a, off), offset=off)
        elif op == "TSETV":
            target = getreg(b, off)
            if not isinstance(target, StaticTable):
                raise StaticAnalysisError(f"{asset_name}: byte {off}: TSETV target is not a static table")
            key = getreg(c, off)
            if not isinstance(key, (str, int)) or isinstance(key, bool):
                raise StaticAnalysisError(f"{asset_name}: byte {off}: TSETV key is not a static string/integer")
            target.set(key, getreg(a, off), offset=off)
        elif op == "CALL":
            if c == 0:
                raise StaticAnalysisError(f"{asset_name}: byte {off}: CALL uses dynamic argument count")
            argument_count = c - 1
            argument_start = a + 2  # dump requires FR2; VM places callee args at BASE+A+2.
            args = [getreg(argument_start + index, off) for index in range(argument_count)]
            function = getreg(a, off)
            target = _call_target(function)
            call_counts[target] += 1
            if target == "require" and args and isinstance(args[0], str):
                imports.append(args[0].replace("\\", "/"))
            results = _invoke_static(function, args, context=context, offset=off)
            if b == 0:
                for index, result in enumerate(results):
                    setreg(a + index, result, off)
            else:
                result_count = b - 1
                if result_count > len(results):
                    raise StaticAnalysisError(
                        f"{asset_name}: byte {off}: CALL requests {result_count} static results, only {len(results)} modeled"
                    )
                for index in range(result_count):
                    setreg(a + index, results[index], off)
            if target == "module" and results and isinstance(results[0], ModuleValue):
                if namespace is not None:
                    raise StaticAnalysisError(f"{asset_name}: byte {off}: multiple module declarations")
                namespace = results[0].name
                globals_["_M"] = results[0]
        elif op in {"RET", "RET0", "RET1", "RETM"}:
            if op == "RET1":
                return_values = (getreg(a, off),)
            elif op == "RET0":
                return_values = ()
            elif op == "RET":
                if b == 0:
                    raise StaticAnalysisError(f"{asset_name}: byte {off}: RET uses dynamic return count")
                return_count = b - 1
                return_values = tuple(getreg(a + index, off) for index in range(return_count))
            else:
                raise StaticAnalysisError(f"{asset_name}: byte {off}: RETM is outside the static subset")
            returned = True
        else:
            raise StaticAnalysisError(
                f"{asset_name}: byte {off}: unsupported opcode {op}; static declaration subset stops here"
            )

    if namespace is None:
        raise StaticAnalysisError(f"{asset_name}: byte {proto.code_offset}: no static module declaration")
    if not returned:
        raise StaticAnalysisError(f"{asset_name}: byte {proto.code_offset}: no terminal return")
    return AnalysisResult(
        asset_name=asset_name,
        namespace=namespace,
        code_offset=proto.code_offset,
        exports=assigned_globals,
        required_modules=tuple(sorted(set(imports))),
        call_counts=dict(sorted(call_counts.items())),
        instruction_count=len(proto.instructions),
        assigned_globals=assigned_globals,
        global_write_offsets={key: tuple(values) for key, values in sorted(global_write_offsets.items())},
        created_tables=tuple(context.created_tables),
        created_descriptors=tuple(context.descriptors),
        created_field_descriptors=tuple(context.field_descriptors),
        created_message_classes=tuple(context.message_classes),
        return_values=return_values,
        static_nodes=budget.nodes,
        static_table_entries=budget.entries,
    )
