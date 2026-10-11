"""Bounded reader for stripped LuaJIT 2.1 bytecode dumps.

This module reads bytecode structures only. It never loads or executes Lua.
Opcode numbers and dump fields follow LuaJIT v2.1 src/lj_bc.h and
src/lj_bcread.c.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any


OPCODE_NAMES = (
    "ISLT ISGE ISLE ISGT ISEQV ISNEV ISEQS ISNES ISEQN ISNEN ISEQP ISNEP "
    "ISTC ISFC IST ISF ISTYPE ISNUM MOV NOT UNM LEN ADDVN SUBVN MULVN DIVVN "
    "MODVN ADDNV SUBNV MULNV DIVNV MODNV ADDVV SUBVV MULVV DIVVV MODVV POW "
    "CAT KSTR KCDATA KSHORT KNUM KPRI KNIL UGET USETV USETS USETN USETP UCLO "
    "FNEW TNEW TDUP GGET GSET TGETV TGETS TGETB TGETR TSETV TSETS TSETB TSETM "
    "TSETR CALLM CALL CALLMT CALLT ITERC ITERN VARG ISNEXT RETM RET RET0 RET1 "
    "FORI JFORI FORL IFORL JFORL ITERL IITERL JITERL LOOP ILOOP JLOOP JMP "
    "BNOT BAND BOR BXOR BSHL BSHR BSAR FUNCF IFUNCF JFUNCF FUNCV IFUNCV JFUNCV "
    "FUNCC FUNCCW"
).split()


class BytecodeError(ValueError):
    """A malformed or intentionally unsupported LuaJIT dump."""


@dataclass(frozen=True)
class Limits:
    max_asset_bytes: int = 16 * 1024 * 1024
    max_prototypes: int = 256
    max_instructions_per_proto: int = 1_000_000
    max_instructions_per_asset: int = 2_000_000
    max_constants_per_proto: int = 100_000
    max_constants_per_asset: int = 250_000
    max_string_bytes: int = 1 * 1024 * 1024
    max_string_bytes_per_asset: int = 8 * 1024 * 1024
    max_table_entries: int = 100_000
    max_table_entries_per_asset: int = 250_000
    max_static_nodes_per_asset: int = 100_000
    max_static_table_entries_per_asset: int = 250_000
    max_registers: int = 255


@dataclass(frozen=True)
class KNum:
    value: int | float
    is_float: bool


@dataclass(frozen=True)
class KTable:
    array: tuple[Any, ...]
    hash_entries: tuple[tuple[Any, Any], ...]


@dataclass(frozen=True)
class KChild:
    pass


@dataclass(frozen=True)
class Instruction:
    pc: int
    byte_offset: int
    opcode: str
    a: int
    b: int
    c: int
    d: int


@dataclass(frozen=True)
class Prototype:
    flags: int
    numparams: int
    framesize: int
    upvalue_count: int
    code_offset: int
    instructions: tuple[Instruction, ...]
    gc_constants: tuple[Any, ...]
    number_constants: tuple[KNum, ...]


@dataclass(frozen=True)
class BytecodeDump:
    flags: int
    prototypes: tuple[Prototype, ...]


class _Reader:
    def __init__(self, data: bytes, start: int = 0, end: int | None = None, *, asset: str = "") -> None:
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else end
        self.asset = asset

    def fail(self, detail: str, at: int | None = None) -> BytecodeError:
        offset = self.pos if at is None else at
        return BytecodeError(f"{self.asset or '<asset>'}: byte {offset}: {detail}")

    def take(self, count: int, what: str) -> bytes:
        if count < 0 or count > self.end - self.pos:
            raise self.fail(f"truncated {what}")
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result

    def uleb(self) -> int:
        start = self.pos
        value = 0
        shift = 0
        for _ in range(5):
            if self.pos >= self.end:
                raise self.fail("truncated ULEB128", start)
            byte = self.data[self.pos]
            self.pos += 1
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                if value > 0xFFFFFFFF:
                    raise self.fail("ULEB128 exceeds uint32", start)
                return value
            shift += 7
        raise self.fail("ULEB128 exceeds five bytes", start)

    def uleb33(self) -> tuple[bool, int]:
        """Read LuaJIT's tagged 33-bit number encoding."""
        start = self.pos
        if self.pos >= self.end:
            raise self.fail("truncated tagged ULEB128", start)
        byte = self.data[self.pos]
        self.pos += 1
        is_float = bool(byte & 1)
        value = (byte & 0x7F) >> 1
        shift = 6
        count = 1
        while byte & 0x80:
            if self.pos >= self.end:
                raise self.fail("truncated tagged ULEB128 continuation", start)
            if count >= 5:
                raise self.fail("tagged ULEB128 exceeds five bytes", start)
            byte = self.data[self.pos]
            self.pos += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            count += 1
        if value > 0xFFFFFFFF:
            raise self.fail("tagged ULEB128 payload exceeds uint32", start)
        return is_float, value


def _read_knumber(reader: _Reader) -> KNum:
    is_float, low = reader.uleb33()
    if not is_float:
        return KNum(low - 0x1_0000_0000 if low & 0x8000_0000 else low, False)
    high = reader.uleb()
    if high > 0xFFFFFFFF:
        raise reader.fail("floating-point high word exceeds uint32")
    bits = (high << 32) | low
    return KNum(struct.unpack("<d", bits.to_bytes(8, "little"))[0], True)


@dataclass
class _Budget:
    constants: int = 0
    instructions: int = 0
    string_bytes: int = 0
    table_entries: int = 0

    def add(self, field: str, count: int, limit: int, reader: _Reader, at: int, label: str) -> None:
        if count < 0:
            raise reader.fail(f"negative {label}", at)
        current = getattr(self, field) + count
        if current > limit:
            raise reader.fail(f"{label} exceeds the per-asset limit", at)
        setattr(self, field, current)


def _int32(value: int) -> int:
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def _u64_words(reader: _Reader, *, signed: bool = False) -> int:
    start = reader.pos
    low = reader.uleb()
    high = reader.uleb()
    if low > 0xFFFFFFFF or high > 0xFFFFFFFF:
        raise reader.fail("64-bit constant word exceeds uint32", start)
    value = (high << 32) | low
    if signed and value & (1 << 63):
        value -= 1 << 64
    return value


def _read_ktab_number(reader: _Reader) -> KNum:
    """Read a constant-table number, encoded as two ordinary ULEBs."""
    start = reader.pos
    low = reader.uleb()
    high = reader.uleb()
    if low > 0xFFFFFFFF or high > 0xFFFFFFFF:
        raise reader.fail("constant-table number word exceeds uint32", start)
    bits = (high << 32) | low
    return KNum(struct.unpack("<d", bits.to_bytes(8, "little"))[0], True)


def _add_string_budget(reader: _Reader, budget: _Budget, limits: Limits, length: int, at: int) -> None:
    if length > limits.max_string_bytes:
        raise reader.fail("constant string exceeds the per-string size limit", at)
    budget.add("string_bytes", length, limits.max_string_bytes_per_asset, reader, at, "constant string bytes")


def _read_ktab_value(reader: _Reader, limits: Limits, budget: _Budget) -> Any:
    tag_at = reader.pos
    tag = reader.uleb()
    if tag >= 5:  # BCDUMP_KTAB_STR: length is stored in the tag itself.
        length = tag - 5
        _add_string_budget(reader, budget, limits, length, tag_at)
        return reader.take(length, "constant-table string")
    if tag == 0:
        return None
    if tag == 1:
        return False
    if tag == 2:
        return True
    if tag == 3:
        return _int32(reader.uleb())
    if tag == 4:
        return _read_ktab_number(reader)
    raise reader.fail(f"unknown constant-table tag {tag}", tag_at)


def _read_kgc(reader: _Reader, limits: Limits, budget: _Budget) -> Any:
    tag_at = reader.pos
    tag = reader.uleb()
    if tag >= 5:  # BCDUMP_KGC_STR: length is stored in the tag itself.
        length = tag - 5
        _add_string_budget(reader, budget, limits, length, tag_at)
        return reader.take(length, "GC string")
    if tag == 0:
        return KChild()
    if tag == 1:
        array_count = reader.uleb()
        hash_count = reader.uleb()
        entry_count = array_count + 2 * hash_count
        if entry_count > limits.max_table_entries:
            raise reader.fail("constant table exceeds the entry limit", tag_at)
        budget.add(
            "table_entries", entry_count, limits.max_table_entries_per_asset,
            reader, tag_at, "constant-table entries",
        )
        array = tuple(_read_ktab_value(reader, limits, budget) for _ in range(array_count))
        entries = tuple(
            (_read_ktab_value(reader, limits, budget), _read_ktab_value(reader, limits, budget))
            for _ in range(hash_count)
        )
        return KTable(array, entries)
    if tag in (2, 3):  # signed/unsigned 64-bit integer stored as two ULEBs.
        return ("i64" if tag == 2 else "u64", _u64_words(reader, signed=(tag == 2)))
    if tag == 4:
        return ("complex", _read_ktab_number(reader), _read_ktab_number(reader))
    raise reader.fail(f"unknown GC constant tag {tag}", tag_at)


def parse_dump(data: bytes, asset_name: str = "", limits: Limits = Limits()) -> BytecodeDump:
    """Parse one stripped, little-endian, FR2 LuaJIT 2.1 chunk."""
    if len(data) > limits.max_asset_bytes:
        raise BytecodeError(f"{asset_name or '<asset>'}: asset exceeds {limits.max_asset_bytes} bytes")
    reader = _Reader(data, asset=asset_name)
    if reader.take(4, "LuaJIT signature/version") != b"\x1bLJ\x02":
        raise reader.fail("expected LuaJIT bytecode version 2", 0)
    dump_flags = reader.uleb()
    # This extractor deliberately supports only this client's stripped x64/FR2 form.
    if dump_flags != 0x0A:
        raise reader.fail(f"unsupported dump flags 0x{dump_flags:x}; expected stripped FR2 0x0a", 4)

    prototypes: list[Prototype] = []
    budget = _Budget()
    saw_end = False
    while reader.pos < reader.end:
        length_at = reader.pos
        proto_length = reader.uleb()
        if proto_length == 0:
            saw_end = True
            break
        if len(prototypes) >= limits.max_prototypes:
            raise reader.fail("prototype count exceeds the limit", length_at)
        proto_end = reader.pos + proto_length
        if proto_end > reader.end:
            raise reader.fail("prototype length exceeds the remaining asset", length_at)
        proto_reader = _Reader(data, reader.pos, proto_end, asset=asset_name)
        if proto_length < 4:
            raise proto_reader.fail("prototype is shorter than its fixed header", reader.pos)
        proto_flags, numparams, framesize, upvalue_count = proto_reader.take(4, "prototype header")
        if proto_flags & ~0x0F:
            raise proto_reader.fail(f"unsupported prototype flags 0x{proto_flags:x}", reader.pos - 4)
        if framesize > limits.max_registers:
            raise proto_reader.fail(
                f"frame has {framesize} registers; limit is {limits.max_registers}",
                reader.pos - 2,
            )
        if numparams > framesize:
            raise proto_reader.fail("parameter count exceeds frame size", reader.pos - 3)

        gc_count = proto_reader.uleb()
        number_count = proto_reader.uleb()
        instruction_count = proto_reader.uleb()
        if gc_count > limits.max_constants_per_proto or number_count > limits.max_constants_per_proto:
            raise proto_reader.fail("constant count exceeds the per-prototype limit")
        budget.add(
            "constants", gc_count + number_count, limits.max_constants_per_asset,
            proto_reader, length_at, "constant count",
        )
        if instruction_count > limits.max_instructions_per_proto:
            raise proto_reader.fail("instruction count exceeds the per-prototype limit")
        budget.add(
            "instructions", instruction_count, limits.max_instructions_per_asset,
            proto_reader, length_at, "instruction count",
        )

        code_offset = proto_reader.pos
        code_bytes = proto_reader.take(instruction_count * 4, "bytecode instructions")
        instructions: list[Instruction] = []
        for pc in range(instruction_count):
            word = int.from_bytes(code_bytes[pc * 4:pc * 4 + 4], "little")
            opcode_index = word & 0xFF
            if opcode_index >= len(OPCODE_NAMES):
                raise proto_reader.fail(f"unknown opcode number {opcode_index}", code_offset + pc * 4)
            instructions.append(
                Instruction(
                    pc=pc,
                    byte_offset=code_offset + pc * 4,
                    opcode=OPCODE_NAMES[opcode_index],
                    a=(word >> 8) & 0xFF,
                    b=(word >> 24) & 0xFF,
                    c=(word >> 16) & 0xFF,
                    d=(word >> 16) & 0xFFFF,
                )
            )

        proto_reader.take(upvalue_count * 2, "upvalue descriptors")
        gc_constants = tuple(_read_kgc(proto_reader, limits, budget) for _ in range(gc_count))
        number_constants = tuple(_read_knumber(proto_reader) for _ in range(number_count))
        if proto_reader.pos != proto_end:
            raise proto_reader.fail(
                f"prototype size mismatch ({proto_end - proto_reader.pos} unconsumed bytes)",
                proto_reader.pos,
            )
        prototypes.append(
            Prototype(
                flags=proto_flags,
                numparams=numparams,
                framesize=framesize,
                upvalue_count=upvalue_count,
                code_offset=code_offset,
                instructions=tuple(instructions),
                gc_constants=gc_constants,
                number_constants=number_constants,
            )
        )
        reader.pos = proto_end

    if not saw_end:
        raise reader.fail("missing zero-length prototype terminator")
    if reader.pos != reader.end:
        raise reader.fail("trailing data after prototype terminator")
    if not prototypes:
        raise reader.fail("dump contains no prototypes")
    if any(isinstance(value, KChild) for proto in prototypes for value in proto.gc_constants):
        raise reader.fail("nested child prototypes are outside the supported static subset")
    return BytecodeDump(dump_flags, tuple(prototypes))
