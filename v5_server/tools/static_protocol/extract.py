"""Safely extract current-version UnityFS protocol TextAssets as inert bytes.

This module only parses Unity container metadata and serialized type trees.  It
never evaluates, imports, or executes Lua content.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import lzma
import os
import platform
import re
import stat
import struct
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .bundle import ExtractedBundle, ExtractionLimits


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_UNITYFS_SIGNATURE = b"UnityFS\x00"
_UNITYFS_VERSION = 8
_ARCHIVE_COMPRESSION_MASK = 0x3F
_ARCHIVE_BLOCKS_AND_DIRECTORY_COMBINED = 0x40
_ARCHIVE_BLOCKS_INFO_AT_END = 0x80
_ARCHIVE_BLOCK_INFO_NEEDS_PADDING = 0x200
_ARCHIVE_SUPPORTED_FLAGS = (
    _ARCHIVE_COMPRESSION_MASK
    | _ARCHIVE_BLOCKS_AND_DIRECTORY_COMBINED
    | _ARCHIVE_BLOCKS_INFO_AT_END
    | _ARCHIVE_BLOCK_INFO_NEEDS_PADDING
)
_BLOCK_STREAMED_FLAG = 0x40
_BLOCK_SUPPORTED_FLAGS = _ARCHIVE_COMPRESSION_MASK | _BLOCK_STREAMED_FLAG
_NODE_SERIALIZED_FLAG = 0x04
_SERIALIZED_FORMAT_VERSION = 22
_TEXT_ASSET_CLASS_ID = 49
_METAFLAG_ALIGNED = 0x4000


@dataclass(frozen=True, slots=True)
class _Block:
    compressed_offset: int
    compressed_size: int
    uncompressed_size: int
    flags: int
    compression: str
    lzma_dictionary_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class _Node:
    offset: int
    size: int
    flags: int
    path: str


@dataclass(slots=True)
class _TypeTreeNode:
    level: int
    type_name: str
    name: str
    byte_size: int
    meta_flags: int
    children: list[_TypeTreeNode]


@dataclass(frozen=True, slots=True)
class _TypeInfo:
    class_id: int
    tree: _TypeTreeNode | None


@dataclass(frozen=True, slots=True)
class _SerializedObject:
    path_id: int
    type_id: int
    class_id: int
    byte_start: int
    byte_size: int


@dataclass(frozen=True, slots=True)
class _SerializedInfo:
    unity_version: str
    format_version: int
    data_offset: int
    object_count: int
    text_asset_count: int
    type_count: int
    type_tree_node_count: int
    objects: tuple[_SerializedObject, ...]
    types: tuple[_TypeInfo, ...]


class _Cursor:
    """Bounds-checked view cursor with explicit byte order and alignment base."""

    __slots__ = ("data", "pos", "end", "endian", "base_offset")

    def __init__(
        self,
        data: bytes | bytearray | memoryview,
        *,
        endian: str = ">",
        base_offset: int = 0,
        end: int | None = None,
    ) -> None:
        view = memoryview(data)
        if view.format != "B" or view.ndim != 1:
            view = view.cast("B")
        self.data = view
        self.pos = 0
        self.end = len(view) if end is None else end
        self.endian = endian
        self.base_offset = base_offset
        if self.end < 0 or self.end > len(view):
            raise ValueError("cursor boundary is outside the supplied buffer")

    @property
    def remaining(self) -> int:
        return self.end - self.pos

    def _unpack(self, fmt: str) -> int:
        size = struct.calcsize(fmt)
        if size > self.remaining:
            raise ValueError("truncated binary structure")
        value = struct.unpack_from(self.endian + fmt, self.data, self.pos)[0]
        self.pos += size
        return int(value)

    def u8(self) -> int:
        return self._unpack("B")

    def u16(self) -> int:
        return self._unpack("H")

    def i16(self) -> int:
        return self._unpack("h")

    def u32(self) -> int:
        return self._unpack("I")

    def i32(self) -> int:
        return self._unpack("i")

    def u64(self) -> int:
        return self._unpack("Q")

    def i64(self) -> int:
        return self._unpack("q")

    def take_view(self, size: int) -> memoryview:
        if size < 0 or size > self.remaining:
            raise ValueError("declared byte range exceeds its parent structure")
        start = self.pos
        self.pos += size
        return self.data[start : start + size]

    def skip(self, size: int) -> None:
        self.take_view(size)

    def cstring(self, max_bytes: int, *, encoding: str = "utf-8") -> str:
        if max_bytes < 0:
            raise ValueError("invalid string bound")
        stop = min(self.end, self.pos + max_bytes + 1)
        end = self.pos
        while end < stop and self.data[end] != 0:
            end += 1
        if end >= stop or end >= self.end:
            raise ValueError("unterminated or overlong string")
        raw = self.data[self.pos : end].tobytes()
        self.pos = end + 1
        try:
            return raw.decode(encoding, "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid encoded string in container metadata") from exc

    def align(self, alignment: int, *, require_zero: bool = False) -> None:
        if alignment <= 0 or alignment & (alignment - 1):
            raise ValueError("alignment must be a positive power of two")
        absolute = self.base_offset + self.pos
        padding = (-absolute) & (alignment - 1)
        view = self.take_view(padding)
        if require_zero and any(view):
            raise ValueError("nonzero padding in a supported Unity structure")


def _is_regular_file_stat(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISREG(info.st_mode) and not attributes & 0x400  # FILE_ATTRIBUTE_REPARSE_POINT


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    """Return fields that have the same meaning for path and handle stats."""

    identity = (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
    )
    if os.name == "nt":
        # Python 3.12+ exposes the same creation-time field for stat() and
        # fstat(); Windows st_ctime_ns is deprecated and differs by API.
        birthtime_ns = getattr(info, "st_birthtime_ns", None)
        if not isinstance(birthtime_ns, int):
            raise ValueError("runtime does not expose a stable Windows file birth time")
        return identity + (birthtime_ns,)
    return identity + (int(info.st_ctime_ns),)


def _stat_change_time(info: os.stat_result) -> int:
    value = getattr(info, "st_ctime_ns", None)
    if not isinstance(value, int):
        raise ValueError("runtime does not expose a stable file change time")
    return value


def _read_regular_file(path: Path, limits: ExtractionLimits) -> tuple[bytearray, str]:
    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except OSError:
        raise
    if not _is_regular_file_stat(path_stat):
        raise ValueError("bundle input must be a regular file")
    if path_stat.st_size <= 0:
        raise ValueError("bundle input is empty")
    if path_stat.st_size > limits.max_input_bytes:
        raise ValueError("bundle input exceeds the configured input byte limit")

    digest = hashlib.sha256()
    data = bytearray(path_stat.st_size)
    view = memoryview(data)
    try:
        with path.open("rb", buffering=0) as stream:
            before = os.fstat(stream.fileno())
            if not _is_regular_file_stat(before):
                raise ValueError("opened bundle input is not a regular file")
            if _stat_identity(before) != _stat_identity(path_stat):
                raise ValueError("bundle input path changed before it could be read")

            position = 0
            while position < len(data):
                end = min(position + 1024 * 1024, len(data))
                count = stream.readinto(view[position:end])
                if not count:
                    raise ValueError("bundle input was truncated while being read")
                digest.update(view[position : position + count])
                position += count

            if stream.read(1):
                raise ValueError("bundle input grew while being read")
            after = os.fstat(stream.fileno())
            if _stat_identity(before) != _stat_identity(after):
                raise ValueError("bundle input changed while being read")
            if _stat_change_time(before) != _stat_change_time(after):
                raise ValueError("bundle input changed while being read")

            final_path_stat = os.stat(path, follow_symlinks=False)
            if (
                _stat_identity(before) != _stat_identity(final_path_stat)
                or _stat_change_time(path_stat) != _stat_change_time(final_path_stat)
                or not _is_regular_file_stat(final_path_stat)
            ):
                raise ValueError("bundle input path changed while being read")
    finally:
        view.release()

    return data, digest.hexdigest()


def _compression_name(code: int) -> str:
    names = {0: "none", 1: "lzma", 2: "lz4", 3: "lz4hc"}
    try:
        return names[code]
    except KeyError as exc:
        raise ValueError(f"unsupported UnityFS compression code {code}") from exc


def _check_compression_sizes(
    compressed_size: int,
    uncompressed_size: int,
    *,
    limits: ExtractionLimits,
    what: str,
) -> None:
    if compressed_size < 0 or uncompressed_size < 0:
        raise ValueError(f"negative {what} size")
    if compressed_size == 0:
        if uncompressed_size != 0:
            raise ValueError(f"empty compressed {what} declares nonempty output")
        return
    if uncompressed_size > compressed_size * limits.max_compression_ratio:
        raise ValueError(f"{what} exceeds the configured decompression ratio")


def _safe_relative_path(value: str, limits: ExtractionLimits, *, label: str) -> str:
    if not value or len(value.encode("utf-8", "strict")) > limits.max_serialized_string_bytes:
        raise ValueError(f"{label} is empty or exceeds its byte limit")
    if value.startswith(("/", "\\")) or "\\" in value or ":" in value:
        raise ValueError(f"{label} is not a safe relative path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"{label} contains an unsafe path component")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError(f"{label} contains a control or surrogate character")
    return value


def _preflight_unityfs(
    raw: bytearray,
    limits: ExtractionLimits,
) -> tuple[
    memoryview,
    str,
    str,
    int,
    int,
    int,
    bytes,
    list[_Block],
    list[_Node],
    int,
    int,
    int,
    int,
]:
    raw_view = memoryview(raw)
    prefix_size = 10 if len(raw_view) >= 18 and raw_view[:10] == b"\x00" * 10 else 0
    bundle_view = raw_view[prefix_size:]
    if len(bundle_view) < 32 or bundle_view[:8].tobytes() != _UNITYFS_SIGNATURE:
        raw_view.release()
        raise ValueError("input is not a supported UnityFS bundle")

    cursor = _Cursor(bundle_view)
    signature = cursor.take_view(8).tobytes()
    if signature != _UNITYFS_SIGNATURE:
        raw_view.release()
        raise ValueError("invalid UnityFS signature")
    unityfs_version = cursor.u32()
    if unityfs_version != _UNITYFS_VERSION:
        raw_view.release()
        raise ValueError(f"unsupported UnityFS format version {unityfs_version}")
    player_version = cursor.cstring(64, encoding="ascii")
    unity_version = cursor.cstring(96, encoding="ascii")
    if not player_version or not unity_version:
        raw_view.release()
        raise ValueError("UnityFS player and engine versions must be present")
    declared_file_size = cursor.u64()
    metadata_compressed_size = cursor.u32()
    metadata_uncompressed_size = cursor.u32()
    archive_flags = cursor.u32()

    if declared_file_size != len(bundle_view):
        raw_view.release()
        raise ValueError("UnityFS declared file size does not exactly match the input")
    if archive_flags & ~_ARCHIVE_SUPPORTED_FLAGS:
        raw_view.release()
        raise ValueError("unsupported UnityFS archive flags")
    if not archive_flags & _ARCHIVE_BLOCKS_AND_DIRECTORY_COMBINED:
        raw_view.release()
        raise ValueError("UnityFS block and directory metadata are not combined")
    if archive_flags & _ARCHIVE_BLOCKS_INFO_AT_END:
        raw_view.release()
        raise ValueError("UnityFS metadata-at-end layout is unsupported")
    if metadata_compressed_size > limits.max_bundle_metadata_bytes:
        raw_view.release()
        raise ValueError("compressed UnityFS metadata exceeds its configured byte limit")
    if metadata_uncompressed_size > limits.max_bundle_metadata_bytes:
        raw_view.release()
        raise ValueError("uncompressed UnityFS metadata exceeds its configured byte limit")
    _check_compression_sizes(
        metadata_compressed_size,
        metadata_uncompressed_size,
        limits=limits,
        what="UnityFS metadata",
    )

    cursor.align(16, require_zero=True)
    metadata_offset = cursor.pos
    if metadata_compressed_size > cursor.remaining:
        raw_view.release()
        raise ValueError("UnityFS metadata block exceeds the input range")
    metadata_compressed = cursor.take_view(metadata_compressed_size)
    metadata_compression = archive_flags & _ARCHIVE_COMPRESSION_MASK
    metadata_bytes = _decompress_block(
        metadata_compressed,
        metadata_uncompressed_size,
        metadata_compression,
        limits,
        what="UnityFS metadata",
    )
    metadata_view = memoryview(metadata_bytes)
    metadata_cursor = _Cursor(metadata_view)

    content_hash = metadata_cursor.take_view(16).tobytes()
    block_count = metadata_cursor.i32()
    if block_count <= 0 or block_count > limits.max_block_count:
        raw_view.release()
        raise ValueError("UnityFS block count is outside the configured range")

    blocks: list[_Block] = []
    total_compressed = metadata_compressed_size
    total_uncompressed = metadata_uncompressed_size
    data_uncompressed = 0
    total_block_io = metadata_compressed_size + metadata_uncompressed_size
    for _ in range(block_count):
        uncompressed_size = metadata_cursor.u32()
        compressed_size = metadata_cursor.u32()
        flags = metadata_cursor.u16()
        if flags & ~_BLOCK_SUPPORTED_FLAGS:
            raw_view.release()
            raise ValueError("unsupported UnityFS data-block flags")
        compression_code = flags & _ARCHIVE_COMPRESSION_MASK
        compression_name = _compression_name(compression_code)
        if compression_code == 4:
            raw_view.release()
            raise ValueError("UnityFS LZHAM compression is unsupported")
        if compressed_size == 0 and uncompressed_size == 0:
            raw_view.release()
            raise ValueError("empty UnityFS data blocks are unsupported")
        _check_compression_sizes(
            compressed_size,
            uncompressed_size,
            limits=limits,
            what="UnityFS data block",
        )
        if compression_code == 0 and compressed_size != uncompressed_size:
            raw_view.release()
            raise ValueError("uncompressed UnityFS block has mismatched lengths")
        total_compressed += compressed_size
        total_uncompressed += uncompressed_size
        data_uncompressed += uncompressed_size
        total_block_io += compressed_size + uncompressed_size
        if total_block_io > limits.max_total_block_io_bytes:
            raw_view.release()
            raise ValueError("UnityFS compressed and decompressed block budget exceeded")
        blocks.append(
            _Block(
                compressed_offset=0,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                flags=flags,
                compression=compression_name,
            )
        )

    node_count = metadata_cursor.i32()
    if node_count <= 0 or node_count > limits.max_node_count:
        raw_view.release()
        raise ValueError("UnityFS node count is outside the configured range")
    if node_count > limits.max_serialized_files:
        raw_view.release()
        raise ValueError("UnityFS serialized node count exceeds its configured limit")
    nodes: list[_Node] = []
    seen_paths: set[str] = set()
    seen_paths_folded: set[str] = set()
    previous_node_end = 0
    for _ in range(node_count):
        offset = metadata_cursor.i64()
        size = metadata_cursor.i64()
        flags = metadata_cursor.u32()
        path = _safe_relative_path(
            metadata_cursor.cstring(limits.max_serialized_string_bytes, encoding="utf-8"),
            limits,
            label="UnityFS node path",
        )
        if offset < 0 or size <= 0 or offset + size > data_uncompressed:
            raw_view.release()
            raise ValueError("UnityFS node range is outside decompressed blocks")
        if offset < previous_node_end:
            raw_view.release()
            raise ValueError("UnityFS node ranges overlap or are out of order")
        previous_node_end = offset + size
        if flags != _NODE_SERIALIZED_FLAG:
            raw_view.release()
            raise ValueError(f"unsupported UnityFS node flags 0x{flags:x}")
        folded = path.casefold()
        if path in seen_paths or folded in seen_paths_folded:
            raw_view.release()
            raise ValueError("duplicate or case-ambiguous UnityFS node path")
        seen_paths.add(path)
        seen_paths_folded.add(folded)
        nodes.append(_Node(offset=offset, size=size, flags=flags, path=path))
    if metadata_cursor.remaining:
        raw_view.release()
        raise ValueError("unexpected trailing bytes in UnityFS block metadata")

    cursor.align(16, require_zero=True)
    block_data_start = cursor.pos
    expected_block_data_bytes = sum(block.compressed_size for block in blocks)
    if expected_block_data_bytes != cursor.remaining:
        raw_view.release()
        raise ValueError("UnityFS block data does not exactly fill the declared file")
    positioned_blocks: list[_Block] = []
    block_offset = block_data_start
    for block in blocks:
        positioned_blocks.append(
            _Block(
                compressed_offset=block_offset,
                compressed_size=block.compressed_size,
                uncompressed_size=block.uncompressed_size,
                flags=block.flags,
                compression=block.compression,
            )
        )
        block_offset += block.compressed_size
    if block_offset != len(bundle_view):
        raw_view.release()
        raise ValueError("UnityFS compressed block ranges do not end at the declared file boundary")

    total_io_bytes = total_compressed + total_uncompressed
    if total_io_bytes != total_block_io or total_io_bytes > limits.max_total_block_io_bytes:
        raw_view.release()
        raise ValueError("UnityFS aggregate block budget exceeded")
    return (
        raw_view,
        player_version,
        unity_version,
        unityfs_version,
        prefix_size,
        archive_flags,
        content_hash,
        positioned_blocks,
        nodes,
        total_compressed,
        total_uncompressed,
        metadata_offset,
        total_io_bytes,
    )


def _decompress_lzma(
    compressed: memoryview,
    expected_size: int,
    limits: ExtractionLimits,
    *,
    what: str,
) -> tuple[bytearray, int]:
    if len(compressed) < 6:
        raise ValueError(f"{what} LZMA block is too short")
    properties = compressed[0]
    dictionary_size = struct.unpack_from("<I", compressed, 1)[0]
    if properties >= 9 * 5 * 5:
        raise ValueError(f"{what} LZMA properties are invalid")
    lc = properties % 9
    remainder = properties // 9
    pb = remainder // 5
    lp = remainder % 5
    if lc > 8 or lp > 4 or pb > 4 or lc + lp > 4:
        raise ValueError(f"{what} LZMA properties are unsupported")
    if dictionary_size < 4096 or dictionary_size > limits.max_lzma_dictionary_bytes:
        raise ValueError(f"{what} LZMA dictionary exceeds the configured limit")
    try:
        decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[
                {
                    "id": lzma.FILTER_LZMA1,
                    "dict_size": dictionary_size,
                    "lc": lc,
                    "lp": lp,
                    "pb": pb,
                }
            ],
        )
        try:
            output_buffer = bytearray(expected_size)
        except (MemoryError, OverflowError) as exc:
            raise ValueError(f"{what} output allocation exceeds available bounded memory") from exc
        pending: bytes | memoryview = compressed[5:]
        produced = 0
        while True:
            remaining = expected_size - produced
            # Small bounded chunks avoid retaining a second full-size copy when
            # joining decoder output. The extra byte detects a false size header.
            max_output = min(1024 * 1024, remaining + 1)
            output = decoder.decompress(pending, max_length=max_output)
            pending = b""
            if output:
                produced += len(output)
                if produced > expected_size:
                    raise ValueError(f"{what} LZMA output exceeds its declared size")
                output_buffer[produced - len(output) : produced] = output
            if decoder.eof:
                if decoder.unused_data:
                    raise ValueError(f"{what} LZMA stream contains trailing bytes")
                break
            if decoder.needs_input:
                raise ValueError(f"{what} LZMA stream ended before its output size")
            if not output:
                raise ValueError(f"{what} LZMA decoder made no progress")
        if produced != expected_size:
            raise ValueError(f"{what} LZMA output length does not match its declaration")
        return output_buffer, dictionary_size
    except lzma.LZMAError as exc:
        raise ValueError(f"invalid {what} LZMA stream") from exc


def _decompress_block(
    compressed: memoryview,
    expected_size: int,
    compression_code: int,
    limits: ExtractionLimits,
    *,
    what: str,
) -> bytes | bytearray:
    if expected_size < 0 or expected_size > limits.max_total_block_io_bytes:
        raise ValueError(f"{what} output exceeds the configured decompression limit")
    if compression_code == 0:
        if len(compressed) != expected_size:
            raise ValueError(f"{what} uncompressed length mismatch")
        return compressed.tobytes()
    if compression_code == 1:
        result, _dictionary_size = _decompress_lzma(compressed, expected_size, limits, what=what)
        return result
    if compression_code in (2, 3):
        try:
            import lz4.block

            result = lz4.block.decompress(compressed, uncompressed_size=expected_size)
        except Exception as exc:
            raise ValueError(f"invalid {what} LZ4 block") from exc
        if len(result) != expected_size:
            raise ValueError(f"{what} LZ4 output length does not match its declaration")
        return result
    raise ValueError(f"unsupported {what} compression code {compression_code}")


def _load_common_strings() -> dict[int, str]:
    try:
        from UnityPy.helpers.TypeTreeNode import get_common_strings

        common_strings = get_common_strings()
    except Exception as exc:
        raise ValueError("could not load UnityPy's bundled Unity common-string table") from exc
    return common_strings


def _runtime_versions() -> dict[str, str]:
    try:
        unitypy_version = importlib.metadata.version("UnityPy")
    except importlib.metadata.PackageNotFoundError as exc:
        raise ValueError("UnityPy version metadata is unavailable for the extraction report") from exc
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "unitypy_version": unitypy_version,
    }


def _read_tree_blob(
    cursor: _Cursor,
    *,
    class_id: int,
    is_ref_type: bool,
    common_strings: dict[int, str],
    limits: ExtractionLimits,
    counters: dict[str, int],
) -> _TypeTreeNode | None:
    node_count = cursor.i32()
    string_buffer_size = cursor.i32()
    if node_count <= 0 or node_count > limits.max_type_tree_nodes_per_file:
        raise ValueError("SerializedFile type-tree node count is outside the configured range")
    if string_buffer_size < 0 or string_buffer_size > limits.max_typetree_string_buffer_bytes:
        raise ValueError("SerializedFile type-tree string buffer exceeds its configured limit")
    counters["type_tree_nodes"] += node_count
    counters["type_tree_string_bytes"] += string_buffer_size
    if counters["type_tree_nodes"] > limits.max_total_type_tree_nodes:
        raise ValueError("aggregate SerializedFile type-tree node limit exceeded")
    if counters["type_tree_string_bytes"] > limits.max_serialized_metadata_bytes:
        raise ValueError("aggregate SerializedFile type-tree string budget exceeded")

    record_size = 32  # format 22, LSB serialized type-tree node records
    record_bytes = cursor.take_view(node_count * record_size)
    string_buffer = cursor.take_view(string_buffer_size)

    def resolve_string(offset: int) -> str:
        if offset & 0x80000000:
            common_offset = offset & 0x7FFFFFFF
            try:
                result = common_strings[common_offset]
            except KeyError as exc:
                raise ValueError("type tree refers to an unknown Unity common string") from exc
            if len(result.encode("utf-8", "strict")) > limits.max_serialized_string_bytes:
                raise ValueError("Unity common string exceeds the configured string limit")
            return result
        if offset >= len(string_buffer):
            raise ValueError("type-tree string offset is outside its string buffer")
        end = offset
        max_end = min(len(string_buffer), offset + limits.max_serialized_string_bytes + 1)
        while end < max_end and string_buffer[end] != 0:
            end += 1
        if end >= max_end or end >= len(string_buffer):
            raise ValueError("type-tree string is unterminated or overlong")
        try:
            return string_buffer[offset:end].tobytes().decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("type-tree string is not valid UTF-8") from exc

    keep_records = class_id == _TEXT_ASSET_CLASS_ID and not is_ref_type
    records: list[tuple[int, str, str, int, int]] = []
    record_struct = struct.Struct(cursor.endian + "hBBIIiiiQ")
    previous_level = -1
    for raw_record in record_struct.iter_unpack(record_bytes):
        _version, level, _type_flags, type_offset, name_offset, byte_size, _index, meta_flags, _ref_hash = raw_record
        if level > 64 or level > previous_level + 1:
            raise ValueError("type-tree hierarchy has an invalid depth jump")
        if previous_level == -1 and level != 0:
            raise ValueError("type-tree root level is invalid")
        type_name = resolve_string(type_offset)
        name = resolve_string(name_offset)
        if any(unicodedata.category(char).startswith("C") for char in type_name + name):
            raise ValueError("type-tree name contains a control or surrogate character")
        if keep_records:
            records.append((level, type_name, name, byte_size, meta_flags))
        previous_level = level

    if not keep_records:
        return None

    root: _TypeTreeNode | None = None
    stack: list[_TypeTreeNode] = []
    for level, type_name, name, byte_size, meta_flags in records:
        node = _TypeTreeNode(level, type_name, name, byte_size, meta_flags, [])
        if level == 0:
            if root is not None:
                raise ValueError("TextAsset type tree has multiple roots")
            root = node
            stack = [node]
            continue
        while stack and stack[-1].level >= level:
            stack.pop()
        if not stack or stack[-1].level != level - 1:
            raise ValueError("TextAsset type-tree parent chain is invalid")
        stack[-1].children.append(node)
        stack.append(node)
    if root is None:
        raise ValueError("TextAsset type tree is empty")
    return root


def _validate_textasset_tree(tree: _TypeTreeNode) -> None:
    if tree.type_name != "TextAsset":
        raise ValueError("embedded class-49 type tree is not a TextAsset")
    if len(tree.children) != 2 or [node.name for node in tree.children] != ["m_Name", "m_Script"]:
        raise ValueError("TextAsset type tree must declare only m_Name followed by m_Script")

    for field_name, node in zip(("m_Name", "m_Script"), tree.children, strict=True):
        if node.type_name != "string" or len(node.children) != 1:
            raise ValueError(f"TextAsset {field_name} must use the supported Unity string type")
        array = node.children[0]
        if array.type_name != "Array" or array.name != "Array" or len(array.children) != 2:
            raise ValueError(f"TextAsset {field_name} has an unsupported Unity string array tree")
        size_node, data_node = array.children
        if (
            size_node.type_name != "int"
            or size_node.name != "size"
            or size_node.children
            or data_node.type_name not in ("char", "UInt8", "SInt8")
            or data_node.name != "data"
            or data_node.children
        ):
            raise ValueError(f"TextAsset {field_name} has an incomplete Unity string declaration")


def _read_serialized_type(
    cursor: _Cursor,
    *,
    format_version: int,
    tree_enabled: bool,
    is_ref_type: bool,
    common_strings: dict[int, str],
    limits: ExtractionLimits,
    counters: dict[str, int],
) -> _TypeInfo:
    class_id = cursor.i32()
    is_stripped = cursor.u8()
    if is_stripped not in (0, 1):
        raise ValueError("invalid SerializedFile type stripped flag")
    script_type_index = cursor.i16()
    if format_version >= 13:
        if (is_ref_type and script_type_index >= 0) or (format_version < 16 and class_id < 0) or (
            format_version >= 16 and class_id == 114
        ):
            cursor.skip(16)
        cursor.skip(16)  # old type hash

    tree = None
    if tree_enabled:
        tree = _read_tree_blob(
            cursor,
            class_id=class_id,
            is_ref_type=is_ref_type,
            common_strings=common_strings,
            limits=limits,
            counters=counters,
        )
        if format_version >= 21:
            if is_ref_type:
                cursor.cstring(limits.max_serialized_string_bytes)
                cursor.cstring(limits.max_serialized_string_bytes)
                cursor.cstring(limits.max_serialized_string_bytes)
            else:
                dependency_count = cursor.i32()
                if dependency_count < 0 or dependency_count > limits.max_type_dependencies:
                    raise ValueError("SerializedFile type dependency count exceeds its configured limit")
                counters["type_dependencies"] += dependency_count
                if counters["type_dependencies"] > limits.max_type_dependencies:
                    raise ValueError("aggregate SerializedFile type dependency limit exceeded")
                cursor.skip(dependency_count * 4)
    if class_id == _TEXT_ASSET_CLASS_ID and not is_ref_type:
        if tree is None:
            raise ValueError("TextAsset class has no embedded type tree")
        _validate_textasset_tree(tree)
    return _TypeInfo(class_id=class_id, tree=tree)


def _preflight_serialized_file(
    data: memoryview,
    *,
    entry_name: str,
    limits: ExtractionLimits,
    aggregate: dict[str, int],
) -> _SerializedInfo:
    if len(data) < 48:
        raise ValueError(f"serialized node {entry_name!r} is shorter than a v22 header")
    header = _Cursor(data, endian=">")
    legacy_metadata_size = header.u32()
    legacy_file_size = header.u32()
    format_version = header.u32()
    legacy_data_offset = header.u32()
    if format_version != _SERIALIZED_FORMAT_VERSION:
        raise ValueError(f"unsupported SerializedFile format version {format_version}")
    byte_order = header.u8()
    reserved = header.take_view(3).tobytes()
    if byte_order not in (0, 1) or reserved != b"\x00\x00\x00":
        raise ValueError("invalid SerializedFile endian marker or reserved bytes")
    endian = "<" if byte_order == 0 else ">"
    header.endian = ">"  # v22 extended header integers are big-endian.
    metadata_size = header.u32()
    file_size = header.u64()
    data_offset = header.u64()
    unknown_header_value = header.u64()
    _ = unknown_header_value

    if file_size != len(data):
        raise ValueError("SerializedFile declared size does not match its UnityFS node")
    if legacy_metadata_size not in (0, metadata_size):
        raise ValueError("legacy and v22 SerializedFile metadata sizes disagree")
    if legacy_file_size not in (0, file_size & 0xFFFFFFFF):
        raise ValueError("legacy and v22 SerializedFile file sizes disagree")
    if legacy_data_offset not in (0, data_offset & 0xFFFFFFFF):
        raise ValueError("legacy and v22 SerializedFile data offsets disagree")
    metadata_end = 48 + metadata_size
    if metadata_size > limits.max_serialized_metadata_bytes:
        raise ValueError("SerializedFile metadata exceeds its configured byte limit")
    if metadata_end > len(data) or data_offset < metadata_end or data_offset > len(data):
        raise ValueError("SerializedFile metadata or data offsets are out of range")
    expected_data_offset = (metadata_end + 15) & ~15
    if data_offset != expected_data_offset:
        raise ValueError("SerializedFile data offset does not match supported 16-byte alignment")
    if any(data[metadata_end:data_offset]):
        raise ValueError("SerializedFile alignment padding is not zero-filled")

    cursor = _Cursor(data, endian=endian, end=metadata_end)
    cursor.pos = 48
    unity_version = cursor.cstring(96, encoding="ascii")
    if not unity_version:
        raise ValueError("SerializedFile Unity version is empty")
    _target_platform = cursor.i32()
    tree_enabled_byte = cursor.u8()
    if tree_enabled_byte not in (0, 1):
        raise ValueError("invalid SerializedFile type-tree enable flag")
    tree_enabled = bool(tree_enabled_byte)
    type_count = cursor.i32()
    if type_count <= 0 or type_count > limits.max_types_per_file:
        raise ValueError("SerializedFile type count is outside the configured range")

    common_strings = _load_common_strings()
    counters = {"type_tree_nodes": 0, "type_tree_string_bytes": 0, "type_dependencies": 0}
    types = tuple(
        _read_serialized_type(
            cursor,
            format_version=format_version,
            tree_enabled=tree_enabled,
            is_ref_type=False,
            common_strings=common_strings,
            limits=limits,
            counters=counters,
        )
        for _ in range(type_count)
    )

    object_count = cursor.i32()
    if object_count < 0 or object_count > limits.max_objects_per_file:
        raise ValueError("SerializedFile object count exceeds its configured limit")
    aggregate["objects"] += object_count
    if aggregate["objects"] > limits.max_total_objects:
        raise ValueError("aggregate SerializedFile object count exceeds its configured limit")

    objects: list[_SerializedObject] = []
    path_ids: set[int] = set()
    ranges: list[tuple[int, int]] = []
    text_asset_count = 0
    for _ in range(object_count):
        cursor.align(4)
        path_id = cursor.i64()
        relative_start = cursor.i64()
        byte_size = cursor.u32()
        type_id = cursor.i32()
        if type_id < 0 or type_id >= len(types):
            raise ValueError("SerializedFile object refers to an invalid type index")
        if relative_start < 0 or byte_size <= 0:
            raise ValueError("SerializedFile object has an invalid data range")
        byte_start = data_offset + relative_start
        byte_end = byte_start + byte_size
        if byte_start < data_offset or byte_end > file_size:
            raise ValueError("SerializedFile object data range is outside its node")
        if path_id in path_ids:
            raise ValueError("SerializedFile contains a duplicate object path ID")
        path_ids.add(path_id)
        class_id = types[type_id].class_id
        if class_id == _TEXT_ASSET_CLASS_ID:
            text_asset_count += 1
            aggregate["text_assets"] += 1
            if aggregate["text_assets"] > limits.max_text_assets:
                raise ValueError("aggregate TextAsset count exceeds its configured limit")
            if byte_size > limits.max_text_asset_object_bytes:
                raise ValueError("TextAsset serialized object exceeds its configured size limit")
        objects.append(
            _SerializedObject(
                path_id=path_id,
                type_id=type_id,
                class_id=class_id,
                byte_start=byte_start,
                byte_size=byte_size,
            )
        )
        ranges.append((byte_start, byte_end))

    ranges.sort()
    previous_end = data_offset
    for start, end in ranges:
        if start < previous_end:
            raise ValueError("SerializedFile object data ranges overlap")
        previous_end = end

    if format_version >= 11:
        script_count = cursor.i32()
        if script_count < 0 or script_count > limits.max_script_types:
            raise ValueError("SerializedFile script-type count exceeds its configured limit")
        aggregate["script_types"] += script_count
        if aggregate["script_types"] > limits.max_script_types:
            raise ValueError("aggregate SerializedFile script-type count exceeds its configured limit")
        for _ in range(script_count):
            cursor.i32()
            cursor.align(4)
            cursor.i64()

    external_count = cursor.i32()
    if external_count < 0 or external_count > limits.max_external_files:
        raise ValueError("SerializedFile external-file count exceeds its configured limit")
    aggregate["external_files"] += external_count
    if aggregate["external_files"] > limits.max_external_files:
        raise ValueError("aggregate SerializedFile external-file count exceeds its configured limit")
    for _ in range(external_count):
        cursor.cstring(limits.max_serialized_string_bytes)
        cursor.skip(16)  # GUID
        cursor.i32()  # external file type
        cursor.cstring(limits.max_serialized_string_bytes)

    ref_type_count = cursor.i32()
    if ref_type_count < 0 or ref_type_count > limits.max_types_per_file:
        raise ValueError("SerializedFile reference-type count exceeds its configured limit")
    aggregate["ref_types"] += ref_type_count
    if aggregate["ref_types"] > limits.max_types_per_file:
        raise ValueError("aggregate SerializedFile reference-type count exceeds its configured limit")
    for _ in range(ref_type_count):
        _read_serialized_type(
            cursor,
            format_version=format_version,
            tree_enabled=tree_enabled,
            is_ref_type=True,
            common_strings=common_strings,
            limits=limits,
            counters=counters,
        )

    cursor.cstring(limits.max_serialized_string_bytes)  # userInformation
    if cursor.pos != metadata_end:
        raise ValueError("SerializedFile metadata length does not match its parsed structures")

    type_tree_node_count = counters["type_tree_nodes"]
    aggregate["type_tree_nodes"] += type_tree_node_count
    if aggregate["type_tree_nodes"] > limits.max_total_type_tree_nodes:
        raise ValueError("aggregate SerializedFile type-tree node count exceeds its limit")
    if text_asset_count and not tree_enabled:
        raise ValueError("TextAsset extraction requires embedded serialized type trees")
    return _SerializedInfo(
        unity_version=unity_version,
        format_version=format_version,
        data_offset=data_offset,
        object_count=object_count,
        text_asset_count=text_asset_count,
        type_count=type_count,
        type_tree_node_count=type_tree_node_count,
        objects=tuple(objects),
        types=types,
    )


_SCALAR_SIZES = {
    "SInt8": 1,
    "UInt8": 1,
    "char": 1,
    "bool": 1,
    "short": 2,
    "SInt16": 2,
    "unsigned short": 2,
    "UInt16": 2,
    "int": 4,
    "SInt32": 4,
    "unsigned int": 4,
    "UInt32": 4,
    "Type*": 4,
    "float": 4,
    "long long": 8,
    "SInt64": 8,
    "unsigned long long": 8,
    "UInt64": 8,
    "FileSize": 8,
    "double": 8,
}


def _parse_textasset_value(
    node: _TypeTreeNode,
    cursor: _Cursor,
    *,
    limits: ExtractionLimits,
    captures: dict[str, str | bytes | None],
    capture_script: bool,
    depth: int = 0,
) -> None:
    if depth > 64:
        raise ValueError("TextAsset type tree exceeds the supported nesting depth")
    name = node.name
    node_type = node.type_name
    value: str | bytes | None = None

    if node_type in _SCALAR_SIZES:
        cursor.skip(_SCALAR_SIZES[node_type])
    elif node_type == "string":
        size = cursor.i32()
        if size < 0 or size > limits.max_text_asset_object_bytes:
            raise ValueError("TextAsset string length exceeds its configured limit")
        if name == "m_Name" and size > limits.max_serialized_string_bytes:
            raise ValueError("TextAsset m_Name exceeds its configured string limit")
        if name == "m_Script" and capture_script and size > limits.max_protocol_asset_bytes:
            raise ValueError("protocol TextAsset string exceeds its per-asset byte limit")
        raw_string = cursor.take_view(size)
        if name == "m_Name":
            try:
                value = raw_string.tobytes().decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise ValueError("TextAsset m_Name is not valid UTF-8") from exc
        elif name == "m_Script" and capture_script:
            value = raw_string.tobytes()
        if size > 0:
            cursor.align(4)
    elif node_type == "TypelessData":
        size = cursor.i32()
        if size < 0 or size > cursor.remaining:
            raise ValueError("TextAsset typeless-data length exceeds its object range")
        if name == "m_Script" and capture_script and size > limits.max_protocol_asset_bytes:
            raise ValueError("protocol TextAsset data exceeds its per-asset byte limit")
        payload = cursor.take_view(size)
        if name == "m_Script" and capture_script:
            value = payload.tobytes()
    elif node_type == "pair":
        if len(node.children) != 2:
            raise ValueError("TextAsset type tree contains an unsupported pair")
        for child in node.children:
            _parse_textasset_value(
                child,
                cursor,
                limits=limits,
                captures=captures,
                capture_script=capture_script,
                depth=depth + 1,
            )
    elif node.children and node.children[0].type_name == "Array":
        array = node.children[0]
        if len(array.children) < 2:
            raise ValueError("TextAsset vector has a malformed Array node")
        count = cursor.i32()
        if count < 0 or count > limits.max_array_items:
            raise ValueError("TextAsset array length exceeds its configured limit")
        subtype = array.children[1]
        if name == "m_Script" and subtype.type_name in ("UInt8", "char", "SInt8"):
            if count > cursor.remaining:
                raise ValueError("TextAsset script byte array exceeds its object range")
            if capture_script and count > limits.max_protocol_asset_bytes:
                raise ValueError("protocol TextAsset byte array exceeds its per-asset byte limit")
            payload = cursor.take_view(count)
            if capture_script:
                value = payload.tobytes()
        elif subtype.type_name in _SCALAR_SIZES:
            width = _SCALAR_SIZES[subtype.type_name]
            if count > cursor.remaining // width:
                raise ValueError("TextAsset primitive array exceeds its object range")
            cursor.skip(count * width)
        else:
            minimum_size = 1 if subtype.type_name in ("string", "TypelessData") else 0
            if minimum_size and count > cursor.remaining // minimum_size:
                raise ValueError("TextAsset variable-size array exceeds its object range")
            for _ in range(count):
                _parse_textasset_value(
                    subtype,
                    cursor,
                    limits=limits,
                    captures=captures,
                    capture_script=capture_script,
                    depth=depth + 1,
                )
        if array.meta_flags & _METAFLAG_ALIGNED:
            cursor.align(4)
    elif node_type.startswith("PPtr<"):
        for child in node.children:
            _parse_textasset_value(
                child,
                cursor,
                limits=limits,
                captures=captures,
                capture_script=capture_script,
                depth=depth + 1,
            )
    elif node.children:
        for child in node.children:
            _parse_textasset_value(
                child,
                cursor,
                limits=limits,
                captures=captures,
                capture_script=capture_script,
                depth=depth + 1,
            )
    else:
        raise ValueError(f"unsupported TextAsset type-tree value {node_type!r}")

    if name == "m_Name":
        if not isinstance(value, str):
            raise ValueError("TextAsset m_Name was not parsed as a string")
        if "name" in captures:
            raise ValueError("TextAsset object contains duplicate m_Name values")
        captures["name"] = value
    elif name == "m_Script":
        if capture_script:
            if not isinstance(value, bytes):
                raise ValueError("TextAsset m_Script was not parsed as byte data")
            if "script" in captures:
                raise ValueError("TextAsset object contains duplicate m_Script values")
            captures["script"] = value
        else:
            captures["script"] = None

    if node.meta_flags & _METAFLAG_ALIGNED:
        cursor.align(4)


def _parse_text_asset(
    node_data: memoryview,
    obj: _SerializedObject,
    tree: _TypeTreeNode,
    *,
    entry_name: str,
    limits: ExtractionLimits,
    capture_script: bool,
) -> tuple[str, bytes | None]:
    object_view = node_data[obj.byte_start : obj.byte_start + obj.byte_size]
    if len(object_view) != obj.byte_size:
        raise ValueError("TextAsset object view does not match its declared size")
    cursor = _Cursor(object_view, endian="<", base_offset=obj.byte_start)
    captures: dict[str, str | bytes | None] = {}
    _parse_textasset_value(
        tree,
        cursor,
        limits=limits,
        captures=captures,
        capture_script=capture_script,
    )
    if cursor.pos != obj.byte_size:
        raise ValueError(f"TextAsset object in {entry_name!r} has unparsed trailing bytes")
    name = captures.get("name")
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError("TextAsset object has an invalid m_Name")
    script = captures.get("script") if capture_script else None
    if capture_script and not isinstance(script, bytes):
        raise ValueError("TextAsset object has no byte-preserving m_Script value")
    return name, script if isinstance(script, bytes) else None


def _is_protocol_name(name: str) -> bool:
    return name.endswith("_pb.lua") or name in ("netproto.lua", "netproto_pb.lua")


def _validate_protocol_name(name: str, limits: ExtractionLimits) -> None:
    encoded = name.encode("utf-8", "strict")
    if len(encoded) > limits.max_serialized_string_bytes or len(name) > 255:
        raise ValueError("protocol TextAsset name exceeds its configured limit")
    if name in (".", "..") or name.startswith(("/", "\\")) or "\\" in name or "/" in name or ":" in name:
        raise ValueError("protocol TextAsset name is not a safe basename")
    if name.rstrip(" .") != name or any(unicodedata.category(char).startswith("C") for char in name):
        raise ValueError("protocol TextAsset name contains unsafe characters")
    if not name.isascii():
        raise ValueError("protocol TextAsset name must use ASCII characters")


def _slice_node(
    blocks: list[bytes | bytearray],
    block_ranges: list[tuple[int, int]],
    node: _Node,
    limits: ExtractionLimits,
) -> memoryview:
    node_end = node.offset + node.size
    for block, (start, end) in zip(blocks, block_ranges, strict=True):
        if start <= node.offset and node_end <= end:
            return memoryview(block)[node.offset - start : node_end - start]
    if node.size > limits.max_cross_block_node_copy_bytes:
        raise ValueError("serialized node crosses block boundaries beyond the copy limit")
    copied = bytearray(node.size)
    copied_view = memoryview(copied)
    written = 0
    for block, (start, end) in zip(blocks, block_ranges, strict=True):
        overlap_start = max(start, node.offset)
        overlap_end = min(end, node_end)
        if overlap_start >= overlap_end:
            continue
        length = overlap_end - overlap_start
        source_start = overlap_start - start
        target_start = overlap_start - node.offset
        copied_view[target_start : target_start + length] = memoryview(block)[source_start : source_start + length]
        written += length
    if written != node.size:
        copied_view.release()
        raise ValueError("serialized node range is not fully covered by decompressed blocks")
    result = copied_view.toreadonly()
    copied_view.release()
    return result


def extract_bundle(
    path: Path,
    expected_sha256: str,
    limits: ExtractionLimits = ExtractionLimits(),
) -> ExtractedBundle:
    """Extract all protocol TextAssets after bounded static container parsing."""

    if not isinstance(expected_sha256, str) or _SHA256_RE.fullmatch(expected_sha256) is None:
        raise ValueError("expected_sha256 must be 64 lowercase hexadecimal characters")
    if not isinstance(limits, ExtractionLimits):
        raise TypeError("limits must be an ExtractionLimits instance")
    input_path = Path(path)
    raw, bundle_sha256 = _read_regular_file(input_path, limits)
    if bundle_sha256 != expected_sha256:
        raise ValueError("bundle SHA-256 does not match the expected fingerprint")

    (
        raw_view,
        player_version,
        unity_version,
        unityfs_version,
        prefix_size,
        archive_flags,
        content_hash,
        blocks,
        nodes,
        total_compressed_bytes,
        total_uncompressed_bytes,
        metadata_offset,
        total_block_io_bytes,
    ) = _preflight_unityfs(raw, limits)

    bundle_view = raw_view[prefix_size:]
    try:
        decompressed_blocks: list[bytes | bytearray] = []
        block_ranges: list[tuple[int, int]] = []
        logical_offset = 0
        for index, block in enumerate(blocks):
            if len(blocks) > 1 and block.uncompressed_size > 64 * 1024 * 1024:
                raise ValueError("multi-block UnityFS contains a block larger than the supported per-block budget")
            compressed_view = bundle_view[
                block.compressed_offset : block.compressed_offset + block.compressed_size
            ]
            decompressed = _decompress_block(
                compressed_view,
                block.uncompressed_size,
                block.flags & _ARCHIVE_COMPRESSION_MASK,
                limits,
                what=f"UnityFS data block {index}",
            )
            start = logical_offset
            logical_offset += len(decompressed)
            decompressed_blocks.append(decompressed)
            block_ranges.append((start, logical_offset))
        expected_data_bytes = sum(block.uncompressed_size for block in blocks)
        if logical_offset != expected_data_bytes:
            raise ValueError("decompressed UnityFS block total does not match the block table")

        aggregate = {"objects": 0, "text_assets": 0, "script_types": 0, "external_files": 0, "ref_types": 0, "type_tree_nodes": 0}
        serialized_reports: list[dict[str, Any]] = []
        protocol_assets: dict[str, bytes] = {}
        asset_locations: dict[str, dict[str, Any]] = {}
        folded_protocol_names: set[str] = set()
        total_protocol_bytes = 0
        text_asset_count = 0

        protocol_source_entries: set[str] = set()

        for node in nodes:
            node_view = _slice_node(decompressed_blocks, block_ranges, node, limits)
            try:
                serialized = _preflight_serialized_file(
                    node_view,
                    entry_name=node.path,
                    limits=limits,
                    aggregate=aggregate,
                )
                if serialized.unity_version != unity_version:
                    raise ValueError(
                        f"SerializedFile version in {node.path!r} does not match the UnityFS engine version"
                    )
                text_asset_count += serialized.text_asset_count
                for obj in serialized.objects:
                    if obj.class_id != _TEXT_ASSET_CLASS_ID:
                        continue
                    type_info = serialized.types[obj.type_id]
                    if type_info.tree is None:
                        raise ValueError("TextAsset object has no validated type tree")
                    asset_name, _ = _parse_text_asset(
                        node_view,
                        obj,
                        type_info.tree,
                        entry_name=node.path,
                        limits=limits,
                        capture_script=False,
                    )
                    if not _is_protocol_name(asset_name):
                        continue
                    _validate_protocol_name(asset_name, limits)
                    folded = asset_name.casefold()
                    if folded in folded_protocol_names:
                        raise ValueError(f"duplicate or case-ambiguous protocol TextAsset name {asset_name!r}")
                    if len(protocol_assets) >= limits.max_protocol_assets:
                        raise ValueError("protocol TextAsset count exceeds its configured limit")
                    if obj.byte_size > limits.max_text_asset_object_bytes:
                        raise ValueError("protocol TextAsset source object exceeds its configured size limit")
                    protocol_source_entries.add(node.path)
                    asset_name_again, script_bytes = _parse_text_asset(
                        node_view,
                        obj,
                        type_info.tree,
                        entry_name=node.path,
                        limits=limits,
                        capture_script=True,
                    )
                    if asset_name_again != asset_name or script_bytes is None:
                        raise ValueError("TextAsset name or script changed between bounded parsing passes")
                    if len(script_bytes) > limits.max_protocol_asset_bytes:
                        raise ValueError("protocol TextAsset bytecode exceeds its per-asset byte limit")
                    total_protocol_bytes += len(script_bytes)
                    if total_protocol_bytes > limits.max_total_protocol_bytes:
                        raise ValueError("aggregate protocol TextAsset bytes exceed their configured limit")
                    protocol_assets[asset_name] = script_bytes
                    folded_protocol_names.add(folded)
                    asset_locations[asset_name] = {
                        "entry": node.path,
                        "object": "TextAsset",
                        "path_id": obj.path_id,
                        "byte_start": obj.byte_start,
                        "byte_size": obj.byte_size,
                        "bundle_uncompressed_byte_start": node.offset + obj.byte_start,
                    }

                serialized_reports.append(
                    {
                        "entry_name": node.path,
                        "unity_version": serialized.unity_version,
                        "format_version": serialized.format_version,
                        "object_count": serialized.object_count,
                        "type_count": serialized.type_count,
                        "type_tree_node_count": serialized.type_tree_node_count,
                        "text_asset_count": serialized.text_asset_count,
                    }
                )
            finally:
                node_view.release()

        if not protocol_assets:
            raise ValueError("no protocol TextAssets matched the supported filename patterns")
        if len(protocol_source_entries) != 1:
            raise ValueError("protocol TextAssets span multiple serialized entries; entry_name would be ambiguous")
        entry_name = next(iter(protocol_source_entries))

        data_block_compressed_bytes = sum(block.compressed_size for block in blocks)
        data_block_uncompressed_bytes = sum(block.uncompressed_size for block in blocks)
        metadata_compressed_bytes = total_compressed_bytes - data_block_compressed_bytes
        metadata_uncompressed_bytes = total_uncompressed_bytes - data_block_uncompressed_bytes
        budget_limits = asdict(limits)
        budget_used = {
            "input_bytes": len(raw),
            "bundle_metadata_offset": metadata_offset,
            "compressed_metadata_bytes": metadata_compressed_bytes,
            "uncompressed_metadata_bytes": metadata_uncompressed_bytes,
            "compressed_data_block_bytes": data_block_compressed_bytes,
            "uncompressed_data_block_bytes": data_block_uncompressed_bytes,
            "compressed_plus_uncompressed_charged_bytes": total_block_io_bytes,
            "block_count": len(blocks),
            "node_count": len(nodes),
            "serialized_file_count": len(serialized_reports),
            "object_count": aggregate["objects"],
            "text_asset_count": text_asset_count,
            "protocol_asset_count": len(protocol_assets),
            "protocol_bytes": total_protocol_bytes,
        }
        container_metadata = {
            "signature": "UnityFS",
            "unityfs_version": unityfs_version,
            "player_version": player_version,
            "unity_version": unity_version,
            "prefix_bytes": prefix_size,
            "declared_file_bytes": len(bundle_view),
            "archive_flags": archive_flags,
            "content_hash": content_hash.hex(),
            "nodes": [
                {
                    "path": node.path,
                    "offset": node.offset,
                    "size": node.size,
                    "flags": node.flags,
                }
                for node in nodes
            ],
            "blocks": [
                {
                    "index": index,
                    "compression": block.compression,
                    "flags": block.flags,
                    "compressed_bytes": block.compressed_size,
                    "uncompressed_bytes": block.uncompressed_size,
                }
                for index, block in enumerate(blocks)
            ],
        }
        runtime_versions = _runtime_versions()

        metadata: dict[str, Any] = {
            "source": {
                "bundle_sha256": bundle_sha256,
                "entry_name": entry_name,
                "expected_sha256_verified": True,
            },
            "bundle": {
                "sha256": bundle_sha256,
                "unityfs_version": unityfs_version,
                "player_version": player_version,
                "unity_version": unity_version,
                **runtime_versions,
                "parser": "bounded static UnityFS and SerializedFile v22 parser",
                "unitypy_usage": "Unity common-string table only; no AssetBundle deserialization",
                "container": container_metadata,
                "serialized_files": serialized_reports,
                "preflight": {
                    "limits": budget_limits,
                    "used": budget_used,
                },
            },
            "container": container_metadata,
            "serialized_files": serialized_reports,
            "budgets": {
                "limits": budget_limits,
                "used": budget_used,
            },
        }
        return ExtractedBundle(
            bundle_sha256=bundle_sha256,
            entry_name=entry_name,
            unity_version=unity_version,
            unityfs_version=unityfs_version,
            text_asset_count=text_asset_count,
            protocol_assets=protocol_assets,
            metadata=metadata,
            asset_locations=asset_locations,
        )
    finally:
        raw_view.release()
