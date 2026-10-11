from __future__ import annotations

import hashlib
import lzma
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from v5_server.tools.static_protocol import extract
from v5_server.tools.static_protocol.bundle import ExtractionLimits


def _pad(data: bytearray, alignment: int) -> None:
    data.extend(b"\x00" * ((-len(data)) & (alignment - 1)))


def _unityfs_fixture(
    *,
    data_uncompressed_size: int = 1,
    data_payload: bytes = b"\x00",
    block_flags: int = 0,
    archive_flags: int = 0x40,
    declared_size_delta: int = 0,
) -> bytes:
    """Make a small UnityFS v8 container with one block and one node."""

    if block_flags & 0x3F == 0 and len(data_payload) != data_uncompressed_size:
        raise ValueError("an uncompressed fixture block must have equal lengths")
    metadata = bytearray(b"\x00" * 16)
    metadata.extend(struct.pack(">iIIH", 1, data_uncompressed_size, len(data_payload), block_flags))
    metadata.extend(struct.pack(">iqqI", 1, 0, data_uncompressed_size, 4))
    metadata.extend(b"CAB-test\x00")

    prefix = b"UnityFS\x00" + struct.pack(">I", 8) + b"5.x.x\x00" + b"2022.3.62f3c1\x00"
    header = bytearray(prefix)
    header.extend(struct.pack(">QIII", 0, len(metadata), len(metadata), archive_flags))
    bundle = header
    _pad(bundle, 16)
    bundle.extend(metadata)
    _pad(bundle, 16)
    bundle.extend(data_payload)
    struct.pack_into(">Q", bundle, len(prefix), len(bundle) + declared_size_delta)
    return bytes(bundle)


def _raw_lzma_block(data: bytes, *, dictionary_size: int = 4096, trailing: bytes = b"") -> bytes:
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": dictionary_size,
            "lc": 3,
            "lp": 0,
            "pb": 2,
        }
    ]
    raw_stream = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    # Unity stores the LZMA1 property byte and dictionary size before the raw stream.
    return b"\x5d" + struct.pack("<I", dictionary_size) + raw_stream + trailing


def _serialized_fixture(*, relative_start: int = 0, extra_tree_field: bool = False) -> bytes:
    """Build a small format-v22 file containing one TextAsset declaration."""

    string_buffer = bytearray()
    string_offsets: dict[str, int] = {}

    def add_string(value: str) -> int:
        if value not in string_offsets:
            string_offsets[value] = len(string_buffer)
            string_buffer.extend(value.encode("ascii") + b"\x00")
        return string_offsets[value]

    records = [
        (0, "TextAsset", "Base"),
        (1, "string", "m_Name"),
        (2, "Array", "Array"),
        (3, "int", "size"),
        (3, "char", "data"),
        (1, "string", "m_Script"),
        (2, "Array", "Array"),
        (3, "int", "size"),
        (3, "char", "data"),
    ]
    if extra_tree_field:
        records.append((1, "int", "unexpected"))

    tree = bytearray(struct.pack("<ii", len(records), 0))
    encoded_records = bytearray()
    for level, type_name, name in records:
        type_offset = add_string(type_name)
        name_offset = add_string(name)
        encoded_records.extend(
            struct.pack(
                "<hBBIIiiiQ",
                1,
                level,
                0,
                type_offset,
                name_offset,
                -1,
                -1,
                0,
                0,
            )
        )
    struct.pack_into("<i", tree, 4, len(string_buffer))
    tree.extend(encoded_records)
    tree.extend(string_buffer)

    def serialized_string(value: bytes) -> bytes:
        result = bytearray(struct.pack("<i", len(value)) + value)
        _pad(result, 4)
        return bytes(result)

    object_data = serialized_string(b"sample_pb.lua") + serialized_string(b"return {}")
    metadata = bytearray(b"2022.3.62f3c1\x00")
    metadata.extend(struct.pack("<iB", 19, 1))  # target platform and embedded type-tree flag
    metadata.extend(struct.pack("<i", 1))  # type count
    metadata.extend(struct.pack("<iBh", 49, 0, -1))  # TextAsset type header
    metadata.extend(b"\x00" * 16)  # old type hash
    metadata.extend(tree)
    metadata.extend(struct.pack("<i", 0))  # type dependencies
    metadata.extend(struct.pack("<i", 1))  # object count
    _pad(metadata, 4)  # object table path IDs are 4-byte aligned
    object_byte_size = len(object_data) if relative_start == 0 else 1
    metadata.extend(struct.pack("<qqIi", 1, relative_start, object_byte_size, 0))
    metadata.extend(struct.pack("<iii", 0, 0, 0))  # scripts, external files, reference types
    metadata.extend(b"\x00")  # userInformation

    data_offset = (48 + len(metadata) + 15) & ~15
    file_size = data_offset + len(object_data)
    header = bytearray(struct.pack(">IIII", len(metadata), file_size, 22, data_offset))
    header.extend(b"\x00\x00\x00\x00")  # little-endian marker and reserved bytes
    header.extend(struct.pack(">IQQQ", len(metadata), file_size, data_offset, 0))
    assert len(header) == 48
    result = header + metadata
    _pad(result, 16)
    result.extend(object_data)
    assert len(result) == file_size
    return bytes(result)


def _serialized_aggregate() -> dict[str, int]:
    return {
        "objects": 0,
        "text_assets": 0,
        "script_types": 0,
        "external_files": 0,
        "ref_types": 0,
        "type_tree_nodes": 0,
    }


class BundleInputTests(unittest.TestCase):
    def test_regular_file_read_accepts_stable_path_and_handle_identity(self) -> None:
        sample = b"stable synthetic bundle input"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "stable.bundle"
            path.write_bytes(sample)

            data, digest = extract._read_regular_file(path, ExtractionLimits())

        self.assertEqual(bytes(data), sample)
        self.assertEqual(digest, hashlib.sha256(sample).hexdigest())

    def test_empty_input_hash_mismatch_and_input_budget_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "input.bundle"

            path.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "bundle input is empty"):
                extract.extract_bundle(path, hashlib.sha256(b"").hexdigest())

            sample = b"not a UnityFS bundle"
            path.write_bytes(sample)
            with self.assertRaisesRegex(ValueError, "SHA-256 does not match"):
                extract.extract_bundle(path, "0" * 64)
            with self.assertRaisesRegex(ValueError, "input exceeds"):
                extract.extract_bundle(
                    path,
                    hashlib.sha256(sample).hexdigest(),
                    ExtractionLimits(max_input_bytes=len(sample) - 1),
                )

    def test_unityfs_charge_budget_rejects_before_data_block_decompression(self) -> None:
        # A 1,024-byte block compressed to 16 bytes is exactly at the 64x
        # ratio ceiling. Its charged metadata+block I/O exceeds this test limit.
        bundle = _unityfs_fixture(
            data_uncompressed_size=1024,
            data_payload=b"x" * 16,
            block_flags=0x41,  # LZMA plus the supported streamed bit
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "budget.bundle"
            path.write_bytes(bundle)
            seen: list[str] = []
            real_decompress = extract._decompress_block

            def tracked_decompress(*args: object, **kwargs: object) -> bytes | bytearray:
                seen.append(str(kwargs.get("what", "")))
                return real_decompress(*args, **kwargs)  # type: ignore[arg-type]

            with patch.object(extract, "_decompress_block", side_effect=tracked_decompress):
                with self.assertRaisesRegex(ValueError, "block budget exceeded"):
                    extract.extract_bundle(
                        path,
                        hashlib.sha256(bundle).hexdigest(),
                        ExtractionLimits(max_total_block_io_bytes=1000),
                    )
            self.assertEqual(seen, ["UnityFS metadata"])

    def test_unityfs_unknown_flags_and_declared_length_mismatch_are_rejected(self) -> None:
        unsupported = _unityfs_fixture(archive_flags=0x10040)
        with self.assertRaisesRegex(ValueError, "unsupported UnityFS archive flags"):
            extract._preflight_unityfs(bytearray(unsupported), ExtractionLimits())

        mismatched = _unityfs_fixture(declared_size_delta=1)
        with self.assertRaisesRegex(ValueError, "declared file size does not exactly match"):
            extract._preflight_unityfs(bytearray(mismatched), ExtractionLimits())


class LzmaBoundaryTests(unittest.TestCase):
    def test_lzma_ratio_and_dictionary_caps_are_checked(self) -> None:
        with self.assertRaisesRegex(ValueError, "decompression ratio"):
            extract._check_compression_sizes(
                1,
                65,
                limits=ExtractionLimits(max_compression_ratio=64),
                what="synthetic block",
            )

        too_large_dictionary = b"\x5d" + struct.pack("<I", 8192) + b"x"
        with self.assertRaisesRegex(ValueError, "dictionary exceeds"):
            extract._decompress_lzma(
                memoryview(too_large_dictionary),
                1,
                ExtractionLimits(max_lzma_dictionary_bytes=4096),
                what="synthetic block",
            )

    def test_lzma_requires_exact_output_and_rejects_trailing_data(self) -> None:
        expected = b"small bounded synthetic LZMA payload"
        encoded = _raw_lzma_block(expected)
        decoded, dictionary_size = extract._decompress_lzma(
            memoryview(encoded), len(expected), ExtractionLimits(), what="synthetic block"
        )
        self.assertEqual(decoded, expected)
        self.assertEqual(dictionary_size, 4096)

        with self.assertRaisesRegex(ValueError, "output exceeds its declared size"):
            extract._decompress_lzma(
                memoryview(encoded), len(expected) - 1, ExtractionLimits(), what="synthetic block"
            )
        with self.assertRaisesRegex(ValueError, "output length does not match"):
            extract._decompress_lzma(
                memoryview(encoded), len(expected) + 1, ExtractionLimits(), what="synthetic block"
            )
        with self.assertRaisesRegex(ValueError, "trailing bytes"):
            extract._decompress_lzma(
                memoryview(_raw_lzma_block(expected, trailing=b"\x00")),
                len(expected),
                ExtractionLimits(),
                what="synthetic block",
            )


class SerializedFileBoundaryTests(unittest.TestCase):
    def _parse(self, data: bytes):
        with patch.object(extract, "_load_common_strings", return_value={}):
            return extract._preflight_serialized_file(
                memoryview(data),
                entry_name="CAB-test",
                limits=ExtractionLimits(),
                aggregate=_serialized_aggregate(),
            )

    def test_small_valid_textasset_tree_and_payload_are_decoded_as_bytes(self) -> None:
        data = _serialized_fixture()
        info = self._parse(data)
        obj = info.objects[0]
        tree = info.types[obj.type_id].tree
        self.assertIsNotNone(tree)
        name, script = extract._parse_text_asset(
            memoryview(data),
            obj,
            tree,
            entry_name="CAB-test",
            limits=ExtractionLimits(),
            capture_script=True,
        )
        self.assertEqual((name, script), ("sample_pb.lua", b"return {}"))

    def test_object_range_past_serialized_file_and_ambiguous_tree_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "object data range is outside its node"):
            self._parse(_serialized_fixture(relative_start=10_000))

        with self.assertRaisesRegex(ValueError, "must declare only m_Name followed by m_Script"):
            self._parse(_serialized_fixture(extra_tree_field=True))


if __name__ == "__main__":
    unittest.main()
