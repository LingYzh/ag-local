"""Data contracts for bounded, read-only protocol bundle extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ExtractionLimits:
    """Hard limits applied before parsing or decompressing untrusted input."""

    max_input_bytes: int = 128 * 1024 * 1024
    max_bundle_metadata_bytes: int = 1 * 1024 * 1024
    max_total_block_io_bytes: int = 512 * 1024 * 1024
    max_lzma_dictionary_bytes: int = 64 * 1024 * 1024
    max_compression_ratio: int = 64
    max_block_count: int = 256
    max_node_count: int = 16_384
    max_serialized_files: int = 64
    max_serialized_metadata_bytes: int = 64 * 1024 * 1024
    max_types_per_file: int = 8_192
    max_type_tree_nodes_per_file: int = 500_000
    max_total_type_tree_nodes: int = 1_000_000
    max_type_dependencies: int = 250_000
    max_script_types: int = 100_000
    max_external_files: int = 100_000
    max_objects_per_file: int = 100_000
    max_total_objects: int = 200_000
    max_text_assets: int = 20_000
    max_text_asset_object_bytes: int = 64 * 1024 * 1024
    max_protocol_assets: int = 256
    max_protocol_asset_bytes: int = 8 * 1024 * 1024
    max_total_protocol_bytes: int = 64 * 1024 * 1024
    max_serialized_string_bytes: int = 4096
    max_typetree_string_buffer_bytes: int = 32 * 1024 * 1024
    max_array_items: int = 8_000_000
    max_cross_block_node_copy_bytes: int = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ExtractedBundle:
    """Protocol TextAssets and source metadata extracted without executing Lua."""

    bundle_sha256: str
    entry_name: str
    unity_version: str
    unityfs_version: int
    text_asset_count: int
    protocol_assets: dict[str, bytes]
    metadata: dict[str, Any] = field(default_factory=dict)
    asset_locations: dict[str, dict[str, Any]] = field(default_factory=dict)
