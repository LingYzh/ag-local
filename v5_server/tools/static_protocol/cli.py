"""Recover declaration IR into a new directory outside a protected source root.

The command reads a pinned input and never executes Lua or starts a service.
An extraction report is static evidence, not compatibility admission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import uuid
from pathlib import Path
from typing import Any


MAX_OUTPUT_BYTES = 32 * 1024 * 1024
TOOL_FILES = ('__init__.py', 'bundle.py', 'bytecode.py', 'cli.py',
    'extract.py', 'schema_ir.py', 'static_vm.py')


def _tool_fingerprints() -> dict[str, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in TOOL_FILES}


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('paths must be absolute without parent traversal')
    return path


def _reject_links(path: Path) -> None:
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('reparse points and symbolic links are not accepted')


def _inside(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def validate_paths(source_root: str, bundle: str, destination: str) -> tuple[Path, Path, Path]:
    root = _absolute(source_root)
    source = _absolute(bundle)
    output = _absolute(destination)
    _reject_links(root)
    _reject_links(source)
    _reject_links(output.parent)
    root = root.resolve(strict=True)
    source = source.resolve(strict=True)
    parent = output.parent.resolve(strict=True)
    output = parent / output.name
    if not root.is_dir() or not source.is_file() or not _inside(source, root):
        raise ValueError('bundle must be a regular file inside the protected source root')
    if not parent.is_dir() or _inside(output, root):
        raise ValueError('output must have an existing parent outside the protected source root')
    if output.exists() or output.is_symlink():
        raise ValueError('output must be a new directory')
    return root, source, output


def _json_bytes(value: Any) -> bytes:
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
        allow_nan=False) + '\n').encode('utf-8')
    if len(data) > MAX_OUTPUT_BYTES:
        raise ValueError('generated artifact exceeds the output size budget')
    return data


def publish_new_directory(output: Path, artifacts: dict[str, bytes]) -> None:
    """Write owned temporary files, then promote the complete directory on Windows."""
    if os.name != 'nt':
        raise ValueError('atomic directory publication currently supports Windows only')
    if output.exists() or output.is_symlink():
        raise ValueError('output already exists')
    parent = output.parent.resolve(strict=True)
    staging = parent / ('.static-protocol-' + uuid.uuid4().hex)
    staging.mkdir()
    written: list[Path] = []
    try:
        for name, data in artifacts.items():
            if Path(name).name != name or name in ('', '.', '..'):
                raise ValueError('invalid artifact filename')
            path = staging / name
            with path.open('xb') as handle:
                written.append(path)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        _reject_links(parent)
        if output.exists() or output.is_symlink():
            raise ValueError('output appeared during extraction')
        # Windows rename refuses an existing destination; no replace operation.
        os.rename(staging, output)
    finally:
        if staging.exists():
            # Remove only files created by this invocation; never recursively delete.
            if staging.resolve(strict=True).parent != parent:
                raise ValueError('staging cleanup escaped its validated parent')
            for path in written:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            staging.rmdir()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args(argv)
    try:
        _, source, output = validate_paths(args.source_root, args.bundle, args.output_directory)
        tool_fingerprints = _tool_fingerprints()
        from .extract import extract_bundle
        from .schema_ir import build_schema
        extracted = extract_bundle(source, args.sha256)
        schema, report = build_schema(extracted)
        if tool_fingerprints != _tool_fingerprints():
            raise ValueError('recovery tool source changed during extraction')
        schema_bytes = _json_bytes(schema)
        schema_hash = hashlib.sha256(schema_bytes).hexdigest()
        report = {**report, 'bundle_extraction': extracted.metadata,
            'recovery_tool_sha256': tool_fingerprints,
            'schema_sha256': schema_hash,
            'runtime_test_performed': False, 'compatibility_admitted': False}
        publish_new_directory(output, {
            'schema.json': schema_bytes,
            'extraction-report.json': _json_bytes(report),
            'schema.sha256': (schema_hash + '\n').encode('ascii'),
        })
        print(json.dumps({'schema_sha256': schema_hash,
            'messages': len(schema['messages']),
            'fields': sum(len(message['fields']) for message in schema['messages']),
            'protocol_assets': len(extracted.protocol_assets),
            'runtime_test_performed': False, 'compatibility_admitted': False}, sort_keys=True))
        return 0
    except (ValueError, OSError, ImportError, KeyError, TypeError) as exc:
        # JSON escaping keeps bounded source locations useful without printing bytes.
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc)[:2048]},
            ensure_ascii=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
