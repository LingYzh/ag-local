"""A read-only compatibility preflight with a private JSONL control pipe.

This entry point deliberately does not import or start the legacy game service.
Its ready event means only that the supplied compatibility bundle passed the
static manifest and artifact checks implemented here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, BinaryIO


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SCHEMA_BYTES = 32 * 1024 * 1024
MAX_CONTROL_LINE_BYTES = 64 * 1024
MAX_JSON_DEPTH = 256
HASH_CHUNK_BYTES = 1024 * 1024

ALLOWED_STATES = {"imported", "static_passed", "hall_passed", "flows_passed"}
KNOWN_STATES = ALLOWED_STATES | {"observed", "quarantined"}
IDENTITY_FIELDS = ("platform", "channel", "architecture", "app_version", "resource_version")
IDENTITY_PLACEHOLDERS = {
    "unknown", "unverified", "n/a", "na", "not applicable", "none", "null",
    "unset", "not set", "not_set", "not-set", "tbd", "todo",
}
REQUIRED_ROLES = {
    "schema", "protocol_overlay", "runtime_lock", "content", "seed", "login_plan",
    "client_exe", "client_sdk", "client_index", "client_scripts",
}
TUPLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ROLE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
MESSAGE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SCALAR_TYPES = {
    "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64",
    "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes",
}
RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
    *(f"COM{index}" for index in ("\u00b9", "\u00b2", "\u00b3")),
    *(f"LPT{index}" for index in ("\u00b9", "\u00b2", "\u00b3")),
}


class PreflightError(Exception):
    """An expected failure with a safe, stable diagnostic code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class DuplicateJsonKeyError(ValueError):
    """Raised by the JSON decoder when any object repeats a property."""


class StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise PreflightError("CLI_INVALID", "command-line arguments are invalid")


def _emit_json_line(stream: BinaryIO, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    stream.write(payload.encode("ascii") + b"\n")
    stream.flush()


def _emit_log(stage: str, code: str, detail: str) -> None:
    _emit_json_line(sys.stderr.buffer, {"stage": stage, "code": code, "detail": detail})


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    del value
    raise ValueError("non-JSON numeric constant")


def _check_json_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting is too deep")
    if isinstance(value, dict):
        for child in value.values():
            _check_json_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _check_json_depth(child, depth + 1)


def _parse_json_bytes(data: bytes, code: str, detail: str) -> Any:
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
        _check_json_depth(value)
        return value
    except PreflightError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKeyError, ValueError, RecursionError):
        raise PreflightError(code, detail) from None


def _is_record(value: Any) -> bool:
    return isinstance(value, dict)


def _is_integer_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value) and value.is_integer()


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _is_descendant(root: Path, candidate: Path) -> bool:
    root_value = os.path.normcase(os.path.abspath(os.fspath(root)))
    candidate_value = os.path.normcase(os.path.abspath(os.fspath(candidate)))
    try:
        common = os.path.commonpath((root_value, candidate_value))
    except (OSError, ValueError):
        return False
    return common == root_value and candidate_value != root_value


def _resolve_existing(path: Path, missing_code: str, read_code: str) -> Path:
    try:
        return path.resolve(strict=True)
    except FileNotFoundError:
        raise PreflightError(missing_code, "required bundle path is missing") from None
    except (OSError, RuntimeError, ValueError):
        raise PreflightError(read_code, "required bundle path could not be resolved") from None


def _resolve_bundle_root(directory: str) -> Path:
    if not directory or "\x00" in directory or len(directory) > 4096:
        raise PreflightError("BUNDLE_PATH_INVALID", "bundle directory is invalid")
    path = Path(directory)
    if not path.is_absolute():
        raise PreflightError("BUNDLE_PATH_INVALID", "bundle directory must be absolute")
    resolved = _resolve_existing(path, "BUNDLE_MISSING", "BUNDLE_READ_FAILED")
    try:
        details = resolved.stat()
    except OSError:
        raise PreflightError("BUNDLE_READ_FAILED", "bundle directory could not be inspected") from None
    if not stat.S_ISDIR(details.st_mode):
        raise PreflightError("BUNDLE_INVALID", "bundle path is not a directory")
    return resolved


def _resolve_beneath(path: Path, root: Path, escape_code: str, missing_code: str, read_code: str) -> Path:
    resolved = _resolve_existing(path, missing_code, read_code)
    if not _is_descendant(root, resolved):
        raise PreflightError(escape_code, "resolved path escapes its allowed root")
    return resolved


def _read_manifest_bytes(path: Path) -> bytes:
    try:
        before_path = path.stat()
        if not stat.S_ISREG(before_path.st_mode):
            raise PreflightError("MANIFEST_INVALID", "manifest.json is not a regular file")
        if before_path.st_size > MAX_MANIFEST_BYTES:
            raise PreflightError("MANIFEST_INVALID", "manifest.json exceeds the size limit")
        with path.open("rb") as stream:
            before_file = os.fstat(stream.fileno())
            if not _same_file_identity(before_path, before_file):
                raise PreflightError("MANIFEST_CHANGED", "manifest.json changed during preflight")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = stream.read(min(HASH_CHUNK_BYTES, MAX_MANIFEST_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_MANIFEST_BYTES:
                    raise PreflightError("MANIFEST_INVALID", "manifest.json exceeds the size limit")
                chunks.append(chunk)
            after_file = os.fstat(stream.fileno())
        after_path = path.stat()
    except PreflightError:
        raise
    except OSError:
        raise PreflightError("MANIFEST_READ_FAILED", "manifest.json could not be read") from None

    if (
        not _same_stat(before_file, after_file)
        or not _same_stat(before_path, after_path)
        or not _same_file_identity(before_path, after_file)
        or total != after_file.st_size
    ):
        raise PreflightError("MANIFEST_CHANGED", "manifest.json changed during preflight")
    return b"".join(chunks)


def _safe_path_components(value: Any) -> list[str]:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PreflightError("ARTIFACT_PATH_UNSAFE", "artifact path must be a non-empty relative path")
    if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value) or ":" in value:
        raise PreflightError("ARTIFACT_PATH_UNSAFE", "absolute, UNC, drive, and ADS paths are forbidden")

    components = re.split(r"[\\/]", value)
    if any(not component or component in {".", ".."} for component in components):
        raise PreflightError("ARTIFACT_PATH_UNSAFE", "empty and traversal path components are forbidden")
    for component in components:
        if re.search(r"[\x00-\x1f<>\"|?*]", component) or component.endswith((".", " ")):
            raise PreflightError("ARTIFACT_PATH_UNSAFE", "artifact path contains an invalid Windows component")
        device_name = component.split(".", 1)[0].rstrip(" .").upper()
        if device_name in RESERVED_WINDOWS_NAMES:
            raise PreflightError("ARTIFACT_PATH_UNSAFE", "artifact path uses a reserved Windows device name")
    return components


def _validate_identity(value: Any) -> None:
    if not _is_record(value):
        raise PreflightError("MANIFEST_INVALID", "identity must be an object")
    missing: list[str] = []
    for field in IDENTITY_FIELDS:
        current = value.get(field)
        if current is None or (isinstance(current, str) and (
            not current.strip() or current.strip().lower() in IDENTITY_PLACEHOLDERS
        )):
            missing.append(field)
        elif not isinstance(current, str):
            raise PreflightError("MANIFEST_INVALID", "identity fields must be strings or null")
    if missing:
        raise PreflightError("MANIFEST_INVALID", "identity is incomplete or contains unknown values")


def _parse_artifact(value: Any, seen_roles: set[str]) -> tuple[str, str, list[str], str]:
    if not _is_record(value):
        raise PreflightError("MANIFEST_INVALID", "artifact entry must be an object")
    role = value.get("role")
    root = value.get("root")
    artifact_path = value.get("path")
    digest = value.get("sha256")
    if not isinstance(role, str) or not ROLE_NAME_RE.fullmatch(role):
        raise PreflightError("MANIFEST_INVALID", "artifact role is invalid")
    if role in seen_roles:
        raise PreflightError("MANIFEST_INVALID", "artifact roles must be unique")
    seen_roles.add(role)
    if root not in ("server", "client"):
        raise PreflightError("MANIFEST_INVALID", "artifact root must be server or client")
    expected_root = "client" if role.startswith("client_") else "server"
    if root != expected_root:
        raise PreflightError("MANIFEST_INVALID", "artifact role uses the wrong root")
    components = _safe_path_components(artifact_path)
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise PreflightError("MANIFEST_INVALID", "artifact sha256 must be 64 hexadecimal characters")
    return role, root, components, digest.lower()


def _normalize_message_name(value: str) -> str:
    normalized = value.strip()
    normalized = re.sub(r"^\.+", "", normalized).lower()
    if not normalized or not MESSAGE_NAME_RE.fullmatch(normalized):
        raise PreflightError("SCHEMA_INVALID", "schema contains an invalid message name")
    return normalized


def _normalize_message_ref(value: str) -> str:
    normalized = value.strip()
    normalized = re.sub(r"^\.+", "", normalized).lower()
    if not normalized or not MESSAGE_NAME_RE.fullmatch(normalized):
        raise PreflightError("UNRESOLVED_TYPE", "schema contains an invalid message reference")
    return normalized


def _validate_schema(data: bytes) -> None:
    document = _parse_json_bytes(data, "SCHEMA_INVALID", "schema is malformed or violates the schema registry contract")
    if len(data) > MAX_SCHEMA_BYTES:
        raise PreflightError("SCHEMA_INVALID", "schema exceeds the size limit")
    if not _is_record(document) or not isinstance(document.get("messages"), list):
        raise PreflightError("SCHEMA_INVALID", "schema must contain a messages array")
    raw_messages = document["messages"]
    if not raw_messages:
        raise PreflightError("SCHEMA_INVALID", "schema messages array must not be empty")

    messages: dict[str, dict[str, Any]] = {}
    pending_message_refs: list[tuple[str, str]] = []
    for raw_message in raw_messages:
        if (
            not _is_record(raw_message)
            or not isinstance(raw_message.get("name"), str)
            or not isinstance(raw_message.get("fields"), list)
        ):
            raise PreflightError("SCHEMA_INVALID", "each schema message needs a name and fields array")
        name = _normalize_message_name(raw_message["name"])
        if name in messages:
            raise PreflightError("SCHEMA_INVALID", "schema contains duplicate normalized message names")

        seen_numbers: set[int] = set()
        seen_names: set[str] = set()
        fields_by_number: dict[int, Any] = {}
        for raw_field in raw_message["fields"]:
            if not _is_record(raw_field):
                raise PreflightError("SCHEMA_INVALID", "schema field must be an object")
            number = raw_field.get("number")
            if (
                not _is_integer_number(number)
                or number < 1
                or number > (2 ** 29) - 1
                or 19_000 <= number <= 19_999
            ):
                raise PreflightError("SCHEMA_INVALID", "schema field number is not a legal protobuf number")
            if number in seen_numbers:
                raise PreflightError("SCHEMA_INVALID", "schema message has duplicate field numbers")
            seen_numbers.add(number)

            field_name = raw_field.get("name")
            if not isinstance(field_name, str) or not FIELD_NAME_RE.fullmatch(field_name):
                raise PreflightError("SCHEMA_INVALID", "schema field name is invalid")
            if field_name in seen_names:
                raise PreflightError("SCHEMA_INVALID", "schema message has duplicate field names")
            seen_names.add(field_name)

            raw_type = raw_field.get("type")
            if not isinstance(raw_type, str) or not raw_type.strip():
                raise PreflightError("SCHEMA_INVALID", "schema field type is required")
            field_type = raw_type.strip().lower()
            if field_type not in SCALAR_TYPES and field_type not in {"message", "enum"}:
                raise PreflightError("SCHEMA_INVALID", "schema field type is unsupported")

            if raw_field.get("label") not in ("required", "optional", "repeated"):
                raise PreflightError("SCHEMA_INVALID", "schema field label is invalid")

            has_ref = "ref" in raw_field
            raw_ref = raw_field.get("ref")
            if field_type == "message" and (
                not has_ref or not isinstance(raw_ref, str) or not raw_ref.strip()
            ):
                raise PreflightError("UNRESOLVED_TYPE", "message field is missing a valid reference")
            if not has_ref or (raw_ref is not None and (
                not isinstance(raw_ref, str) or not raw_ref.strip()
            )):
                raise PreflightError("SCHEMA_INVALID", "schema field reference must be a non-empty string or null")
            if field_type in SCALAR_TYPES and raw_ref is not None:
                raise PreflightError("SCHEMA_INVALID", "scalar schema fields cannot contain references")
            if field_type == "message":
                pending_message_refs.append((name, _normalize_message_ref(raw_ref)))
            fields_by_number[int(number)] = raw_field
        messages[name] = fields_by_number

    for _, target in pending_message_refs:
        if target not in messages:
            raise PreflightError("UNRESOLVED_TYPE", "schema message reference does not resolve")


def _validate_manifest(value: Any) -> tuple[str, list[tuple[str, str, list[str], str]]]:
    if not _is_record(value):
        raise PreflightError("MANIFEST_INVALID", "manifest root must be an object")
    manifest_version = value.get("manifest_version")
    if not _is_integer_number(manifest_version) or manifest_version != 1:
        raise PreflightError("MANIFEST_INVALID", "manifest_version must be integer 1")

    tuple_id = value.get("tuple_id")
    if not isinstance(tuple_id, str) or not TUPLE_ID_RE.fullmatch(tuple_id):
        raise PreflightError("MANIFEST_INVALID", "tuple_id is invalid")

    state = value.get("state")
    if not isinstance(state, str) or state not in KNOWN_STATES:
        raise PreflightError("MANIFEST_INVALID", "manifest state is unsupported")
    if state not in ALLOWED_STATES:
        raise PreflightError("MANIFEST_STATE_REJECTED", "manifest state is diagnostic or quarantined")

    capabilities = value.get("capabilities")
    if not _is_record(capabilities) or capabilities.get("hall") not in ("unverified", "passed"):
        raise PreflightError("MANIFEST_INVALID", "capabilities.hall is invalid")
    _validate_identity(value.get("identity"))

    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        raise PreflightError("MANIFEST_INVALID", "artifacts must be an array")
    seen_roles: set[str] = set()
    entries = [_parse_artifact(artifact, seen_roles) for artifact in artifacts]
    missing_roles = REQUIRED_ROLES - seen_roles
    if missing_roles:
        raise PreflightError("ARTIFACTS_INCOMPLETE", "required compatibility artifact roles are missing")
    return tuple_id, entries


def _hash_artifact(path: Path, is_schema: bool) -> tuple[str, bytes | None]:
    try:
        before_path = path.stat()
        if not stat.S_ISREG(before_path.st_mode):
            raise PreflightError("ARTIFACT_NOT_FILE", "artifact is not a regular file")
        if is_schema and before_path.st_size > MAX_SCHEMA_BYTES:
            raise PreflightError("SCHEMA_INVALID", "schema exceeds the size limit")
        digest = hashlib.sha256()
        captured: list[bytes] | None = [] if is_schema else None
        byte_count = 0
        with path.open("rb") as stream:
            before_file = os.fstat(stream.fileno())
            if not _same_file_identity(before_path, before_file):
                raise PreflightError("ARTIFACT_CHANGED", "artifact changed during preflight")
            while True:
                chunk = stream.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                byte_count += len(chunk)
                if is_schema and byte_count > MAX_SCHEMA_BYTES:
                    raise PreflightError("SCHEMA_INVALID", "schema exceeds the size limit")
                digest.update(chunk)
                if captured is not None:
                    captured.append(chunk)
            after_file = os.fstat(stream.fileno())
        after_path = path.stat()
    except PreflightError:
        raise
    except OSError:
        raise PreflightError("ARTIFACT_READ_FAILED", "artifact could not be read") from None

    if (
        not _same_stat(before_file, after_file)
        or not _same_stat(before_path, after_path)
        or not _same_file_identity(before_path, after_file)
        or byte_count != after_file.st_size
    ):
        raise PreflightError("ARTIFACT_CHANGED", "artifact changed during preflight")
    data = b"".join(captured) if captured is not None else None
    return digest.hexdigest(), data


def _preflight(directory: str) -> str:
    bundle_root = _resolve_bundle_root(directory)
    manifest_alias = bundle_root / "manifest.json"
    manifest_path = _resolve_beneath(
        manifest_alias,
        bundle_root,
        "MANIFEST_PATH_UNSAFE",
        "MANIFEST_MISSING",
        "MANIFEST_READ_FAILED",
    )
    manifest_bytes = _read_manifest_bytes(manifest_path)
    manifest_after = _resolve_beneath(
        manifest_alias,
        bundle_root,
        "MANIFEST_PATH_UNSAFE",
        "MANIFEST_MISSING",
        "MANIFEST_READ_FAILED",
    )
    if os.path.normcase(os.fspath(manifest_after)) != os.path.normcase(os.fspath(manifest_path)):
        raise PreflightError("MANIFEST_CHANGED", "manifest.json changed during preflight")
    manifest = _parse_json_bytes(
        manifest_bytes,
        "MANIFEST_INVALID",
        "manifest.json is malformed or violates manifest v1",
    )
    tuple_id, entries = _validate_manifest(manifest)

    verified_roles: set[str] = set()
    for role, root_name, components, expected_digest in entries:
        root_alias = bundle_root / root_name
        resolved_root = _resolve_beneath(
            root_alias,
            bundle_root,
            "ARTIFACT_ROOT_UNSAFE",
            "ARTIFACT_ROOT_MISSING",
            "ARTIFACT_ROOT_READ_FAILED",
        )
        try:
            root_info = resolved_root.stat()
        except OSError:
            raise PreflightError("ARTIFACT_ROOT_READ_FAILED", "artifact root could not be inspected") from None
        if not stat.S_ISDIR(root_info.st_mode):
            raise PreflightError("ARTIFACT_ROOT_INVALID", "artifact root is not a directory")

        artifact_alias = resolved_root.joinpath(*components)
        artifact_path = _resolve_beneath(
            artifact_alias,
            resolved_root,
            "ARTIFACT_PATH_UNSAFE",
            "ARTIFACT_MISSING",
            "ARTIFACT_READ_FAILED",
        )
        actual_digest, schema_bytes = _hash_artifact(artifact_path, role == "schema")

        root_after = _resolve_beneath(
            root_alias,
            bundle_root,
            "ARTIFACT_ROOT_UNSAFE",
            "ARTIFACT_ROOT_MISSING",
            "ARTIFACT_ROOT_READ_FAILED",
        )
        artifact_after = _resolve_beneath(
            artifact_alias,
            resolved_root,
            "ARTIFACT_PATH_UNSAFE",
            "ARTIFACT_MISSING",
            "ARTIFACT_READ_FAILED",
        )
        if (
            os.path.normcase(os.fspath(root_after)) != os.path.normcase(os.fspath(resolved_root))
            or os.path.normcase(os.fspath(artifact_after)) != os.path.normcase(os.fspath(artifact_path))
        ):
            raise PreflightError("ARTIFACT_CHANGED", "artifact path changed during preflight")
        if actual_digest != expected_digest:
            raise PreflightError("ARTIFACT_HASH_MISMATCH", "artifact SHA-256 did not match the manifest")
        verified_roles.add(role)
        if role == "schema":
            _validate_schema(schema_bytes if schema_bytes is not None else b"")

    if REQUIRED_ROLES - verified_roles:
        raise PreflightError("ARTIFACTS_INCOMPLETE", "required compatibility artifact roles are missing")
    return tuple_id


def _parse_cli(argv: list[str] | None) -> tuple[str, str]:
    parser = StrictArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--bundle", required=True)
    try:
        args = parser.parse_args(argv)
    except PreflightError:
        raise
    except SystemExit:
        raise PreflightError("CLI_INVALID", "command-line arguments are invalid") from None

    instance_id = args.instance_id
    if not isinstance(instance_id, str):
        raise PreflightError("CLI_INVALID", "instance id must be a UUIDv4")
    try:
        parsed_id = uuid.UUID(instance_id)
    except (ValueError, AttributeError):
        raise PreflightError("CLI_INVALID", "instance id must be a UUIDv4") from None
    if parsed_id.version != 4 or str(parsed_id) != instance_id:
        raise PreflightError("CLI_INVALID", "instance id must be a canonical UUIDv4")
    bundle = args.bundle
    if not isinstance(bundle, str) or not bundle or "\x00" in bundle or len(bundle) > 4096:
        raise PreflightError("BUNDLE_PATH_INVALID", "bundle directory is invalid")
    if not Path(bundle).is_absolute():
        raise PreflightError("BUNDLE_PATH_INVALID", "bundle directory must be absolute")
    return instance_id, bundle


def _is_canonical_uuid4(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _validate_control_request(value: Any, instance_id: str) -> tuple[str, str] | None:
    if not _is_record(value) or set(value) != {"version", "instanceId", "requestId", "command"}:
        return None
    version = value.get("version")
    if isinstance(version, bool) or version != 1 or not isinstance(version, int):
        return None
    if value.get("instanceId") != instance_id:
        return None
    request_id = value.get("requestId")
    if not _is_canonical_uuid4(request_id):
        return None
    command = value.get("command")
    if command not in ("status", "shutdown"):
        return None
    return request_id, command


def _read_bounded_line(stream: BinaryIO) -> bytes | None:
    line = stream.readline(MAX_CONTROL_LINE_BYTES + 1)
    if not line:
        return None
    if len(line) > MAX_CONTROL_LINE_BYTES:
        while line and not line.endswith(b"\n"):
            line = stream.readline(MAX_CONTROL_LINE_BYTES + 1)
        raise PreflightError("CONTROL_LINE_TOO_LARGE", "control line exceeds the size limit")
    if line.endswith(b"\n"):
        line = line[:-1]
        if line.endswith(b"\r"):
            line = line[:-1]
    return line


def _control_loop(instance_id: str, tuple_id: str) -> int:
    while True:
        try:
            line = _read_bounded_line(sys.stdin.buffer)
        except PreflightError as error:
            _emit_log("control", error.code, error.detail)
            continue
        except OSError:
            _emit_log("control", "CONTROL_READ_FAILED", "control input could not be read")
            return 1
        if line is None:
            return 0

        try:
            request = _parse_json_bytes(line, "CONTROL_INVALID", "control request is invalid")
        except PreflightError as error:
            _emit_log("control", error.code, error.detail)
            continue
        validated = _validate_control_request(request, instance_id)
        if validated is None:
            _emit_log("control", "CONTROL_INVALID", "control request envelope is invalid")
            continue

        request_id, command = validated
        state = "STOPPED" if command == "shutdown" else "READY"
        _emit_json_line(sys.stdout.buffer, {
            "kind": "response",
            "version": 1,
            "instanceId": instance_id,
            "requestId": request_id,
            "result": {
                "ok": True,
                "value": {
                    "state": state,
                    "instanceId": instance_id,
                    "scope": "python-compatibility",
                    "businessReady": False,
                    "tupleId": tuple_id,
                    "lastError": None,
                },
            },
        })
        if command == "shutdown":
            return 0


def main(argv: list[str] | None = None) -> int:
    try:
        instance_id, bundle = _parse_cli(argv)
        tuple_id = _preflight(bundle)
    except PreflightError as error:
        _emit_log("preflight", error.code, error.detail)
        return 1
    except Exception:
        _emit_log("preflight", "INTERNAL_ERROR", "preflight failed due to an internal error")
        return 1

    try:
        _emit_json_line(sys.stdout.buffer, {
            "kind": "ready",
            "version": 1,
            "instanceId": instance_id,
            "scope": "python-compatibility",
            "businessReady": False,
            "tupleId": tuple_id,
        })
    except OSError:
        _emit_log("preflight", "CONTROL_WRITE_FAILED", "ready event could not be written")
        return 1
    try:
        return _control_loop(instance_id, tuple_id)
    except Exception:
        _emit_log("control", "CONTROL_INTERNAL_ERROR", "control service failed due to an internal error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
