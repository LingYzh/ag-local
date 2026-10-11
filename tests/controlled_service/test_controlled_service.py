import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SERVICE_PATH = REPOSITORY_ROOT / "v5_server" / "bootstrap" / "controlled_service.py"
REQUIRED_ROLES = (
    "schema", "protocol_overlay", "runtime_lock", "content", "seed", "login_plan",
    "client_exe", "client_sdk", "client_index", "client_scripts",
)
INSTANCE_ID = "94b1bc4e-4813-4a1f-a3db-4aefb2dc3c12"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


class ControlledServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="ap-controlled-")
        self.bundle = Path(self.temporary_directory.name) / "bundle"
        (self.bundle / "server").mkdir(parents=True)
        (self.bundle / "client").mkdir()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _manifest(self, state="static_passed", schema=None, identity=None):
        if schema is None:
            schema = {"messages": [{"name": "pkg.Empty", "fields": []}]}
        artifacts = []
        for role in REQUIRED_ROLES:
            root = "client" if role.startswith("client_") else "server"
            relative_path = f"{role}.json" if role == "schema" else f"{role}.bin"
            data = json.dumps(schema, separators=(",", ":")).encode("utf-8") if role == "schema" else f"payload:{role}".encode("ascii")
            target = self.bundle / root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            artifacts.append({
                "role": role,
                "root": root,
                "path": relative_path,
                "sha256": _sha256(data),
            })
        document = {
            "manifest_version": 1,
            "tuple_id": "tuple-2026-10-a",
            "state": state,
            "identity": identity or {
                "platform": "windows",
                "channel": "global",
                "architecture": "x64",
                "app_version": "5.3.1",
                "resource_version": "321",
            },
            "capabilities": {"hall": "unverified"},
            "artifacts": artifacts,
        }
        (self.bundle / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
        return document

    def _request(self, command, instance_id=INSTANCE_ID, request_id=None, extra=None):
        value = {
            "version": 1,
            "instanceId": instance_id,
            "requestId": request_id or str(uuid.uuid4()),
            "command": command,
        }
        if extra:
            value.update(extra)
        return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"

    def _run(self, instance_id=INSTANCE_ID, input_bytes=b""):
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.Popen(
            [
                sys.executable,
                str(SERVICE_PATH),
                "--instance-id",
                instance_id,
                "--bundle",
                str(self.bundle.resolve()),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=environment,
        )
        stdout, stderr = process.communicate(input=input_bytes, timeout=15)
        return process.returncode, stdout, stderr

    def _json_lines(self, data):
        return [json.loads(line) for line in data.splitlines() if line]

    def test_complete_manifest_emits_ready_and_repeated_status(self):
        self._manifest()
        first_id = "4fc167a1-44bf-4bd8-aabc-dbbf4fd647af"
        second_id = "fe27fc95-e81b-4c52-8fae-6dd4218f2c31"
        shutdown_id = "facb9124-b0c0-4666-84c1-1c5098fb855e"
        requests = (
            self._request("status", request_id=first_id)
            + self._request("status", request_id=second_id)
            + self._request("shutdown", request_id=shutdown_id)
        )

        exit_code, stdout, stderr = self._run(input_bytes=requests)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, b"")
        messages = self._json_lines(stdout)
        self.assertEqual([message["kind"] for message in messages], ["ready", "response", "response", "response"])
        self.assertEqual(messages[0], {
            "kind": "ready",
            "version": 1,
            "instanceId": INSTANCE_ID,
            "scope": "python-compatibility",
            "businessReady": False,
            "tupleId": "tuple-2026-10-a",
        })
        self.assertEqual(
            [message["requestId"] for message in messages[1:]],
            [first_id, second_id, shutdown_id],
        )
        self.assertEqual(
            [message["result"]["value"]["state"] for message in messages[1:]],
            ["READY", "READY", "STOPPED"],
        )
        for message in messages[1:]:
            self.assertEqual(message["result"]["value"]["businessReady"], False)
            self.assertIsNone(message["result"]["value"]["lastError"])

    def test_observed_and_quarantined_manifests_are_rejected_without_ready(self):
        for state in ("observed", "quarantined"):
            with self.subTest(state=state):
                self._manifest(state=state)

                exit_code, stdout, stderr = self._run()

                self.assertEqual(exit_code, 1)
                self.assertEqual(stdout, b"")
                self.assertEqual(self._json_lines(stderr)[0]["code"], "MANIFEST_STATE_REJECTED")

    def test_unknown_identity_is_rejected(self):
        identity = {
            "platform": "windows",
            "channel": "global",
            "architecture": "x64",
            "app_version": "5.3.1",
            "resource_version": "unknown",
        }
        self._manifest(identity=identity)

        exit_code, stdout, stderr = self._run()

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(self._json_lines(stderr)[0]["code"], "MANIFEST_INVALID")

    def test_duplicate_manifest_json_key_is_rejected(self):
        self._manifest()
        manifest_path = self.bundle / "manifest.json"
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(manifest_text.replace('"manifest_version": 1,', '"manifest_version": 1, "manifest_version": 1,'), encoding="utf-8")

        exit_code, stdout, stderr = self._run()

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(self._json_lines(stderr)[0]["code"], "MANIFEST_INVALID")

    def test_hash_mismatch_is_rejected(self):
        document = self._manifest()
        document["artifacts"][0]["sha256"] = "0" * 64
        (self.bundle / "manifest.json").write_text(json.dumps(document), encoding="utf-8")

        exit_code, stdout, stderr = self._run()

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(self._json_lines(stderr)[0]["code"], "ARTIFACT_HASH_MISMATCH")

    def test_unresolved_schema_message_reference_is_rejected(self):
        schema = {
            "messages": [{
                "name": "pkg.Entry",
                "fields": [{
                    "number": 1,
                    "name": "child",
                    "type": "message",
                    "label": "optional",
                    "ref": "pkg.Missing",
                }],
            }],
        }
        self._manifest(schema=schema)

        exit_code, stdout, stderr = self._run()

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(self._json_lines(stderr)[0]["code"], "UNRESOLVED_TYPE")

    def test_request_with_extra_field_is_logged_without_response(self):
        self._manifest()
        invalid = self._request("status", extra={"unexpected": True})
        shutdown = self._request("shutdown", request_id="facb9124-b0c0-4666-84c1-1c5098fb855e")

        exit_code, stdout, stderr = self._run(input_bytes=invalid + shutdown)

        self.assertEqual(exit_code, 0)
        messages = self._json_lines(stdout)
        self.assertEqual([message["kind"] for message in messages], ["ready", "response"])
        self.assertEqual(messages[1]["requestId"], "facb9124-b0c0-4666-84c1-1c5098fb855e")
        self.assertEqual(self._json_lines(stderr)[0]["code"], "CONTROL_INVALID")

    def test_oversized_control_line_is_logged_and_does_not_block_shutdown(self):
        self._manifest()
        oversized = b"{" + (b" " * (64 * 1024)) + b"}\n"
        shutdown = self._request("shutdown", request_id="facb9124-b0c0-4666-84c1-1c5098fb855e")

        exit_code, stdout, stderr = self._run(input_bytes=oversized + shutdown)

        self.assertEqual(exit_code, 0)
        self.assertEqual([message["kind"] for message in self._json_lines(stdout)], ["ready", "response"])
        self.assertEqual(self._json_lines(stderr)[0]["code"], "CONTROL_LINE_TOO_LARGE")

    def test_wrong_instance_request_is_logged_without_response(self):
        self._manifest()
        wrong_instance = "2fdf94e2-8be8-4fa9-8ee6-d00ba6a96f3e"

        exit_code, stdout, stderr = self._run(input_bytes=self._request("status", instance_id=wrong_instance))

        self.assertEqual(exit_code, 0)
        messages = self._json_lines(stdout)
        self.assertEqual([message["kind"] for message in messages], ["ready"])
        self.assertEqual(self._json_lines(stderr)[0]["code"], "CONTROL_INVALID")

    def test_shutdown_acknowledges_stopped_and_exits_zero(self):
        self._manifest()
        request_id = "facb9124-b0c0-4666-84c1-1c5098fb855e"

        exit_code, stdout, stderr = self._run(input_bytes=self._request("shutdown", request_id=request_id))

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, b"")
        messages = self._json_lines(stdout)
        self.assertEqual(messages[-1]["result"]["value"]["state"], "STOPPED")

    def test_eof_after_ready_exits_cleanly(self):
        self._manifest()

        exit_code, stdout, stderr = self._run()

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, b"")
        self.assertEqual([message["kind"] for message in self._json_lines(stdout)], ["ready"])

    def test_traversal_artifact_path_is_rejected(self):
        document = self._manifest()
        document["artifacts"][0]["path"] = "..\\outside.bin"
        (self.bundle / "manifest.json").write_text(json.dumps(document), encoding="utf-8")

        exit_code, stdout, stderr = self._run()

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(self._json_lines(stderr)[0]["code"], "ARTIFACT_PATH_UNSAFE")

    def test_directory_link_escape_is_rejected_when_supported(self):
        self._manifest()
        outside = Path(self.temporary_directory.name) / "outside"
        outside.mkdir()
        (outside / "artifact.bin").write_bytes(b"outside")
        link = self.bundle / "server" / "escape"
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"directory symlinks are unavailable: {type(error).__name__}")

        document = json.loads((self.bundle / "manifest.json").read_text(encoding="utf-8"))
        document["artifacts"][0]["path"] = "escape/artifact.bin"
        document["artifacts"][0]["sha256"] = _sha256(b"outside")
        (self.bundle / "manifest.json").write_text(json.dumps(document), encoding="utf-8")

        exit_code, stdout, stderr = self._run()

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(self._json_lines(stderr)[0]["code"], "ARTIFACT_PATH_UNSAFE")


if __name__ == "__main__":
    unittest.main()
