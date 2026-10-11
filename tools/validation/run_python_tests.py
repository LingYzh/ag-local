"""Run all synthetic Python suites with an explicit repository import boundary."""
from __future__ import annotations

import argparse
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

# -I omits CWD/user-site/PYTHONPATH. Only the repository containing this runner is added.
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.validation.provenance import provenance, source_hashes
GROUPS = ("controlled_service", "network", "static_protocol", "evidence", "python_environment")


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records: list[dict] = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"test": test.id(), "result": "passed"})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.records.append({"test": test.id(), "result": "skipped", "reason": reason})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append({"test": test.id(), "result": "failed"})

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append({"test": test.id(), "result": "error"})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--group", action="append", choices=GROUPS,
                        help="Run only selected suites; default runs every required suite")
    args = parser.parse_args()
    if not sys.flags.isolated:
        parser.error("run this entry with Python -I")
    if args.output.exists():
        parser.error("output must be a new file")
    before = source_hashes()
    suite = unittest.TestSuite()
    groups: dict[str, int] = {}
    selected_groups = tuple(dict.fromkeys(args.group or GROUPS))
    for name in selected_groups:
        directory = ROOT / "tests" / name
        if not directory.exists():
            parser.error(f"missing required synthetic test group: {name}")
        discovered = unittest.TestLoader().discover(str(directory), pattern="test_*.py")
        groups[name] = discovered.countTestCases()
        if not groups[name]:
            parser.error(f"empty test group: {name}")
        suite.addTests(discovered)
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    unchanged = before == source_hashes()
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "synthetic_only": True,
        "passed": result.wasSuccessful() and unchanged, "sources_unchanged": unchanged,
        "run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "groups": groups, "tests": result.records,
        "not_executed_groups": [name for name in GROUPS if name not in selected_groups],
        "provenance": provenance(before),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
