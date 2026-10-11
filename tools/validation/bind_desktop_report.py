"""Attach source/ASAR provenance to a completed synthetic Electron smoke report."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.validation.provenance import provenance, sha256, source_hashes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--smoke", type=Path)
    parser.add_argument("--asar", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.smoke:
        if args.output or args.asar or args.snapshot.exists():
            parser.error("snapshot mode requires a new snapshot path only")
        args.snapshot.parent.mkdir(parents=True, exist_ok=True)
        with args.snapshot.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(provenance(), stream, indent=2)
            stream.write("\n")
        return 0
    if not args.output or args.output.exists():
        parser.error("binding mode requires a new output file")
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    if snapshot["source_sha256"] != source_hashes():
        parser.error("source files changed after the build snapshot; rebuild and rerun smoke")
    smoke = json.loads(args.smoke.read_text(encoding="utf-8"))
    checks = smoke.get("checks")
    if smoke.get("passed") is not True or not isinstance(checks, list) or not checks:
        parser.error("a successful smoke report with named checks is required")
    # Do not propagate fixture paths, bundle reports or other uncontrolled fields.
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "smoke_timestamp": smoke.get("timestamp"), "passed": True, "synthetic_only": True,
        "mode": "package" if args.asar else "source", "check_count": len(checks),
        "checks": checks, "provenance": snapshot,
        "raw_smoke_sha256": sha256(args.smoke),
        "environment": {key: smoke.get("environment", {}).get(key)
                        for key in ("electron", "chrome", "node", "platform", "architecture")},
        "instance_ids": smoke.get("instanceIds"),
        "business_ready": False, "hall_executed": False,
    }
    if args.asar:
        report["asar_sha256"] = sha256(args.asar)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
