#!/usr/bin/env python3
"""Fail the required check unless every selected package target was exercised."""

import json
import os
from pathlib import Path
import sys


def validate(matrix, jobs, root):
    if set(jobs) != {"prepare", "build", "smoke"} or any(job["result"] != "success" for job in jobs.values()):
        raise ValueError("Package preparation, builds, and smoke jobs must all succeed")
    entries = matrix.get("include", [])
    if not entries:
        raise ValueError("Empty package matrix is not an intentional skip")
    expected = set()
    for entry in entries:
        spec = json.loads(entry["spec"])
        target = spec["distro"] + "-" + spec["architecture"]
        if target in expected:
            raise ValueError("Duplicate package target")
        expected.add(target)
        path = root / ("smoke-results-" + target) / "result.json"
        result = json.loads(path.read_text())
        if result.get("fresh") != "passed":
            raise ValueError("Fresh installation did not pass: " + target)
        if result.get("upgrade") == "skipped":
            if result.get("reason") != "No older compatible released daemon/NSS package pair":
                raise ValueError("Unrecognized upgrade skip: " + target)
            print(target + ": fresh passed; upgrade explicitly skipped: " + result["reason"])
        elif result.get("upgrade") != "passed":
            raise ValueError("Upgrade was required but did not pass: " + target)
        else:
            print(target + ": fresh and upgrade passed")
    found = {p.parent.name.removeprefix("smoke-results-") for p in root.glob("*/result.json")}
    if found != expected:
        raise ValueError("Unexpected or missing target results")


if __name__ == "__main__":
    validate(json.loads(os.environ["MATRIX"]), json.loads(os.environ["JOB_RESULTS"]), Path(sys.argv[1]))
