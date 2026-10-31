#!/usr/bin/env python3
"""
Validate generated Sigma rules with pySigma, the reference implementation.

This is a genuine third-party check: the emitted YAML is parsed by the same
library the Sigma ecosystem uses, and every detection condition is resolved
against the selections it references.

It deliberately does NOT use `sigma check`'s MITRE tag validator, which fetches
the ATT&CK data set at runtime and would make the check depend on network
availability rather than on rule correctness.

Usage: python3 scripts/validate-sigma.py <directory-of-yml-files>
"""

from __future__ import annotations

import pathlib
import sys

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: validate-sigma.py <directory>", file=sys.stderr)
        return 2

    directory = pathlib.Path(sys.argv[1])
    files = sorted(directory.glob("*.yml"))
    if not files:
        print(f"FAIL: no .yml rule files found in {directory}", file=sys.stderr)
        return 1

    failures = 0
    for path in files:
        try:
            collection = SigmaCollection.from_yaml(path.read_text())
        except Exception as exc:  # noqa: BLE001 - report any parse failure
            print(f"FAIL {path.name}: {type(exc).__name__}: {exc}")
            failures += 1
            continue

        rules = list(collection.rules)
        correlations = [r for r in rules if isinstance(r, SigmaCorrelationRule)]
        detections = [r for r in rules if not isinstance(r, SigmaCorrelationRule)]

        if not detections:
            print(f"FAIL {path.name}: no detection rules parsed")
            failures += 1
            continue

        # Resolving a condition proves every identifier it references exists.
        try:
            for rule in detections:
                for parsed in rule.detection.parsed_condition:
                    parsed.parse()
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {path.name}: condition did not resolve: {type(exc).__name__}: {exc}")
            failures += 1
            continue

        # A correlation must reference rules that are defined in the same stream.
        defined = {rule.name for rule in detections if rule.name}
        for correlation in correlations:
            referenced = {str(ref.reference) for ref in correlation.rules}
            missing = referenced - defined
            if missing:
                print(f"FAIL {path.name}: correlation references undefined rule(s): {sorted(missing)}")
                failures += 1

        summary = ", ".join(
            [f"{len(detections)} detection rule(s)"]
            + ([f"{len(correlations)} correlation rule(s)"] if correlations else [])
        )
        print(f"OK   {path.name}: {summary}")
        for correlation in correlations:
            print(
                f"       correlation type={correlation.type.name.lower()} "
                f"timespan={correlation.timespan.spec} "
                f"group_by={correlation.group_by}"
            )

    if failures:
        print(f"\n{failures} Sigma rule file(s) failed validation.", file=sys.stderr)
        return 1

    print(f"\nAll {len(files)} Sigma rule file(s) validated with pySigma.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
