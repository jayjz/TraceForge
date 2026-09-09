"""Evaluate the independent two-case oracle; exit 0 pass, 1 mismatch, 2 error."""

import argparse
import json
from pathlib import Path

from traceforge.adapters.cipherloop import load_case, validate_normalized
from traceforge.evaluation.baseline_contract import (
    FIXTURES,
    ArtifactError,
    canonical_artifact,
    read,
    write,
)


def evaluate_case(folder, case):
    try:
        steps, events, metadata, capture, provenance = load_case(folder, case)
        findings = capture["verified_findings"]
        expected = case["expected"]
        checks = [
            {
                "id": "verified_count",
                "passed": len(findings) == expected["verified_count"],
                "reference": "capture.json#/verified_findings",
            },
            {
                "id": "rejected_count",
                "passed": events[0]["payload"]["rejected_count"]
                == expected["rejected_count"],
                "reference": f"trajectory_{case['id']}.jsonl:3",
            },
        ]
        if expected["verified_count"]:
            for key in ("source", "sink", "taint_path"):
                checks.append(
                    {
                        "id": key,
                        "passed": len(findings) == 1
                        and findings[0][key] == expected[key],
                        "reference": f"capture.json#/verified_findings/0/{key}",
                    }
                )
        success = all(check["passed"] for check in checks)
        normalized = {
            "trajectory_id": case["id"],
            "task": {"description": case["task"]},
            "steps": steps,
            "outcome": {"success": success},
            "metadata": {
                "harness": "cipherloop-offline-v1",
                "cipherloop": {
                    "capture": capture,
                    "recorder_metadata": canonical_artifact("metadata", metadata),
                    "validation_events": events,
                    "provenance": provenance,
                    "task_origin": "independent fixture manifest",
                    "outcome_scope": "two-case fixture oracle",
                    "metric_definitions": {
                        "total_retries": "upstream planner invocation counter; harness supplied 0, planner not run",
                        "compressed_findings_count": "compressed tool-output batches",
                        "compression_ratio": "raw characters / retained dictionary characters; not tokens or cost",
                        "candidate_to_verified_ratio": "candidates / verified per validation invocation; null for zero verified",
                    },
                },
            },
        }
        validate_normalized(normalized)
        return {
            "case": case["id"],
            "status": "pass" if success else "fail",
            "checks": checks,
            "observed": events[0]["payload"],
            "unavailable": capture["unavailable"],
        }, normalized
    except ArtifactError as exc:
        # Never assign outcome.success to an incomplete execution.
        return {"case": case["id"], "status": "error", "error": str(exc)}, None


def evaluate(directory):
    cases = read(FIXTURES / "manifest.json")["cases"]
    results = []
    for case in cases:
        result, normalized = evaluate_case(directory / case["id"], case)
        results.append(result)
        if normalized is not None:
            write(directory / case["id"] / "normalized.json", normalized)
        else:
            # A previous successful evaluation must not survive invalidated input.
            (directory / case["id"] / "normalized.json").unlink(missing_ok=True)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    results = evaluate(args.directory)
    print(json.dumps(results, indent=2, sort_keys=True))
    return (
        2
        if any(r["status"] == "error" for r in results)
        else 1
        if any(r["status"] == "fail" for r in results)
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
