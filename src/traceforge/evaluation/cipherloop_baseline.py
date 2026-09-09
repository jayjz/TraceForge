"""Evaluate the independent two-case oracle; exit 0 pass, 1 mismatch, 2 error."""

import argparse
import json
from pathlib import Path

from traceforge.adapters.cipherloop import load_case, validate_normalized
from traceforge.evaluation.baseline_contract import (
    CASE_IDS,
    ArtifactError,
    canonical_artifact,
    load_manifest,
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
                "harness": provenance["normalization_version"],
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


def invalidate_output(directory, case_id):
    """Only the two reserved result filenames are evaluator-owned.

    Do this before any reads, so even a manifest failure cannot leave old success.
    Never traverse a case-directory symlink or recursively remove anything.
    """
    folder = directory / case_id
    if directory.is_symlink() or folder.is_symlink():
        raise ArtifactError(f"refusing symlinked output directory: {folder}")
    try:
        (folder / "normalized.json").unlink(missing_ok=True)
    except OSError as exc:
        raise ArtifactError(
            f"cannot invalidate {folder / 'normalized.json'}; any existing result is stale: {exc}"
        ) from exc


def error_result(case_id, exc):
    return {"case": case_id, "status": "error", "error": str(exc)}


def evaluate(directory):
    invalidations = {}
    for case_id in CASE_IDS:
        try:
            invalidate_output(directory, case_id)
        except (ArtifactError, OSError) as exc:
            invalidations[case_id] = str(exc)
    try:
        cases = load_manifest()["cases"]
    except ArtifactError as exc:
        return [
            error_result(
                case_id,
                f"{exc}; {invalidations[case_id]}" if case_id in invalidations else exc,
            )
            for case_id in CASE_IDS
        ]
    results = []
    for case in cases:
        case_id = case["id"]
        if case_id in invalidations:
            results.append(error_result(case_id, invalidations[case_id]))
            continue
        try:
            result, normalized = evaluate_case(directory / case_id, case)
            if normalized is not None:
                write(directory / case_id / "normalized.json", normalized)
        except ArtifactError as exc:
            result = error_result(case_id, exc)
        results.append(result)
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
