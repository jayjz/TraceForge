"""Capture two synthetic scanner responses through real CipherLoop components."""

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from traceforge.evaluation.baseline_contract import (
    FIXTURES,
    ArtifactError,
    canonical_artifact,
    digest,
    environment,
    provenance,
    read,
    require,
    sha,
    write,
)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def generate(repo, output):
    manifest = read(FIXTURES / "manifest.json")
    require(
        git(repo, "rev-parse", "HEAD") == manifest["cipherloop_commit"],
        "CipherLoop commit mismatch",
    )
    require(
        not git(repo, "status", "--porcelain", "--untracked-files=all"),
        "CipherLoop working tree must be clean",
    )
    require(
        environment() == read(FIXTURES / "environment.json"),
        "capture environment differs from environment.json",
    )
    sources = {}
    for case in manifest["cases"]:
        data = (repo / case["source"]).read_bytes()
        require(
            sha(data) == case["source_sha256"], f"{case['id']}: fixture hash mismatch"
        )
        ast.parse(data.decode(), filename=case["source"])
        sources[case["id"]] = data
    # Refuse reuse because the upstream recorder appends to existing ledgers.
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(repo / "src"))
    from cipherloop.core.trajectory import TrajectoryRecorder
    from cipherloop.executor import validator
    from cipherloop.executor.compressor import compressor_node
    from langchain_core.messages import AIMessage, ToolMessage
    from langgraph.graph.message import add_messages

    index = {"provenance": provenance(), "cases": {}}
    for case in manifest["cases"]:
        case_id = case["id"]
        folder = output / case_id
        folder.mkdir()
        source = sources[case_id]
        (folder / "source.py").write_bytes(source)
        raw = json.dumps({"results": [case["candidate"]]}, sort_keys=True)
        call_id = f"{case_id}-scan"
        messages = [
            AIMessage(
                content="",
                id=f"{case_id}-ai",
                tool_calls=[
                    {
                        "name": "run_semgrep",
                        "args": {"target_path": "app.py"},
                        "id": call_id,
                    }
                ],
            ),
            ToolMessage(
                content=raw,
                name="run_semgrep",
                tool_call_id=call_id,
                id=f"{case_id}-tool",
            ),
        ]
        state = {
            "messages": messages,
            "compressed_findings": [],
            "verified_findings": [],
            "target_directory": "/workspace/target_repo",
            "current_plan": None,
            "retries": 0,
        }
        recorder = TrajectoryRecorder(case_id, str(folder))
        config = {"configurable": {"__trajectory_recorder__": recorder}}
        reads = []

        def fixture_read(arguments, reads=reads, source=source):
            event = {"arguments": arguments, "status": "error"}
            reads.append(event)
            require(
                arguments
                == {"filepath": "app.py", "start_line": 1, "end_line": 1_000_000},
                "unexpected validator read",
            )
            event.update(status="ok", source_sha256=sha(source))
            return source.decode()

        with (
            patch(
                "cipherloop.tools.filesystem.execute_in_sandbox",
                side_effect=AssertionError("tactical execution forbidden"),
            ),
            patch.object(validator, "read_file", SimpleNamespace(invoke=fixture_read)),
        ):
            compressed = compressor_node(state, config)
            state["messages"] = add_messages(messages, compressed["messages"])
            state["compressed_findings"] = compressed["compressed_findings"]
            require(not state["messages"], "message shearing failed")
            validated = validator.validator_node(state, config)
            require(
                len(reads) == 1 and reads[0]["status"] == "ok",
                "validation read failed or missing",
            )
            state.update(validated)
            recorder.finalize(state)

        ledger = [
            json.loads(line)
            for line in recorder.trajectory_file.read_text().splitlines()
        ]
        metadata = read(recorder.metadata_file)
        span = case["slice"]
        capture = {
            "run_id": case_id,
            "execution_status": "completed",
            "synthetic_scanner": True,
            "source_sha256": sha(source),
            "scanner_input_sha256": sha(raw.encode()),
            "compressed_findings": compressed["compressed_findings"],
            "verified_findings": validated["verified_findings"],
            "validation_reads": reads,
            "removed_message_ids": [m.id for m in compressed["messages"]],
            "remaining_messages": 0,
            "source_slice": {
                **span,
                "file": "app.py",
                "text": "".join(
                    source.decode().splitlines(keepends=True)[
                        span["start_line"] - 1 : span["end_line"]
                    ]
                ),
            },
            "references": {
                "raw_result_row": 2,
                "validation_row": 3,
                "source": "source.py",
            },
            "unavailable": [
                "original_agent_task",
                "final_report",
                "models",
                "recovery",
                "safety",
                "cost",
                "tokens",
                "rubric_scores",
            ],
        }
        write(folder / "capture.json", capture)
        index["cases"][case_id] = {
            "source_sha256": sha(source),
            **{
                f"{name}_sha256": digest(canonical_artifact(name, value))
                for name, value in (
                    ("ledger", ledger),
                    ("metadata", metadata),
                    ("capture", capture),
                )
            },
        }
    # Written last: no complete index exists if any capture failed.
    write(output / "index.json", index)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cipherloop", type=Path, default=Path("../CipherLoop"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        generate(args.cipherloop.resolve(), args.output.resolve())
    except (ArtifactError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"capture error: {exc}", file=sys.stderr)
        return 2
    print(f"Captured toy and safe in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
