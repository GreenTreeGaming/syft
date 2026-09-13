"""Generate a standalone HTML demo report from saved Syft JSON."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from syft.agent.models import AgentRun
from syft.eval.ground_truth import load_ground_truth
from syft.models.analysis import WorkflowAnalysis
from syft.reporting.html_report import write_html_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render a zero-network Syft HTML demo report from saved JSON"
    )
    parser.add_argument("--analysis", required=True, type=Path, help="WorkflowAnalysis JSON file")
    parser.add_argument("--agent-run", type=Path, help="optional AgentRun JSON with explanations and action URLs")
    parser.add_argument("--ground-truth", type=Path, help="optional ground-truth JSON for the confusion matrix")
    parser.add_argument("--output", required=True, type=Path, help="destination .html path")
    arguments = parser.parse_args(argv)

    try:
        workflow = WorkflowAnalysis.model_validate_json(arguments.analysis.read_text(encoding="utf-8"))
        agent_run = None
        if arguments.agent_run is not None:
            agent_run = AgentRun.model_validate_json(arguments.agent_run.read_text(encoding="utf-8"))
        ground_truth = None
        if arguments.ground_truth is not None:
            ground_truth = load_ground_truth(arguments.ground_truth)
        path = write_html_report(
            arguments.output,
            workflow,
            agent_run=agent_run,
            ground_truth=ground_truth,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
