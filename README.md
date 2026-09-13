# Syft deterministic CI triage

Syft turns a failed pytest test into a structured, versioned `TestAnalysis`. Classification is entirely deterministic: an LLM never decides whether a failure is `FLAKY`, `REGRESSION`, or `ESCALATE`.

## What is included

- GitHub Actions failed/last-green run discovery and safe JUnit artifact download
- pytest JUnit failure parsing
- five isolated pytest reruns with timeout evidence
- Git diff plus direct-import analysis using Python's AST
- optional previous-commit verification in a temporary Git worktree
- pure, explainable classification rules that favor `ESCALATE` when evidence is missing
- sanitized JSON traces with stable `analysis_id` values
- evaluation metrics, including the safety-critical `REGRESSION -> FLAKY` count

This repository intentionally does not contain the LLM agent, Slack/Linear integrations, or pull-request automation.

## Setup

Python 3.12 or newer is required.

```bash
cd /Users/sarvajithkarun/Desktop/Projects/syft
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

Set `GITHUB_TOKEN` and `GITHUB_REPOSITORY=owner/repo` when using GitHub run discovery. Unit tests do not need credentials.

## Run an analysis

```bash
python -m syft \
  tests/test_checkout.py::test_checkout \
  --repo /path/to/fixture-repository \
  --current-commit f8a2391 \
  --last-green-commit a42db91
```

The command prints compact consumer JSON and writes a full sanitized evidence trace beneath `<repo>/traces/`. The compact JSON retains attempt outcomes, durations, and exit codes but omits repeated raw pytest output. Omit `--current-commit` to use `HEAD`. Use `--skip-previous-check` when the last-green worktree cannot run in the local environment; this leaves prior behavior as `null` rather than inventing evidence.

Do not copy `/path/to/fixture-repository` literally; replace it with a real checkout. The maintained fixture can be run with:

```bash
.venv/bin/python -m syft \
  tests/test_checkout.py::test_checkout \
  --repo /Users/sarvajithkarun/Desktop/Projects/syft-testing \
  --current-commit f29ac136363632d73a16afc45576ab83af7978d2 \
  --last-green-commit 4deaeab237d31edd88ba473cb6b551fb74cc71d5 \
  --github-repository GreenTreeGaming/syft-testing \
  --branch codex/regression-fixture \
  --workflow-run-id 34770710053 \
  --workflow-name CI \
  --artifact-name pytest-junit
```

Run this as your normal user. `sudo` selects a different Python environment and is unnecessary.

Library usage:

```python
from pathlib import Path

from syft.deterministic.pipeline import analyze_failed_test

analysis = analyze_failed_test(
    repo_path=Path("/path/to/repo"),
    test_node_id="tests/test_checkout.py::test_checkout",
    current_commit="f8a2391",
    last_green_commit="a42db91",
)
print(analysis.model_dump_json(indent=2))
```

Use `analysis.consumer_dump_json(indent=2)` for the compact Person B contract. `model_dump_json()` retains complete rerun output for auditing and trace persistence.

## Discover workflow evidence

```python
from pathlib import Path

from syft.deterministic.github_runs import GitHubActionsClient

with GitHubActionsClient.from_environment() as github:
    failed = github.latest_failed_run(branch="main")
    previous_green = github.previous_successful_run(failed, branch="main")
    artifact = github.download_junit_artifact(failed.id, Path("artifacts"))
```

## Analyze the latest failed workflow automatically

Export GitHub configuration without placing the token in source control, then run the coordinator:

```bash
export GITHUB_TOKEN="$(gh auth token)"
export GITHUB_REPOSITORY="GreenTreeGaming/syft-testing"

python -m syft poll \
  --repo /Users/sarvajithkarun/Desktop/Projects/syft-testing \
  --branch codex/regression-fixture \
  --green-branch main \
  --artifact-name pytest-junit \
  --ground-truth /Users/sarvajithkarun/Desktop/Projects/syft-testing/eval/ground_truth.json
```

The coordinator discovers the newest failed run, finds the prior successful run, downloads its JUnit artifact, analyzes every failed test from a detached checkout, writes full traces, and prints a compact `WorkflowAnalysis` JSON envelope. When `--ground-truth` is provided, the confusion matrix and regression safety metrics are printed to stderr.

## Run tests

```bash
python -m pytest
```

## Classification rules

- Mixed passes and failures, with no directly related source change: `FLAKY`.
- Every rerun fails and directly related source changed: `REGRESSION`, unless prior-commit behavior conflicts.
- Missing evidence, timeouts, all-pass reruns, or conflicting signals: `ESCALATE`.

`REGRESSION -> FLAKY` is treated as the highest-risk classification mistake.

## Current limitations

- Related-code analysis follows direct imports only; it is intentionally not a full dependency graph.
- Previous-commit execution assumes the active Python environment can run that revision.
- GitHub artifact selection uses an explicit name or common JUnit artifact naming conventions.
- Confidence values are explainable rule scores, not statistical probabilities.
