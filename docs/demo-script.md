# Syft two-minute demo script

## Before recording

- Keep the fixture PRs open. `syft-testing/main` is the green baseline; `codex/regression-fixture` is the intentionally failing branch.
- Revoke the previously exposed Slack webhook and keep the replacement secret.
- Open the six assets in separate tabs in the order below.
- Turn on Do Not Disturb, hide bookmarks and personal tabs, and use browser zoom that keeps IDs and evidence readable.
- Do not show a terminal containing environment variables or secret-bearing command history.

## 0:00–0:15 — The risk

**Screen:** title or architecture diagram.

**Say:** “CI teams lose time to flaky failures, but automatically skipping a real regression is worse. Syft makes that safety decision deterministically and uses AI only to explain the evidence.”

## 0:15–0:32 — A real failed workflow

**Screen:** `01-failed-ci.png`.

**Say:** “This GitHub Actions run has three failures at once: a real checkout regression, an intermittent cache test, and an environment failure with conflicting evidence. The run also uploads machine-readable JUnit evidence.”

## 0:32–0:55 — Evidence, not guessing

**Screen:** terminal or `02-workflow-analysis.png`.

**Say:** “Syft downloads that artifact, reruns each failing test five times at the exact commit, compares the last green revision, and checks directly related source changes. The result is one flaky test, one regression, and one escalation.”

Point briefly to:

- `test_checkout`: 0/5 passed, related code changed, confidence 0.97.
- `test_cache_warmup_race`: 2/5 passed, no related code changed, confidence 0.91.
- `test_unexplained_environment_failure`: 0/5 passed but no related code change, so Syft refuses to guess.

## 0:55–1:15 — AI behind a hard boundary

**Screen:** checkout explanation in the generated report or `03b-llm-explanation.png`.

**Say:** “Only after classification does the LLM read the bounded evidence and exact-commit source. It correctly explains that checkout subtracts tax, producing 92 instead of 108. Its schema has no classification or confidence field, so it cannot change the decision.”

## 1:15–1:32 — Safe automated action

**Screen:** `04-flaky-quarantine-pr.png`.

**Say:** “For the flaky test, Syft opens a narrowly scoped quarantine PR with the rerun evidence and analysis ID. The follow-up CI proves the flaky test is skipped while the real regression remains visible.”

## 1:32–1:45 — Humans retain the risky work

**Screen:** `05-linear-tickets.png`.

**Say:** “The regression is never modified automatically. It becomes a detailed Linear ticket. Conflicting evidence becomes a separate needs-triage ticket instead of a fabricated answer.”

## 1:45–1:54 — One operational digest

**Screen:** `06-slack-digest.png`.

**Say:** “The team receives one Slack digest with counts, confidence, and direct links—not a flood of per-test notifications.”

## 1:54–2:00 — Reliability close

**Screen:** confusion matrix in the generated report or `03-reliability-metrics.png`.

**Say:** “Across the live fixture and 15 classifier boundary cases, Syft produced zero regression false negatives and zero regressions labeled flaky. When it is uncertain, it escalates.”

## Backup commands

Safe dry-run with structured AI explanations:

```bash
python -m syft agent \
  --input /tmp/syft-analysis.json \
  --repo /Users/sarvajithkarun/Desktop/Projects/syft-testing \
  --use-openai
```

Reliability benchmark:

```bash
python -m syft.eval.benchmark --input eval/classifier_benchmark.json
```

Do not rerun `--execute` during the recording. The actions already exist, and a live external write adds avoidable demo risk.
