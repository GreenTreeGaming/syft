# Syft submission checklist

## Repositories

- [ ] Decide whether judges need public access; both repositories are currently private.
- [ ] `syft/main` contains the deterministic engine, action agent, security fix, CI, and benchmark.
- [ ] `syft-testing/main` remains the green baseline.
- [ ] Fixture PR #1 remains open with the three intentional failures.
- [ ] Quarantine PR #2 remains open and visibly changes only the flaky test.
- [ ] Remove the stale `signal-collection` branch when it is no longer needed.

## Security

- [ ] Revoke the Slack webhook exposed in terminal output and replace it.
- [ ] Confirm no API keys appear in screenshots, recordings, shell history, `.env`, traces, or committed files.
- [ ] Never display the Slack Incoming Webhooks configuration page while recording.
- [ ] Keep `.syft-agent-state.json` uncommitted.

## Verification

- [ ] `python -m pytest` reports 46 passing tests.
- [ ] `python -m syft.eval.benchmark --input eval/classifier_benchmark.json` reports 15/15 correct.
- [ ] GitHub Actions passes on Python 3.12 and 3.14.
- [ ] Fixture baseline run is green.
- [ ] Fixture regression run shows three failures and a JUnit artifact.
- [ ] Quarantine PR run shows two failures and one skipped test.
- [ ] Linear SYF-5 and SYF-6 are readable and contain analysis IDs.
- [ ] Slack digest contains three classifications and working action links.

## Demo assets

- [ ] `01-failed-ci.png` — three failures and JUnit artifact.
- [ ] `02-workflow-analysis.png` — all three classifications and rerun counts.
- [ ] `03-reliability-metrics.png` — accuracy, confusion matrix, and zero regression false negatives.
- [ ] `03b-llm-explanation.png` — optional exact checkout hypothesis.
- [ ] `04-flaky-quarantine-pr.png` — narrow test edit plus evidence-rich PR description.
- [ ] `05-linear-tickets.png` — regression and escalation tickets together.
- [ ] `06-slack-digest.png` — one digest with links.
- [ ] Generated HTML report opens locally with no missing content or console errors.

## Recording

- [ ] Rehearse against `docs/demo-script.md` and finish below two minutes.
- [ ] Record at readable resolution with notifications disabled.
- [ ] Avoid live external writes; use the already-created actions.
- [ ] Export a backup MP4 and verify audio before submission.
- [ ] Keep a second copy of the video and screenshots outside `/tmp`.

## Final claims

- [ ] Say “100% on the controlled evaluation,” not “100% accurate in production.”
- [ ] Distinguish the 15-case rule-boundary benchmark from the three-case end-to-end fixture.
- [ ] Lead with zero regressions classified as flaky.
- [ ] State that confidence values are rule scores, not calibrated probabilities.
- [ ] State the direct-import limitation and the human-escalation safety valve.
