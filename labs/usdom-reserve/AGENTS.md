# USDOM continuity rules

- At the start of every continuation, especially after context compaction, read
  `docs/CONTINUATION-STATE.md` before planning or editing.
- Treat the worktree, test output and release-gate output as authoritative. Use
  the continuation document as an index, then revalidate only the state needed
  for the next action. Do not repeat completed stages without contradictory new
  evidence.
- After every discrete advancement, update `docs/CONTINUATION-STATE.md` with
  what changed, the evidence produced and the exact next action. Keep the
  current checkpoint concise and append one entry to its progress log.
- Preserve the operator policy recorded in that document. In particular, do
  not push, deploy, move funds, mine or run expensive RISC Zero proving unless
  the operator explicitly authorizes the specific action.
- External audit and an absolute zero-risk guarantee are not release gates.
  Objective code, configuration, evidence and live-identity failures remain
  fail-closed conditions. Residual risk may be accepted for an exact release.

