# PureVoting 2.0 — working rules for Claude Code

- `contracts/` is the source of truth for every interface. Change a contract before changing code that depends on it, record it in `contracts/CHANGELOG.md`, and run `python tools/validate_contracts.py`.
- Design decisions live in `docs/decisions.md` (all confirmed in v1.0 except D-02, delegated to Harits, and D-15, delegated to Anik). Changing a confirmed decision is a team-lead (Seungmin) call and goes through a PR.
- Overall design: `docs/system-design.md`. Role designs: `docs/roles/core-web.md`, `docs/roles/ledger.md`, `docs/roles/rules-ai.md`. English documents are the reference (D-19).
- Project supervisor: `.claude/agents/psp1-project-supervisor.md`. Call it (review only, it never edits) at these points:
  - before a design is confirmed (contracts / architecture changes)
  - when reviewing a PR that touches `contracts/`, the ledger, the rule engine or the audit agent
  - weekly progress checks, after integration tests, and before the final presentation
  Its report format and stage gates (G0–G6) are defined in that file. Fix P0/P1 findings before moving to the next gate.
