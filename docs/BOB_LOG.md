# IBM Bob usage log

One row per Bob task. Bob appends rows itself (rule 9 in `AGENTS.md`).
The raw, automatic log of every prompt and session end is in `docs/bob/session-log.jsonl` (written by the hooks in `.bob/settings.json`).

| Date       | Mode                   | Task                             | Output (files / commit) | Notes                                                                                            |
| ---------- | ---------------------- | -------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------ |
| 2025-07-30 | Agent                  | Set up fork and record baseline  | `docs/BASELINE.md`      | Node v24.11.0, pnpm 10.30.3; build 6/6 ✅; tests 910/910 ✅; 0 pre-existing failures             |
| 2025-07-30 | 🔍 Secret Leak Auditor | Audit credential/vars leak paths | `docs/AUDIT.md`         | 10 findings (2 Critical/High E2B+NodeVM, 5 High/Medium trace+log+S1, 3 disproved); all CONFIRMED |
| 2025-07-30 | Plan                   | Design Zero-Context Guard        | `docs/DESIGN.md`        | Covers F-01–F-10; 8 subtasks; 2 new files, 4 modified files; awaiting approval                   |
