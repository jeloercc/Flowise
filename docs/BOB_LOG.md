# IBM Bob usage log

One row per Bob task. Bob appends rows itself (rule 9 in `AGENTS.md`).
The raw, automatic log of every prompt and session end is in `docs/bob/session-log.jsonl` (written by the hooks in `.bob/settings.json`).

| Date       | Mode  | Task                            | Output (files / commit) | Notes                                                                                |
| ---------- | ----- | ------------------------------- | ----------------------- | ------------------------------------------------------------------------------------ |
| 2025-07-30 | Agent | Set up fork and record baseline | `docs/BASELINE.md`      | Node v24.11.0, pnpm 10.30.3; build 6/6 ✅; tests 910/910 ✅; 0 pre-existing failures |
