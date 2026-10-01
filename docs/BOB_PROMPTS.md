# Master prompts for IBM Bob

Prompts for every phase of the Zero-Context Guard project, in the order you will use them.

## How this kit works

Good prompts for Bob have two layers.

1. **The permanent layer (already installed, you never retype it):**
   - `AGENTS.md`: project context, commands and rules. Bob loads it in every mode.
   - `.bob/custom_modes.yaml`: three expert modes, each with its role, method, file permissions and stop rules.
     - 🔍 **Secret Leak Auditor**: reads code, writes only `docs/*.md`, cannot run commands.
     - 🛡️ **Guard Engineer**: test-first, can run commands, can edit only `packages/components` (src, Custom Tool, tests), `docs/` and `demo/`.
     - 📣 **Hackathon Writer**: writes only Markdown for judges, with evidence.
   - `.bob/settings.json` + `.bob/hooks/`: log every prompt (with keys redacted) and every session end to `docs/bob/session-log.jsonl`.
   - `.bobignore`: Bob cannot read `.env`, `encryption.key` or databases. Zero-Context, applied to Bob itself.
2. **The task layer (the prompts below):** short, because the mode already knows *how* to work. They only say *what* to do and *when it is done*.

### Template

```
CONTEXT: @file1 @file2          ← point at files; never "read the whole repo"
TASK:    one sentence
CONSTRAINTS: bullets            ← what not to touch, fake secrets only, scope
OUTPUT:  exact file and format
DONE WHEN: checkable criteria   ← tests pass, every item marked, file exists
```

### Six rules

1. One task per Bob session. Start a new task when the goal changes; it keeps context small and saves Bobcoins.
2. Use `@file` mentions instead of asking Bob to explore everything.
3. Ask for evidence: `file:line` for every claim.
4. Name the output file and its format.
5. Always end with **DONE WHEN**. Bob stops at the right place and you can check it.
6. Make Bob challenge its own work (prompts 1.3 and 2.4).

---

## Day 0: get the code

Source project: https://github.com/FlowiseAI/Flowise (archived, Apache 2.0; archived repositories can still be forked).

1. On GitHub, open the link above and click **Fork**. Keep the fork public so the judges can see it, and invite your teammates.
2. Clone it to your **internal disk** (pnpm uses symlinks, which often fail on external exFAT drives).
3. Copy this kit into the root of the clone and open that folder in Bob IDE.

You can let Bob do steps 2 and 3. Open an empty folder such as `~/code` in Bob IDE and use:

### 0.1 Clone · mode: Agent (built-in)

```
Clone my fork and prepare the working branch.
1. Run: git clone https://github.com/<YOUR_GITHUB_USER>/Flowise.git
2. In the new Flowise folder: git checkout -b zero-context-guard
3. Unzip ~/Downloads/bob-kit.zip into the Flowise folder root (it contains AGENTS.md, .bob/, .bobignore and docs/).
4. Add "._*" and ".DS_Store" to .gitignore, then commit only the kit files with the message "chore: add IBM Bob kit (modes, rules, hooks, prompts)".
DONE WHEN: git log shows that commit on branch zero-context-guard. Then tell me to reopen Bob IDE on the Flowise folder.
```

---

## Day 1: prepare and audit

### 1.1 Baseline · mode: Agent (built-in)

```
Set up this Flowise fork and record a baseline. Do not change any source code.
1. Check node --version (must be >= 20) and pnpm --version. If pnpm is missing, tell me the install command instead of installing it.
2. Run pnpm install, then pnpm build. If the build fails with "heap out of memory", retry with NODE_OPTIONS=--max-old-space-size=4096.
3. Run pnpm --filter flowise-components test. Record passed / failed / skipped counts and the duration.
4. Write docs/BASELINE.md: versions, commands run, results, and every failing test (name + one-line reason), labeled "pre-existing".
DONE WHEN: docs/BASELINE.md exists with the test counts, and a row is appended to docs/BOB_LOG.md.
```

### 1.2 Security audit · mode: 🔍 Secret Leak Auditor

```
Audit how secrets can leak in this Flowise fork. Follow your METHOD.
CONTEXT:
@packages/components/src/utils.ts
@packages/components/src/httpSecurity.ts
@packages/components/nodes/tools/CustomTool/core.ts
@packages/components/nodes/tools/CustomTool/CustomTool.ts
Then use the Explore subagent to find: (a) where tool errors become messages for the LLM, (b) where tool input/output is stored (chat messages, executions, analytics), (c) whether $vars can be used inside prompts.

Confirm or disprove each hypothesis. Do not assume any is true.
H1 Custom Tool return values go back to the LLM unfiltered.
H2 Every Custom Tool receives ALL workspace variables as $vars, including runtime ones read from process.env.
H3 checkDenyList blocks private IPs and localhost but not public hosts, so an injected URL can receive a key that the tool code adds to the request.
H4 In secureAxiosRequest / secureFetch, headers (including Authorization) are kept when a redirect goes to a different host.
H5 handleErrorMessage and parseJsonBody can copy secret-bearing text into errors that reach the LLM.
H6 handleToolStart / handleToolEnd send full tool input and output to tracing callbacks.
H7 With E2B_APIKEY set, $vars are serialized into code sent to a third-party sandbox.

OUTPUT: docs/AUDIT.md with
1) summary table: ID, sink, severity, confidence, LLM-controllable (yes/no)
2) one section per finding in your FOR EACH FINDING format
3) "Disproved hypotheses" with evidence
4) "Recommended scope for a 1-day fix" (max 3 findings)
DONE WHEN: H1-H7 are each marked CONFIRMED, DISPROVED or UNVERIFIED with file:line evidence, and a row is appended to docs/BOB_LOG.md.
```

### 1.3 Challenge the audit · mode: Ask (built-in)

```
Act as a skeptical reviewer of @docs/AUDIT.md.
For each CONFIRMED finding, try to break it: is there a guard, sanitizer, config default or code path the auditor missed? Is the severity inflated?
OUTPUT: a table in the chat: ID, verdict (stands / downgrade / wrong), reason with file:line.
CONSTRAINTS: do not edit files.
```

Then switch back to 🔍 Secret Leak Auditor: `Apply the review above to @docs/AUDIT.md. Keep a "Review notes" section listing what changed.`

### 1.4 "Before" attack demo · mode: 🛡️ Guard Engineer

```
Build a reproducible "before" demo of the exfiltration finding in @docs/AUDIT.md. Use fake secrets only.
Create:
1. demo/custom-tool-vulnerable.js: the JavaScript body of a Flowise Custom Tool "fetch_issue" that takes {url}, reads $vars.DEMO_API_KEY and calls the URL with the header "Authorization: Bearer <key>" using the sandboxed axios, returning the response body. This is how integrations are typically written today.
2. demo/injection.md: content an attacker could plant (an issue or a web page) with a prompt injection that makes the agent call fetch_issue with <ATTACKER_URL>.
3. demo/README.md: steps to reproduce in the Flowise UI: create the variable DEMO_API_KEY = sk-FAKE-DEMO-0000000000, create the tool, build an agent flow, feed it the injection, watch the receiver.
CONSTRAINTS:
- localhost and private IPs are blocked by checkDenyList (@packages/components/src/httpSecurity.ts), so the receiver must be a public request-inspector URL; leave the placeholder <ATTACKER_URL>.
- Do not change any Flowise source code in this task.
DONE WHEN: following demo/README.md, the fake key appears in the receiver; a row is appended to docs/BOB_LOG.md.
```

---

## Day 2: build the guard

### 2.1 Design · mode: Plan (built-in)

```
Using @docs/AUDIT.md and @AGENTS.md, design the Zero-Context Guard for the Custom Tool.
Requirements:
R1 Neither the LLM nor the tool code ever sees a raw secret. Tools call $secureRequest(name, url, options).
R2 The Custom Tool node gets an optional "Secret Bindings" input (JSON): [{ "name", "credentialId", "credentialField", "allowedHosts": [] }]. The existing UI renders it from the node definition; no changes in packages/ui.
R3 Resolve with getCredentialData only at request time; keep values in memory only for that call.
R4 Enforce allowedHosts on the first request and on every redirect hop; drop Authorization on cross-host redirects; reject URLs with userinfo; https only by default.
R5 Redact resolved values (raw, URL-encoded, base64) and common key patterns from results, thrown errors and anything passed to handleToolEnd.
R6 Emit an audit event for every allowed or blocked use, without values.
R7 With no bindings, behavior is identical to today.
R8 Scope: NodeVM path only. E2B and Agentflow are roadmap.
OUTPUT: docs/DESIGN.md with: a Mermaid sequence diagram, module API (TypeScript signatures), files to change, a test plan mapped to R1-R8, a threat model (including what this does NOT protect against), and risks.
CONSTRAINTS: ask me before deciding anything not covered by R1-R8.
DONE WHEN: every requirement R1-R8 maps to at least one planned test.
```

### 2.2 Tests first · mode: 🛡️ Guard Engineer

```
From @docs/DESIGN.md, write the unit tests for the guard BEFORE any implementation, in the location the design names.
Cover at least:
- allowed host: request succeeds, auth header added, result contains no secret
- host not allowed: blocked, audit event "blocked", no network call made
- tricky URLs: api.github.com.evil.com, evil.com/api.github.com, user:pass@api.github.com, API.GITHUB.COM (allowed), http:// when https is required
- redirect from an allowed host to another host: blocked, or Authorization dropped, as the design says
- redaction of the raw, URL-encoded and base64 secret in the body, in an echoed header, and in a thrown error
- handleToolEnd receives the redacted string
- a tool without bindings returns exactly what the current implementation returns
CONSTRAINTS: mock the network, no real HTTP. Do not implement the guard yet.
DONE WHEN: the tests run and fail for the expected reason (module or function missing), not because of syntax errors.
```

### 2.3 Implement · mode: 🛡️ Guard Engineer

```
Implement the Zero-Context Guard so the tests from step 2.2 pass, following @docs/DESIGN.md.
Work in this order; run the tests after each step and give a 3-line summary:
1) packages/components/src/secretGuard.ts: resolve, host check, redirect handling, redaction, audit events.
2) @packages/components/nodes/tools/CustomTool/core.ts: expose $secureRequest in the sandbox; redact before handleToolEnd and before throwing.
3) @packages/components/nodes/tools/CustomTool/CustomTool.ts: add the optional "Secret Bindings" input and pass it to the tool in init().
After step 3, run the full component test suite and pnpm --filter flowise-components build.
DONE WHEN: the new tests pass, pre-existing results match @docs/BASELINE.md, and the build passes. Propose one Conventional Commit per step.
```

### 2.4 Attack your own code · mode: 🛡️ Guard Engineer (review only)

```
Review the diff (git diff main...HEAD) as an attacker who controls the LLM's tool arguments and the content of external pages. Goal: get a secret out, or send it to a host that is not allowed.
Check: URL parsing tricks, redirects, DNS, encodings (URL, base64, hex, split across fields), error paths, timeouts, two tool calls running at the same time, logs and tracing, and tools with no bindings.
OUTPUT: for each issue: attack, file:line, impact, minimal fix. For each category with no issue, say what you checked.
CONSTRAINTS: do not edit files in this task.
```

Then: `Fix issues #N and #M from the review, test-first, one commit each.`

### 2.5 "After" demo · mode: 🛡️ Guard Engineer

```
Add the protected version of the demo.
1. demo/custom-tool-protected.js: same tool, but it calls $secureRequest('demo', url) and never reads the key.
2. Extend demo/README.md with an "After" section: the binding to configure ({ name: 'demo', allowedHosts: ['<legit API host>'] }), the same injection, the expected result (blocked + audit event), and where to see the audit event.
CONSTRAINTS: do not change guard code in this task.
DONE WHEN: following the "After" steps, the receiver gets nothing and the audit event shows decision "blocked".
```

---

## Day 3: tell the story

### 3.1 README · mode: 📣 Hackathon Writer

```
Write README.md for the judges. Sections:
1. What it is (2 sentences)
2. Why it matters (Flowise end-of-life + OWASP LLM02:2025, with links)
3. Demo: before / after (link demo/README.md)
4. How it works (link the diagram in docs/DESIGN.md)
5. Quick start (exact commands)
6. Tests (command + results from a real run)
7. Improvements Made (table: change, files, test that proves it)
8. Tech stack
9. How we used IBM Bob (table: phase, Bob mode, what Bob produced, evidence link)
10. Limitations and roadmap
CONSTRAINTS: only facts present in the repo; TODO(number) where a number is missing.
```

### 3.2 Submission texts · mode: 📣 Hackathon Writer

```
Using @README.md, write docs/SUBMISSION.md with:
1. Project description, max 100 words
2. Track: Theme 2 — Modernize What Matters
3. Tech stack as a bullet list
4. Improvements Made in 5-8 bullets
Report the word count of each part.
```

### 3.3 Pitch deck outline · mode: 📣 Hackathon Writer

```
Write docs/PITCH_OUTLINE.md, 8 slides max. For each slide: title (max 8 words), up to 3 bullets, the visual to show, and speaker notes (2 sentences).
Required slides: team and project intro, the problem, the attack, solution and architecture, how Bob was used (with counts from docs/bob/session-log.jsonl), results (tests, findings closed), roadmap and learnings.
```

### 3.4 Video script · mode: 📣 Hackathon Writer

```
Write docs/VIDEO_SCRIPT.md for a demo of at most 2:50.
Table: timestamp, what is on screen, narration (spoken English, max 25 words per row).
Show: the leak, Bob auditing and planning, tests going green, the same attack blocked, the audit event.
End with the total word count (target 330-380 words).
```

### 3.5 Bob usage evidence · mode: 📣 Hackathon Writer

```
Read docs/bob/session-log.jsonl and @docs/BOB_LOG.md. Write docs/BOB_USAGE.md:
- totals: sessions, prompts, active days
- table of the main sessions: date, goal, mode, outcome, commit
- 3 short examples of prompts that changed the result, and why
CONSTRAINTS: never include anything that looks like a key or token.
```

---

## Rescue prompts (any mode)

| Situation | Prompt |
| --- | --- |
| Bob is going in circles | `Stop. In 5 bullets: what you tried, the exact error, your current hypothesis, and the smallest next experiment. Do not change files.` |
| The diff is too big | `This change touches too much. Go back to the last green state and redo only step N with the smallest possible diff.` |
| A claim sounds wrong | `Show the exact lines (file:line) that prove that. If you cannot, mark it UNVERIFIED.` |
| The conversation is long | `Summarize the state for a fresh session in 10 lines: goal, done, files changed, failing tests, next step.` Then paste it into a new task. |
| Bob wants to edit outside its mode | Decide yourself. If it is justified, switch to Agent mode for that one change and log why in docs/BOB_LOG.md. |
