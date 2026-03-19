# SASTbench Handoff Context

This file captures the full working context from the conversation used to shape the benchmark plan. It is intended to be reused in a different repo or a fresh session.

## 1. User Goal

The user wants to build a benchmark that can become the default reference benchmark for SAST on agentic codebases, similar in role to a benchmark like XBow in its category.

The user explicitly wants:

- practitioners and scanner builders to use it
- strong real-world case coverage
- diverse synthetic agent functionality
- focus on vulnerabilities that are common in agentic systems
- Python, TypeScript, and Rust as the initial languages

The user also stated:

- agentic benchmark should be very precise
- real-world cases are easiest to build and maintain
- more real-world cases are better
- synthetic cases should cover diverse agent domains such as medical, end-user, coding, and other agent types

## 2. Main Positioning Decision

The benchmark should **not** launch as a general next-generation SAST benchmark.

It should launch as:

`The benchmark for evaluating SAST tools on agentic codebases.`

Core message:

`Can your scanner find real vulnerabilities in agentic repos without flagging the code the agent is supposed to run?`

This narrower wedge was judged much stronger for adoption and memorability than a broad "benchmark for all SAST" framing.

## 3. Primary Audiences

Priority order:

1. Practitioners choosing scanners for agentic products
2. Scanner builders improving agentic precision and recall
3. Researchers citing benchmarked behavior on modern codebases

V1 should optimize first for practitioners and scanner builders.

## 4. V1 Scope Decision

V1 should stay narrow in taxonomy and broad in product stories.

The benchmark should be:

- diverse in agent functionality
- narrow in vulnerability families

V1 canonical vulnerability kinds:

- `command_injection`
- `path_traversal`
- `ssrf`

Things intentionally excluded from V1 scoring:

- general logic bugs
- prompt injection as a standalone static category
- secret scanning quality
- severity calibration across tools
- end-to-end runtime exploit benchmarking

## 5. Tracks

The benchmark plan evolved to this track structure:

- `Core Track`: fixed self-contained vendored cases, no setup required
- `Full Track`: pinned real-world public repo snapshots
- `Patch Track`: deferred to V2

Important V1 decision:

- `Full Track` is intentionally **uncapped**
- more qualified real-world cases are encouraged
- only quality, reproducibility, and taxonomy fit should constrain Full Track growth

## 6. Language Scope

Initial languages:

- Python
- TypeScript
- Rust

Important follow-up decision:

- Rust should not be treated as optional in spirit
- V1 should actively include at least one strong Rust Full Track case
- `openai/codex` became the main Rust-first real-world candidate

## 7. Core Benchmark Identity

The benchmark was shaped around this core claim:

`SASTbench evaluates whether static analyzers can detect real vulnerabilities in agentic codebases without treating intentional agent capabilities as vulnerabilities.`

The distinguishing benchmark properties are:

- real vulnerability detection
- capability-aware false-positive measurement
- mixed-intent scoring
- region-level annotation
- public reproducible real-world cases

## 8. Scoring Direction

The scoring direction agreed on in the conversation:

- use region overlap and canonical kind matching
- do not require severity match for official detection scoring
- do not depend on rule-name exact matching
- do not use raw finding counts as the main objective

Primary V1 metrics:

- `Recall`
- `Precision`
- `Capability FP Rate`
- `Mixed-Intent Accuracy`

Top-line score:

`Agentic Score = geometric_mean(Recall, 1 - Capability FP Rate, Mixed-Intent Accuracy)`

## 9. Annotation Direction

The plan moved from file-level intent toward region-level annotation.

Key idea:

- official cases should be annotated at path + line-range level
- capability-safe regions must declare why they are safe
- vulnerable regions must declare accepted canonical kinds

Guard contracts standardized for V1:

- `allowlist`
- `workspace_root`
- `host_allowlist`
- `scheme_allowlist`

## 10. Full Track Size Decision

This changed significantly during the conversation.

Original direction:

- small Full Track in V1

Final direction:

- `Core Track` remains disciplined and fixed
- `Full Track` should expand aggressively
- "the more the better" for real-world cases
- real-world cases are considered easier to build and maintain

Practical V1 target after the conversation:

- at least 15 total official cases
- 12 Core Track cases minimum
- 5 to 10+ real-world cases in `v1.0.0` if they annotate cleanly
- no hard cap on qualified Full Track cases

## 11. Synthetic Design Principle

The synthetic cases were explicitly redesigned to avoid toy snippets.

Core principle:

`untrusted user-controlled or model-controlled input reaches a high-power tool without the required guard`

This repeated failure pattern should drive V1 synthetic cases.

Synthetic diversity should come from:

- agent role
- product domain
- trust-boundary location

Not from:

- too many unrelated vulnerability families

## 12. Synthetic Agent Archetypes

The conversation explicitly asked for broad diversity in agent functionality.

Recommended archetypes:

- coding agent
- browser or travel agent
- medical research assistant
- medical triage assistant
- customer support assistant
- workspace organizer
- local ops or devops helper
- end-user productivity assistant

Important note:

- domain diversity is encouraged
- bug pattern should stay centered on capability-boundary mistakes

## 13. Synthetic Mini-Repo Shape

Synthetic Core Track cases should use a compact mini-repo shape rather than a single-file toy.

Recommended shape:

```text
case/
|-- case.json
|-- context.md
`-- project/
    |-- README.md
    |-- app/
    |   `-- entrypoint
    |-- agent/
    |   |-- planner
    |   |-- router
    |   `-- state
    |-- tools/
    |   |-- exec_tool
    |   |-- file_tool
    |   `-- http_tool
    |-- guards/
    |   |-- policy
    |   `-- validators
    |-- config/
    `-- tests/
```

Synthetic authoring expectations:

- one clear agent entrypoint
- at least one high-power capability
- realistic enough local context for scanners
- vulnerable behavior should live in tool wrappers, guards, helpers, or boundary checks
- safe cases should still use dangerous APIs, but safely

## 14. Core Track Synthetic Matrix

The synthetic matrix settled on 12 Core Track cases:

| ID | Language | Agent archetype | Case type | Primary capability | Canonical kind | Core story |
|----|----------|-----------------|-----------|--------------------|----------------|------------|
| `PY-SV-001` | Python | medical research agent | `synthetic_vulnerable` | network | `ssrf` | Agent fetches references or imaging URLs from model-suggested sources without host restrictions. |
| `PY-SV-002` | Python | document export assistant | `synthetic_vulnerable` | filesystem | `path_traversal` | Agent writes generated reports to a user-selected path without workspace-root enforcement. |
| `PY-CS-001` | Python | coding agent | `capability_safe` | execution | safe exec | Agent can run tests, but only through a fixed command allowlist. |
| `PY-MI-001` | Python | medical triage assistant | `mixed_intent` | network | `ssrf` | Safe clinical-source fetch path and unsafe arbitrary preview path coexist in one mini-repo. |
| `TS-SV-001` | TypeScript | coding agent in web IDE | `synthetic_vulnerable` | execution | `command_injection` | Tool runner forwards model-generated shell fragments directly into a command invocation helper. |
| `TS-SV-002` | TypeScript | travel or browser planning agent | `synthetic_vulnerable` | network | `ssrf` | Browser helper fetches arbitrary URLs for metadata or screenshots without enforcing approved hosts. |
| `TS-CS-001` | TypeScript | customer support fetch agent | `capability_safe` | network | safe network | Agent retrieves approved ticketing or CRM endpoints through a strict host allowlist. |
| `TS-MI-001` | TypeScript | consumer browser assistant | `mixed_intent` | network | `ssrf` | One navigation path enforces domain policy while a secondary helper bypasses it. |
| `RS-SV-001` | Rust | workspace refactor agent | `synthetic_vulnerable` | filesystem | `path_traversal` | Agent rewrites files using relative paths from plan steps without canonical workspace checks. |
| `RS-SV-002` | Rust | build or test runner agent | `synthetic_vulnerable` | execution | `command_injection` | Local build helper constructs shell commands from unchecked task parameters. |
| `RS-CS-001` | Rust | file organizer agent | `capability_safe` | filesystem | safe file | Agent can move files, but only inside a canonicalized workspace root. |
| `RS-MI-001` | Rust | local ops assistant | `mixed_intent` | execution | `command_injection` | Safe allowlisted maintenance commands and unsafe debug passthrough live side by side. |

## 15. Real-World Repo Selection Strategy

Real-world repos should be:

- public
- public fix or public disclosure available
- pinned vulnerable commit available
- clear vulnerable region exists
- reproducible locally
- mirrorable if upstream disappears

Important decision:

- use popular repos with public GitHub Security advisories
- use those advisories as the starting pool for case authoring
- keep all GHSA IDs in the plan for future work
- rank them by benchmark fit, not just severity

## 16. Why `claude-code` and `codex` Became Important

These were initially missed in the first shortlist, then explicitly added after the user called them out.

Reason for adding them:

- `anthropics/claude-code` is one of the strongest possible benchmark sources for agentic SAST
- `openai/codex` is strategically important because it gives a strong Rust-first real-world coding-agent target

This materially improved the plan.

## 17. Priority 1 Real-World Target Repos

Priority 1 repos after the conversation:

- `anthropics/claude-code`
- `anomalyco/opencode`
- `openai/codex`
- `microsoft/semantic-kernel`
- `langchain-ai/langgraph`
- `langchain-ai/langchain`
- `browser-use/browser-use`
- `Significant-Gravitas/AutoGPT`

Priority 2 repos after the conversation:

- `open-webui/open-webui`
- `OpenHands/OpenHands`
- `openinterpreter/open-interpreter`
- `continuedev/continue`
- `crewAIInc/crewAI`

## 18. Ranked GHSA Pool

All listed GHSA items were intentionally retained in the plan.

The final ranking/fitting logic used:

- `V1-first`
- `V1-reserve`
- `V2`
- `Future`

### Top `V1-first` real-world candidates

1. `anthropics/claude-code` / `GHSA-66q4-vfjg-2qhh`
   - likely `command_injection`
   - Shell / TypeScript
   - direct command injection

2. `anomalyco/opencode` / `GHSA-vxw4-wv6m-9hhh`
   - likely `command_injection`
   - TypeScript
   - arbitrary command execution

3. `anthropics/claude-code` / `GHSA-vhw5-3g5m-8ggf`
   - likely `ssrf`
   - Shell / TypeScript
   - domain validation bypass

4. `browser-use/browser-use` / `GHSA-x39x-9qw5-ghrf`
   - likely `ssrf`
   - Python
   - `allowed_domains` boundary bypass

5. `openai/codex` / `GHSA-w5fx-fh39-j5rw`
   - likely `path_traversal`
   - Rust
   - sandbox/path configuration bypass

6. `anthropics/claude-code` / `GHSA-q728-gf8j-w49r`
   - likely `path_traversal`
   - Shell / TypeScript
   - path restriction bypass

7. `langchain-ai/langchain` / `GHSA-2g6r-c272-w58r`
   - likely `ssrf`
   - Python
   - SSRF in a popular framework

### Other retained GHSA items

The full retained advisory pool included these additional items:

- `anthropics/claude-code`
  - `GHSA-mhg7-666j-cqg4`
  - `GHSA-ff64-7w26-62rf`
  - `GHSA-mmgp-wc2j-qcv7`
- `anomalyco/opencode`
  - `GHSA-c83v-7274-4vgp`
- `microsoft/semantic-kernel`
  - `GHSA-2ww3-72rp-wpp4`
  - `GHSA-xjw9-4gw8-4rqx`
- `langchain-ai/langgraph`
  - `GHSA-g48c-2wqr-h844`
  - `GHSA-mhr3-j7m5-c7c9`
  - `GHSA-9rwj-6rc7-p77c`
  - `GHSA-wwqv-p2pp-99h5`
  - `GHSA-7p73-8jqx-23r8`
- `langchain-ai/langchain`
  - `GHSA-c67j-w6g6-q2cm`
  - `GHSA-6qv9-48xg-fc7f`
- `Significant-Gravitas/AutoGPT`
  - `GHSA-4crw-9p35-9x54`
  - `GHSA-r277-3xc5-c79v`
  - `GHSA-rc89-6g7g-v5v7`
  - `GHSA-ggc4-4fmm-9hmc`
  - `GHSA-r55v-q5pc-j57f`
  - `GHSA-m2wr-7m3r-p52c`
  - `GHSA-x77j-qg2x-fgg6`
  - `GHSA-5cqw-g779-9f9x`
  - `GHSA-958f-37vw-jx8f`
  - `GHSA-wvjg-9879-3m7w`

## 19. First Recommended Full Track Build Set

The conversation converged on this recommended initial Full Track build order:

1. `anthropics/claude-code` / `GHSA-66q4-vfjg-2qhh`
2. `anomalyco/opencode` / `GHSA-vxw4-wv6m-9hhh`
3. `browser-use/browser-use` / `GHSA-x39x-9qw5-ghrf`
4. `openai/codex` / `GHSA-w5fx-fh39-j5rw`
5. `langchain-ai/langchain` / `GHSA-2g6r-c272-w58r`

Then expand with:

- `anthropics/claude-code` / `GHSA-vhw5-3g5m-8ggf`
- `anthropics/claude-code` / `GHSA-q728-gf8j-w49r`
- `Significant-Gravitas/AutoGPT` / `GHSA-wvjg-9879-3m7w`
- `anthropics/claude-code` / `GHSA-mhg7-666j-cqg4`
- `Significant-Gravitas/AutoGPT` / `GHSA-ggc4-4fmm-9hmc`
- `Significant-Gravitas/AutoGPT` / `GHSA-r55v-q5pc-j57f`
- `anomalyco/opencode` / `GHSA-c83v-7274-4vgp`
- `microsoft/semantic-kernel` / `GHSA-2ww3-72rp-wpp4`

## 20. Governance Expectations

The benchmark was explicitly framed as something that should be credible enough to become a reference benchmark.

So the plan should include:

- semantic versioning
- frozen released labels
- raw output retention
- reproducible result submission
- public adjudication log
- no silent relabeling after release

This is a critical part of the benchmark strategy, not an optional polish task.

## 21. Biggest Strategic Recommendations From the Conversation

These were the strongest repeated recommendations:

- do not broaden the benchmark claim too early
- keep V1 taxonomy narrow
- keep synthetic product stories broad
- keep Core Track disciplined
- aggressively expand Full Track with qualified real-world cases
- use real-world agent/coding-agent repos with public GHSA advisories as the main growth engine
- favor reproducibility and case clarity over case count only

## 22. Open Questions Left Unresolved

These questions were still open at the end of the conversation:

1. Should `capability_boundary_bypass` be promoted into V1 taxonomy now, given how well `claude-code` and `codex` fit that category?
2. Should the 12-case synthetic matrix be turned into a concrete backlog with exact file names, vulnerable regions, and safe regions?
3. Should the benchmark continue to keep V1 strictly at `command_injection`, `path_traversal`, and `ssrf`, or admit one boundary-bypass class because it is so central to modern coding agents?

## 23. Files Updated In This Repo During The Conversation

The plan file in this repo was updated heavily:

- `SAST_BENCHMARK_PLAN.md`

This handoff file was created to carry the context into another repo:

- `SASTBENCH_HANDOFF_CONTEXT.md`

## 24. Recommended Next Step In A Fresh Repo

If continuing in another repo, the next best step is:

1. copy this handoff file into the new repo
2. create the benchmark skeleton from the current plan
3. implement the schema and normalized results format
4. build the 12 Core Track synthetic cases
5. start Full Track with:
   - `anthropics/claude-code` / `GHSA-66q4-vfjg-2qhh`
   - `anomalyco/opencode` / `GHSA-vxw4-wv6m-9hhh`
   - `browser-use/browser-use` / `GHSA-x39x-9qw5-ghrf`
   - `openai/codex` / `GHSA-w5fx-fh39-j5rw`
   - `langchain-ai/langchain` / `GHSA-2g6r-c272-w58r`

## 25. Short Summary

The conversation produced a benchmark direction with these defining properties:

- focused on SAST for agentic codebases
- Python, TypeScript, and Rust
- narrow V1 taxonomy
- diverse agent functionality
- region-level annotations
- uncapped real-world Full Track
- strong emphasis on coding-agent repos with GHSA-backed cases
- synthetic cases centered on repeated capability-boundary failures
