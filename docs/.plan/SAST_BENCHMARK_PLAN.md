# SASTbench for Agentic Codebases

## 1. Benchmark Identity

**Name:** `SASTbench`

**Core claim:** `SASTbench evaluates whether static analyzers can detect real vulnerabilities in agentic codebases without treating intentional agent capabilities as vulnerabilities.`

This benchmark is not trying to be the benchmark for all SAST. The wedge is narrower and stronger:

- Agentic code often performs dangerous actions on purpose.
- Good scanners should still find real bugs inside that code.
- Good scanners should not flood users with false positives on intentional, properly-guarded capability code.
- Mixed-intent repos matter: the same repo can contain both safe capability regions and genuinely vulnerable regions.

## 2. Primary Users

- Practitioners choosing scanners for agentic products
- Scanner builders improving precision and recall on agentic repos
- Researchers studying benchmarked SAST behavior on modern codebases

V1 is optimized first for practitioners and scanner builders. Researchers should be able to cite it, but research completeness is not the first release goal.

## 3. What V1 Measures

V1 answers three questions:

1. Does the scanner detect real vulnerabilities in agentic code?
2. Does it avoid flagging intentional, properly-guarded capability code?
3. Can it distinguish safe and unsafe regions inside the same codebase?

V1 does **not** try to measure:

- General non-security logic bugs
- Prompt injection as a standalone category
- Secret scanning quality
- Severity calibration across vendors
- End-to-end agent runtime exploits

## 4. Language Scope

The initial language set is:

- Python
- TypeScript
- Rust

V1 must include Core Track cases in all three languages.

Full Track should include real-world cases in all three languages when high-quality public cases exist. Full Track is intentionally uncapped in V1: add qualified real-world cases aggressively as long as they meet the case bar and do not force taxonomy drift. V1 should actively include at least one strong Rust real-world case, and `openai/codex` is a prime candidate.

## 5. Tracks

### Core Track

Self-contained, vendored cases. No external repos required.

Purpose:

- 5-minute quickstart
- deterministic runs
- baseline public leaderboard

### Full Track

Core Track plus pinned snapshots from real public repositories.

Purpose:

- whole-repo realism
- stronger public credibility
- less argument about missing repo context

### Patch Track

Deferred to V2.

Purpose:

- verify whether scanners still flag fixed code
- measure regression noise on patched snapshots

## 6. V1 Canonical Vulnerability Kinds

V1 uses a small canonical taxonomy. Adapters map tool-specific rules into these benchmark kinds:

- `command_injection`
- `path_traversal`
- `ssrf`
- `auth_bypass`
- `authz_bypass`

These five are enough to stress the main agentic capability surfaces:

- executing commands
- reading and writing files
- making outbound network requests
- authenticating callers and connections
- enforcing per-identity permission scopes

V1 will not score by CWE alone. CWE data may be stored for reporting, but official matching uses canonical kinds plus region overlap.

## 7. V1 Case Types

V1 contains four case types:

- `synthetic_vulnerable`
- `capability_safe`
- `mixed_intent`
- `real_world_disclosed`

Definitions:

- `synthetic_vulnerable`: self-contained code with a real flaw and a known vulnerable region
- `capability_safe`: intentionally dangerous-looking code that is correctly guarded and should not be flagged
- `mixed_intent`: a repo or mini-repo containing both safe capability regions and vulnerable regions in the same project
- `real_world_disclosed`: public repo snapshot with pinned vulnerable commit and clear ground truth

## 8. V1 Official Case Count

V1 ships with **at least 15 official cases**.

### Core Track minimum

- 6 `synthetic_vulnerable` cases
- 3 `capability_safe` cases
- 3 `mixed_intent` cases

Core Track is the fixed no-setup baseline and should remain disciplined.

### Full Track minimum

- at least 3 `real_world_disclosed` cases

### Full Track target

- 5 to 10+ `real_world_disclosed` cases in `v1.0.0` if they annotate cleanly
- no hard cap for V1 as long as each case meets the real-world case bar

### Core Track language distribution

- Python: 4 cases
- TypeScript: 4 cases
- Rust: 4 cases

### Full Track language distribution

- prioritize quality over symmetry
- actively include at least one strong Rust real-world case in the first public release
- do not weaken the case quality bar just to force a language balance

## 9. V1 Case Design Rules

Every official case must satisfy these rules:

- one primary canonical vulnerability kind per case
- one clearly annotated vulnerable region
- no hidden benchmark-only assumptions
- full scanner context available inside the scanned directory
- deterministic input paths and file layout
- explicit explanation of why the code is safe or unsafe

Every `capability_safe` case must state the guard contract that makes the code acceptable.

Examples of guard contracts:

- command execution restricted to an allowlist
- filesystem access restricted to a workspace root
- outbound network access restricted to approved hosts

Every `mixed_intent` case must include:

- at least one `capability_safe` region
- at least one `vulnerable` region
- the same capability family present in both regions

That last rule is important. Mixed-intent cases must test the scanner's ability to separate safe and unsafe uses of the same general behavior.

## 10. V1 Synthetic Design

Core Track should not look like tiny toy snippets. Each synthetic case should be a compact but realistic mini-repo with a believable agent purpose, a clear trust boundary, and one primary capability family under test.

### Repeated Failure Pattern

V1 synthetic cases should repeatedly test one recurring agentic failure pattern:

`untrusted user-controlled or model-controlled input reaches a high-power tool without the required guard`

This pattern is intentionally narrow. Diversity should come from agent functionality, not from adding many unrelated vulnerability classes.

Model the pattern using these components:

- `source`: user request, tool arguments, model plan, web content, external document metadata
- `carrier`: planner, router, task state, tool wrapper, helper function, config bridge
- `sink`: command execution, filesystem access, outbound network request
- `missing guard`: allowlist, workspace-root check, host allowlist, scheme restriction, normalization step

### Synthetic Agent Archetypes

Use diverse agent purposes in Core Track so the benchmark feels representative of real products:

- coding agent
- browser or travel agent
- medical research or triage assistant
- customer support assistant
- workspace organizer
- local ops or devops helper

The domain story can vary widely, but the bug pattern should stay fixed around agent capability boundaries.

### Exact V1 Mini-Repo Shape

Each synthetic case should use a mini-repo layout like this:

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

Rules for this layout:

- every case has one clear agent entrypoint
- every case exposes at least one high-power capability
- vulnerable behavior should live in a tool wrapper, helper, or boundary check
- safe behavior should still call the dangerous capability, but through a proper guard
- scanners should get enough local context to resolve the relevant flow

Allowed entrypoint styles:

- CLI task runner
- local HTTP API
- IDE or editor command
- browser-task worker
- background agent loop

### Guard Contracts

Every synthetic case must encode why a capability-safe region is safe.

Use these standard V1 guard contracts:

- `allowlist` for command execution
- `workspace_root` for filesystem access
- `host_allowlist` for outbound network
- `scheme_allowlist` for URL handling when needed

Avoid custom one-off safety stories in V1. Reuse these guard contracts so scoring and documentation stay consistent.

### V1 Synthetic Case Matrix

The Core Track should start with the following 12 synthetic cases:

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

### Synthetic Authoring Rules

When authoring synthetic cases:

- keep one primary canonical kind per case
- keep the vulnerable region small and explicit
- keep helper code realistic enough for scanners to analyze cross-function flow
- do not hide the vulnerability behind unrealistic obfuscation in V1
- do not make the safe cases trivial by removing dangerous APIs entirely
- keep mixed-intent cases focused on one capability family appearing in both safe and unsafe regions

### Synthetic Diversity Principle

Core Track should be diverse in agent purpose and narrow in vulnerability families.

That means:

- many product stories
- few canonical vulnerability kinds
- repeated capability-boundary mistakes

This is what makes the benchmark agentic rather than just another generic SAST fixture suite.

## 11. Case Schema Direction

The official schema should move from file-level intent to region-level annotations.

Required fields for V1:

```json
{
  "schemaVersion": "1.0.0",
  "id": "SB-PY-001",
  "track": "core",
  "caseType": "mixed_intent",
  "language": "python",
  "canonicalKind": "command_injection",
  "files": {
    "root": "project/"
  },
  "regions": [
    {
      "id": "R1",
      "path": "project/agent/runner.py",
      "startLine": 20,
      "endLine": 42,
      "label": "capability_safe",
      "capability": "code_execution",
      "requiredGuards": ["allowlist"]
    },
    {
      "id": "R2",
      "path": "project/web/handler.py",
      "startLine": 10,
      "endLine": 26,
      "label": "vulnerable",
      "acceptedKinds": ["command_injection"]
    }
  ],
  "expectedOutcome": {
    "mustDetectRegionIds": ["R2"],
    "mustNotFlagRegionIds": ["R1"]
  }
}
```

Notes:

- `path` plus line range is the official scoring target.
- Severity is stored for display only. Severity is not part of V1 detection scoring.
- `requiredGuards` documents why a capability-safe region is safe.

## 12. Scoring Rules

### Official Matching

A finding counts as a true positive only if:

- the adapter maps it to the correct `canonicalKind`
- the finding location overlaps an annotated `vulnerable` region

A finding counts as a capability false positive if:

- it overlaps an annotated `capability_safe` region
- its mapped kind matches the capability family being exercised

A case counts as missed if no true positive is produced for its required vulnerable region.

### V1 Official Metrics

- `Recall = TP / (TP + FN)`
- `Precision = TP / (TP + FP)`
- `Capability FP Rate = capability_safe_cases_flagged / total_capability_safe_cases`
- `Mixed-Intent Accuracy = mixed_intent_cases_scored_cleanly / total_mixed_intent_cases`

`mixed_intent_cases_scored_cleanly` means:

- the vulnerable region was detected
- no capability-safe region in that case was incorrectly flagged

### V1 Top-Line Score

The top-line leaderboard metric should be:

`Agentic Score = geometric_mean(Recall, 1 - Capability FP Rate, Mixed-Intent Accuracy)`

Rationale:

- `Recall` rewards real vulnerability detection
- `1 - Capability FP Rate` rewards low noise on intentional capability code
- `Mixed-Intent Accuracy` rewards correct boundary understanding inside one repo

Precision remains visible and important, but the benchmark's identity should stay centered on the agentic-specific dimensions.

### What V1 Does Not Score

V1 does not use:

- severity thresholds
- advisory CVSS matching
- rule-name exact matching
- raw finding counts as the main objective

These can still appear in reports, but they should not determine official pass/fail scoring.

## 13. Adapter Strategy

Official leaderboard runs must use named adapters, not arbitrary shell strings.

Use:

- `--scanner semgrep`
- `--scanner bandit`
- `--scanner <tool-name>`

Each adapter must:

- capture scanner version
- run the tool in the case directory
- normalize output into a canonical benchmark JSON schema
- map tool rules to benchmark `canonicalKind`
- preserve raw output for auditing

Keep `--scanner-cmd` for local experiments only. Do not allow `--scanner-cmd` results onto the official leaderboard.

Use Python adapters under `adapters/` rather than shell-only wrappers. This keeps the benchmark more portable across macOS, Linux, and Windows.

## 14. Repository Layout

```text
sastbench/
|-- README.md
|-- manifest.json
|-- schema/
|   |-- case.schema.json
|   `-- results.schema.json
|-- taxonomy/
|   |-- canonical_kinds.json
|   |-- capabilities.json
|   `-- languages.json
|-- cases/
|   |-- core/
|   |   |-- synthetic_vulnerable/
|   |   |-- capability_safe/
|   |   `-- mixed_intent/
|   `-- full/
|       `-- real_world_disclosed/
|-- adapters/
|   |-- README.md
|   |-- semgrep/
|   |-- bandit/
|   `-- <tool>/
|-- scripts/
|   |-- run.py
|   |-- validate.py
|   |-- report.py
|   `-- setup_repos.py
`-- tests/
    |-- test_scoring.py
    |-- test_validation.py
    `-- test_adapters.py
```

## 15. Real-World Case Selection Bar

A real-world case is eligible only if all of the following are true:

- public repository
- public fix or public disclosure
- pinned vulnerable commit
- clear vulnerable region that can be annotated
- reproducible checkout and scan
- scanner can run with local repo context only
- repository can be mirrored if upstream disappears

Prefer cases where the fix clearly demonstrates the missing guard or unsafe flow.

Do not include weak real-world cases just to increase count. Case quality matters more than benchmark size.

## 16. Initial Real-World Target Repos

The initial target set should prioritize popular public repositories that already have published GitHub Security advisories and advisories that map well to the benchmark's canonical kinds.

### Priority 1

These are the strongest initial sources for Full Track cases:

| Repo | Why it fits | Likely case types |
|------|-------------|-------------------|
| `anthropics/claude-code` | Flagship coding agent repo with many published advisories directly aligned to command execution, file restriction bypass, network boundary bypass, and trust-boundary failures | `command_injection`, `path_traversal`, `ssrf`, capability boundary failures |
| `anomalyco/opencode` | High-visibility coding agent repo with public advisories directly relevant to command execution | `command_injection`, capability boundary failures |
| `openai/codex` | High-visibility Rust-first coding agent with a published sandbox and path-configuration advisory directly relevant to workspace boundary enforcement | `path_traversal`, capability boundary failures |
| `microsoft/semantic-kernel` | Popular agent framework with public advisories involving agent function calling and file write behavior | `path_traversal`, command or tool-execution boundary issues |
| `langchain-ai/langgraph` | Agent orchestration framework with multiple published advisories | `ssrf`, `command_injection`, injection and boundary issues |
| `langchain-ai/langchain` | Very popular framework with multiple published advisories and broad industry recognition | `ssrf`, injection, unsafe dynamic behavior |
| `browser-use/browser-use` | Strong agent-specific target with browser and network boundary behavior | `ssrf`, capability boundary failures |
| `Significant-Gravitas/AutoGPT` | High-star agent repo with many published advisories and strong name recognition | `ssrf`, command execution, auth and boundary issues |

### Priority 1 Ranked Advisory Pool

Retain all of the GHSA entries below for future use. The ranking is by benchmark fit, not by vulnerability severity. A lower rank means the advisory is more likely to turn into a clean benchmark case for the current plan.

Legend for `Fit`:

- `V1-first`: strong immediate candidate for the first Full Track set
- `V1-reserve`: good fallback if one of the first cases does not annotate cleanly
- `V2`: valuable, but outside the current V1 taxonomy or language discipline
- `Future`: worth keeping, but weaker benchmark fit for now

| Rank | Repo | GHSA | Likely canonical kind | Language | Fit | Confidence | Notes |
|------|------|------|-----------------------|----------|-----|------------|-------|
| 1 | `anthropics/claude-code` | `GHSA-66q4-vfjg-2qhh` | `command_injection` | Shell / TypeScript | `V1-first` | High | Direct command injection in a flagship coding-agent repo with a very strong agentic benchmark story. |
| 2 | `anomalyco/opencode` | `GHSA-vxw4-wv6m-9hhh` | `command_injection` | TypeScript | `V1-first` | High | Direct arbitrary command execution in a high-visibility coding-agent repo. |
| 3 | `anthropics/claude-code` | `GHSA-vhw5-3g5m-8ggf` | `ssrf` | Shell / TypeScript | `V1-first` | High | Domain validation bypass maps cleanly to outbound network boundary failure. |
| 4 | `browser-use/browser-use` | `GHSA-x39x-9qw5-ghrf` | `ssrf` | Python | `V1-first` | High | Clear outbound boundary bypass through `allowed_domains`. |
| 5 | `openai/codex` | `GHSA-w5fx-fh39-j5rw` | `path_traversal` | Rust | `V1-first` | Medium-High | Strong sandbox and path-boundary case in a Rust coding-agent repo, and a strong fit for the Rust Full Track story. |
| 6 | `anthropics/claude-code` | `GHSA-q728-gf8j-w49r` | `path_traversal` | Shell / TypeScript | `V1-first` | High | Path restriction bypass with arbitrary file write behavior fits the workspace-boundary model well. |
| 7 | `langchain-ai/langchain` | `GHSA-2g6r-c272-w58r` | `ssrf` | Python | `V1-first` | High | Explicit SSRF in a very widely used framework. |
| 8 | `Significant-Gravitas/AutoGPT` | `GHSA-wvjg-9879-3m7w` | `ssrf` | Python | `V1-reserve` | Medium-High | DNS rebinding in a requests wrapper fits the agentic network-boundary story well. |
| 9 | `anthropics/claude-code` | `GHSA-mhg7-666j-cqg4` | `command_injection` | Shell | `V1-reserve` | High | Strong command-injection case, but overlaps with the top Claude Code command-exec case. |
| 10 | `Significant-Gravitas/AutoGPT` | `GHSA-ggc4-4fmm-9hmc` | `ssrf` | Python | `V1-reserve` | Medium | Plausibly strong, but less differentiated than the DNS rebinding case. |
| 11 | `Significant-Gravitas/AutoGPT` | `GHSA-r55v-q5pc-j57f` | `ssrf` | Python | `V1-reserve` | Medium | Useful fallback, but overlaps heavily with other SSRF-style cases. |
| 12 | `anomalyco/opencode` | `GHSA-c83v-7274-4vgp` | `command_injection` | TypeScript | `V1-reserve` | Medium | Strong impact, but the XSS-to-command-exec chain may be noisier to model cleanly in SAST. |
| 13 | `microsoft/semantic-kernel` | `GHSA-2ww3-72rp-wpp4` | `path_traversal` | C# / .NET | `V1-reserve` | Medium | Strong case quality, but the advisory is centered on the .NET SDK rather than the initial language set. |
| 14 | `microsoft/semantic-kernel` | `GHSA-xjw9-4gw8-4rqx` | `out_of_scope_v1` | C# / .NET | `V2` | Medium | Real RCE case, but not a clean fit for the current 3-kind V1 taxonomy. |
| 15 | `Significant-Gravitas/AutoGPT` | `GHSA-4crw-9p35-9x54` | `out_of_scope_v1` | Python | `V2` | Medium | Relevant agentic RCE, but maps more to capability-boundary bypass than the current V1 taxonomy. |
| 16 | `Significant-Gravitas/AutoGPT` | `GHSA-r277-3xc5-c79v` | `out_of_scope_v1` | Python | `V2` | Medium | Similar to the previous disabled-block RCE case and likely redundant for V1. |
| 17 | `langchain-ai/langchain` | `GHSA-6qv9-48xg-fc7f` | `out_of_scope_v1` | Python | `V2` | Medium | Template injection is interesting, but it does not map cleanly to the V1 canonical kinds. |
| 18 | `langchain-ai/langchain` | `GHSA-c67j-w6g6-q2cm` | `out_of_scope_v1` | Python | `V2` | Medium | Valuable for a broader injection track, but not for the first V1 taxonomy. |
| 19 | `langchain-ai/langgraph` | `GHSA-9rwj-6rc7-p77c` | `out_of_scope_v1` | Python | `V2` | Medium | Likely clean SQL injection, but SQL injection is not in the V1 canonical set. |
| 20 | `langchain-ai/langgraph` | `GHSA-7p73-8jqx-23r8` | `out_of_scope_v1` | Python | `V2` | Medium | Similar to the prior SQL injection case and better saved for a V2 taxonomy expansion. |
| 21 | `langchain-ai/langgraph` | `GHSA-wwqv-p2pp-99h5` | `out_of_scope_v1` | Python | `V2` | Medium | Real RCE, but the fit to the initial benchmark categories is weaker. |
| 22 | `langchain-ai/langgraph` | `GHSA-mhr3-j7m5-c7c9` | `out_of_scope_v1` | Python | `V2` | Medium | Deserialization RCE is valuable, but not part of the V1 canonical set. |
| 23 | `langchain-ai/langgraph` | `GHSA-g48c-2wqr-h844` | `out_of_scope_v1` | Python | `V2` | Medium | Similar deserialization issue with the same V1 taxonomy mismatch. |
| 24 | `anthropics/claude-code` | `GHSA-ff64-7w26-62rf` | `out_of_scope_v1` | TypeScript / Config | `V2` | Medium-High | Highly relevant sandbox escape, but better represented in a later boundary-bypass track. |
| 25 | `anthropics/claude-code` | `GHSA-mmgp-wc2j-qcv7` | `out_of_scope_v1` | TypeScript / Config | `V2` | Medium-High | Workspace trust bypass is important, but belongs in a later trust-boundary track. |
| 26 | `Significant-Gravitas/AutoGPT` | `GHSA-x77j-qg2x-fgg6` | `out_of_scope_v1` | Python | `V2` | Medium | Authorization bypass belongs in a later boundary or auth track, not V1. |
| 27 | `Significant-Gravitas/AutoGPT` | `GHSA-rc89-6g7g-v5v7` | `out_of_scope_v1` | Python | `Future` | Low-Medium | Secret exposure is important, but secret-handling is explicitly out of scope for V1. |
| 28 | `Significant-Gravitas/AutoGPT` | `GHSA-958f-37vw-jx8f` | `out_of_scope_v1` | Python | `Future` | Low-Medium | Cross-user result leakage is relevant, but better suited to a different benchmark track. |
| 29 | `Significant-Gravitas/AutoGPT` | `GHSA-m2wr-7m3r-p52c` | `out_of_scope_v1` | Python | `Future` | Low-Medium | ReDoS is a valid bug, but far from the core V1 agentic capability story. |
| 30 | `Significant-Gravitas/AutoGPT` | `GHSA-5cqw-g779-9f9x` | `out_of_scope_v1` | Python | `Future` | Low-Medium | DoS in an RSS block is useful later, but weak as an initial benchmark case. |

### Recommended First Full Track Cases

Start with the cases below before expanding to the rest of the GHSA pool. These are ranked by benchmark fit, public visibility, and confidence that the advisory can be turned into a clean annotated case for V1.

| Rank | Repo | GHSA | Likely canonical kind | Language | Confidence | Why it is a strong first case |
|------|------|------|-----------------------|----------|------------|-------------------------------|
| 1 | `anthropics/claude-code` | `GHSA-66q4-vfjg-2qhh` | `command_injection` | Shell / TypeScript | High | Direct command injection in a flagship coding-agent repo with a very strong benchmark narrative. |
| 2 | `anomalyco/opencode` | `GHSA-vxw4-wv6m-9hhh` | `command_injection` | TypeScript | High | Direct arbitrary command execution in a high-visibility coding-agent repo. |
| 3 | `browser-use/browser-use` | `GHSA-x39x-9qw5-ghrf` | `ssrf` | Python | High | Clear outbound network boundary bypass through `allowed_domains`. |
| 4 | `openai/codex` | `GHSA-w5fx-fh39-j5rw` | `path_traversal` | Rust | Medium-High | Strong sandbox and path-boundary case in a Rust coding-agent repo. |
| 5 | `langchain-ai/langchain` | `GHSA-2g6r-c272-w58r` | `ssrf` | Python | High | Explicit SSRF in a very popular framework with strong ecosystem credibility. |

### Practical Recommendation

Use the first five ranked cases as the initial `Full Track` build target:

1. `anthropics/claude-code` / `GHSA-66q4-vfjg-2qhh`
2. `anomalyco/opencode` / `GHSA-vxw4-wv6m-9hhh`
3. `browser-use/browser-use` / `GHSA-x39x-9qw5-ghrf`
4. `openai/codex` / `GHSA-w5fx-fh39-j5rw`
5. `langchain-ai/langchain` / `GHSA-2g6r-c272-w58r`

Then keep expanding with the rest of the `V1-first` set and the strongest `V1-reserve` cases:

- `anthropics/claude-code` / `GHSA-vhw5-3g5m-8ggf`
- `anthropics/claude-code` / `GHSA-q728-gf8j-w49r`
- `Significant-Gravitas/AutoGPT` / `GHSA-wvjg-9879-3m7w`
- `anthropics/claude-code` / `GHSA-mhg7-666j-cqg4`
- `Significant-Gravitas/AutoGPT` / `GHSA-ggc4-4fmm-9hmc`
- `Significant-Gravitas/AutoGPT` / `GHSA-r55v-q5pc-j57f`
- `anomalyco/opencode` / `GHSA-c83v-7274-4vgp`
- `microsoft/semantic-kernel` / `GHSA-2ww3-72rp-wpp4`

V1 Full Track is intentionally uncapped. More real-world cases are encouraged as long as each case remains reproducible, maps cleanly to the V1 taxonomy, and can be annotated without ambiguity.

### Priority 2

These can be added after the first strong Full Track cases are stable:

| Repo | Why it fits | Notes |
|------|-------------|-------|
| `open-webui/open-webui` | Very popular AI application with many published advisories | More web-app heavy; use only if the cases map cleanly to the agentic benchmark story |
| `OpenHands/OpenHands` | Popular agent repo with strong relevance | Good ecosystem signal, but published-advisory depth is weaker than the Priority 1 set |
| `openinterpreter/open-interpreter` | Strong agent relevance | Use if a qualifying public disclosed case is available |
| `continuedev/continue` | Good developer-tool relevance | Use if a qualifying public disclosed case is available |
| `crewAIInc/crewAI` | Popular multi-agent framework | Use if a qualifying public disclosed case is available |

### Selection Guidance

- Use Priority 1 repos first for the first 5 Full Track cases, then keep expanding Full Track with every additional case that meets the quality bar.
- Prefer early repo diversity across coding agents, browser agents, and frameworks.
- Prefer advisories with a pinned fix commit and a clear vulnerable region.
- Prefer cases that exercise the benchmark's three V1 canonical kinds.
- Prefer cases that test mixed-intent boundaries, not just classic web vulnerabilities in isolation.
- Keep Full Track uncapped in V1. More real-world cases are better if they stay reproducible and taxonomically clean.
- Actively include at least one strong Rust real-world case in the first public release.

### Known Public Advisory Sources

The following repos are already strong public advisory sources and should be checked first during case authoring:

- `anomalyco/opencode`
- `anthropics/claude-code`
- `langchain-ai/langchain`
- `langchain-ai/langgraph`
- `microsoft/semantic-kernel`
- `browser-use/browser-use`
- `openai/codex`
- `Significant-Gravitas/AutoGPT`
- `open-webui/open-webui`

## 17. Governance

This section is mandatory if the goal is to become a reference benchmark.

### Versioning

- benchmark releases use semantic versioning
- each public leaderboard is tied to an exact benchmark version
- official case labels are frozen within a released version

### Reproducibility

Every published official result must include:

- benchmark version
- scanner name and version
- adapter version
- command invocation
- raw scanner output
- normalized benchmark output

### Disputes

Maintain a public adjudication log for:

- disputed labels
- disputed adapter mappings
- disputed real-world case eligibility

Do not silently relabel a released case. Any scoring-impacting label change requires a benchmark version bump.

### Submissions

Allow vendor and community submissions only if they are reproducible from raw outputs. Unverifiable scoreboard entries should not be published.

## 18. V1 Deliverables

`v1.0.0` should include:

- frozen schema
- canonical taxonomy for the 5 V1 kinds
- at least 15 official cases
- Core Track in Python, TypeScript, and Rust
- Full Track with the strongest qualifying public cases, with no hard cap on qualified real-world additions
- at least 2 official adapters
- JSON results output
- simple shareable HTML report
- public baseline results

The HTML report in V1 should be simple:

- summary metrics
- per-case table
- per-track table
- links to raw outputs

Do not spend early time on rich charts. The first release needs credibility more than presentation.

## 19. V1 Build Order

Build in this order:

1. Freeze schema, taxonomy, and scoring rules.
2. Implement canonical normalized results format.
3. Build 6 synthetic vulnerable cases.
4. Build 3 capability-safe cases.
5. Build 3 mixed-intent cases.
6. Implement 2 official adapters.
7. Add the first 5 real-world disclosed cases.
8. Publish baseline results.
9. Keep expanding Full Track with any additional qualified real-world cases.
10. Add lightweight HTML reporting.

This order keeps the benchmark stable before expanding surface area.

## 20. V2 Scope

V2 expands depth without diluting the benchmark identity.

### V2 Goals

- expand from 15 to roughly 30-36 official cases
- strengthen Full Track coverage across all three languages
- add Patch Track
- add more mixed-intent cases
- add one new canonical kind only if it is well-defined and cross-tool mappable

### V2 Candidate Additions

- `capability_boundary_bypass` as a fourth canonical kind
- more whole-repo cases from agentic tools and frameworks
- differential reporting across benchmark versions
- adapter conformance tests
- case authoring helper

### V2 Non-Goals Unless Proven Stable

- arbitrary logic bug scoring
- prompt injection as a generic static finding category
- broad CWE coverage for its own sake

## 21. V2 Deliverables

`v2.0.0` should include:

- 30-36 official cases
- Core, Full, and Patch tracks
- stronger Rust Full Track coverage
- adapter conformance suite
- scanner comparison mode in the report
- submission documentation and leaderboard policy

## 23. OWASP Agentic Top 10 Alignment

SASTbench maps its cases to the OWASP Top 10 for Agentic Security (ASI01 through ASI10) as a **reporting crosswalk**.  The decision is deliberate: the OWASP categories provide a shared industry vocabulary for risk communication, but they are too broad and overlapping to use as a scoring taxonomy for a static analysis benchmark.

### Design decision

SASTbench retains its own 5-kind canonical taxonomy (`command_injection`, `path_traversal`, `ssrf`, `auth_bypass`, `authz_bypass`) for all scoring.  The OWASP mapping is metadata stored in each case's `standards.owaspAgenticTop10` field, carrying a `primary` ASI category and optional `secondary` categories.

This design means:

- Adapters do not need to emit ASI labels.  They continue mapping tool rules to canonical kinds.
- Scoring (Recall, Capability FP Rate, Mixed-Intent Accuracy, Agentic Score) is computed entirely from canonical kinds and region overlap.
- Reports can aggregate results by ASI category for compliance-oriented audiences without changing the underlying scoring.
- The benchmark can adopt future OWASP revisions by updating case metadata without re-scoring past results.

### Coverage profile

SASTbench covers ASI01 (Prompt Injection) through ASI07 (Insecure Multi-Agent Communication) with varying depth.  ASI02 (Improper Output Handling) has the strongest coverage because taint flow from LLM output to dangerous sinks is the benchmark's core testing pattern.

ASI08 (Inadequate Error Handling), ASI09 (Insufficient Logging), and ASI10 (Resource Exhaustion) are out of scope.  These categories describe operational qualities that static analysis cannot reliably benchmark: error-handling completeness is a code-quality concern, logging adequacy is an observability concern, and resource exhaustion is a runtime-policy concern.

The full mapping table and per-ASI case lists are maintained in `docs/OWASP_AGENTIC_TOP10_MAPPING.md`.

## 22. Final Positioning

The benchmark should be described publicly as:

`The benchmark for evaluating SAST tools on agentic codebases.`

The homepage message should be:

`Can your scanner find real vulnerabilities in agentic repos without flagging the code the agent is supposed to run?`

That message is narrower than "next-generation SAST benchmark," but it is much more likely to become memorable, reproducible, and widely cited.
