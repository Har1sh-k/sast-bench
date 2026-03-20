# OWASP Agentic Security Top 10 -- SASTbench Mapping

SASTbench aligns with the [OWASP Top 10 for Agentic Security](https://owasp.org/www-project-top-10-for-agentic-security/) as a **reporting crosswalk**, not a replacement for the benchmark's own scoring taxonomy.

The mapping documented here enables users and report consumers to filter or aggregate SASTbench results by OWASP ASI category.  It does not change how cases are scored.  SASTbench scoring always uses its own 5-kind canonical taxonomy (`command_injection`, `path_traversal`, `ssrf`, `auth_bypass`, `authz_bypass`) plus region overlap matching.  The OWASP mapping is metadata layered on top.

## Mapping Table

| ASI ID | OWASP Category | SASTbench Kind(s) | Coverage | SAST Suitability |
|--------|----------------|-------------------|----------|------------------|
| ASI01 | Prompt Injection / Agent Goal Hijack | `command_injection` | Covered (PY-SV-003 + secondaries) | Medium -- SAST detects where untrusted prompt data reaches tool sinks |
| ASI02 | Improper Output Handling | `command_injection`, `ssrf`, `path_traversal` | Strong -- primary coverage across most cases | High -- classic taint from LLM output to sinks |
| ASI03 | Excessive Agency | `command_injection`, `path_traversal` | Covered -- mixed\_intent + capability\_safe cases | Medium -- SAST finds missing guards but can't reason about autonomy scope |
| ASI04 | Supply Chain / Untrusted Code | `command_injection` | Covered (TS-SV-003, TS-RW-012, TS-RW-018, PY-RW-007) | Medium-High -- plugin loading without verification |
| ASI05 | Insufficient Access Controls | `auth_bypass`, `authz_bypass` | Strong -- 9+ OpenClaw real-world cases | Medium -- missing auth checks on endpoints |
| ASI06 | Memory Poisoning | `command_injection` | Covered (PY-SV-004, planned) | Medium -- poisoned retrieval reaching execution sinks |
| ASI07 | Insecure Multi-Agent Communication | `auth_bypass` | Covered (RS-SV-004, planned) | Medium -- missing authentication on inter-agent endpoints |
| ASI08 | Inadequate Error Handling | Not in scope | Not covered | Low -- error handling quality is not a taint-flow problem |
| ASI09 | Insufficient Logging | Not in scope | Not covered | Very low -- operational concern, not static analysis |
| ASI10 | Resource Exhaustion / DoS | Not in scope | Not covered | Low -- resource limits are runtime policy |

## Per-ASI Case Lists

### ASI01 -- Prompt Injection / Agent Goal Hijack

Cases where untrusted prompt data reaches a high-power tool sink.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-PY-SV-003 | `command_injection` | Core | Primary |
| SB-TS-SV-001 | `command_injection` | Core | Secondary |
| SB-TS-SV-002 | `ssrf` | Core | Secondary |
| SB-RS-SV-002 | `command_injection` | Core | Secondary |
| SB-PY-SV-001 | `ssrf` | Core | Secondary |

### ASI02 -- Improper Output Handling

Cases where LLM or tool output flows to a dangerous sink without sanitization.  This is the broadest category and SASTbench's strongest coverage area.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-PY-SV-001 | `ssrf` | Core | Primary |
| SB-PY-SV-002 | `path_traversal` | Core | Primary |
| SB-PY-SV-003 | `command_injection` | Core | Secondary |
| SB-TS-SV-001 | `command_injection` | Core | Primary |
| SB-TS-SV-002 | `ssrf` | Core | Primary |
| SB-TS-SV-003 | `command_injection` | Core | Secondary |
| SB-RS-SV-001 | `path_traversal` | Core | Primary |
| SB-RS-SV-002 | `command_injection` | Core | Primary |
| SB-RS-SV-003 | `path_traversal` | Core | Primary |
| SB-TS-MI-001 | `ssrf` | Core | Secondary |
| SB-RS-MI-001 | `command_injection` | Core | Secondary |
| SB-PY-MI-001 | `ssrf` | Core | Secondary |
| SB-PY-RW-001 | `ssrf` | Full | Primary |
| SB-PY-RW-002 | `ssrf` | Full | Primary |
| SB-PY-RW-003 | `ssrf` | Full | Primary |
| SB-PY-RW-004 | `ssrf` | Full | Primary |
| SB-PY-RW-005 | `ssrf` | Full | Primary |
| SB-RS-RW-001 | `path_traversal` | Full | Primary |
| SB-TS-RW-001 | `command_injection` | Full | Primary |
| SB-TS-RW-002 | `command_injection` | Full | Primary |
| SB-TS-RW-005 | `command_injection` | Full | Primary |
| SB-TS-RW-006 | `path_traversal` | Full | Primary |
| SB-TS-RW-007 | `command_injection` | Full | Primary |
| SB-TS-RW-008 | `path_traversal` | Full | Primary |
| SB-TS-RW-011 | `command_injection` | Full | Primary |
| SB-TS-RW-014 | `ssrf` | Full | Primary |
| SB-PY-RW-006 | `path_traversal` | Full | Primary |
| SB-PY-RW-007 | `command_injection` | Full | Secondary |

### ASI03 -- Excessive Agency

Cases where an agent has more capability than needed, or where the benchmark tests the boundary between safe capability use and unsafe over-reach.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-PY-CS-001 | `command_injection` | Core | Primary |
| SB-TS-CS-001 | `ssrf` | Core | Primary |
| SB-RS-CS-001 | `path_traversal` | Core | Primary |
| SB-PY-MI-001 | `ssrf` | Core | Primary |
| SB-TS-MI-001 | `ssrf` | Core | Primary |
| SB-RS-MI-001 | `command_injection` | Core | Primary |
| SB-PY-SV-002 | `path_traversal` | Core | Secondary |
| SB-RS-SV-001 | `path_traversal` | Core | Secondary |
| SB-RS-SV-003 | `path_traversal` | Core | Secondary |
| SB-PY-RW-001 | `ssrf` | Full | Secondary |

### ASI04 -- Supply Chain / Untrusted Code

Cases where untrusted code from plugins, packages, or registries is loaded without verification.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-TS-SV-003 | `command_injection` | Core | Primary |
| SB-TS-RW-012 | `path_traversal` | Full | Primary |
| SB-TS-RW-018 | `command_injection` | Full | Primary |
| SB-PY-RW-007 | `command_injection` | Full | Primary |

### ASI05 -- Insufficient Access Controls

Cases where authentication or authorization checks are missing or bypassable.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-TS-RW-003 | `auth_bypass` | Full | Primary |
| SB-TS-RW-004 | `auth_bypass` | Full | Primary |
| SB-TS-RW-009 | `authz_bypass` | Full | Primary |
| SB-TS-RW-010 | `authz_bypass` | Full | Primary |
| SB-TS-RW-013 | `auth_bypass` | Full | Primary |
| SB-TS-RW-015 | `auth_bypass` | Full | Primary |
| SB-TS-RW-016 | `authz_bypass` | Full | Primary |
| SB-TS-RW-017 | `authz_bypass` | Full | Primary |
| SB-TS-RW-019 | `authz_bypass` | Full | Primary |

### ASI06 -- Memory Poisoning

Cases where poisoned retrieval data reaches an execution sink.

No cases are shipped yet.  PY-SV-004 is planned to cover this category by modeling a RAG pipeline where poisoned embeddings reach a code-execution tool.

### ASI07 -- Insecure Multi-Agent Communication

Cases where inter-agent endpoints lack authentication.

No cases are shipped yet.  RS-SV-004 is planned to cover this category by modeling an unauthenticated inter-agent RPC surface.

### ASI08 -- Inadequate Error Handling

Not in scope.

### ASI09 -- Insufficient Logging

Not in scope.

### ASI10 -- Resource Exhaustion / DoS

Not in scope.

## Why ASI08-ASI10 Are Out of Scope

SASTbench is a static analysis benchmark.  Its scoring is built around taint-flow detection and region-level finding overlap.  Three ASI categories fall outside that model:

- **ASI08 (Inadequate Error Handling)**: Error handling quality is a code quality concern, not a taint-flow problem.  SAST tools do not typically produce findings for "insufficient error handling," and there is no meaningful way to annotate a vulnerable region or measure recall for this category.

- **ASI09 (Insufficient Logging)**: Logging adequacy is an operational and compliance concern.  It requires runtime context (what was logged, where, in what format) that static analysis cannot observe.  Including it would dilute the benchmark's focus without producing useful scanner differentiation.

- **ASI10 (Resource Exhaustion / DoS)**: Resource limits are runtime policy.  Whether an agent can be exhausted depends on deployment configuration (timeouts, rate limits, memory caps), not on source code patterns that SAST can reliably flag.  A benchmark case for DoS would not produce consistent, reproducible scores across scanners.

These three categories are valuable for agentic security programs but belong in runtime testing, observability audits, or operational checklists rather than in a static analysis benchmark.

## Relationship Between SASTbench Scoring and the OWASP Mapping

SASTbench uses its own 5-kind canonical taxonomy for scoring:

- `command_injection`
- `path_traversal`
- `ssrf`
- `auth_bypass`
- `authz_bypass`

The official metrics (Recall, Capability FP Rate, Mixed-Intent Accuracy, Agentic Score) are computed entirely from this taxonomy.  A finding is scored based on whether the adapter maps it to the correct canonical kind and whether it overlaps the correct annotated region.

The OWASP mapping is **metadata** stored in each case's `standards.owaspAgenticTop10` field.  It enables:

- Filtering results by ASI category in reports
- Aggregating coverage statistics by OWASP category for compliance narratives
- Mapping SASTbench findings to organizational risk frameworks that reference the OWASP Agentic Top 10

The OWASP mapping does **not**:

- Change how true positives, false positives, or false negatives are determined
- Replace the canonical kind as the matching key
- Affect the Agentic Score computation
- Require adapters to emit ASI category labels

In short, the OWASP mapping is a reporting crosswalk that sits alongside the scoring system without replacing it.
