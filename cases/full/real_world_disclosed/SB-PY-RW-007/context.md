# SB-PY-RW-007: Semantic Kernel InMemoryVectorStore RCE via filter eval injection

## Advisory
- Repo: `microsoft/semantic-kernel`
- GHSA: `GHSA-xjw9-4gw8-4rqx`
- CVE: `CVE-2026-26030`
- Vulnerable commit: `c4d0a623f22a9a138e98759127525ce9d47d3607`
- Fix commit: `d6d4f3bc124b998da16e9e20460d9dd89a15fbbe`
- Fix code commit: `2f1ff2f7743680d08da5382ffc8f78be6755e26c` (PR #13505)

## Scenario

Semantic Kernel's `InMemoryCollection` provides a vector store that
supports user-defined filter expressions. Filters are passed as Python
lambda strings (e.g., `"lambda x: x.key == 1"`), parsed via `ast.parse`,
validated against an AST node type allowlist, and then executed with
`eval()`.

## Vulnerability

The `_parse_and_validate_filter` method (lines 329-391) compiles and
evaluates user-supplied lambda strings. Although it employs an AST
allowlist (lines 97-142) and restricts `ast.Name` nodes to only the
lambda parameter, it permits `ast.Attribute` nodes without checking
the attribute name. This allows access to dunder attributes such as
`__class__`, `__bases__`, `__subclasses__`, and `__globals__`.

An attacker can craft a filter string that traverses the Python object
hierarchy to reach dangerous classes (e.g., `os._wrap_close`) and
invoke arbitrary commands:

```python
lambda x: x.__class__.__bases__[0].__subclasses__()[133].__init__.__globals__['system']('id')
```

The `eval()` call at line 384 uses `{"__builtins__": {}}` as the
globals dict, but this does not prevent attribute-based traversal
from the lambda parameter object itself.

## Source / Carrier / Sink
- Source: user-supplied filter string passed to collection search methods
- Carrier: `_parse_and_validate_filter()` parses and compiles the string;
  the AST allowlist permits `ast.Attribute` without blocking dunder names
- Sink: `eval(code, {"__builtins__": {}}, {})` at line 384 executes the
  compiled code
- Missing guard: no restriction on attribute names accessed via
  `ast.Attribute` nodes; dunder attributes like `__class__`,
  `__subclasses__`, `__globals__` are reachable

## Annotated Region
- File: `python/semantic_kernel/connectors/in_memory.py`
- Lines: 329-391
- Why this region is the scoring target: it contains the entire
  `_parse_and_validate_filter` method including the insufficiently
  guarded `eval()` call that enables arbitrary code execution through
  dunder attribute traversal

## Scanner Expectation
A scanner should flag the `eval()` call at line 384 for executing
user-controlled code with an insufficient AST-based sandbox that
fails to block attribute-based object hierarchy traversal.
