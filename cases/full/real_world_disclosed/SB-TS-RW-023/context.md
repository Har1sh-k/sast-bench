# SB-TS-RW-023: WriteFileTool arbitrary file write via unvalidated file_path

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-jv9m-vf54-chjj`
- CVE: `CVE-2025-61913`
- Vulnerable commit: `a0dca552a2b425a042fff955511128cd2b253e7a`
- Fix commit: `1fb12cd93143592a18995f63b781d25b354d48a3`
- Patched in: flowise@3.0.8

## Scenario

Flowise provides a `WriteFileTool` that LLM agents can invoke to write files to the server's filesystem. The tool is registered as a `StructuredTool` with a schema accepting `file_path` and `text` parameters. When an agent flow includes this tool, the LLM can call it with arbitrary file paths and content during conversation.

## Vulnerability

The `WriteFileTool._call()` method (line 81-84) directly passes the LLM-controlled `file_path` parameter to `this.store.writeFile(file_path, text)` without any validation:

```typescript
async _call({ file_path, text }: z.infer<typeof this.schema>) {
    await this.store.writeFile(file_path, text)
    return 'File written to successfully.'
}
```

The `file_path` comes from the LLM's tool-call output, which in turn can be influenced by user chat input. There is no check that the path falls within the configured `basePath` workspace, no path traversal prevention (e.g., blocking `../`), no allowlist of permitted directories, and no file extension restrictions.

An attacker can instruct the LLM to write to sensitive paths such as `~/.ssh/authorized_keys` (for SSH access), `/etc/ld.so.preload` (for library hijacking), or the application's own `package.json` (to modify start commands). The `NodeFileStore` used as the backing store performs raw filesystem writes without any sandboxing.

The fix introduces workspace boundary enforcement with `enforceWorkspaceBoundaries`, path validation via a `validateFilePath` utility, maximum file size checks, and allowed extension filtering.

## Source / Carrier / Sink
- Source: LLM tool-call output providing `file_path` and `text` parameters, ultimately influenced by user chat messages
- Carrier: `WriteFileTool._call()` method receives the parameters from the LLM's structured tool invocation
- Sink: `this.store.writeFile(file_path, text)` at line 82, which writes attacker-controlled content to an attacker-controlled path on the server filesystem
- Missing guard: no workspace boundary validation, no path traversal prevention, no directory allowlist, no file extension restrictions

## Annotated Region
- File: `packages/components/nodes/tools/WriteFile/WriteFile.ts`
- Lines: 59-85
- Why this region is the scoring target: it contains the entire `WriteFileTool` class including the `_call()` method where the LLM-controlled `file_path` flows directly into `this.store.writeFile()` without any path validation or workspace confinement

## Scanner Expectation
A scanner should flag `this.store.writeFile(file_path, text)` at line 82 for writing to an unvalidated, LLM-controlled file path. The vulnerability pattern is a tool-use sink that accepts an externally controlled path without workspace boundary checks, enabling arbitrary file write and subsequent code execution.
