# SB-TS-RW-022: Function constructor injection in CustomMCP via mcpServerConfig

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-3gcm-f6qx-ff7p`
- CVE: `CVE-2025-59528`
- Vulnerable commit: `e002e617df6177cb603c8c569d224bce5fb96b33`
- Fix commit: `4af067a444a579f260d99e8c8eb0ae3d5d9b811a`
- Patched in: flowise@3.0.6

## Scenario

Flowise's CustomMCP node allows users to input configuration settings for connecting to an external MCP (Model Context Protocol) server. The `getTools` method in `CustomMCP.ts` reads the `mcpServerConfig` parameter from user input, performs variable substitution, and then calls `convertToValidJSONString()` to parse the config string into a JSON object before passing it to the MCP toolkit.

## Vulnerability

The `convertToValidJSONString` function (lines 262-270) uses the JavaScript `Function()` constructor to parse the input string:

```typescript
const jsObject = Function('return ' + inputString)()
```

The `inputString` parameter originates from the `mcpServerConfig` field submitted via the `/api/v1/node-load-method/customMCP` API endpoint. The `substituteVariablesInString` function at line 220 performs template variable replacement but applies no security filtering. The resulting string is passed directly to `Function()`, which compiles and executes it as JavaScript code with full Node.js runtime privileges.

An attacker can submit a payload like `({x:(function(){process.mainModule.require("child_process").execSync("id")})()})` as the `mcpServerConfig` value, which gets evaluated by the Function constructor, executing arbitrary system commands on the server.

The fix replaces `Function('return ' + inputString)()` with `JSON5.parse(inputString)`, which safely parses relaxed JSON without executing arbitrary code.

## Source / Carrier / Sink
- Source: `mcpServerConfig` parameter from API request body at `/api/v1/node-load-method/customMCP`
- Carrier: `getTools()` method reads `nodeData.inputs?.mcpServerConfig` (line 133), passes it through `substituteVariablesInString()` (line 171), then to `convertToValidJSONString()` (line 172)
- Sink: `Function('return ' + inputString)()` at line 264, which compiles and executes the user-controlled string as JavaScript
- Missing guard: no input sanitization or safe parsing; the Function constructor should never be used on user-controlled input

## Annotated Region
- File: `packages/components/nodes/tools/MCP/CustomMCP/CustomMCP.ts`
- Lines: 262-270
- Why this region is the scoring target: it contains the `convertToValidJSONString` function where user-controlled input is passed to the `Function()` constructor, enabling arbitrary code execution

## Scanner Expectation
A scanner should flag `Function('return ' + inputString)()` at line 264 for executing user-controlled input via the Function constructor. The data flow runs from the `mcpServerConfig` API parameter through `substituteVariablesInString` into the dangerous `Function()` call without any sanitization or sandboxing.
