# SB-TS-RW-028: Flowise SQL injection in importChatflows via unsanitized chatflow IDs

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-9c4c-g95m-c8cp`
- Vulnerable commit: `ca69a39b8226b3a6ac218339aa602e8b3a8c8d02`
- Fix commit: `f963e5aa48a0697798ed63a84e826b1734ee2275`

## Scenario

Flowise provides an import/export feature that lets authenticated users
bulk-import chatflows from a JSON file via the
`POST /api/v1/chatflows/importchatflows` endpoint. The `importChatflows`
service function receives an array of chatflow objects from the uploaded
JSON, checks whether any IDs already exist in the database, and then
inserts new records for those that do not collide.

## Vulnerability

The `importChatflows` function (lines 221-269 of
`packages/server/src/services/chatflows/index.ts`) builds a SQL
`IN (...)` clause by directly string-interpolating each `newChatflow.id`
from the imported JSON into a raw SQL string:

```typescript
let ids = '('
let count: number = 0
const lastCount = newChatflows.length - 1
newChatflows.forEach((newChatflow) => {
    ids += `'${newChatflow.id}'`       // <-- unsanitized user input
    if (lastCount != count) ids += ','
    if (lastCount == count) ids += ')'
    count += 1
})

const selectResponse = await repository
    .createQueryBuilder('cf')
    .select('cf.id')
    .where(`cf.id IN ${ids}`)          // <-- raw SQL injection
    .getMany()
```

The `newChatflow.id` value comes directly from the imported JSON file
with no validation or sanitization. An attacker can set the chatflow ID
to a payload such as `') AND 1=0 UNION SELECT encryptedData FROM
credential --` to break out of the `IN (...)` clause and inject
arbitrary SQL.

The advisory includes a working blind SQL injection PoC that uses
boolean-based extraction to leak encrypted credentials from the
`credential` table, including API keys for connected LLM providers.

The fix validates that all imported IDs conform to UUID format before
using them in queries, preventing injection through malformed IDs.

## Source / Carrier / Sink
- Source: `newChatflow.id` field from the imported JSON payload, received
  via the `POST /api/v1/chatflows/importchatflows` endpoint
- Carrier: the `forEach` loop (lines 233-238) that builds the `ids`
  string by concatenating each chatflow ID with template literal
  interpolation `'${newChatflow.id}'`
- Sink: TypeORM `createQueryBuilder().where(\`cf.id IN ${ids}\`)` at
  line 240, which passes the raw interpolated string directly into SQL
- Missing guard: no UUID format validation, no parameterized query
  binding for the IN clause values

## Annotated Region
- File: `packages/server/src/services/chatflows/index.ts`
- Lines: 221-269
- Why this region is the scoring target: it contains the entire
  `importChatflows` function including the unsafe string-interpolation
  SQL construction pattern from user-supplied chatflow IDs

## Scanner Expectation
A scanner should flag the `importChatflows` function (lines 221-269 of
`packages/server/src/services/chatflows/index.ts`) for constructing a
SQL query via string interpolation of user-controlled input
(`newChatflow.id`). The `ids` string is built by concatenating
unsanitized values from imported JSON and then passed directly into a
TypeORM `.where()` clause, enabling SQL injection.
