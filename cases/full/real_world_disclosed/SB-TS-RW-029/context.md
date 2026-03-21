# SB-TS-RW-029: n8n SQL injection in MySQL, PostgreSQL, and Microsoft SQL database nodes

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-f3f2-mcxc-pwjx`
- Vulnerable commit: `9ce3ac092cf7339f3c4a416cdea6e5fa2d5b22b9`
- Fix commit: `f73fae6fe7fc34907bba102648a9997186aa4385`

## Scenario

n8n provides MySQL, PostgreSQL, and Microsoft SQL nodes that allow
workflow builders to perform database operations (select, insert, update,
delete) through a visual interface. These nodes accept configuration
parameters including table names, column selections, where clauses, sort
rules, and limits. Where clauses are specified as structured objects with
`column`, `condition` (operator), and `value` fields.

## Vulnerability

The disclosed issue spans three database-node implementations in the same
feature family:

- MySQL and PostgreSQL accept workflow-controlled `where` objects and
  interpolate the `condition` operator directly into SQL without an
  allowlist.
- MySQL also interpolates `rule.direction` directly into `ORDER BY`.
- Microsoft SQL constructs query fragments from workflow-controlled table,
  column, and key identifiers without escaping them.

This benchmark case requires detection of the two primary helper sinks
(`addWhereClauses()` for MySQL and PostgreSQL) and also credits scanners
that find the adjacent MySQL sort-direction sink or the Microsoft SQL
identifier-interpolation sinks from the same advisory.

### MySQL (lines 480-536 of `packages/nodes-base/nodes/MySql/v2/helpers/utils.ts`)

```typescript
whereQuery += ` ${escapeSqlIdentifier(clause.column)} ${
    clause.condition            // <-- unvalidated, interpolated directly
}${valueReplacement}${operator}`;
```

The MySQL helper also exposes a second sink in `addSortRules()`:

```typescript
orderByQuery += ` ${escapeSqlIdentifier(rule.column)} ${rule.direction}${endWith}`;
```

### PostgreSQL (lines 129-188 of `packages/nodes-base/nodes/Postgres/v2/helpers/utils.ts`)

```typescript
whereQuery += ` ${columnReplacement} ${clause.condition}${valueReplacement}${operator}`;
```

The where clause objects originate from `getNodeParameter('where', i, [])`,
which is cast directly to `WhereClause[]` without any type or value
validation:

```typescript
const whereClauses =
    ((this.getNodeParameter('where', i, []) as IDataObject).values as WhereClause[]) || [];
```

The `condition` field is expected to be one of `=`, `>`, `<`, `>=`,
`<=`, `IS NULL`, or `IS NOT NULL`, but since it comes from workflow
configuration parameters that can be set via expressions or the API,
an attacker can supply arbitrary SQL in this field.

### Microsoft SQL (`packages/nodes-base/nodes/Microsoft/Sql/GenericFunctions.ts`)

The Microsoft SQL node has a parallel identifier-escaping problem:

```typescript
export function formatColumns(columns: string) {
    return columns
        .split(',')
        .map((column) => `[${column.trim()}]`)   // <-- no escaping of ] or nested identifiers
        .join(', ');
}
```

```typescript
const condition = `${item.updateKey} = @condition`;   // <-- unescaped identifier
setValues.push(`[${col}] = @v${index}`);              // <-- unescaped identifier
```

```typescript
const query = `DELETE FROM ${escapeTableName(
    table,
)} WHERE [${deleteKey}] IN (${valuesPlaceholder.join(', ')});`;
```

The fix adds stricter where-clause validation for MySQL/PostgreSQL and
escapes identifier-bearing fields in the Microsoft SQL helper paths.

## Source / Carrier / Sink
- Source: workflow configuration parameters (`where`, `sort`, `table`,
  `columns`, `updateKey`, `deleteKey`)
  set via the n8n UI, API, or expressions by a user with workflow
  editing permissions
- Carrier: the `execute` functions in `select.operation.ts` and
  `deleteTable.operation.ts` that read the parameters via
  `getNodeParameter()` and cast them to `WhereClause[]` / `SortRule[]`
  without validation; Microsoft SQL operations pass table/column/key
  identifiers into query-building helpers
- Sink: `addWhereClauses()` in MySQL utils.ts (line 530-532) and
  PostgreSQL utils.ts (line 184) where `clause.condition` is directly
  interpolated into SQL; `addSortRules()` in MySQL utils.ts (line 551)
  where `rule.direction` is interpolated; `formatColumns()`,
  `updateOperation()`, and `deleteOperation()` in Microsoft SQL
  `GenericFunctions.ts` where identifiers are concatenated into queries
- Missing guard: no allowlist validation for SQL operators/directions and
  no safe escaping for Microsoft SQL identifier fields

## Annotated Regions

### R1: MySQL addWhereClauses
- File: `packages/nodes-base/nodes/MySql/v2/helpers/utils.ts`
- Lines: 480-536
- Why this region is the scoring target: the `addWhereClauses` function
  constructs WHERE clause SQL by interpolating the unvalidated
  `clause.condition` operator field directly into the query string,
  while column names are properly escaped and values are parameterized

### R2: MySQL addSortRules
- File: `packages/nodes-base/nodes/MySql/v2/helpers/utils.ts`
- Lines: 538-554
- Why this region is included: the helper appends `rule.direction`
  directly into `ORDER BY` without constraining it to `ASC` or `DESC`

### R3: PostgreSQL addWhereClauses
- File: `packages/nodes-base/nodes/Postgres/v2/helpers/utils.ts`
- Lines: 129-188
- Why this region is the scoring target: same pattern as MySQL -- the
  `clause.condition` field is interpolated directly into the SQL WHERE
  clause without validation against an allowlist of operators

### R4: Microsoft SQL formatColumns
- File: `packages/nodes-base/nodes/Microsoft/Sql/GenericFunctions.ts`
- Lines: 89-93
- Why this region is included: the helper wraps workflow-controlled
  column names in brackets without escaping embedded `]` characters

### R5: Microsoft SQL updateOperation
- File: `packages/nodes-base/nodes/Microsoft/Sql/GenericFunctions.ts`
- Lines: 176-200
- Why this region is included: workflow-controlled `updateKey` and
  selected columns are inserted into the `UPDATE` statement as raw
  identifiers

### R6: Microsoft SQL deleteOperation
- File: `packages/nodes-base/nodes/Microsoft/Sql/GenericFunctions.ts`
- Lines: 203-238
- Why this region is included: workflow-controlled `deleteKey` is
  inserted directly into the `DELETE ... WHERE [key] IN (...)` clause

## Scanner Expectation
A scanner should flag the `addWhereClauses` functions in both
`packages/nodes-base/nodes/MySql/v2/helpers/utils.ts` (lines 480-536)
and `packages/nodes-base/nodes/Postgres/v2/helpers/utils.ts` (lines
129-188) for interpolating user-controlled `condition` values directly
into SQL query strings. Scanners should also get credit if they find the
adjacent MySQL `addSortRules()` sink or the Microsoft SQL identifier
interpolation bugs from the same disclosed issue.
