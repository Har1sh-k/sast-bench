# SB-TS-RW-029: n8n SQL injection via unvalidated where-clause operators in MySQL and PostgreSQL nodes

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

The `addWhereClauses` utility functions in both the MySQL and PostgreSQL
node helpers accept where-clause objects and construct SQL query strings.
While column names are escaped using `escapeSqlIdentifier()` and values
are parameterized with `?` placeholders (MySQL) or `$N` placeholders
(PostgreSQL), the `condition` operator field is interpolated directly
into the SQL string without validation.

### MySQL (lines 480-536 of `packages/nodes-base/nodes/MySql/v2/helpers/utils.ts`)

```typescript
whereQuery += ` ${escapeSqlIdentifier(clause.column)} ${
    clause.condition            // <-- unvalidated, interpolated directly
}${valueReplacement}${operator}`;
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

Additionally, the `addSortRules` function in the MySQL utils (line 551)
interpolates `rule.direction` directly into the ORDER BY clause without
validating it is either `ASC` or `DESC`. The PostgreSQL `select`
operation (line 129 of `select.operation.ts`) also directly interpolates
the `limit` value into the query string via template literal
(`` query += ` LIMIT ${limit}` ``), though this is lower severity since
the limit parameter is typed as a number.

The fix adds a `getWhereClauses` function that validates each clause
against a known set of allowed operator values before use, and
restricts `direction` to exactly `ASC` or `DESC`.

## Source / Carrier / Sink
- Source: workflow configuration parameters (`where`, `sort`, `limit`)
  set via the n8n UI, API, or expressions by a user with workflow
  editing permissions
- Carrier: the `execute` functions in `select.operation.ts` and
  `deleteTable.operation.ts` that read the parameters via
  `getNodeParameter()` and cast them to `WhereClause[]` / `SortRule[]`
  without validation
- Sink: `addWhereClauses()` in MySQL utils.ts (line 530-532) and
  PostgreSQL utils.ts (line 184) where `clause.condition` is directly
  interpolated into the SQL query string; also `addSortRules()` in
  MySQL utils.ts (line 551) where `rule.direction` is interpolated
- Missing guard: no validation that `condition` is one of the allowed
  SQL operators, no validation that `direction` is `ASC` or `DESC`

## Annotated Regions

### R1: MySQL addWhereClauses
- File: `packages/nodes-base/nodes/MySql/v2/helpers/utils.ts`
- Lines: 480-536
- Why this region is the scoring target: the `addWhereClauses` function
  constructs WHERE clause SQL by interpolating the unvalidated
  `clause.condition` operator field directly into the query string,
  while column names are properly escaped and values are parameterized

### R2: PostgreSQL addWhereClauses
- File: `packages/nodes-base/nodes/Postgres/v2/helpers/utils.ts`
- Lines: 129-188
- Why this region is the scoring target: same pattern as MySQL -- the
  `clause.condition` field is interpolated directly into the SQL WHERE
  clause without validation against an allowlist of operators

## Scanner Expectation
A scanner should flag the `addWhereClauses` functions in both
`packages/nodes-base/nodes/MySql/v2/helpers/utils.ts` (lines 480-536)
and `packages/nodes-base/nodes/Postgres/v2/helpers/utils.ts` (lines
129-188) for interpolating user-controlled `condition` values directly
into SQL query strings. While column names and values are handled safely,
the operator/condition field bypasses all escaping and parameterization.
