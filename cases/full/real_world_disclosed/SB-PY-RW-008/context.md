# SB-PY-RW-008: Dify missing role check on workflow API endpoints

## Advisory
- Repo: `langgenius/dify`
- GHSA: `GHSA-6pw4-jqhv-3626`
- CVE: `CVE-2025-43862`
- Vulnerable commit: `a1d8c86ee3b9669e93cde86d9dd6240d3d6aa785`
- Fix commit: `cc4a4ec7963ff23ce70f5b05267066b5226ae5e4`

## Scenario

Dify is an open-source LLM app development platform. Its console API exposes
workflow management endpoints under `/apps/<app_id>/workflows/*` that allow
reading, syncing, running, publishing, and converting workflows. These
endpoints are protected by `@login_required` and
`@account_initialization_required` decorators, but no role-based check is
performed to verify the current user has editor, owner, or admin privileges.

## Vulnerability

The workflow API controllers in `api/controllers/console/app/workflow.py`
define multiple `Resource` subclasses that handle workflow operations:

- `DraftWorkflowApi` (lines 29-101): GET to read draft workflow, POST to
  sync/update draft workflow graph and features
- `DraftWorkflowRunApi` (lines 206-234): POST to execute a draft workflow
- `WorkflowTaskStopApi` (lines 237-250): POST to stop a running task
- `DraftWorkflowNodeRunApi` (lines 253-275): POST to run a single node
- `PublishedWorkflowApi` (lines 278-311): GET to read published workflow,
  POST to publish a draft workflow
- `ConvertToWorkflowApi` (lines 355-387): POST to convert an app to
  workflow mode

None of these handler methods check the user's role. The decorators applied
are `@setup_required`, `@login_required`, `@account_initialization_required`,
and `@get_app_model`, but none of these enforce editor-level access. Any
authenticated user with any role (including `normal` or viewer roles) can
invoke these endpoints directly via the API, bypassing the UI-level hiding.

The fix adds `if not current_user.is_editor: raise Forbidden()` at the
start of every handler method.

## Source / Carrier / Sink
- Source: HTTP request from any authenticated user to workflow API endpoints
- Carrier: Flask-RESTful `Resource` handler methods dispatch the request
  through `@login_required` which only checks authentication, not
  authorization role
- Sink: `WorkflowService` methods execute workflow operations (read, sync,
  run, publish, convert) without any role verification
- Missing guard: role-based authorization check (`current_user.is_editor`)
  in each handler method before dispatching to the service layer

## Annotated Regions
- R1: File `api/controllers/console/app/workflow.py`, lines 29-101
  (`DraftWorkflowApi` class) - GET and POST handlers for draft workflow
  read/sync lack role check
- R2: File `api/controllers/console/app/workflow.py`, lines 206-311
  (`DraftWorkflowRunApi`, `WorkflowTaskStopApi`, `DraftWorkflowNodeRunApi`,
  `PublishedWorkflowApi`) - workflow execution, stop, node run, and publish
  endpoints lack role check
- R3: File `api/controllers/console/app/workflow.py`, lines 355-400
  (`ConvertToWorkflowApi` and route registrations) - app-to-workflow
  conversion endpoint lacks role check

## Scanner Expectation
A scanner should flag the workflow API Resource handler methods for missing
role-based authorization checks. Each handler is decorated with
`@login_required` and `@account_initialization_required` but never verifies
`current_user.is_editor`, allowing any authenticated user to access, modify,
execute, and publish workflows.
