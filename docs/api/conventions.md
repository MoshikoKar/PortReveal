# API conventions

Rules the PortReveal REST API follows. New endpoints follow them too. The interactive reference
is at `/api/docs` (OpenAPI at `/api/openapi.json`) when `APP_ENV` is not `production`.

## Versioning

- `/api/v1/...` is the versioned path for integrations, scripts and other clients. It serves the same
  routes as `/api/...`, which the bundled UI uses. Every route exists under both prefixes.
- **Freeze policy for v1:** changes are additive only. New endpoints, new optional request fields and
  new response fields can appear. Existing fields are not removed, renamed or retyped, and a status code
  does not change meaning.
- A breaking change ships as `/api/v2` next to v1. v1 stays available until the release notes announce
  its removal, and those notes list what changed.
- Clients must ignore response fields they do not know.

## Resources and paths

- Collections use plural nouns: `/api/devices`, `/api/networks`, `/api/saved-searches`.
- Path segments use kebab-case. JSON fields use snake_case.
- Settings live under `/api/settings/{section}`, one router (`backend/app/api/settings.py`) for all
  sections, including `web-capture`.
- **Hosts by IP:** `GET /api/hosts/{ip}` is the canonical path. `GET /api/host/{ip}` is a compatibility
  alias with the same body, kept for Shodan-style clients (Shodan uses `/shodan/host/{ip}`). Use the
  plural path in new code. The alias may be dropped in v2.
- **Deprecated field:** the host document returns its open services as `ports`, and again as `data`
  (the Shodan field name). `data` is deprecated and will be removed in v2. Read `ports`.

## Methods and status codes

| Operation | Method | Success |
|---|---|---|
| Read | `GET` | `200` |
| Create a resource | `POST /api/{collection}` | `201` with the new resource |
| Replace a settings section or an entity | `PUT` | `200` with the stored result |
| Partial update | `PATCH` | `200` with the stored result |
| Delete | `DELETE` | `204`, no body |
| Action (see below) | `POST` | `200` with a result body |

**PUT vs PATCH.** `PUT` is a full replace: send every field. Optional fields you leave out are reset to
their defaults. Settings sections (`/api/settings/*`) and these entities use `PUT`: networks, exclusions,
saved searches, and the device profile (`/api/devices/{uuid}/profile`). `PATCH` updates only the fields
you send, and is used where partial edits are common (`/api/users/{id}`). A new entity that needs
partial updates gets `PATCH`. Do not add `PUT` routes that silently keep fields you left out.

**Deletes.** `DELETE` answers `204 No Content`. For API tokens, `DELETE /api/tokens/{id}` is a *soft*
revoke. The token is marked `revoked: true` and stays in the list for the audit trail, but it can never
authenticate again. `POST /api/tokens/{id}/revoke` does the same thing and returns the updated token.

**Errors.** `4xx` means the request was wrong: `400` for a malformed search query (with `pos`), `401`,
`403`, `404`, `409` for state conflicts, `415`, `422` for validation, and `429` for rate limits. `5xx`
means the server failed, or an upstream it called did (`502` when a test email could not be sent).
A failure is never a `200` with `"ok": false`.

Every error body has the same envelope (`backend/app/api/errors.py`):

```json
{"code": "conflict", "message": "Scan is already completed", "detail": "Scan is already completed"}
```

- `code` is stable and machine-readable; branch on it, not on the message. By default it follows the
  status (`bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `unsupported_media_type`,
  `validation_error`, `rate_limited`, `internal_error`, `upstream_failed`, ...). Some errors are more
  specific: `invalid_query` (search syntax, adds `pos`), `invalid_target` (scan targets),
  `smtp_send_failed` (notification test).
- `message` is a sentence you can show to people.
- `detail` is the field older clients read. It equals `message`, except on `422` validation errors, where
  it keeps FastAPI's list of errors. The same list is also in `details` as `{loc, msg, type}` objects.
- Unhandled server errors answer `500` with `code: internal_error` and no exception text. Quote the
  `X-Request-Id` to find the log lines.

## Actions (RPC-style endpoints)

Some operations are not CRUD. They are `POST` verbs under the resource they act on:

- `POST /api/scans/{id}/cancel`, `POST /api/web-captures/{id}/cancel`
- `POST /api/networks/{id}/reset-baseline`
- `POST /api/tokens/{id}/revoke`
- `POST /api/settings/notifications/test`, `POST /api/settings/ldap/test`,
  `POST /api/settings/retention/run`
- `POST /api/inventory/ad-sync`

Rules for actions:

- The path is `/api/{resource}[/{id}]/{verb}`, where the verb is a kebab-case imperative.
- Do not add new top-level verb paths (`/api/do-something`). Find the resource the action belongs to.
- An action never runs on `GET`. `GET` has no side effects.

## Lists and pagination

- Paged lists take `?page=` (1-based) and `?page_size=`, and return
  `{"items": [...], "total": n, "page": p, "page_size": s}`. One shared dependency
  (`Paging` in `backend/app/api/common.py`) sets the defaults and limits.
- The default page size is 50 and the maximum is 500. Some endpoints set their own limits with
  `paging_with(default, max)`:

| Endpoint | Default | Max | Why |
|---|---|---|---|
| Most lists (`/api/devices`, `/api/events`, `/api/scans`, `/api/audit`, ...) | 50 | 500 | |
| `GET /api/search` | 25 | 100 | Each page scores hosts and nests their services |
| `GET /api/scans/{id}/events` | 50 | 500 | Scan detail no longer embeds events |
| `GET /api/web-hosts` | 50 | 500 | Returns `hosts` instead of `items`, plus `total`, `page`, `page_size` |

- Small admin collections (users, networks, exclusions, tokens, webhooks, saved searches) are returned
  as plain arrays without paging. They stay arrays within v1; OpenAPI marks each one (`UNPAGED_LIST`
  in `common.py`). A new collection that can grow uses the paged envelope.
- Responses that are not lists but wrap results in a named key have a response model in OpenAPI:
  `POST /api/scans` → `ScansStarted` (`{"scans": [...]}`), `POST /api/web-captures` → `CaptureStarted`
  (`{"capture": {...}}`), `GET /api/web-hosts` → `WebHostsPage`, `GET /api/exposed-ports` →
  `ExposedPorts` (`{"ports", "total", "truncated"}`).

## Correlation

- Every response carries `X-Request-Id`. A client can send its own id (1-64 characters from
  `A-Z a-z 0-9 . _ : -`) and the server echoes it. Otherwise the server generates one.
- JSON logs (`LOG_FORMAT=json`) include the same `request_id`. The UI shows it as the reference on
  server errors, so a reported reference leads straight to the matching log lines.
