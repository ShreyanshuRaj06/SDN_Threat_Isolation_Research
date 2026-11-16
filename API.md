# API: Internal Service Contracts

There is no public API. These are **proposed internal contracts** between services on the management network. The PDF says the exact endpoint and authentication mechanism "still need a team implementation choice"; everything here is a proposal.

## Conventions
- Base: `/v1` (versioning: breaking change -> `/v2`; additive fields non-breaking).
- Auth: service token in `Authorization: Bearer <token>` over a management-network-only interface (mTLS is a stronger alternative). Roles: `listener`, `risk_engine`, `operator`, `auditor`.
- Headers: `Content-Type: application/json`, `Idempotency-Key` (= `event_id` or `action_id`).
- Pagination: `?limit` (default 50, max 200) + `?cursor`. Sorting: `?sort=-occurred_at`. Filtering: `status`, `event_type`, `subject_ip`, `from`, `to`.
- Rate limits (proposal): 100 req/s per service for events; 5 req/s for operator actions; 429 on excess.
- **Standard error:**
```json
{ "error": { "code": "invalid_event", "message": "sensor not permitted", "status": 400, "request_id": "req-123" } }
```
Codes: 400 invalid_event, 401 unauthorized, 403 forbidden, 404 not_found, 409 duplicate/conflict, 422 unsafe_action, 429 rate_limited, 503 dependency_unavailable, 500 internal.

## Events (listener -> risk engine)  [PRD MVP 4 · table: events]
### POST /v1/events
Auth: role `listener`. Body (normalized alert):
```json
{ "event_id":"example-event-001","sensor_id":"ips-edge-1","event_type":"alert",
  "src_ip":"192.0.2.10","dest_ip":"198.51.100.20","signature":"illustrative threat signature",
  "subject_status":"requires direction validation","requested_action":null }
```
Success `202`: `{ "event_id":"example-event-001","status":"accepted" }`. Errors: 400, 401, 403 (sensor not permitted), 409 (duplicate), 429.
Rule: log text must never become a command; `requested_action` is ignored by the engine.

## Actions (risk engine -> Ryu)  [PRD MVP 3, 5 · tables: actions, action_events]
### POST /v1/actions
Auth: `risk_engine`. Body:
```json
{ "incident_id":"example-incident-001","action_id":"example-action-001","switch_id":"s1",
  "match":{"ingress_port":1,"ipv4_src":"192.0.2.10","ipv4_dst":"198.51.100.20","ip_proto":6,"tcp_dst":22},
  "action_type":"temporary_drop","priority":200,"ttl_s":60,"policy_version":"p1","evidence_refs":["example-suricata-event-001"] }
```
Success `202`: `{ "action_id":"...","state":"controller_accepted" }` (acceptance only, not containment). Errors: 401, 403, 409 (duplicate action_id), 422 (scope too broad / not approved), 503 (switch unreachable).
### GET /v1/actions/{action_id}
Auth: `operator`,`auditor`. Returns state plus `action_events`. 404 if unknown.
### POST /v1/actions/{action_id}/rollback
Auth: `operator`. Removes the exact rule (by cookie); returns `reverted` after verified restoration. Errors: 404, 409 (already expired/reverted), 503.

## Incidents  [PRD MVP 6 · tables: incidents, events]
### GET /v1/incidents  and  GET /v1/incidents/{id}
Auth: `operator`,`auditor`. List supports pagination/filter/sort above; detail returns the linked timeline.

## Evidence  [PRD V2 · tables: sealed_bundles, chain_checkpoints]
### POST /v1/incidents/{id}/seal
Auth: `risk_engine` or `operator`. Queues sealing; `202`. Errors: 404, 503.
### POST /v1/evidence/{bundle_id}/verify
Auth: `auditor`. Returns checks: `decrypt`, `signature`, `record_hash`, `chain_links`, `checkpoint`, each pass/fail with missing-record warnings.

## Health  [PRD V2 · no table]
### GET /v1/health
Auth: `operator`. Returns sensor/Ryu/AI status, spool depth, lost-event count, degraded-protection seconds.

## Flags (do not map cleanly)
- `GET /v1/health` has no table (metrics only).
- Explanation worker has no endpoint: it writes `explanations` directly.
- Authentication mechanism is an unresolved team decision.
