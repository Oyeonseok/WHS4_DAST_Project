# Authentication Endpoint Provenance Design

## Problem

AI-Dast creates a target session before Recon and can later reuse that session
without replaying the login flow. The session bundle currently preserves only
the authenticated browser state and its integrity metadata. It does not
preserve the HTTP endpoints observed while the operator authenticated.

This creates an evidence gap. Attack may safely exercise an authentication
endpoint as an `agent_proposed` request, but a finding requires an endpoint ID
owned by the completed Recon scan. A login endpoint omitted from Recon therefore
cannot support a durable finding even when the request itself completes.

Authentication traffic must remain outside active Recon request generation, but
its sanitized endpoint metadata must remain available as passive, provenance-
bearing evidence.

## Goals

- Preserve authentication endpoints as `method + normalized path + origin`
  metadata without retaining credentials or request/response bodies.
- Carry that metadata in the target session bundle so a later Recon run can
  import it without replaying login requests.
- Record imported endpoints in the Recon database with explicit authentication
  bootstrap provenance.
- Refresh the metadata after a successful reauthentication.
- Continue accepting legacy session bundles that do not contain endpoint
  metadata, while making the missing provenance observable.
- Keep active Recon method restrictions unchanged.

## Non-goals

- Replaying login requests during session restoration.
- Persisting passwords, tokens, cookies, authorization headers, query strings,
  request bodies, or response bodies in the endpoint metadata.
- Guessing authentication endpoints for legacy or externally produced bundles.
- Weakening the Attack finding requirement for a Recon-backed endpoint ID.
- Expanding the active Recon request policy beyond `GET`, `HEAD`, and `OPTIONS`.

## Considered approaches

### 1. Persist sanitized endpoint metadata in the session bundle (selected)

Capture authentication request metadata in a separate, passive recorder during
operator login. Store only allowlisted fields in `Session.json`, validate them
when loading the bundle, and import them into the Recon database.

This preserves provenance across runs without replaying a state-changing request
and keeps the finding integrity contract intact.

### 2. Replay login during every Recon

This would make the endpoint observable to the existing runtime capture, but it
would duplicate authentication side effects, complicate MFA, and defeat session
reuse. It is rejected.

### 3. Allow findings to reference agent-proposed URLs directly

This would avoid changing the session bundle, but it would weaken the current
requirement that a finding be grounded in a completed Recon surface. It is
rejected for this change.

## Session bundle contract

`Session.json` gains an optional `authentication_endpoints` array. Each entry
contains only:

- `method`: uppercase HTTP method;
- `origin`: normalized `scheme://host:port` origin;
- `path`: normalized path without query or fragment;
- `source`: the fixed value `auth_bootstrap`;
- `observed_at`: capture timestamp when available.

The array is optional for backward compatibility. Loading rejects malformed
entries, unsupported schemes, origins outside the selected target, paths
containing query/fragment/userinfo,
and unknown fields that could conceal sensitive data. Duplicate entries are
collapsed by `(method, origin, path)`.

Normalization replaces numeric, UUID, high-entropy, percent-encoded, and
authentication-token path segments with a non-secret template marker. A
credential-bearing raw path is never written to the bundle, diagnostics, or
Recon database.

The bundle integrity map continues to cover the browser state files. The bundle
file itself remains protected by the existing session binding and filesystem
controls; endpoint metadata contains no authentication material.

## Capture flow

The operator login browser remains outside active Recon policy enforcement. A
dedicated authentication observer records request metadata only. It does not
retain headers, bodies, query values, response bodies, or credentials.

Only requests within the selected target origin are eligible. External
identity-provider and authentication-bootstrap traffic is not stored as a
target endpoint because it belongs to a different origin and cannot ground a
finding against the selected target.

After successful session export, the sanitized, deduplicated observations are
written into the new bundle field. A failed or cancelled login produces no
usable session bundle.

When runtime reauthentication succeeds, the newly observed authentication
endpoint set replaces the prior set for the resulting session snapshot. It is
not appended blindly, preventing stale endpoints from accumulating forever.

## Restore and Recon import flow

When a target session is loaded, its authentication endpoint entries are parsed
and validated together with the existing session binding. Before endpoint
discovery completes, same-target entries are inserted through the normal Recon
endpoint upsert path with `source_tool=auth_bootstrap` and a passive observation
record.

Import does not consume the active HTTP request budget because it sends no
request. It also does not bypass host, port, or path scope checks. A POST endpoint
may appear in the Recon inventory as passively observed evidence even though
active Recon remains limited to safe methods.

Passive authentication observations use a dedicated channel. They are persisted
as evidence but never supplied as browser navigation, crawler, ffuf, API-probe,
or other active-discovery seeds.

The resulting endpoint ID is available to Attack task selection, request
grounding, attempt persistence, and finding reproduction.

## Legacy bundles

A bundle without `authentication_endpoints` remains valid. Loading it emits a
structured diagnostic indicating that authentication endpoint provenance is
unavailable, then proceeds without inventing an endpoint.

This preserves existing Phase C artifacts and user-created bundles. The next
successful interactive authentication creates an upgraded bundle containing
the new metadata.

An empty `authentication_endpoints` array is distinct from an absent field:
empty means capture completed but observed no in-boundary authentication
endpoint; absent means legacy or unknown provenance.

## Error handling and privacy

- Sensitive request material is discarded at capture time rather than redacted
  after persistence.
- Invalid metadata fails session loading instead of being partially imported.
- Out-of-scope entries are rejected and recorded as diagnostics without sending
  traffic.
- Database import is idempotent through the existing endpoint uniqueness rules.
- Diagnostics report counts and normalized endpoint coordinates only; they do
  not include query strings, headers, bodies, cookies, or storage values.

## Testing

Tests will be added before production changes and will cover:

1. A successful login stores a sanitized POST endpoint without secrets.
2. Loading a new bundle returns validated authentication endpoint metadata.
3. Recon imports restored authentication endpoints with `auth_bootstrap`
   provenance and does not issue the login request again.
4. Duplicate observations collapse to one endpoint.
5. Out-of-scope or malformed endpoint metadata is rejected.
6. A legacy bundle remains loadable and emits the missing-provenance diagnostic.
7. Reauthentication refreshes rather than blindly appends endpoint metadata.
8. Existing Recon safe-method enforcement remains unchanged.
9. Attack can bind an authentication attempt and finding to the imported Recon
   endpoint ID.

Relevant focused tests will run first, followed by the complete test suite.
