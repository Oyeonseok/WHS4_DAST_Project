# Scope-time referenced-policy preparation

Approved intent: the user approved generic referenced-policy collection and clarified that AI must finish policy preparation when Scope.md is created; scan launch should apply the saved interpretation. This is the authoritative design.

## Outcome

Collect the primary program views, observe their real policy-document links, let the collection-time AI choose applicable references by meaning, capture those documents in a bounded isolated public reader, and analyze the resulting evidence before saving Scope.json/Scope.md. Fresh Scope must include explicit required_request_headers and execution_rules.exclusions (empty lists when reviewed and absent). Complete approved documents launch using saved rules without another interpretation/fetch. Existing request-context semantic binding remains a separate evidence check; this does not pre-classify uncaptured target resources.

A referenced disclosure document is not a blanket testing blocker simply because it is absent: AI must reason from the captured content and obligation's phase. Testing obligations stay execution controls; reporting/public-disclosure obligations stay submission requirements. Ambiguous or missing potentially applicable testing obligations still hold. No blocker is removed by matching its English label or a service name.

## Evidence and collection contract

- Keep ProgramPage.text as the original program capture and its content_sha256 as its original digest. Add optional bounded observed-link/reference-capture fields with legacy defaults, plus one shared combined evidence-text accessor for interpretation and quote validation. The Scope JSON/manifest hashes cover all added evidence.
- Real DOM hrefs and labels from both public and authenticated readers are observed before navigating away from each primary view. Native collection supplies observed links in its structured collection result; its trusted browser observation is the same provenance boundary as existing native captured_text. The native agent does not fetch external policy documents itself.
- Collection-time AI chooses only application-supplied candidate IDs and exact contiguous source quotes. It receives untrusted captured text and candidates with browsing/tools disabled. Do not classify documents with Neon/HackerOne names, header allowlists, policy prose regexes or label filters. Selected references carry their parent/source quote and an interpretation of testing/reporting/disclosure/mixed/unknown applicability. Preserve inability to resolve a selected reference.
- Reference transport is separate from authenticated program sessions: public HTTPS GET only, no cookies/Authorization/identity headers or login/form submission, no environment proxy inheritance. Reject credentials, malformed URLs and non-public addresses; validate every redirect, pin a validated public address for each connection while preserving hostname/TLS verification, and retain requested/final URL, timestamp, text and digest. There is no target security testing or asset expansion.
- Bound observations to 128 links per page, selection to 8 documents total, recursion to depth 2, redirects to 3, each raw response to 1 MiB, total combined evidence to 120000 characters, per-request timeout to 15 seconds. Require readable text/HTML; inaccessible, unsupported, oversized or depth/count-limited references are recorded as unresolved, never treated as permission. Do not recurse forever or silently trim evidence. Selection calls happen only during collection and are bounded by the same queue.
- Reference quotes can support narrowing operational requirements, but only original program text can authorize assets. Reject every asset grounded solely in an external document, including an external document's own example targets. Preserve contextual source origin for all captured documents.
- Capture only actual policy document links chosen from observed candidates, not search results or model-invented destinations. A lexical URL/HTML parser may discover candidate hrefs; AI decides their policy meaning.

## Integration

ScopeCoordinator.collect_draft performs enrichment before final interpretation/grounding/draft save for native, public and authenticated flows. Existing initial native analysis may be reused only if enrichment did not change the evidence and all fresh contracts are complete; otherwise re-interpret during collection. Injectable selector/document-reader hooks support entirely local tests. No target/resource discovery happens here.

Both production model adapters share collection-time selection and instructions about combined evidence and lifecycle phases. The aidast-scope skill distinguishes collection of explicitly observed policy references from offline interpretation. ProgramPage primary text, external provenance and failures are persisted and shown in Scope.md. The coordinator fails a fresh incomplete header/exclusion interpretation before approval; never defer known missing preparation to first scan.

Existing approved Scope/Approval/Manifest/policies/DBs remain byte-identical. Older documents lacking reference evidence retain conservative behavior and can require normal Scope re-collection/review; never rewrite approval hashes or patch a saved blocker label. Existing aggregate authorization UI stays; no new consent checklist. No actual Neon/model calls, server restart, commit or scan is part of implementation verification.

## Verification

Meaningful RED/GREEN must demonstrate: an observed arbitrary/localized disclosure reference is captured before interpretation; constraints from reference text persist and apply; reporting-only requirements do not become launch blockers; missing testing references remain explicit holds; invented candidates/quotes fail; SSRF/private redirect/credentials/cookies/proxy/oversize/unsupported responses send no forbidden request; nested links/count/depth bounded; primary-only asset authorization; all collection modes; fresh incomplete AI data rejected at draft time; approved complete Scope launches with interpreter/network patched to fail; old artifacts unchanged. AI accuracy remains probabilistic: injected deterministic model outputs prove contracts and application behavior, not real-model semantic quality.

## Authority clarification from preflight

Combined analysis must preserve primary-only allowed_activities/permission facts, since that list has no item-level provenance mapping. The collector may first analyze primary text, then analyze enriched evidence and retain primary authority while accepting narrowed execution/reporting requirements. An asset supporting quote itself must belong to original program text; merely mentioning the asset in external evidence is insufficient. ScopeHeaderResolver also uses the combined quote/budget accessor. These clarify the existing no-expansion requirement.

## Recollection usability correction

The existing dashboard start path returns the old verified Scope whenever canonical files exist; it does not actually recollect. To make the approved feature usable for current programs, add explicit refresh and preserve old versions. ScopeCollectionRequest.refresh defaults false. Each job saves an app-owned validated output_path; refresh with an existing canonical approval chooses canonical_program_dir/revisions/<scopejob_id>, and normal first collection chooses the original canonical directory. Worker, decision and approved-scope lookup use that exact saved path. Legacy rows fall back to canonical. No arbitrary client path or overwrite.

The approved catalog lists verified canonical and revision Scope files under the original program identity. The dashboard exposes Collect again, uses the existing explicit review/approval flow, presents compact captured-reference state and full prepared execution rules, and lets the operator select the new scope for scans. Pending/rejected/failed refresh leaves previous approved versions usable. No existing actual artifacts or job DB are changed during implementation tests.

## Verified implementation addendum

Review identified that primary captures contain multiple views. The implementation stores at most six `PrimaryPolicyView` records with exact original text, URL and at most 128 observed links each. Offline selection is grounded separately in each view, with at most fourteen calls and 112 retained reference edges; the eight-document, depth-two and transport/evidence limits remain unchanged. Saved edges retain their primary view index. Legacy flat captures remain compatible.

Persisted execution blockers reserve 176 entries: at most 64 freshly extracted blockers plus 112 generated reference holds. Fresh extraction retains its explicit 64-entry boundary. Maximum cases complete draft persistence/approval/reload and remain held at launch. The actual selected revision is also passed through the isolated worker and bounded CLI revision option. All decisions and additional verification are recorded in the archived ledger.
