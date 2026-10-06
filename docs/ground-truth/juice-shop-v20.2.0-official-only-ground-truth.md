# OWASP Juice Shop v20.2.0 --- Official-Only Ground Truth (v8)

> **Rule:** The `*_observed` fields contain only information explicitly
> present in the official OWASP Juice Shop Companion Guide
> [Challenge solutions](https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html)
> chapter. Separately marked `code_derived` blocks are not official-guide
> ground truth.
>
> The supplied guide states that its solutions are compatible with
> **OWASP Juice Shop v20.2.0** and that, where multiple solutions exist,
> it normally presents one representative solution.
>
> **No inferred fields are included in the official-guide layer.** CWE mappings, custom
> vulnerability families/subtypes, DAST-scope labels, inferred HTTP
> methods, inferred authentication requirements, custom validation
> grades, negative controls, match keys, and model-written success
> oracles have been removed from that layer.
>
> `gt_id` below is only a local dataset identifier for indexing. It is
> **not** claimed to be an OWASP identifier.

## Code-derived supplement (not official)

Some records carry an additional `code_derived` block. It is **not** taken
from the official guide. It was filled by reading the OWASP Juice Shop
v20.2.0 source (git tag `v20.2.0`, commit `5658473`) where the guide's
solution text names no endpoint, no method or no parameter. `source` and
`evidence` (file:line) in each block say where the value comes from.

-   `paths_observed`, `http_methods_observed`, `input_names_observed`
    remain exactly as extracted from the official guide.
-   `code_derived.paths` / `http_methods` / `input_names` are
    code-based and must not be counted as official ground truth.
-   `code_derived.review_note` flags an existing guide-derived value that
    does not match the source or looks incidental. It does not change it.
-   Records without a `code_derived` block were left as extracted. Some
    (for example JS20-002 Mass Dispel) are UI/WebSocket-only.

## Extraction scope (what `*_observed` means)

Each `*_observed` list holds **only the technical values that the
challenge's own exploitation path acts on** — the endpoint actually
targeted, the method used against it, and the parameter/header the
attacker supplies or manipulates.

The following are deliberately **excluded**, even when they appear as
strings inside the same official solution section:

-   **Evidence / quoted data** — e.g. parameters appearing inside a
    quoted access-log entry, a leaked request, or sample JSON that the
    attacker does not themselves send.
-   **Incidental mentions** — a path named only to describe something
    (what a file *is*, where to *find* comment IDs first), not acted on.
-   **Post-solution asides** — "Did you notice…", trivia, or follow-up
    narrative after the challenge is already solved.
-   **Bonus rounds** — alternative/advanced attacks presented after the
    primary solution (labelled "Bonus Round").
-   **Cross-references** — paths/params belonging to a *different*
    challenge that this solution merely points to.

Rationale: in v6 these were conflated with genuine targets (ChatGPT
review, 2026-10). Challenge **inventory** (list, count, difficulty) is
high-confidence; the `*_observed` fields are now scoped to the
exploitation target so that inventory and technical fields carry the
same meaning across all 116 records.

## Included fields

-   `gt_id`: local indexing ID
-   `challenge`: challenge heading from the supplied official solution
    chapter, with typographic quotation marks normalized to ASCII
-   `difficulty`: star section in which the challenge appears
-   `paths_observed`: localhost Juice Shop paths the exploitation path
    targets (per the scope rule above)
-   `http_methods_observed`: HTTP methods used by the exploitation path
-   `input_names_observed`: parameter/header names the attacker supplies
    or manipulates in the exploitation path

If the official solution section does not explicitly state one of these
technical values, the corresponding list is empty.

> **v8 verification (2026-10-05):** All 116 unique challenge titles and
> guide star-section difficulties were checked against the official
> `Challenge solutions` page. Removed a passive broken-image request,
> an external SoundCloud query key, invalid token-sale URL artifacts,
> and a request quoted only in leaked logs. Collapsed normalized
> change-password query examples to the path explicitly named by the
> guide. Added explicitly supplied review-update fields and the 2FA
> search parameter and request `Content-Type` headers. Removed
> post-solution alternative paths from JS20-080. Code-derived global JWT checks no longer appear as
> literal paths. Infrastructure file paths now include their mounted
> `/infrastructure` prefix.
> Added the guide's relative routes `/juicy-nft`, `/bee-haven` and `/wallet`,
> and the NFT verification endpoint in the code supplement. Numbered route
> and frontend citations were rechecked against tag `v20.2.0` and corrected
> to physical file line numbers.
> The official page repeats the Token Sale heading once above an expired
> coupon procedure; that duplicate is not a second challenge record.
>
> **v7 changelog (relative to v6):** scope rule above now enforced.
> Removed solution-context contamination:
> - JS20-087 — dropped `/#/search?q=` (Bonus Round reflected-XSS
>   delivery, not the primary change-password solution).
> - JS20-090 — dropped `/api/Complaints` (post-solution "Did you
>   notice" aside) and `current` / `new` / `repeat` (parameters quoted
>   from a leaked access-log entry, not sent by the attacker; the actual
>   solution logs in at `/#/login`).
> - JS20-109 — dropped `/rest/products/<id>/reviews` (referenced only to
>   fetch comment IDs beforehand, in a config comment; the liked-review
>   target is `/rest/products/reviews`).
> - JS20-072 — dropped `/rest/products/{id}/reviews` (generic endpoint
>   description) and `/rest/products/1/reviews` (example used to read a
>   review first); kept the two `sleep(...)` paths that carry the
>   injection.
>
> v6 inventory fixes (still in effect): 4 previously-missing
> login challenges added; token-sale paths moved from the typosquatting
> challenge to *Learn about the Token Sale*; non-parameter words purged
> from `input_names_observed`; genuine missing parameters added;
> truncated paths restored; `/etc/passwd` heading repaired; gt_ids
> renumbered sequentially (116 records).

------------------------------------------------------------------------

## JS20-001 --- Access a confidential document

``` yaml
gt_id: "JS20-001"
challenge: "Access a confidential document"
difficulty: 1
paths_observed:
  - "/ftp/legal.md"
  - "/ftp"
  - "/ftp/acquisitions.md"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-002 --- Close multiple "Challenge solved"-notifications in one go

``` yaml
gt_id: "JS20-002"
challenge: "Close multiple \"Challenge solved\"-notifications in one go"
difficulty: 1
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-003 --- Find the carefully hidden 'Score Board' page

``` yaml
gt_id: "JS20-003"
challenge: "Find the carefully hidden 'Score Board' page"
difficulty: 1
paths_observed:
  - "/#/score-board"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-004 --- Find the endpoint that serves usage data to be scraped by a popular monitoring system

``` yaml
gt_id: "JS20-004"
challenge: "Find the endpoint that serves usage data to be scraped by a popular monitoring system"
difficulty: 1
paths_observed:
  - "/metrics"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-005 --- Follow the DRY principle while registering a user

``` yaml
gt_id: "JS20-005"
challenge: "Follow the DRY principle while registering a user"
difficulty: 1
paths_observed:
  - "/#/register"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-006 --- Give a devastating zero-star feedback to the store

``` yaml
gt_id: "JS20-006"
challenge: "Give a devastating zero-star feedback to the store"
difficulty: 1
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/api/Feedbacks"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:421-425; models/feedback.ts"
```

## JS20-007 --- Find an accidentally deployed code sandbox

``` yaml
gt_id: "JS20-007"
challenge: "Find an accidentally deployed code sandbox"
difficulty: 1
paths_observed:
  - "/#/web3-sandbox"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-008 --- Let us redirect you to one of our crypto currency addresses

``` yaml
gt_id: "JS20-008"
challenge: "Let us redirect you to one of our crypto currency addresses"
difficulty: 1
paths_observed:
  - "/redirect?to="
http_methods_observed:
  []
input_names_observed:
  - "to"
```

## JS20-009 --- Perform a DOM XSS attack

``` yaml
gt_id: "JS20-009"
challenge: "Perform a DOM XSS attack"
difficulty: 1
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/#/search?q="
  http_methods:
    []
  input_names:
    - "q"
  evidence: "frontend/src/app/search-result/search-result.component.ts:128-135"
```

## JS20-010 --- Provoke an error that is neither very gracefully nor consistently handled

``` yaml
gt_id: "JS20-010"
challenge: "Provoke an error that is neither very gracefully nor consistently handled"
difficulty: 1
paths_observed:
  - "/rest/qwertz"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-011 --- Read our privacy policy

``` yaml
gt_id: "JS20-011"
challenge: "Read our privacy policy"
difficulty: 1
paths_observed:
  - "/#/privacy-security/privacy-policy"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-012 --- Retrieve the photo of Bjoern's cat in "melee combat-mode"

``` yaml
gt_id: "JS20-012"
challenge: "Retrieve the photo of Bjoern's cat in \"melee combat-mode\""
difficulty: 1
paths_observed:
  - "/#/photo-wall"
  - "/assets/public/images/uploads/%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-013 --- Use the bonus payload in the DOM XSS challenge

``` yaml
gt_id: "JS20-013"
challenge: "Use the bonus payload in the DOM XSS challenge"
difficulty: 1
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/#/search?q="
  http_methods:
    []
  input_names:
    - "q"
  evidence: "frontend/src/app/search-result/search-result.component.ts:128-135"
```

## JS20-014 --- A developer was careless with hardcoding unused but still valid credentials

``` yaml
gt_id: "JS20-014"
challenge: "A developer was careless with hardcoding unused but still valid credentials"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/login"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:615; routes/login.ts"
```

## JS20-015 --- Access the administration section of the store

``` yaml
gt_id: "JS20-015"
challenge: "Access the administration section of the store"
difficulty: 2
paths_observed:
  - "/#/administration"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-016 --- Behave like any "white hat" should before getting into the action

``` yaml
gt_id: "JS20-016"
challenge: "Behave like any \"white hat\" should before getting into the action"
difficulty: 2
paths_observed:
  - "/.well-known/security.txt"
  - "/security.txt"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-017 --- Determine the answer to Emma's security question

``` yaml
gt_id: "JS20-017"
challenge: "Determine the answer to Emma's security question"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/security-question"
    - "/rest/user/reset-password"
  http_methods:
    - "GET"
    - "POST"
  input_names:
    []
  evidence: "server.ts:617-618; routes/resetPassword.ts"
```

## JS20-018 --- Determine the answer to John's security question

``` yaml
gt_id: "JS20-018"
challenge: "Determine the answer to John's security question"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/security-question"
    - "/rest/user/reset-password"
  http_methods:
    - "GET"
    - "POST"
  input_names:
    []
  evidence: "server.ts:617-618; routes/resetPassword.ts"
```

## JS20-019 --- Get rid of all 5-star customer feedback

``` yaml
gt_id: "JS20-019"
challenge: "Get rid of all 5-star customer feedback"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/api/Feedbacks/:id"
  http_methods:
    - "DELETE"
  input_names:
    []
  evidence: "server.ts:380,452,505 (Feedback REST resource and PUT denial); routes/verify.ts:217-221 feedbackChallenge"
```

## JS20-020 --- Inform the shop about an algorithm or library it should definitely not use the way it does

``` yaml
gt_id: "JS20-020"
challenge: "Inform the shop about an algorithm or library it should definitely not use the way it does"
difficulty: 2
paths_observed:
  - "/#/contact"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-021 --- Log in with MC SafeSearch's original user credentials

``` yaml
gt_id: "JS20-021"
challenge: "Log in with MC SafeSearch's original user credentials"
difficulty: 2
paths_observed:
  - "/#/login"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-022 --- Log in with the administrator's user account

``` yaml
gt_id: "JS20-022"
challenge: "Log in with the administrator's user account"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/login"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:615; routes/login.ts"
```

## JS20-023 --- Log in with the administrator's user credentials without previously changing them or applying SQL Injection

``` yaml
gt_id: "JS20-023"
challenge: "Log in with the administrator's user credentials without previously changing them or applying SQL Injection"
difficulty: 2
paths_observed:
  - "/#/login"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-024 --- Obtain the password (hash) of the currently logged-in user directly from a REST API endpoint

``` yaml
gt_id: "JS20-024"
challenge: "Obtain the password (hash) of the currently logged-in user directly from a REST API endpoint"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/whoami"
  http_methods:
    - "GET"
  input_names:
    []
  evidence: "server.ts:619; routes/currentUser.ts"
```

## JS20-025 --- Perform a reflected XSS attack

``` yaml
gt_id: "JS20-025"
challenge: "Perform a reflected XSS attack"
difficulty: 2
paths_observed:
  - "/#/track-result?id="
http_methods_observed:
  []
input_names_observed:
  - "id"
```

## JS20-026 --- Register a user with an empty email and password

``` yaml
gt_id: "JS20-026"
challenge: "Register a user with an empty email and password"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/api/Users"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:441; routes/verify.ts emptyUserRegistration"
```

## JS20-027 --- Reveal some behind-the-scenes information on the chatbot as a non-admin user

``` yaml
gt_id: "JS20-027"
challenge: "Reveal some behind-the-scenes information on the chatbot as a non-admin user"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/chat"
  http_methods:
    - "POST"
  input_names:
    - "show_tool_calls"
  evidence: "server.ts:657; routes/chat.ts:203-207 (cookie show_tool_calls=true, non-admin role)"
```

## JS20-028 --- Take over the wallet containing our official Soul Bound Token

``` yaml
gt_id: "JS20-028"
challenge: "Take over the wallet containing our official Soul Bound Token"
difficulty: 2
paths_observed:
  - "/juicy-nft"
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/web3/submitKey"
    - "/rest/web3/nftUnlocked"
  http_methods:
    - "POST"
    - "GET"
  input_names:
    - "privateKey"
  evidence: "server.ts:660-661; routes/checkKeys.ts:14-17,33-36"
```

## JS20-029 --- Trick the chatbot into generating a coupon code for you

``` yaml
gt_id: "JS20-029"
challenge: "Trick the chatbot into generating a coupon code for you"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/chat"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:657; routes/chat.ts"
```

## JS20-030 --- Use a deprecated B2B interface that was not properly shut down

``` yaml
gt_id: "JS20-030"
challenge: "Use a deprecated B2B interface that was not properly shut down"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/file-upload"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:328; routes/fileUpload.ts"
```

## JS20-031 --- View another user's shopping basket

``` yaml
gt_id: "JS20-031"
challenge: "View another user's shopping basket"
difficulty: 2
paths_observed:
  - "/#/basket"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-032 --- Access the misplaced Infrastructure as Code files

``` yaml
gt_id: "JS20-032"
challenge: "Access the misplaced Infrastructure as Code files"
difficulty: 2
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/infrastructure/Dockerfile"
    - "/infrastructure/docker-compose.yml"
  http_methods:
    - "GET"
  input_names:
    []
  evidence: "server.ts:267-283 (mounts infrastructure files); routes/verify.ts:71 (matches request URL suffix .tf, Dockerfile, docker-compose.yml)"
  review_note: "The .tf suffix is a match pattern, not a single concrete URL path."
```

## JS20-033 --- Change the href of the link within the O-Saft product description

``` yaml
gt_id: "JS20-033"
challenge: "Change the href of the link within the O-Saft product description"
difficulty: 3
paths_observed:
  - "/rest/products/search?q="
  - "/api/Products/9"
http_methods_observed:
  - "PUT"
input_names_observed:
  - "q"
  - "description"
  - "Content-Type"
```

## JS20-034 --- Change the name of a user by performing Cross-Site Request Forgery from another origin

``` yaml
gt_id: "JS20-034"
challenge: "Change the name of a user by performing Cross-Site Request Forgery from another origin"
difficulty: 3
paths_observed:
  - "/profile"
http_methods_observed:
  - "POST"
input_names_observed:
  - "username"
```

## JS20-035 --- Convince the chatbot to give you a coupon of 50% or more

``` yaml
gt_id: "JS20-035"
challenge: "Convince the chatbot to give you a coupon of 50% or more"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/chat"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:657; routes/chat.ts"
```

## JS20-036 --- Exfiltrate the entire DB schema definition via SQL Injection

``` yaml
gt_id: "JS20-036"
challenge: "Exfiltrate the entire DB schema definition via SQL Injection"
difficulty: 3
paths_observed:
  - "/rest/products/search"
http_methods_observed:
  []
input_names_observed:
  - "q"
```

## JS20-037 --- Extract the chatbot's system prompt using prompt injection

``` yaml
gt_id: "JS20-037"
challenge: "Extract the chatbot's system prompt using prompt injection"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/chat"
    - "/api/Complaints"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:657,399-401; routes/verify.ts:342-350 (solved when a stored complaint is sufficiently similar to the system prompt)"
```

## JS20-038 --- Log in with Amy's original user credentials

``` yaml
gt_id: "JS20-038"
challenge: "Log in with Amy's original user credentials"
difficulty: 3
paths_observed:
  - "/#/login"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-039 --- Log in with Bender's user account

``` yaml
gt_id: "JS20-039"
challenge: "Log in with Bender's user account"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/login"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:615; routes/login.ts"
```

## JS20-040 --- Log in with Chris' erased user account

``` yaml
gt_id: "JS20-040"
challenge: "Log in with Chris' erased user account"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/login"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:615; routes/login.ts"
```

## JS20-041 --- Log in with Jim's user account

``` yaml
gt_id: "JS20-041"
challenge: "Log in with Jim's user account"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/login"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:615; routes/login.ts"
```

## JS20-042 --- Mint the Honey Pot NFT by gathering BEEs from the bee haven

``` yaml
gt_id: "JS20-042"
challenge: "Mint the Honey Pot NFT by gathering BEEs from the bee haven"
difficulty: 3
paths_observed:
  - "/bee-haven"
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/web3/nftMintListen"
    - "/rest/web3/walletNFTVerify"
  http_methods:
    - "GET"
    - "POST"
  input_names:
    - "walletAddress"
  evidence: "server.ts:662-663; routes/nftMint.ts:12-43"
```

## JS20-043 --- Obtain a Deluxe Membership without paying for it

``` yaml
gt_id: "JS20-043"
challenge: "Obtain a Deluxe Membership without paying for it"
difficulty: 3
paths_observed:
  - "/#/payment/deluxe"
http_methods_observed:
  - "POST"
input_names_observed:
  - "paymentMode"
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/deluxe-membership"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:648; routes/deluxe.ts:22-46"
```

## JS20-044 --- Perform a persisted XSS attack bypassing a client-side security mechanism

``` yaml
gt_id: "JS20-044"
challenge: "Perform a persisted XSS attack bypassing a client-side security mechanism"
difficulty: 3
paths_observed:
  - "/api/Users"
  - "/#/administration"
http_methods_observed:
  - "POST"
input_names_observed:
  - "email"
  - "password"
  - "Content-Type"
```

## JS20-045 --- Perform a persisted XSS attack without using the frontend application at all

``` yaml
gt_id: "JS20-045"
challenge: "Perform a persisted XSS attack without using the frontend application at all"
difficulty: 3
paths_observed:
  - "/api/Products"
  - "/#/search"
http_methods_observed:
  - "POST"
input_names_observed:
  - "name"
  - "description"
  - "price"
  - "Content-Type"
  - "Authorization"
```

## JS20-046 --- Place an order that makes you rich

``` yaml
gt_id: "JS20-046"
challenge: "Place an order that makes you rich"
difficulty: 3
paths_observed:
  - "/api/BasketItems/{id}"
  - "/#/basket"
http_methods_observed:
  - "PUT"
input_names_observed:
  - "quantity"
  - "Content-Type"
  - "Authorization"
```

## JS20-047 --- Post a product review as another user or edit any user's existing review

``` yaml
gt_id: "JS20-047"
challenge: "Post a product review as another user or edit any user's existing review"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  - "PUT"
input_names_observed:
  - "author"
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/products/:id/reviews"
  http_methods:
    - "PUT"
  input_names:
    []
  evidence: "server.ts:652; routes/createProductReviews.ts"
```

## JS20-048 --- Post some feedback in another user's name

``` yaml
gt_id: "JS20-048"
challenge: "Post some feedback in another user's name"
difficulty: 3
paths_observed:
  - "/#/contact"
  - "/api/Feedbacks"
http_methods_observed:
  - "POST"
input_names_observed:
  - "userId"
  - "UserId"
```

## JS20-049 --- Prove that you actually read our privacy policy

``` yaml
gt_id: "JS20-049"
challenge: "Prove that you actually read our privacy policy"
difficulty: 3
paths_observed:
  - "/#/privacy-security/privacy-policy"
  - "/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-050 --- Put an additional product into another user's shopping basket

``` yaml
gt_id: "JS20-050"
challenge: "Put an additional product into another user's shopping basket"
difficulty: 3
paths_observed:
  - "/api/BasketItems"
http_methods_observed:
  - "POST"
input_names_observed:
  - "ProductId"
  - "BasketId"
  - "quantity"
  - "Authorization"
```

## JS20-051 --- Register as a user with administrator privileges

``` yaml
gt_id: "JS20-051"
challenge: "Register as a user with administrator privileges"
difficulty: 3
paths_observed:
  - "/api/Users"
http_methods_observed:
  - "POST"
input_names_observed:
  - "email"
  - "password"
  - "role"
  - "Content-Type"
```

## JS20-052 --- Reset Jim's password via the Forgot Password mechanism

``` yaml
gt_id: "JS20-052"
challenge: "Reset Jim's password via the Forgot Password mechanism"
difficulty: 3
paths_observed:
  - "/#/forgot-password"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-053 --- Reset the password of Bjoern's OWASP account via the Forgot Password mechanism

``` yaml
gt_id: "JS20-053"
challenge: "Reset the password of Bjoern's OWASP account via the Forgot Password mechanism"
difficulty: 3
paths_observed:
  - "/#/forgot-password"
  - "/assets/public/images/uploads/12.jpg"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-054 --- Retrieve the content of C:\Windows\system.ini or /etc/passwd from the server

``` yaml
gt_id: "JS20-054"
challenge: "Retrieve the content of C:\\Windows\\system.ini or /etc/passwd from the server"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/file-upload"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:328; routes/fileUpload.ts"
```

## JS20-055 --- Submit 10 or more customer feedbacks within 10 seconds

``` yaml
gt_id: "JS20-055"
challenge: "Submit 10 or more customer feedbacks within 10 seconds"
difficulty: 3
paths_observed:
  - "/#/contact"
  - "/rest/captcha/"
  - "/api/Feedbacks/"
http_methods_observed:
  - "GET"
  - "POST"
input_names_observed:
  - "captchaId"
  - "captcha"
  - "comment"
  - "rating"
```

## JS20-056 --- The Juice Shop is susceptible to a known vulnerability in a library for which an advisory has already been issued

``` yaml
gt_id: "JS20-056"
challenge: "The Juice Shop is susceptible to a known vulnerability in a library for which an advisory has already been issued"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/api/Feedbacks"
    - "/api/Complaints"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "routes/verify.ts:305-309 (csafHashValue searched in feedback/complaints)"
```

## JS20-057 --- Upload a file larger than 100 kB

``` yaml
gt_id: "JS20-057"
challenge: "Upload a file larger than 100 kB"
difficulty: 3
paths_observed:
  - "/file-upload"
http_methods_observed:
  - "POST"
input_names_observed:
  - "file"
```

## JS20-058 --- Upload a file that has no .pdf or .zip extension

``` yaml
gt_id: "JS20-058"
challenge: "Upload a file that has no .pdf or .zip extension"
difficulty: 3
paths_observed:
  - "/file-upload"
http_methods_observed:
  - "POST"
input_names_observed:
  - "file"
```

## JS20-059 --- Inform the shop about the use of a known vulnerable infrastructure component

``` yaml
gt_id: "JS20-059"
challenge: "Inform the shop about the use of a known vulnerable infrastructure component"
difficulty: 3
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/api/Feedbacks"
    - "/api/Complaints"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "routes/verify.ts:318-327 (mongo + 4.4.29 searched in feedback/complaints)"
```

## JS20-060 --- Access a developer's forgotten backup file

``` yaml
gt_id: "JS20-060"
challenge: "Access a developer's forgotten backup file"
difficulty: 4
paths_observed:
  - "/ftp"
  - "/ftp/package.json.bak"
  - "/ftp/package.json.bak%00.adoc"
  - "/ftp/package.json.bak%2500.adoc"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-061 --- Access a misplaced SIEM signature file

``` yaml
gt_id: "JS20-061"
challenge: "Access a misplaced SIEM signature file"
difficulty: 4
paths_observed:
  - "/ftp/suspicious_errors.yml%2500.adoc"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-062 --- Access a salesman's forgotten backup file

``` yaml
gt_id: "JS20-062"
challenge: "Access a salesman's forgotten backup file"
difficulty: 4
paths_observed:
  - "/ftp/coupons_2013.adoc.bak%2500.adoc"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-063 --- Apply some advanced cryptanalysis to find the real easter egg

``` yaml
gt_id: "JS20-063"
challenge: "Apply some advanced cryptanalysis to find the real easter egg"
difficulty: 4
paths_observed:
  - "/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-064 --- Bypass a security control with a Poison Null Byte

``` yaml
gt_id: "JS20-064"
challenge: "Bypass a security control with a Poison Null Byte"
difficulty: 4
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/ftp/:file"
  http_methods:
    - "GET"
  input_names:
    []
  evidence: "server.ts:289; routes/fileServer.ts:23-48 (poison-null-byte cutoff after .md/.pdf allowlist)"
```

## JS20-065 --- Bypass the Content Security Policy and perform an XSS attack on a legacy page

``` yaml
gt_id: "JS20-065"
challenge: "Bypass the Content Security Policy and perform an XSS attack on a legacy page"
difficulty: 4
paths_observed:
  - "/profile"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-066 --- Enforce a redirect to a page you are not supposed to redirect to

``` yaml
gt_id: "JS20-066"
challenge: "Enforce a redirect to a page you are not supposed to redirect to"
difficulty: 4
paths_observed:
  - "/redirect?to="
  - "/redirect"
http_methods_observed:
  []
input_names_observed:
  - "to"
  - "pwned"
```

## JS20-067 --- Find the hidden easter egg

``` yaml
gt_id: "JS20-067"
challenge: "Find the hidden easter egg"
difficulty: 4
paths_observed:
  - "/ftp/eastere.gg%2500.adoc"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-068 --- Gain access to any access log file of the server

``` yaml
gt_id: "JS20-068"
challenge: "Gain access to any access log file of the server"
difficulty: 4
paths_observed:
  - "/ftp"
  - "/support/logs"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-069 --- Identify an unsafe product that was removed from the shop and inform the shop which ingredients are dangerous

``` yaml
gt_id: "JS20-069"
challenge: "Identify an unsafe product that was removed from the shop and inform the shop which ingredients are dangerous"
difficulty: 4
paths_observed:
  - "/#/contact"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-070 --- Inform the shop about a high-severity vulnerability

``` yaml
gt_id: "JS20-070"
challenge: "Inform the shop about a high-severity vulnerability"
difficulty: 4
paths_observed:
  - "/#/contact"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-071 --- Inform the shop about a typosquatting trick it has been a victim of

``` yaml
gt_id: "JS20-071"
challenge: "Inform the shop about a typosquatting trick it has been a victim of"
difficulty: 4
paths_observed:
  - "/#/contact"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-072 --- Let the server sleep for some time

``` yaml
gt_id: "JS20-072"
challenge: "Let the server sleep for some time"
difficulty: 4
paths_observed:
  - "/rest/products/sleep(2000)/reviews"
  - "/rest/products/sleep(999999)/reviews"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-073 --- Log in with Bjoern's Gmail account

``` yaml
gt_id: "JS20-073"
challenge: "Log in with Bjoern's Gmail account"
difficulty: 4
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/login"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:615; routes/login.ts"
```

## JS20-074 --- Order the Christmas special offer of 2014

``` yaml
gt_id: "JS20-074"
challenge: "Order the Christmas special offer of 2014"
difficulty: 4
paths_observed:
  - "/#/search"
  - "/rest/products/search?q="
  - "/rest/products/search"
  - "/#/login"
  - "/api/BasketItems"
  - "/#/basket"
http_methods_observed:
  - "GET"
  - "POST"
input_names_observed:
  - "q"
  - "BasketId"
  - "ProductId"
  - "quantity"
  - "Content-Type"
```

## JS20-075 --- Perform a persisted XSS attack bypassing a server-side security mechanism

``` yaml
gt_id: "JS20-075"
challenge: "Perform a persisted XSS attack bypassing a server-side security mechanism"
difficulty: 4
paths_observed:
  - "/#/contact"
  - "/#/about"
  - "/#/administration"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-076 --- Perform a persisted XSS attack through an HTTP header

``` yaml
gt_id: "JS20-076"
challenge: "Perform a persisted XSS attack through an HTTP header"
difficulty: 4
paths_observed:
  - "/#/privacy-security/last-login-ip"
  - "/rest/saveLoginIp"
http_methods_observed:
  []
input_names_observed:
  - "X-Forwarded-For"
  - "True-Client-IP"
```

## JS20-077 --- Rat out a notorious character hiding in plain sight in the shop

``` yaml
gt_id: "JS20-077"
challenge: "Rat out a notorious character hiding in plain sight in the shop"
difficulty: 4
paths_observed:
  - "/#/contact"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-078 --- Reset Bender's password via the Forgot Password mechanism

``` yaml
gt_id: "JS20-078"
challenge: "Reset Bender's password via the Forgot Password mechanism"
difficulty: 4
paths_observed:
  - "/#/forgot-password"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-079 --- Reset Uvogin's password via the Forgot Password mechanism

``` yaml
gt_id: "JS20-079"
challenge: "Reset Uvogin's password via the Forgot Password mechanism"
difficulty: 4
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/security-question"
    - "/rest/user/reset-password"
  http_methods:
    - "GET"
    - "POST"
  input_names:
    []
  evidence: "server.ts:617-618; routes/resetPassword.ts"
```

## JS20-080 --- Retrieve a list of all user credentials via SQL Injection

``` yaml
gt_id: "JS20-080"
challenge: "Retrieve a list of all user credentials via SQL Injection"
difficulty: 4
paths_observed:
  - "/rest/products/search"
http_methods_observed:
  []
input_names_observed:
  - "q"
```

## JS20-081 --- Steal someone else's personal data without using Injection

``` yaml
gt_id: "JS20-081"
challenge: "Steal someone else's personal data without using Injection"
difficulty: 4
paths_observed:
  - "/#/order-completion/5267-829f123593e9d098"
  - "/#/track-result/new?id="
  - "/rest/track-order/5267-829f123593e9d098"
  - "/#/privacy-security/data-export"
http_methods_observed:
  []
input_names_observed:
  - "id"
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/user/data-export"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:639-640; routes/dataExport.ts:99-103"
```

## JS20-082 --- Successfully redeem an expired campaign coupon code

``` yaml
gt_id: "JS20-082"
challenge: "Successfully redeem an expired campaign coupon code"
difficulty: 4
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/basket/:id/coupon/:coupon"
    - "/rest/basket/:id/checkout"
  http_methods:
    - "PUT"
    - "POST"
  input_names:
    []
  evidence: "server.ts:624,623; routes/order.ts:186-194 (evaluated in placeOrder)"
```

## JS20-083 --- Log in with the cloud admin's user account

``` yaml
gt_id: "JS20-083"
challenge: "Log in with the cloud admin's user account"
difficulty: 4
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    []
  http_methods:
    []
  input_names:
    - "Authorization"
  evidence: "server.ts:372 app.use(verify.jwtChallenges()); routes/verify.ts:85-86 (RS256, email matching cloud-admin@)"
  review_note: "The global JWT middleware does not define one challenge-specific URL path."
```

## JS20-084 --- Learn about the Token Sale before its official announcement

``` yaml
gt_id: "JS20-084"
challenge: "Learn about the Token Sale before its official announcement"
difficulty: 5
paths_observed:
  - "/#/tokensale-ico-ea"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-085 --- Update multiple product reviews at the same time

``` yaml
gt_id: "JS20-085"
challenge: "Update multiple product reviews at the same time"
difficulty: 5
paths_observed:
  - "/rest/products/reviews"
http_methods_observed:
  - "PATCH"
input_names_observed:
  - "id"
  - "message"
  - "Content-Type"
  - "Authorization"
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  review_note: "difficulty in data/static/challenges.yml is 4 (NoSQL Manipulation); this dataset records 5 (guide star section)."
```

## JS20-086 --- All your orders are belong to us

``` yaml
gt_id: "JS20-086"
challenge: "All your orders are belong to us"
difficulty: 5
paths_observed:
  - "/#/order-history"
  - "/rest/track-order/"
  - "/rest/track-order/x"
  - "/rest/track-order/'"
  - "/rest/track-order/''"
  - "/rest/track-order/'%20%7C%7C%20true%20%7C%7C%20'"
http_methods_observed:
  - "GET"
input_names_observed:
  []
```

## JS20-087 --- Change Bender's password into slurmCl4ssic without using SQL Injection or Forgot Password

``` yaml
gt_id: "JS20-087"
challenge: "Change Bender's password into slurmCl4ssic without using SQL Injection or Forgot Password"
difficulty: 5
paths_observed:
  - "/rest/user/change-password"
http_methods_observed:
  - "GET"
input_names_observed:
  - "current"
  - "new"
  - "repeat"
  - "Authorization"
```

## JS20-088 --- Deprive the shop of earnings by downloading the blueprint for one of its products

``` yaml
gt_id: "JS20-088"
challenge: "Deprive the shop of earnings by downloading the blueprint for one of its products"
difficulty: 5
paths_observed:
  - "/public/images/products/3d_keychain.jpg"
  - "/assets/public/images/products/JuiceShop.stl"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-089 --- Drop some explosive data into a vulnerable file-handling endpoint

``` yaml
gt_id: "JS20-089"
challenge: "Drop some explosive data into a vulnerable file-handling endpoint"
difficulty: 5
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/file-upload"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:328; routes/fileUpload.ts"
```

## JS20-090 --- Dumpster dive the Internet for a leaked password and log in to the original user account it belongs to

``` yaml
gt_id: "JS20-090"
challenge: "Dumpster dive the Internet for a leaked password and log in to the original user account it belongs to"
difficulty: 5
paths_observed:
  - "/#/login"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-091 --- Forge an essentially unsigned JWT token

``` yaml
gt_id: "JS20-091"
challenge: "Forge an essentially unsigned JWT token"
difficulty: 5
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "email"
  - "alg"
  - "Authorization"
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    []
  http_methods:
    []
  input_names:
    []
  evidence: "server.ts:372 app.use(verify.jwtChallenges()); routes/verify.ts:79-80 (alg none, email matching jwtn3d@)"
  review_note: "The global JWT middleware does not define one challenge-specific URL path."
```

## JS20-092 --- Gain read access to an arbitrary local file on the web server

``` yaml
gt_id: "JS20-092"
challenge: "Gain read access to an arbitrary local file on the web server"
difficulty: 5
paths_observed:
  []
http_methods_observed:
  - "POST"
input_names_observed:
  - "email"
  - "securityAnswer"
  - "layout"
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/dataerasure"
  http_methods:
    - "POST"
  input_names:
    - "layout"
  evidence: "server.ts:675; routes/dataErasure.ts:69,95-106"
```

## JS20-093 --- Give the server something to chew on for quite a while

``` yaml
gt_id: "JS20-093"
challenge: "Give the server something to chew on for quite a while"
difficulty: 5
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/file-upload"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:328; routes/fileUpload.ts"
```

## JS20-094 --- Inform the development team about a danger to some of their credentials

``` yaml
gt_id: "JS20-094"
challenge: "Inform the development team about a danger to some of their credentials"
difficulty: 5
paths_observed:
  - "/#/contact"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-095 --- Inform the shop about a leaked API key

``` yaml
gt_id: "JS20-095"
challenge: "Inform the shop about a leaked API key"
difficulty: 5
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/api/Feedbacks"
    - "/api/Complaints"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "routes/verify.ts:312-316 (API key searched in feedback/complaints)"
```

## JS20-096 --- Inform the shop about a typosquatting imposter that dug itself deep into the frontend

``` yaml
gt_id: "JS20-096"
challenge: "Inform the shop about a typosquatting imposter that dug itself deep into the frontend"
difficulty: 5
paths_observed:
  - "/3rdpartylicenses.txt"
  - "/#/contact"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-097 --- Log in with the (non-existing) accountant without ever registering that user

``` yaml
gt_id: "JS20-097"
challenge: "Log in with the (non-existing) accountant without ever registering that user"
difficulty: 5
paths_observed:
  - "/#/login"
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  review_note: "difficulty in data/static/challenges.yml is 4 (Ephemeral Accountant); this dataset records 5 (guide star section)."
```

## JS20-098 --- Perform a Remote Code Execution that would keep a less hardened application busy forever

``` yaml
gt_id: "JS20-098"
challenge: "Perform a Remote Code Execution that would keep a less hardened application busy forever"
difficulty: 5
paths_observed:
  - "/api-docs"
  - "/api-docs/#/Order/post_orders"
http_methods_observed:
  - "POST"
input_names_observed:
  - "orderLinesData"
  - "Authorization"
```

## JS20-099 --- Perform an unwanted information disclosure by accessing data cross-domain

``` yaml
gt_id: "JS20-099"
challenge: "Perform an unwanted information disclosure by accessing data cross-domain"
difficulty: 5
paths_observed:
  - "/rest/user/whoami"
http_methods_observed:
  []
input_names_observed:
  - "Authorization"
  - "callback"
```

## JS20-100 --- Reset Morty's password via the Forgot Password mechanism

``` yaml
gt_id: "JS20-100"
challenge: "Reset Morty's password via the Forgot Password mechanism"
difficulty: 5
paths_observed:
  - "/#/forgot-password"
  - "/rest/user/reset-password"
http_methods_observed:
  []
input_names_observed:
  - "X-Forwarded-For"
```

## JS20-101 --- Reset the password of Bjoern's internal account via the Forgot Password mechanism

``` yaml
gt_id: "JS20-101"
challenge: "Reset the password of Bjoern's internal account via the Forgot Password mechanism"
difficulty: 5
paths_observed:
  - "/#/forgot-password"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-102 --- Retrieve the language file that never made it into production

``` yaml
gt_id: "JS20-102"
challenge: "Retrieve the language file that never made it into production"
difficulty: 5
paths_observed:
  - "/i18n/en.json"
  - "/i18n/de_DE.json"
  - "/i18n/nl_NL.json"
  - "/i18n/zh_CN.json"
  - "/i18n/zh_HK.json"
  - "/i18n/tlh_AA.json"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-103 --- Solve the 2FA challenge for user "wurstbrot"

``` yaml
gt_id: "JS20-103"
challenge: "Solve the 2FA challenge for user \"wurstbrot\""
difficulty: 5
paths_observed:
  - "/rest/products/search?q="
http_methods_observed:
  []
input_names_observed:
  - "q"
```

## JS20-104 --- Stick cute cross-domain kittens all over our delivery boxes

``` yaml
gt_id: "JS20-104"
challenge: "Stick cute cross-domain kittens all over our delivery boxes"
difficulty: 5
paths_observed:
  - "/#/deluxe-membership"
  - "/#/deluxe-membership?testDecal="
  - "/test"
  - "/redirect"
http_methods_observed:
  []
input_names_observed:
  - "testDecal"
```

## JS20-105 --- Embed an XSS payload into our promo video

``` yaml
gt_id: "JS20-105"
challenge: "Embed an XSS payload into our promo video"
difficulty: 6
paths_observed:
  - "/promotion"
  - "/video"
  - "/assets/public/videos/owasp_promo.mp4"
  - "/assets/public/videos"
  - "/assets/public/videos/owasp_promo.vtt"
  - "/#/complain"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-106 --- Forge a coupon code that gives you a discount of at least 80%

``` yaml
gt_id: "JS20-106"
challenge: "Forge a coupon code that gives you a discount of at least 80%"
difficulty: 6
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/basket/:id/coupon/:coupon"
    - "/rest/basket/:id/checkout"
  http_methods:
    - "PUT"
    - "POST"
  input_names:
    []
  evidence: "server.ts:624,623; routes/order.ts:182-185 (evaluated in placeOrder)"
```

## JS20-107 --- Forge an almost properly RSA-signed JWT token

``` yaml
gt_id: "JS20-107"
challenge: "Forge an almost properly RSA-signed JWT token"
difficulty: 6
paths_observed:
  - "/encryptionkeys"
  - "/encryptionkeys/jwt.pub"
http_methods_observed:
  []
input_names_observed:
  - "email"
  - "alg"
  - "Authorization"
```

## JS20-108 --- Infect the server with juicy malware by abusing arbitrary command execution

``` yaml
gt_id: "JS20-108"
challenge: "Infect the server with juicy malware by abusing arbitrary command execution"
difficulty: 6
paths_observed:
  - "/ftp/quarantine"
  - "/profile"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-109 --- Like any review at least three times as the same user

``` yaml
gt_id: "JS20-109"
challenge: "Like any review at least three times as the same user"
difficulty: 6
paths_observed:
  - "/rest/products/reviews"
http_methods_observed:
  - "POST"
input_names_observed:
  - "id"
  - "Authorization"
```

## JS20-110 --- Log in with the support team's original user credentials

``` yaml
gt_id: "JS20-110"
challenge: "Log in with the support team's original user credentials"
difficulty: 6
paths_observed:
  - "/ftp/incident-support.kdbx"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-111 --- Overwrite the Legal Information file

``` yaml
gt_id: "JS20-111"
challenge: "Overwrite the Legal Information file"
difficulty: 6
paths_observed:
  - "/ftp/legal.md"
  - "/#/login"
  - "/#/complain"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-112 --- Perform a Remote Code Execution that occupies the server for a while without using infinite loops

``` yaml
gt_id: "JS20-112"
challenge: "Perform a Remote Code Execution that occupies the server for a while without using infinite loops"
difficulty: 6
paths_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "orderLinesData"
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/b2b/v2/orders"
  http_methods:
    - "POST"
  input_names:
    []
  evidence: "server.ts:667; routes/b2bOrder.ts"
```

## JS20-113 --- Request a hidden resource on server through server

``` yaml
gt_id: "JS20-113"
challenge: "Request a hidden resource on server through server"
difficulty: 6
paths_observed:
  - "/profile"
  - "/profile/image/url"
  - "/solve/challenges/server-side?key="
http_methods_observed:
  []
input_names_observed:
  - "imageUrl"
  - "key"
```

## JS20-114 --- Solve challenge #999

``` yaml
gt_id: "JS20-114"
challenge: "Solve challenge #999"
difficulty: 6
paths_observed:
  - "/rest/continue-code/apply/69OxrZ8aJEgxONZyWoz1Dw4BvXmRGkM6Ae9M7k2rK63YpqQLPjnlb5V5LvDj"
http_methods_observed:
  - "PUT"
input_names_observed:
  []
```

## JS20-115 --- Unlock Premium Challenge to access exclusive content

``` yaml
gt_id: "JS20-115"
challenge: "Unlock Premium Challenge to access exclusive content"
difficulty: 6
paths_observed:
  - "/encryptionkeys"
  - "/encryptionkeys/premium.key"
  - "/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us"
http_methods_observed:
  []
input_names_observed:
  []
```

## JS20-116 --- Withdraw more ETH from the new wallet than you deposited

``` yaml
gt_id: "JS20-116"
challenge: "Withdraw more ETH from the new wallet than you deposited"
difficulty: 6
paths_observed:
  - "/wallet"
http_methods_observed:
  []
input_names_observed:
  []
code_derived:
  source: "juice-shop v20.2.0 source (tag v20.2.0, 5658473); not from the official guide"
  paths:
    - "/rest/web3/walletExploitAddress"
  http_methods:
    - "POST"
  input_names:
    - "walletAddress"
  evidence: "server.ts:664; routes/web3Wallet.ts:12-29 contractExploitListener"
```

## Provenance policy

This file intentionally does not classify or reinterpret the challenges.
Any later benchmark-specific schema should be stored separately from
this official-only layer so that OWASP-provided facts and
project-specific normalization cannot be confused.
