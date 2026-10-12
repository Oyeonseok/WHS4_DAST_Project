# VulnBank Legacy --- Official Writeup Ground Truth (v3)

> **Source rule:** This dataset is normalized only from the supplied
> legacy writeup identified by the user as the original writeup linked
> from the official GitHub project.
>
> **No model-inferred vulnerability taxonomy is added.** No CWE, custom
> vulnerability family, severity, DAST-scope decision, inferred HTTP
> method, inferred authentication requirement, or model-written success
> oracle is included.
>
> A section marked `confirmed_in_writeup` means the supplied writeup
> itself describes a successful exploitation/observed weakness.
> `not_confirmed` means the author explicitly says the attempted issue
> was not found or could not be demonstrated. `documented_reference`
> means the section discusses a category/reference and points to related
> exploitation elsewhere rather than establishing a clean standalone
> finding in that section.
>
> `gt_id` is a local indexing identifier only; it is not claimed to be
> an official VulnBank identifier.

## Extraction scope (what `endpoints_observed` / `input_names_observed` mean)

Each list holds **only the technical values that the section's own
exploitation path acts on** — the application endpoint actually
attacked and the parameter/field the attacker supplies or manipulates.

Deliberately **excluded**, even when the string appears in the section:

-   **Tooling / environment strings** — a shell prompt's working
    directory (e.g. `~/Desktop` from an `sqlmap` command line), a tool
    download link, or an APK release URL. These are not app endpoints.
-   **URL-parse artifacts** — a leftover `//host:port/...` fragment that
    duplicates a clean `/path` already listed.
-   **Evidence / narration tokens** — a word occurring only in a results
    sentence (e.g. "same reference and timestamp") or in prose
    describing the category, not a field the attacker sends.
-   **Illustrative field lists** — fields the author *names as testable
    examples* (e.g. `header_type`, `header_algorithm`) without actually
    manipulating them in that section.

Conversely, a parameter the section's exploit clearly relies on is
**included even if the author does not format it as a request field**
(e.g. the `is_admin` mass-assignment property driving the registration
privilege-escalation).

> **v3 changelog (relative to v2):** strict re-application of the scope
> rule to two records whose values were still illustrative/referential,
> not manipulated by that section's own exploit:
> - VB-L-21 (TOKEN MANIPULATION) — removed `username`, `user_id`,
>   `is_admin`, `timestamp`. The writeup lists them in one "For
>   example … e.g., …" sentence as payload fields that *can* be
>   manipulated, the same sentence that names `header_type` /
>   `header_algorithm` (already removed in v2); the section's only
>   confirmed finding is the missing token-expiry. Same rule, same
>   verdict for all six — `input_names_observed` is now empty.
> - VB-L-10 (BOPLA) — removed `user_id`, `card_id`. This section is
>   `documented_reference`: it says excessive-data-exposure was "found
>   none", names `user_id` only as the kind of field to look for, and
>   defers `card_id` to be "exploited below" (points to #11 and the
>   card sections). Neither is an input this section's own exploit
>   acts on. The actual card_id / is_admin / balance manipulations
>   remain recorded on the sections that perform them (VB-L-11, -15,
>   -22, -27, -28, -29).
>
> **v2 changelog (relative to v1):**
> - **Removed tooling/environment contamination:** `/Desktop` from
>   VB-L-01 (it is the `sqlmap -r` shell prompt's `~/Desktop` working
>   directory, not an app endpoint); the two GitHub download links from
>   VB-L-37 (jadx tool + apk release, not attacked endpoints).
> - **Removed URL-parse duplicate:** `//127.0.0.1:5000/static/uploads/610046_etc_passwd`
>   from VB-L-19, keeping the clean `/static/uploads/610046_etc_passwd`.
> - **Removed narration/illustrative tokens from `input_names_observed`:**
>   `password` from VB-L-02, VB-L-04, VB-L-36; `password`/`balance`/`timestamp`
>   from VB-L-13 (all from results/description prose, not sent fields);
>   `header_type`/`header_algorithm` from VB-L-21 (named only as testable
>   examples); `username`/`password` from VB-L-37 (hardcoded-hint prose in
>   a SAST section, not request inputs).
> - **Added genuine exploit parameters that were missing:** `is_admin` +
>   `user_id` to VB-L-03 (authorization bypass / impersonation), `is_admin`
>   to VB-L-11 (the mass-assignment property that performs the privilege
>   escalation).
> - Section inventory, titles, numbering, and `writeup_status` values are
>   unchanged from v1 (38 sections; 34 confirmed / 1 documented_reference
>   / 3 not_confirmed).

## Source overview

The writeup describes VulnBank as a deliberately vulnerable Web
Application, API, and Mobile Application for pentesters, bug bounty
hunters, and security researchers, and says it contains about 40
noticeable vulnerabilities.

## Normalized records

## VB-L-01 --- SQL Injection on Login

``` yaml
gt_id: "VB-L-01"
writeup_number: 1
title: "SQL Injection on Login"
source_line: 62
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "username"
  - "password"
writeup_evidence:
  []
```

## VB-L-02 --- Weak Password Reset (brute-force 3-digit PIN)

``` yaml
gt_id: "VB-L-02"
writeup_number: 2
title: "Weak Password Reset (brute-force 3-digit PIN)"
source_line: 94
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "username"
writeup_evidence:
  - source_line: 97
    observation: "And a good spot to find rate-limiting is in brute-forcing OTPs and performing username enumeration."
  - source_line: 101
    observation: "On your browser, go to the reset password and place in the username of the user you want to reset. An OTP get sent to the user (3-digits). Turn on burpsuite proxy, then place in a random 3-digit pin, so that burpsuite can capture the request. Now it’s time to brute-force."
  - source_line: 105
    observation: "Intruder bruteforcing the OTP."
  - source_line: 106
    observation: "We have successfully exploited the weak password reset by brute-forcing. On to the next"
```

## VB-L-03 --- JWT Token Manipulation

``` yaml
gt_id: "VB-L-03"
writeup_number: 3
title: "JWT Token Manipulation"
source_line: 108
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "is_admin"
  - "user_id"
writeup_evidence:
  - source_line: 143
    observation: "Admin Page access with modified token"
```

## VB-L-04 --- USERNAME ENUMERATION

``` yaml
gt_id: "VB-L-04"
writeup_number: 4
title: "USERNAME ENUMERATION"
source_line: 144
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "username"
writeup_evidence:
  - source_line: 161
    observation: "Bingo, we found the admin user, and an OTP has been sent for password reset. Using the above password reset vulnerability, we can take over the admin account."
```

## VB-L-05 --- TOKEN STORAGE VULNERABILITIES

``` yaml
gt_id: "VB-L-05"
writeup_number: 5
title: "TOKEN STORAGE VULNERABILITIES"
source_line: 163
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 170
    observation: "Weak token storage"
```

## VB-L-06 --- ACCESS OTHER USERS' TRANSACTION HISTORY VIA ACCOUNT NUMBER

``` yaml
gt_id: "VB-L-06"
writeup_number: 6
title: "ACCESS OTHER USERS’ TRANSACTION HISTORY VIA ACCOUNT NUMBER"
source_line: 173
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  - "/transactions/:account-number"
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 189
    observation: "We have a 200 OK we found our vulnerability. moving on."
```

## VB-L-07 --- UPLOAD MALICIOUS FILES

``` yaml
gt_id: "VB-L-07"
writeup_number: 7
title: "UPLOAD MALICIOUS FILES"
source_line: 191
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 199
    observation: "And from the third screenshot, we can see a successful upload, whereby the application doesn’t filter file-type upload. This is a medium — high vulnerability depending on the case."
```

## VB-L-08 --- ACCESS ADMIN PANEL

``` yaml
gt_id: "VB-L-08"
writeup_number: 8
title: "ACCESS ADMIN PANEL"
source_line: 201
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  - "/sup3r_s3cr3t_admin"
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 204
    observation: "I exploited a weak token management vulnerability."
  - source_line: 205
    observation: "By exploiting it, I got access as an admin user and I found the /sup3r_s3cr3t_admin directory."
```

## VB-L-09 --- MANIPULATE JWT CLAIMS

``` yaml
gt_id: "VB-L-09"
writeup_number: 9
title: "MANIPULATE JWT CLAIMS"
source_line: 218
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "user_id"
  - "is_admin"
writeup_evidence:
  []
```

## VB-L-10 --- EXPLOITING BOPLA (EXCESSIVE DATA EXPOSURE AND MASS ASSIGNMENT)

``` yaml
gt_id: "VB-L-10"
writeup_number: 10
title: "EXPLOITING BOPLA (EXCESSIVE DATA EXPOSURE AND MASS ASSIGNMENT)"
source_line: 235
writeup_status: "documented_reference"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-11 --- PRIVILEGE ESCALATION THROUGH REGISTRATION

``` yaml
gt_id: "VB-L-11"
writeup_number: 11
title: "PRIVILEGE ESCALATION THROUGH REGISTRATION"
source_line: 248
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "username"
  - "password"
  - "is_admin"
writeup_evidence:
  []
```

## VB-L-12 --- ATTEMPT NEGATIVE AMOUNT TRANSFERS

``` yaml
gt_id: "VB-L-12"
writeup_number: 12
title: "ATTEMPT NEGATIVE AMOUNT TRANSFERS"
source_line: 264
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-13 --- RACE CONDITIONS IN TRANSFER

``` yaml
gt_id: "VB-L-13"
writeup_number: 13
title: "RACE CONDITIONS IN TRANSFER"
source_line: 274
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 306
    observation: "Multiple transaction had same reference and timestamp (proved race condition)"
  - source_line: 307
    observation: "Race condition exploited successfully."
```

## VB-L-14 --- TRANSACTION HISTORY ACCESS

``` yaml
gt_id: "VB-L-14"
writeup_number: 14
title: "TRANSACTION HISTORY ACCESS"
source_line: 309
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 317
    observation: "Note: even being unauthenticated, the vulnerability still persists… so it is a HIGH vulnerability!!!"
```

## VB-L-15 --- BALANCE MANIPULATION

``` yaml
gt_id: "VB-L-15"
writeup_number: 15
title: "BALANCE MANIPULATION"
source_line: 321
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  - "/register"
http_methods_observed:
  []
input_names_observed:
  - "is_admin"
  - "balance"
writeup_evidence:
  - source_line: 328
    observation: "Adding the balance json body to the API and we can see that it manipulated the users balance, and we have more than enough."
```

## VB-L-16 --- UPLOAD UNAUTHORIZED FILE TYPES

``` yaml
gt_id: "VB-L-16"
writeup_number: 16
title: "UPLOAD UNAUTHORIZED FILE TYPES"
source_line: 335
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 342
    observation: "We have successfully exploited the unauthorized file type upload."
```

## VB-L-17 --- ATTEMPT PATH TRAVERSAL

``` yaml
gt_id: "VB-L-17"
writeup_number: 17
title: "ATTEMPT PATH TRAVERSAL"
source_line: 344
writeup_status: "not_confirmed"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 352
    observation: "The only endpoint found that referenced a file in server, yet I tried different Path Traversal technique. Couldn’t pull this one off, or maybe it doesn’t exist."
```

## VB-L-18 --- UPLOAD OVERSIZED FILES

``` yaml
gt_id: "VB-L-18"
writeup_number: 18
title: "UPLOAD OVERSIZED FILES"
source_line: 354
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-19 --- TEST FILE OVERWRITE SCENARIOS

``` yaml
gt_id: "VB-L-19"
writeup_number: 19
title: "TEST FILE OVERWRITE SCENARIOS"
source_line: 360
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  - "/static/uploads/610046_etc_passwd"
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-20 --- FILE TYPE BYPASS

``` yaml
gt_id: "VB-L-20"
writeup_number: 20
title: "FILE TYPE BYPASS"
source_line: 372
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-21 --- TOKEN MANIPULATION

``` yaml
gt_id: "VB-L-21"
writeup_number: 21
title: "TOKEN MANIPULATION"
source_line: 383
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 395
    observation: "Another vulnerability found on the lab, is that the token lacks expiry time, and that’s a vulnerability in itself."
```

## VB-L-22 --- BOLA/BOPLA in API endpoints

``` yaml
gt_id: "VB-L-22"
writeup_number: 22
title: "BOLA/BOPLA in API endpoints"
source_line: 400
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "is_admin"
  - "balance"
  - "card_id"
  - "current_balance"
writeup_evidence:
  - source_line: 421
    observation: "Unauthorized access of a users’ card transaction history leading to a BOLA attack."
```

## VB-L-23 --- INFORMATION DISCLOSURE

``` yaml
gt_id: "VB-L-23"
writeup_number: 23
title: "INFORMATION DISCLOSURE"
source_line: 423
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-24 --- ERROR MESSAGE ANALYSIS

``` yaml
gt_id: "VB-L-24"
writeup_number: 24
title: "ERROR MESSAGE ANALYSIS"
source_line: 431
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "username"
writeup_evidence:
  []
```

## VB-L-25 --- EXPLOIT MASS ASSIGNMENT IN CARD LIMIT UPDATES

``` yaml
gt_id: "VB-L-25"
writeup_number: 25
title: "EXPLOIT MASS ASSIGNMENT IN CARD LIMIT UPDATES"
source_line: 434
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "balance"
writeup_evidence:
  []
```

## VB-L-26 --- ANALYZE CARD NUMBER GENERATION PATTERNS

``` yaml
gt_id: "VB-L-26"
writeup_number: 26
title: "ANALYZE CARD NUMBER GENERATION PATTERNS"
source_line: 448
writeup_status: "not_confirmed"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 451
    observation: "I’ve analyzed it and there’s nothing I can do here."
```

## VB-L-27 --- ACCESS UNAUTHORIZED CARD DETAILS

``` yaml
gt_id: "VB-L-27"
writeup_number: 27
title: "ACCESS UNAUTHORIZED CARD DETAILS"
source_line: 454
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  - "/update-limit"
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 465
    observation: "leading to unauthorized access to user card details."
```

## VB-L-28 --- TEST CARD FREEZING BYPASSES

``` yaml
gt_id: "VB-L-28"
writeup_number: 28
title: "TEST CARD FREEZING BYPASSES"
source_line: 467
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "card_id"
writeup_evidence:
  - source_line: 476
    observation: "Bingo, we successfully froze a users’ card. I can’t really call it a freezing bypass; it is more of an authorization bypass on card freeze."
```

## VB-L-29 --- TRANSACTION HISTORY MANUPULATION

``` yaml
gt_id: "VB-L-29"
writeup_number: 29
title: "TRANSACTION HISTORY MANUPULATION"
source_line: 478
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "card_id"
writeup_evidence:
  - source_line: 485
    observation: "But if we take a look at other card history, we get a success message. Which tells us that the request was successful."
```

## VB-L-30 --- CARD LIMIT VALIDATION BYPASS

``` yaml
gt_id: "VB-L-30"
writeup_number: 30
title: "CARD LIMIT VALIDATION BYPASS"
source_line: 487
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  - "balance"
  - "current_balance"
writeup_evidence:
  - source_line: 499
    observation: "The request got accepted and the card limit is set, and the balance got accepted."
```

## VB-L-31 --- TEST BILLER ENUMERATION

``` yaml
gt_id: "VB-L-31"
writeup_number: 31
title: "TEST BILLER ENUMERATION"
source_line: 504
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  - "/api/billers/by-categories/:category_id"
http_methods_observed:
  []
input_names_observed:
  - "category_id"
writeup_evidence:
  []
```

## VB-L-32 --- PAYMENT AMOUNT VALIDATION BYPASS

``` yaml
gt_id: "VB-L-32"
writeup_number: 32
title: "PAYMENT AMOUNT VALIDATION BYPASS"
source_line: 517
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 524
    observation: "No error given, we have been able to exploit this. Paying $1,000,000 into the bill is also accepted, leading to a High Vulnerability."
```

## VB-L-33 --- ACCESS UNAUTHORIZED PAYMENT HISTORY

``` yaml
gt_id: "VB-L-33"
writeup_number: 33
title: "ACCESS UNAUTHORIZED PAYMENT HISTORY"
source_line: 526
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 537
    observation: "Now after JWT token manipulation, and refresh the payment history, we get another users’ history."
```

## VB-L-34 --- SQL INJECTION IN BILLER SELECTION

``` yaml
gt_id: "VB-L-34"
writeup_number: 34
title: "SQL INJECTION IN BILLER SELECTION"
source_line: 541
writeup_status: "not_confirmed"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  - source_line: 542
    observation: "No SQL injection found in the Biller Selection."
```

## VB-L-35 --- REFERENCE NUMBER PREDICTION

``` yaml
gt_id: "VB-L-35"
writeup_number: 35
title: "REFERENCE NUMBER PREDICTION"
source_line: 544
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-36 --- RACE CONDITION EXPLOITATION IN PAYMENTS

``` yaml
gt_id: "VB-L-36"
writeup_number: 36
title: "RACE CONDITION EXPLOITATION IN PAYMENTS"
source_line: 555
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-37 --- APK Hardcoded Flag

``` yaml
gt_id: "VB-L-37"
writeup_number: 37
title: "APK Hardcoded Flag"
source_line: 569
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## VB-L-38 --- SECRET ENDPOINT DETECTION

``` yaml
gt_id: "VB-L-38"
writeup_number: 38
title: "SECRET ENDPOINT DETECTION"
source_line: 578
writeup_status: "confirmed_in_writeup"
endpoints_observed:
  []
http_methods_observed:
  []
input_names_observed:
  []
writeup_evidence:
  []
```

## Inventory summary

-   Numbered writeup sections normalized: **38**
-   `confirmed_in_writeup`: **34**
-   `documented_reference`: **1**
-   `not_confirmed`: **3**

## Provenance policy

This is an **official-writeup layer**, not a benchmark interpretation
layer. If later evaluation needs DAST applicability, TP/FP matching
rules, CWE mapping, or success oracles, keep those in a separate
benchmark configuration so they cannot be mistaken for facts stated by
the VulnBank writeup.

The pinned-source comparison of all 38 sections is recorded separately in
[VulnBank legacy writeup code comparison](vulnbank-legacy-code-comparison.md).
Its code findings do not change the writeup-only statuses above.
