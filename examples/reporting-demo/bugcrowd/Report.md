# [SYNTHETIC EXAMPLE] Cross-account invoice disclosure through a missing ownership check

> SYNTHETIC EXAMPLE / OFFLINE FIXTURE. No real target was tested; not a real program submission.

## Description

Offline synthetic example: Account B ([EMAIL_2]) can read invoice inv_demo_A_001 belonging to Account A ([EMAIL_1]) by changing the invoice identifier. A nonexistent identifier returns 404. All statuses and invoice attributes are generated fixture data.

## Target

https://api.reports-demo.invalid

## VRT category

Broken Access Control > IDOR (illustrative category; verify the program's current VRT)

## Technical severity

Medium (illustrative sample; program-specific assessment required)

## Prerequisites

Two synthetic accounts with separate sessions: Account A owns the invoice; Account B does not.
Known fixture invoice inv_demo_A_001. No enumeration or live requests are needed for this example.

## Steps to reproduce

1. In the fixture, simulate GET https://api.reports-demo.invalid/api/invoices/inv_demo_A_001 as Account A using Authorization: [TOKEN_3]
2. Change only the session to Account B: Authorization: [TOKEN_5]
3. Compare the fixture attributes: both observations contain inv_demo_A_001, owner [EMAIL_1], amount 1200 USD, and one record.
4. As Account B, simulate a request for inv_demo_missing_999. The control returns HTTP 404 without invoice attributes.

## Expected behavior

A non-owner should receive 403 or a uniform 404 without another account's invoice attributes.

## Actual behavior

The cross-account fixture observation returns 200 with the owner account's invoice metadata, while the nonexistent-record control returns 404.

## Demonstrated impact

Illustrated confidentiality impact: a user with one known invoice identifier can read another test account's owner identity and invoice amount. The example establishes only a simulated single-record read; bulk extraction, write access and live-system impact are not demonstrated.

## Remediation

Resolve the invoice through the authenticated principal's permitted records, enforce ownership on the server, and add owner/non-owner/nonexistent-record authorization regression checks.

## Evidence metadata

Text metadata only; raw HTTP bodies, images and videos are not included.

- Evidence/evidence-001.json (requested attachment; metadata only)
- Evidence/evidence-002.json (requested attachment; metadata only)
- Evidence/evidence-003.json (requested attachment; metadata only)
