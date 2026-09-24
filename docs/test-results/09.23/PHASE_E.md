# Phase E — finding 판정 및 Report (2026-09-23 시작, 09-24 KST 계속)

## Juice Shop 증거 대조

Phase D scan `scan_b96c39ed94034315b911ed9f75287fd5`의 finding 3건과 Validation case 3건을 대조했다.

| finding | Validation | 수동 대조 |
| --- | --- | --- |
| `GET /rest/products/search`의 공개 `q` SQL Injection | `CONFIRMED` | **TP (증거 기준)**: 정상 검색 대조군 HTTP 200/921B, 음성 대조군 200/30B, 대상 요청 3회 각각 200/21,581B. 삭제 표시 레코드 assertion은 음성 대조군에서 실패, 대상 요청 3회에서 성공했다. |
| 인증 우회 SQL Injection | `INCONCLUSIVE` | **UNRESOLVED**: Validation 사전 적격성 평가 출력의 schema/근거 검증이 실패해 `UNKNOWN`으로 보류됐다. 음성 판정으로 세지 않는다. |
| 비인증 설정 정보 노출 | `INCONCLUSIVE` | **UNRESOLVED**: 동일한 사전 적격성 평가 실패로 재현 단계가 진행되지 않았다. 음성 판정으로 세지 않는다. |

`CONFIRMED` case는 Attack finding 및 reproduction spec 1건과 연결되고, source attempt/request ID가 기록돼 있다. 해당 case에는 validation attempt 5건, evidence 7건이 연결돼 있으며 Pipeline DB의 foreign key 검사 위반은 0건이다. 입증된 영향은 공개 검색 결과에서 삭제 표시 레코드가 노출되는 범위다. 더 민감한 데이터 접근이나 인증 우회까지 확장해 판정하지 않는다.

동일한 Juice Shop image digest의 선행 [Phase E 판정](../main-branch/phase_e/1_VULNBANK_JUICESHOP_PHASE_E.md)에는 `GET /rest/products/search`의 `q` SQL Injection이 대표 ground truth로 이미 기록돼 있다. 따라서 위 TP는 선행 ground truth와 이번 독립 Validation 증거가 모두 일치한 판정이다. 다만 version별 전체 `ELIGIBLE` 목록은 실행 전에 완전히 동결되지 않았으므로 전체 후보군의 FN, recall, F1은 **NOT_MEASURED**로 유지한다. 판정 가능한 finding만의 precision도 표본이 1건이라 전체 제품 수치로 일반화하지 않는다. `INCONCLUSIVE` 두 건을 FP나 FN으로 바꾸지 않는다.

## VulnBank 증거 대조

인증 dashboard scan `scan_489efa6c771844e3b0790e85006a4d08`에는 finding이 없었다. 공개 루트 scan `scan_843d0e9fd97548cbac8e66a016d5097f`에는 finding 3건이 생성됐지만 Validation replay는 **0건**이며 세 case 모두 `INCONCLUSIVE`다.

| finding | 사전 gate 결과 | 수동 대조 |
| --- | --- | --- |
| 인증 프로필 사진 URL import SSRF | `candidate_integrity / endpoint_method` | **UNRESOLVED**: `POST /upload_profile_picture_url` 재현 spec이 `GET /` endpoint ID에 연결됐다. 내부 응답 수집 주장은 독립 Validation으로 확인되지 않았다. |
| 비밀번호 재설정 PIN 노출 | `candidate_integrity / endpoint_method` | **UNRESOLVED**: `POST /api/v1/forgot-password` 재현 spec이 `GET /api/v3/forgot-password` endpoint ID에 연결됐다. Attack ledger의 해당 POST 1건은 `RequestGuardError`로 실패했다. PIN 노출·계정 변경 주장을 독립 재현하지 못했다. |
| 공개 OpenAPI 문서 보안 설정 | `eligibility_unknown` | **UNSUPPORTED**: 공개 `GET /static/openapi.json` 문서의 route 열거는 관측됐지만, 현재 finding 설명은 민감정보 접근이나 권한 우회 같은 실제 보안 영향을 제시하지 않는다. 동일 고정 VulnBank source에 대한 선행 [판정](../main-branch/phase_e/1_VULNBANK_JUICESHOP_PHASE_E.md)도 이 공개 문서 노출을 unsupported로 분류했다. |

앞의 두 후보는 endpoint provenance 결함 때문에 Validation에서 요청 자체가 만들어지지 않았다. 공개 OpenAPI 후보는 정책 적격성 모델 출력의 schema/근거 검증 실패로 `UNKNOWN`이 됐다. 세 case를 FP나 FN으로 세지 않는다.

## 로컬 Report 초안

Juice Shop의 `CONFIRMED` case `vcase_186fc95404894b3d97cb7789ff746908`로 `aidast report run ... --platform hackerone`을 실행했다. 이 플랫폼 인자는 **로컬 문서 형식** 선택이며 외부 제출은 수행하지 않았다. `Report.md`, `Report.json`, `Report.db`, context/schema 파일이 `result/test-runs/09.23/phase-e/juice-shop/`에 생성됐다. 명령 exit 0, `aidast report status` 재확인 결과는 `drafted`, `stale=false`다.

초안의 인용 ID 7개는 모두 원본 Validation에서 허용된 evidence 7개에 속한다(범위 밖 인용 0건). 제목, asset, 영향은 공개 product-search `q` SQL Injection과 삭제 표시 catalog record 노출로 제한했고 secret 데이터·파일·코드 실행을 주장하지 않는다. 긍정 대조군 1건, 음성 대조군 1건, 대상 replay 3건을 구분한다. 다만 context에 정확한 query payload 값이 없어 초안도 이를 명시하고 저장된 실행 순서만 요약한다. 별도 exact-payload 재현 절차가 필요한 외부 제출용 초안으로는 아직 부족하다. severity와 CVSS 필드는 비어 있으며 검증된 LOW 영향보다 높은 등급을 주장하지 않는다.

## Phase E 판정

**PARTIAL.** 6개 finding의 증거 기준 분류는 TP 1, UNSUPPORTED 1, UNRESOLVED 4, FP 0, duplicate 0이다. 대표 `CONFIRMED` case의 로컬 Report 생성, evidence 인용, source binding 및 stale 검사는 통과했다. 전체 `ELIGIBLE` ground truth가 확정되지 않았고 4건이 미판정이므로 FN·recall·F1 및 전체 제품 precision은 **NOT_MEASURED**다. 외부 플랫폼으로 보고서를 제출하지 않았다.
