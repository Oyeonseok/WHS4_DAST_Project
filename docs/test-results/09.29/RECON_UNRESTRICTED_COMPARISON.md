# Recon 제한 해제 재실측 — 2026-09-29

사용자 요청에 따라 요청 예산·도구 속도·전체 실행 시간 상한을 해제하고, 동결한 변경 전/후 소스로 전체 Recon 네 실행을 완료했다. **수집률과 성공률은 아래 실제 결과로 판단한다.** 이전 58/71·22/47을 이번의 제한된 51/71·14/47과 섞어 코드 개선이라고 설명했던 비교 기준도 정정한다.

## 동일 제한 해제 조건의 변경 전/후

| 대상 | 변경 전 Surface（제한 해제） | 변경 후 Surface（제한 해제） | Surface 2xx 경로 | 원시 GET 응답 건수 | 신규 / 손실 경로 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Juice Shop | 58/71 | 57/71 | 51→50 | 14470→14483 | 0 / 1 |
| VulnBank | 22/47 | 17/47 | 19→14 | 14598→14568 | 0 / 5 |

| 대상 | 원시 GET 관측 경로 | 원시 2xx 경로 | 내용/대조 확인 2xx 경로 | 없는 경로 대조 GET 건수 |
| --- | ---: | ---: | ---: | ---: |
| Juice Shop | 61→60 | 51→50 | 47→46 | 13→10 |
| VulnBank | 34→18 | 19→14 | 19→14 | 6→2 |

- Juice Shop: ffuf 루트 3→3개, 실행 633.9→625.6초, Surface 신규 0개·손실 1개, 2xx 신규 0개·손실 1개.
- VulnBank: ffuf 루트 3→3개, 실행 903.3→901.86초, Surface 신규 0개·손실 5개, 2xx 신규 0개·손실 5개.

**같은 제한 해제 조건에서는 수집률 개선을 확인하지 못했다.** Juice Shop은 Surface·2xx 각각 1개, VulnBank는 각각 5개 손실됐다. 신규 Surface·2xx 경로는 두 대상 모두 0개다. 낮은 정책 한도만으로 앞선 감소를 전부 설명했던 해석은 맞지 않는다.

Surface는 실제 관측 근거가 있는 비2xx도 포함하며 2xx와 분리한다. 모든 집계 Surface 경로에 실제 HTTP 응답 기록이 있다. 원시 응답 건수에는 반복·정적 파일·대조 요청이 섞인다. 내용/대조 확인은 HTTP 2xx의 업무상 성공을 보증하는 지표가 아니다. Juice Shop의 동일 SPA shell은 선언된 `/` 외에서 양성 본문 근거로 사용하지 않았다.

## 동일 조건에서 남은 손실의 추적

- VulnBank 손실 5개: `/api/ai/rate-limit-status`, `/api/ai/system-info`, `/api/bill-categories`, `/api/billers/by-category/<int:category_id>`, `/transactions/<account_number>`. 변경 후에는 다섯 경로 모두 HTTP 관측이 없으며 인증 실패 응답으로 바뀐 것이 아니다.
- 변경 전에는 ffuf가 끝난 후 adaptive JS가 `/static/dashboard.js`를 인증 상태로 가져왔다. 캐시 JS에는 `rate-limit-status`, `bill-categories`, `by-category`, `transactions` 근거가 있고 실제 값으로 상세 GET 3개를 실행했다. 변경 후에는 adaptive JS/API 분석이 ffuf보다 먼저 끝났다. ffuf가 나중에 얻은 `/dashboard` HTML에는 같은 script 참조가 있지만 그 script를 후속 분석하지 않았으며 상세 GET은 0개다. 근거 우선 순서로 바꾸면서 **늦게 발견한 HTML·JS를 재분석하는 후속 단계가 빠진 회귀**가 드러났다. 단순 정책 완화로 해결되지 않는다. [BankLossTrace.json](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/BankLossTrace.json).
- `/api/ai/system-info`는 변경 전의 비인증 browser 관측을 `observed_json_recovery`가 Surface에 복구했다. 앞선 script 네 경로와 같은 값 연결로 발견됐다고 단정하지 않는다. 변경 전 ZAP OpenAPI 단계에는 오류 1건이 있고, 변경 후에는 오류 없이 결과 0개였다. 이 경로의 최초 생성 도구는 추가 추적이 필요하다.
- Juice Shop 손실은 `/api/Products/:id`다. 두 버전 모두 상세 분석 전에 46개 항목의 정상 collection JSON을 관측했으므로 collection/인증 근거 자체가 없었던 것은 아니다. 둘 다 내부 상세 GET 20개 상한을 채웠지만 실행 후보가 달랐고, 변경 후에는 해당 detail/control 요청이 아예 생성되지 않았다. 변경 후 다른 collection family에서 서로 다른 실제 ID가 두 번 선택된 점도 있다. 내부 상세 후보의 순서·family별 배분이 손실과 연결돼 있지만, 어떤 코드 변경 하나가 이 경로를 밀어냈는지는 아직 단독 재현으로 확정하지 않았다. [JuiceDetailLossTrace.json](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/JuiceDetailLossTrace.json).

다음 수정 우선순위는 ① 새 문서/JS/JSON 근거를 증분으로 다시 연결하는 후속 단계, ② 상세 GET의 경로 family별 배분과 요청 variant 검증 구분, ③ 아래 동적 source query 회귀다. 특정 대상 경로나 서버 정답을 발견 로직에 넣는 방식은 사용하지 않는다.

## 기존 58·22보다 낮았던 이유와 재실측 대조

| 대상 | 이전 무제한 진단 | 이번 0.5 rps·500회 개선 코드 | 이번 제한 해제 개선 코드 |
| --- | ---: | ---: | ---: |
| Juice Shop | 58/71（2xx 51） | 51/71（2xx 45） | 57/71（2xx 50） |
| VulnBank | 22/47（2xx 19） | 14/47（2xx 12） | 17/47（2xx 14） |

이전 진단의 원시 GET 응답은 Juice Shop 14,481건·VulnBank 14,500건이었다. 0.5 rps·500회 실행에서는 각각 388·399건이었다. 총 정책 500회 중 브라우저 우선 몫 20%를 보호해 일반 활성 단계와 선행 probe에 허용된 수는 400회였고, 이후 보류는 각각 51·166회였다. ffuf의 150초 제한도 다시 적용됐다.

0.5 rps는 ffuf에 요청 간 2초 지연으로 전달된다. 150초 안에 약 75개 단어를 시도할 수 있으나, 같은 `common.txt`에서 `dashboard`는 1,375행, `profile`은 3,328행, `security.txt`는 3,704행, `video`는 4,422행이다. 보정 요청과 실제 네트워크 시간까지 있어 목록 뒤쪽에 도달하지 못했다. 여기에 전체 횟수 gate도 겹쳤다. 따라서 낮아진 결과를 인증·ID 연결 코드만의 효과로 설명하면 안 된다.

이전 Surface에서 제한된 개선 결과에 없던 경로는 Juice Shop 7개·VulnBank 8개였다. 이 경로들은 제한된 실행에서 실패 응답으로 바뀐 것이 아니라 **HTTP 관측 자체가 없었다**. Juice Shop 7개 중 6개와 Bank의 `/dashboard`·`/healthz`·`/merchant`는 이전에 ffuf user agent로 관측됐다. Bank에서 늦게 발견한 문서의 값/JS와 후속 요청 연결도 별도 한계다. [HistoricalDropAudit.json](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/HistoricalDropAudit.json).

이번은 두 소스 버전을 같은 제한 해제 런처로 비교했다. 다만 이전 58·22 진단은 범용 상위 prefix 2개와 `/`로 ffuf 루트를 선택했고, 이번도 **같은 범용 루트 선택 규칙**을 사용했다. Katana의 전체 실행 시간 제한도 이번에는 제거했다. 따라서 이전 진단과의 숫자 차이를 요청 예산 하나의 단독 인과 효과로 주장하지 않는다. 이전에서 복구·여전히 누락·추가된 경로는 [HistoricalComparison.json](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/HistoricalComparison.json)에 별도 기록했다.

## 실제 해제한 제한과 유지한 조건

- 기존 TargetPolicy의 선언 값은 원본대로 보존했다. 진단 런처의 임시 소스 overlay에서 프록시 요청 횟수 gate만 제거하고 Broker의 횟수 gate를 해제했다. 실제 요청 수가 500회를 넘었는지 검증했다. 제품 기본 제한 로직을 삭제한 변경이 아니다.
- ffuf의 `-rate`, `-p`, `-maxtime`, `-maxtime-job`은 모두 0이며 subprocess 전체 timeout도 없다. `resources/wordlists/common.txt` 4,752행을 각 선택 루트에서 완료했다.
- Katana는 `-rl 0`, `-ct 0`, 지연 옵션 제거와 subprocess 전체 timeout 해제다. ZAP 전체 subprocess timeout도 해제했다. 실제 실행 인자와 종료 상태를 산출물 검사에서 확인했다.
- ZAP는 두 버전 모두 같은 설치 addon과 비공개 임시 프로필 환경에서 실행했다. 기준선에는 도구 환경만 격리하고 인증 헤더 추가/발견 로직은 바꾸지 않았다. 이전 실험이 남겼던 정확한 로컬 origin의 가려진 replacer 규칙 4개만 정리해 기준선의 잘못된 인증 주입도 방지했다. [정리 기록](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/ZapBaselineStateCleanup.json).
- 대상 origin·호스트/포트·메서드·제외 규칙·신원 헤더·실제 요청 검사는 유지했다. 단일 요청 timeout 15초·동시 1·크롤 깊이 2와 scripts 40·상세 GET 20 등 발견 알고리즘의 내부 한도도 유지했다. 따라서 알고리즘 내부 한도까지 모두 없앤 실험은 아니다.
- 두 버전 모두 같은 기존 계정·session seed·정상 로그인·실제 시작 URL `/`이다. 계정 신원을 로컬에서 대조했다. 데이터/권한 fixture를 생성하지 않았다. 서버 데이터 전체 불변 스냅샷은 없고 로그인 기록·시각·AI 출력 변동은 남는다.
- URL 대상 `HTTP_PROBE`·`ORIGIN_DISCOVERY`·`ENDPOINT_DISCOVERY` 전체를 실행했다. 모든 task 성공, DB integrity/FK 정상이다. 단계별 스킵/오류는 비교 JSON에 별도 기록했다. 서버 소스·정답은 네 실행 종료 후 평가에만 읽었다.

정상 로그인 POST는 Recon 준비 단계의 별도 요청이다. 브라우저가 생성한 프로토콜/기타 메서드 관측은 아래와 같이 따로 보고한다. 원시 상세 경로/건수는 산출물 검사 JSON에 있다.

- Juice Shop baseline: GET/HEAD/OPTIONS 외 DB 응답 관측 3건.
- Juice Shop improved: GET/HEAD/OPTIONS 외 DB 응답 관측 4건.
- VulnBank baseline: GET/HEAD/OPTIONS 외 DB 응답 관측 0건.
- VulnBank improved: GET/HEAD/OPTIONS 외 DB 응답 관측 0건.

10 rps만 적용한 실행은 사용자 지시 변경 때 중단해 최종 비교에서 제외했다. 처음 기본 AI 루트 선택기로 진행한 제한 해제 trial도 실제 ZAP 실행명에 대한 시간 상한 해제 누락을 수정하며 제외했고, 최종 비교는 이전 진단과 같은 범용 루트 선택 규칙으로 새로 완료했다. [제외 기록](../../../result/test-runs/09.29/recon-auth-parameters-10rps/ExcludedRuns.json).

## 코드 변경·검증·남은 한계

이번에는 생산 코드의 추가 기능 수정 없이 앞서 보완한 인증·ID·쿼리 연결을 제한 해제 조건에서 실측했다. 초기 미커밋 소스와 이 작업의 12개 파일만 반영한 개선 소스를 그대로 재사용했다. 다른 팀의 동시 변경은 비교 소스에 추가하지 않았고 작업 폴더에 보존했다.

비교 중 workspace의 `mitm_proxy.py` 실행 환경 수정이 추가된 것도 보존했다. 이 변경은 이미 동결한 네 실행의 소스에는 포함되지 않으며, 검사에서는 현재 workspace 일치 대신 ZIP+진단 overlay와 실제 실행 소스 hash를 대조했다.

앞서 추적한 원인은 ZAP 인증 전달 누락, 쿼리 소실/요청 조건 중복, DOM·필수 query 연결 부족, ffuf 선행 예산 소비였다. 기존 로그인/저장 세션 기능을 유지하면서 origin 한정 인증 전달·비공개 ZAP 프로필·실제 값 연결·요청 identity·근거 우선 순서를 보완했다. [원인과 코드·회귀 검사 상세](RECON_AUTH_PARAMETERS.md). 당시 동결 소스 회귀 712개·서브테스트 58개, workspace 회귀 730개·서브테스트 58개 통과 및 실제 ZAP/AI 통합 근거는 그 문서에 있다.

이번 실측의 계정/설정/wordlist 일치, 실제 제한 해제·Scope·캡처 범위·DB·로그/보고서 인증정보 비노출은 [ArtifactChecks.json](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/ArtifactChecks.json)으로 확인했다. 인증 값을 포함하는 원시 DB/session 등은 비공개 실험 자산으로 보관했다. 후보/원시 응답과 Surface·2xx·내용 확인을 구분한 전체 목록은 [Comparison.json](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/Comparison.json)에 있다.

남은 한계는 상세 GET 20개·scripts 40개, 복잡한 JS/DOM event와 여러 동적 query, OpenAPI path/ref와 외부 server 선언, 일부 `/api/resource`·배열/data[].id 가정, ffuf 이후 새 HTML/JS 근거를 재분석하는 흐름이다. 인증 헤더는 세션 snapshot으로 동적 서명/회전을 모두 지원하지 않는다. 수집되지 않은 경로와 401/403은 정상 일반 계정의 성공 검증과 구분해야 한다. 무근거 값이나 외부 명세 origin 재매핑으로 성공 수를 채우지 않는다.

오프라인 가상 앱 재현에서는 **동적 source query의 회귀**도 확인했다. `/catalog/?term=${q}` 응답의 실제 `key`를 `/records/${k}`에 연결하는 명시적 서비스 관계가 이전에는 1개 binding이었고 현재는 0개다. 정적 target query는 현재 제대로 보존된다. 추가 동적 시각 query는 두 버전 모두 지원하지 않았다. [GenericQueryLimit.json](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/GenericQueryLimit.json). 이는 특정 대상에 의존하지 않는 코드 한계이며, 실제 대상의 경로 손실 전부를 이 재현 하나로 설명하지 않는다. 이번 정책 영향 비교 중 생산 코드는 바꾸지 않았으므로 이 회귀는 남은 수정 항목이다.
