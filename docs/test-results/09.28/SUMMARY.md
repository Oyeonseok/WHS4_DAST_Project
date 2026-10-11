# Recon 핵심 요약 — 09.28–09.29

최신 결과는 **요청 예산·도구 속도·전체 시간 상한을 해제한 진단**이다. 기존 미커밋 변경을 보존하고, 동일 계정·설정에서 변경 전/후 전체 Recon을 비교했다.

| 대상 | 변경 전 Surface（제한 해제） | 변경 후 Surface（제한 해제） | Surface 2xx 경로 | 원시 GET 응답 건수 | 신규 / 손실 경로 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Juice Shop | 58/71 | 57/71 | 51→50 | 14470→14483 | 0 / 1 |
| VulnBank | 22/47 | 17/47 | 19→14 | 14598→14568 | 0 / 5 |

| 대상 | 이전 무제한 진단 | 이번 0.5 rps·500회 개선 코드 | 이번 제한 해제 개선 코드 |
| --- | ---: | ---: | ---: |
| Juice Shop | 58/71（2xx 51） | 51/71（2xx 45） | 57/71（2xx 50） |
| VulnBank | 22/47（2xx 19） | 14/47（2xx 12） | 17/47（2xx 14） |

같은 제한 해제 조건에서 신규 경로는 없고 Juice Shop 1개·VulnBank 5개가 손실됐다. 요청 제한만의 문제가 아니라 코드 회귀도 남아 있다. Bank는 ffuf 이후 발견한 페이지/JS를 재분석하지 않는 흐름, Juice Shop은 정상 collection을 얻고도 20개 상세 요청 내에서 해당 family를 검증하지 못하는 후보 배분을 우선 보완해야 한다. 일반 가상 앱의 동적 source query 연결 회귀도 확인됐다.

0.5 rps·500회 결과를 이전 58·22와 직접 비교해 개선이라고 설명한 것은 비교 기준이 달랐다. 제한된 실행의 실제 활성 허용 요청은 400회였고 이전 진단은 약 14,500건의 GET 응답을 수집했다. 이전/이번 무제한 진단은 같은 범용 ffuf 루트 선택 규칙을 사용하지만 Katana 시간 조건·소스 시점이 달라 차이를 한 요인의 효과로 단정하지 않는다.

핵심 보완은 ZAP 단계의 인증 헤더 전달·비공개 프로필, JS/JSON 쿼리 보존, 실제 DOM/OpenAPI 필수 값 연결, 쿼리·인증별 요청 검증, ffuf보다 근거 검증을 먼저 실행하는 순서다. 대상 이름·업무 경로·정답을 발견 코드에 추가하지 않았다.

Surface에는 근거 있는 비2xx도 포함한다. 원시 응답·경로·HTTP 2xx·본문/대조 확인은 따로 집계했으며, Juice Shop의 SPA shell을 정상 API 응답으로 간주하지 않았다. 요청 횟수/속도/전체 시간 해제와 별도로 Scope·읽기 조건, 동시 1·개별 15초·깊이 2, scripts 40·상세 GET 20 등의 내부 한도는 남는다. 복잡한 값 흐름·외부 server 명세·ffuf 이후 새 문서 재분석도 다음 개선 지점이다.

일반 가상 앱에서는 동적 source query 응답→상세 ID 연결이 이전 1개 binding에서 현재 0개로 줄어드는 회귀도 재현했다. 정적 query 보존의 효과와 이 손실을 구분해야 하며, 정책 해제만으로 모든 코드 한계가 해결된 것은 아니다.

이번에는 추가 생산 코드 변경 없이 동결한 두 소스를 재사용했다. 앞선 회귀/실제 ZAP·AI 통합 검증과 이번 네 실행의 계정·DB·Scope·제한 해제·인증정보 비노출 근거를 보존했다. 10 rps 중간 실행은 지시 변경으로 중단했고 수집률에 합산하지 않았다. 기본 AI 루트 선택기/진단 런처 수정 전 trial도 최종 비교에서 제외했다.

- [최신 제한 해제 실측·신규/손실·한계](../09.29/RECON_UNRESTRICTED_COMPARISON.md) · [비교 JSON](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/Comparison.json) · [산출물 검사](../../../result/test-runs/09.29/recon-auth-parameters-unrestricted/ArtifactChecks.json)
- [인증·ID·쿼리 원인/변경 및 제한 조건 실측](../09.29/RECON_AUTH_PARAMETERS.md) · [GET 별도 검증](../09.29/GET_ROUTE_LIVE_CHECK.md) · [역사적 지표](_archive/recon_metrics.json)

다른 팀의 정책 원문·필수 신원 헤더·제외 규칙·공유 요청 제한 변경도 보존했다. [정책 검증](../../../result/test-runs/09.28/generic-policy-exclusions/verification.json) · [운영 옵션](../../OPERATIONS.md). 원시 DB/session은 인증정보를 포함하므로 제한된 실험 디렉터리에 보관한다.
