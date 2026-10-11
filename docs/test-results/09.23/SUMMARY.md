# 09.23 실험 요약 — 로컬 통합 실행과 초기 안정화

**Juice Shop·VulnBank의 공개/인증 Recon과 통합 파이프라인을 완료하고, SQL Injection 1건을 독립 재현했다.** 실행을 막던 CLI·외부 통신·태깅·경로 병합 문제를 수정했지만, 전체 취약점 탐지 정확도와 반복 실행 성능은 측정하지 못했다.

## 범위와 실험 조건

- 기록 범위: 이 폴더의 Phase A~F와 Recon 수집률 문서. 실험은 **2026-09-23에 시작했으며 Phase D~F 기록은 09-24 KST까지 이어진다.**
- 대상: Juice Shop 20.2.0, VulnBank 고정 소스 `5e5ea542…`. 시작 코드 `a97d4561…`에서 실패 분석 중 수정한 작업 트리를 사용했다.
- 공개 Recon·통합 실행: 0.5 RPS, 요청 상한 500, depth 2, 실제 동시성 1. 인증 Recon은 요청 상한 150.
- 수집률 분모: Juice Shop application GET route 71개, VulnBank 47개. 아래 수치는 완료 실행의 비제외 GET endpoint를 기준 목록과 대조한 값이며, 취약점 탐지율이 아니다.

## 어떤 실험을 했고 결과는 어땠나

| 실험 | 결과 | 핵심 정량 지표 |
| --- | --- | --- |
| A: 서비스·DB·도구·승인 정책 사전 점검 | PASS | 두 대상 홈페이지 각각 3/3회 HTTP 200. 응답 중앙값 Juice Shop 12.31 ms, VulnBank 13.425 ms |
| B: 비로그인 Recon 및 태깅 | 첫 실행 실패 후 수정·재실행 PASS | 최종 두 scan 완료. 태깅 Juice Shop 249/249건, VulnBank 301/301건 성공; 실패 0건 |
| C: 인증 세션·시작 URL별 Recon | PASS | Juice Shop primary, VulnBank primary·secondary 사용. 인증 Recon 4회 완료, 세 identity의 비밀값/JWT 대조 일치 0건 |
| D: Recon → Attack → Chaining → Validation 통합 실행 | PASS — 실행 경로 검증 | Juice Shop, VulnBank 인증 dashboard, VulnBank 공개 루트의 3회 실행 모두 exit 0. finding 총 6건, Validation `CONFIRMED` 1건·`INCONCLUSIVE` 5건 |
| E: finding 증거 대조·로컬 Report | PARTIAL | TP 1, UNSUPPORTED 1, UNRESOLVED 4, FP 0, duplicate 0. Report 인용 7/7개가 허용 증거, `stale=false` |
| F: 동일 초기 상태로 대상별 3회 반복 평가 | NOT RUN | 복원 기준 미검증. 실행 시간·요청 수·모델 사용량의 중앙값/변동 범위는 `NOT_MEASURED` |

통합 실행의 세부 결과는 다음과 같다. Chaining 완료와 chain 발견은 다른 지표다.

| 통합 실행 | Attack task 완료 / skip | Finding | Validation | Chain |
| --- | ---: | ---: | --- | ---: |
| Juice Shop primary | 9 / 2 | 3 | CONFIRMED 1, INCONCLUSIVE 2 | 0 |
| VulnBank primary `/dashboard` | 2 / 3 | 0 | case 0 | 0 — finding 부재로 Chaining skipped |
| VulnBank 공개 `/` | 10 / 1 | 3 | INCONCLUSIVE 3, 실제 replay 0 | 0 |

## 바뀐 내용과 확인된 성과

| 문제 | 변경 | 변경 후 관측 |
| --- | --- | --- |
| `recon` CLI가 `run_root`를 참조해 요청 전 종료 | 통합 `run`에서만 전용 출력 경로 계산 | CLI 회귀 테스트 13개 통과, 최종 Recon 실행 가능 |
| VulnBank 브라우저 지원 경로가 외부 font 요청 허용 | loopback Scope의 범위 밖 passive 요청을 브라우저·프록시 양쪽에서 차단 | 첫 실패 scan은 외부 HTTP 200 34건. 최종 두 공개 scan의 저장 HTTP transaction은 범위 밖 host 0건 |
| 50건 태깅 배치가 약 300초 제한에 도달 | 배치 50→25건, Codex 제한 300→600초; 모델 계약 오류 배치를 분할 재처리 | 기존 미처리 175/175건 재처리 성공. 최종 공개 Recon은 합계 550/550건 성공, 23배치 실패 0건 |
| 서로 다른 공개 루트 경로가 `/:param`으로 병합 | 루트 첫 segment를 경로 수만으로 변수 학습하지 않음 | VulnBank의 병합 회귀 시도에서 4/47로 떨어진 적중이 최종 11/47로 복구. 중간 시도는 최종 집계에서 제외 |

## Recon의 정량적 성과

여러 scan이 있는 대상은 **해당 Phase 안의 적중 집합을 중복 제거**했다. B·C·D는 인증·시작 URL·실행 구성도 달라 아래 차이를 단일 코드 수정의 효과로 해석하지 않는다.

| Phase | Juice Shop | VulnBank | 두 대상 합계 |
| --- | ---: | ---: | ---: |
| B: 공개 Recon | 7/71 (9.9%) | 11/47 (23.4%) | 18/118 (15.3%) |
| C: 인증 Recon | 9/71 (12.7%) | 10/47 (21.3%) — 인증 3회 합집합 | 19/118 (16.1%) |
| D: 통합 실행의 Recon | 9/71 (12.7%) | 16/47 (34.0%) — 공개·dashboard 합집합 | 25/118 (21.2%) |

Phase B 대비 D는 합계 **7개 경로 증가, 약 5.9%p 상승**했다. Juice Shop에는 basket·whoami 경로가 추가됐고, VulnBank는 공개 11개에 인증 dashboard 경로 5개가 추가됐다.

SQL Injection TP 1건은 `/rest/products/search`에서 대상 3회 모두 HTTP 200/21,581B와 삭제 표시 레코드 노출 assertion 성공을 확인한 결과다. VulnBank 공개 후보 중 2건은 endpoint method/path 연결 오류, 1건은 적격성 평가 실패로 재현 전에 보류됐다. 이를 실제 재현 실패나 음성 판정으로 세지 않는다.

## 검증 기록과 남은 과제

- 원본에 기록된 검증: 태깅 수정 후 전체 suite `1046 passed, 6 skipped, 642 subtests passed`. 이후 경로 수정본의 전체 suite는 helper broker timeout 테스트 1개가 두 차례 실패했고 단독 재실행만 통과했다. **최신 전체 suite PASS로 기록하지 않는다.**
- 통합 실행 3회의 DB foreign key 위반과 미종결 요청은 0건. 저장 Recon 거래 및 Attack/Validation 요청의 범위 밖 host도 0건이었다.
- 다음 과제: endpoint provenance·적격성 gate 보완, GET 수집 확대, 초기 상태 복원 검증. 전체 ELIGIBLE 정답 집합이 동결되지 않아 FN·recall·F1·제품 전체 precision은 `NOT_MEASURED`다.
- 로컬 Report는 payload 전문이 없어 외부 제출용 재현 절차가 미완성이다.

## 원본 근거

- 전체 맥락: [README](_archive/README.md), [Recon 수집률·실행별 scan ID](_archive/RECON_COVERAGE.md).
- 사전 점검·수정·인증: [Phase A](_archive/PHASE_A.md), [Phase B](_archive/PHASE_B.md), [Phase C](_archive/PHASE_C.md).
- 통합 실행·판정·미실행 범위: [Phase D](_archive/PHASE_D.md), [Phase E](_archive/PHASE_E.md), [Phase F](_archive/PHASE_F.md).
- 실행 원본 위치: `result/test-runs/09.23/phase-b/`, `phase-c/`, `phase-d/`, `phase-e/`의 DB·Surface·로그·Report. 원본 문서에 대상별 scan과 경로가 기록돼 있다.
