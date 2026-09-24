# 2026-09-23 로컬 대상 테스트 결과

[Phase별 결과 문서 작성 정책](../PHASE_RESULT_FORMAT_POLICY.md)은 이후 단계별 결과의 공통 항목과 판정·증거 기록 순서를 정한다.

`docs/test-plans/LOCAL_FUNCTIONAL_LAB.md`와 `VULNBANK_JUICESHOP_EVALUATION_PLAN.md`에 따라 Juice Shop과 VulnBank를 점검했다. 시작 기준 commit은 `a97d456156d1c7632b05bd800f61a561e9144ed8`이며, Phase B 실패 분석 중 CLI, 프록시 안전 경계, 태깅 재시도, path 정규화 코드를 수정했다. 최종 Phase B 두 스캔은 같은 수정본에서 순차 실행했다. 이 결과 세트는 코드와 초기 데이터가 고정된 3회 비교 실험은 아니다.

| 단계 | 판정 | 근거 |
| --- | --- | --- |
| [A](PHASE_A.md) | PASS | 서비스·DB health, 브라우저, Scope 무결성 및 exact loopback 정책 확인 |
| [B](PHASE_B.md) | PASS | 수정 후 두 대상 Recon 완료, 외부 HTTP 저장 0건, 태깅 실패 0건 |
| [C](PHASE_C.md) | PASS | Juice Shop primary 및 VulnBank primary·secondary 인증 Surface와 비밀값 비노출 확인 |
| [D](PHASE_D.md) | PASS | Juice Shop·VulnBank 인증·공개 통합 stage 종료; Juice Shop case 1건 재현 |
| [E](PHASE_E.md) | PARTIAL | TP 1, unsupported 1, unresolved 4; 로컬 Report 초안 생성·stale 검증 완료 |
| [F](PHASE_F.md) | NOT RUN | 동일 초기 상태 복원 절차 미검증, 3회 반복 미수행 |

[Phase B·C·D Recon 수집률 비교표](RECON_COVERAGE.md)는 동일한 고정 application GET route 기준으로 실행별 값과 단계별 중복 제거 합집합을 구분한다. 이후 결과 세트는 [Recon 수집률 기록 형식](../RECON_COVERAGE_TEMPLATE.md)을 사용한다.

## 로컬 회귀 테스트

- CLI 수정 회귀 테스트: 먼저 예상한 `AttributeError` 실패를 확인하고 수정 후 `ReconCliTests` 13개 통과.
- 관련 Recon suite: `69 passed, 14 subtests passed`.
- `TMPDIR=/private/tmp`에서 태깅 재시도 수정 후 전체 suite는 `1046 passed, 6 skipped, 642 subtests passed`였다. 로그는 `result/test-runs/09.23/pytest-full-after-annotation-fix.log`에 있다.
- path 정규화 수정 후 전체 suite 두 차례에서 helper broker의 2초 응답 제한 테스트 1개가 실패했고 나머지는 `1046 passed, 6 skipped, 642 subtests passed`였다. 해당 테스트 단독 재실행은 통과했다. 최신 전체 suite를 PASS로 취급하지 않는다. 로그는 `result/test-runs/09.23/pytest-full-phase-b-rerun.log`에 있다.

## 다음 단계

Phase B의 Recon 게이트는 두 대상 모두 통과했고 Phase D 통합 실행은 대상별로 종료됐다. Phase E의 미판정 4건은 Validation의 endpoint provenance·정책 적격성 gate 문제와 연결된다. Phase F의 반복 비교에는 대상 초기 상태 복원과 고정 코드/모델 기준이 추가로 필요하다.
