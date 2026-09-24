# Phase F — 반복 평가 (2026-09-23 시작, 09-24 KST 계속)

## 판정

**NOT RUN — 초기 상태 복원 기준 미검증.** [테스트 계획](../../test-plans/VULNBANK_JUICESHOP_EVALUATION_PLAN.md)은 대상별 shakedown 성공 후 초기 상태를 복원하고 동일 조건으로 총 3회 실행하도록 정한다. Phase B는 두 대상 모두 통과했고 Phase D에서는 Juice Shop 및 VulnBank 인증 dashboard와 공개 루트 통합 실행이 완료됐다.

VulnBank PostgreSQL과 업로드 파일, Juice Shop 컨테이너 상태를 동일한 baseline으로 되돌리는 절차를 아직 검증하지 않았다. 실행 시간·요청 수·모델 사용량의 3회 중앙값과 변동 범위는 **NOT_MEASURED**다. Phase D의 단일 shakedown을 반복 평가 표본으로 사용하지 않는다.

09-24 KST 점검에서 세 테스트 컨테이너는 실행 중이며, VulnBank DB와 업로드는 각각 `aidast-functional-lab_bank-data`, `aidast-functional-lab_bank-uploads` named volume에 저장되는 것을 확인했다. DB 크기는 약 8.5 MB, 업로드는 약 1.6 MB/5개 파일이다. 현재 상태는 Phase D 실행 이후의 상태이므로, 지금 만든 백업을 최초 실행 전 baseline으로 간주할 수 없다. 복원 검증 없이 이 데이터를 초기화하거나 3회 결과를 비교하지 않는다.
