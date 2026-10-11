# Recon application GET route 수집률 기록 형식

이 문서는 [Phase별 결과 문서 작성 정책](PHASE_RESULT_FORMAT_POLICY.md)의 Recon 지표 세부 형식이다.

새 결과 세트의 `RECON_COVERAGE.md`에 이 형식을 복사한다. Phase B Recon-only, Phase C 인증 Recon, Phase D 통합 실행의 Recon을 같은 단위로 기록한다. 단계별 문서에서도 이 파일을 링크하고 수집률을 인용한다.

## 1. 기준과 산정 규칙

1. 대상 image digest/source commit과 기준 route 목록 파일의 경로·버전을 고정한다. 현재 기준은 [Juice Shop 71개·VulnBank 47개 application GET route](main-branch/phase_b/PHASE_B_ENDPOINT_BASELINE.md)다. 버전이 바뀌면 새 기준 목록을 만들고 수치를 별도 세트로 취급한다.
2. 완료된 각 scan의 `Recon.db`에서 `endpoints.method`, `path`, `normalized_path`, `source_tools`, `is_excluded`를 확인한다. `is_excluded=1`, 순수 ffuf 후보와 평가 기준 밖 경로는 분자에서 제외한다. 중단·실패 scan은 실행별 표에 `EXCLUDED`로 기록하고 단계 합집합에 넣지 않는다.
3. 식별 단위는 `GET + application route path template`이다. method는 정확히 일치시키고 trailing slash를 제거하되 `/`는 유지한다. 실제 path의 한 segment가 기준의 `:parameter` 한 칸에 일치한다. `normalized_path`의 parameter 이름이 기준과 달라도 실제 path로 대조한다. 같은 route의 반복 관측은 한 번만 센다.
4. `수집률 = 고유 적중 route 수 / 고정 기준 route 수 × 100`, `누락 = 기준 route 수 - 적중 route 수`로 계산해 소수점 첫째 자리까지 적는다. 같은 대상의 여러 scan을 합칠 때는 적중 **집합의 합집합**을 먼저 구한다. 전체 합계는 대상별 적중 수와 분모를 각각 더한다. 퍼센트 평균과 이전 단계 누적값을 사용하지 않는다.
5. `DB endpoints`, observation 수, HTTP transaction 수는 별도 운영 지표다. 이 숫자를 수집률 분자로 사용하지 않는다. 인증이 필요한 route까지 포함한 고정 전체 분모는 단일 실행에서 접근 가능한 route만의 recall과 다르며, 취약점 탐지율도 아니다.

## 2. 실행 정보

| 항목 | 값 |
| --- | --- |
| 결과 날짜·코드 commit | `<YYYY-MM-DD>` · `<commit>` |
| Juice Shop image digest | `<sha256:...>` |
| VulnBank source commit | `<commit>` |
| 기준 route 목록·SHA-256 | `<문서 경로·버전·파일 hash>` |
| 정책·인증 차이 | `<RPS, request cap, start URL, identity 등>` |

## 3. 실행별 수집률

각 실행을 한 줄로 쓰고 실패 실행도 `Recon stage`와 `포함` 여부를 남긴다. 인증 identity와 시작 경로를 실행 이름에 적는다.

| Phase | 대상·실행 | scan ID | Recon stage | 포함 | DB endpoints | 적중 / 기준 | 누락 | 수집률 | `Recon.db` 경로 |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| B | `<대상·공개 루트>` | `<scan_id>` | `<completed/failed>` | `<YES/EXCLUDED>` | `<n>` | `<n / N>` | `<n>` | `<n.n% 또는 N/A>` | `<path>` |
| C | `<대상·identity·시작 경로>` | `<scan_id>` | `<completed/failed>` | `<YES/EXCLUDED>` | `<n>` | `<n / N>` | `<n>` | `<n.n% 또는 N/A>` | `<path>` |
| D | `<대상·identity·시작 경로>` | `<scan_id>` | `<completed/failed>` | `<YES/EXCLUDED>` | `<n>` | `<n / N>` | `<n>` | `<n.n% 또는 N/A>` | `<path>` |

## 4. 단계별 대상 합집합

같은 대상·같은 단계의 scan ID를 열거하고 고유 적중 route를 한 번씩만 센다. `합계`는 두 대상의 분자·분모 합이다.

| Phase | 대상 | 포함한 scan ID | 고유 적중 / 기준 | 누락 | 수집률 |
| --- | --- | --- | ---: | ---: | ---: |
| B | Juice Shop | `<scan_ids>` | `<n / N>` | `<n>` | `<n.n%>` |
| B | VulnBank | `<scan_ids>` | `<n / N>` | `<n>` | `<n.n%>` |
| **B 합계** | **두 대상** | 대상별 합집합 | **`<n / N>`** | **`<n>`** | **`<n.n%>`** |
| C | Juice Shop | `<scan_ids>` | `<n / N>` | `<n>` | `<n.n%>` |
| C | VulnBank | `<scan_ids>` | `<n / N>` | `<n>` | `<n.n%>` |
| **C 합계** | **두 대상** | 대상별 합집합 | **`<n / N>`** | **`<n>`** | **`<n.n%>`** |
| D | Juice Shop | `<scan_ids>` | `<n / N>` | `<n>` | `<n.n%>` |
| D | VulnBank | `<scan_ids>` | `<n / N>` | `<n>` | `<n.n%>` |
| **D 합계** | **두 대상** | 대상별 합집합 | **`<n / N>`** | **`<n>`** | **`<n.n%>`** |

## 5. 적중·누락 및 해석

- 기준 대비 적중 GET route 목록: `<target별 목록 또는 검증 가능한 문서 링크>`
- 누락 GET route 목록: `<기준 목록에서 적중을 뺀 목록 또는 검증 가능한 문서 링크>`
- 중단·실패 실행과 제외 사유: `<scan ID, 사유>`
- 시작 경로·인증 상태 때문에 미방문한 영역: `<설명>`
- 다른 기준 버전, 정책, 모델 또는 수집 규칙과의 차이: `<설명>`
- Phase B→C→D 변화: `<단계별 합집합의 추가·이탈 route. 단계 수치를 누적으로 표현하지 않음>`
