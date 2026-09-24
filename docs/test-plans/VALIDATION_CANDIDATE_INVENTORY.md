# Validation 후보 데이터 인벤토리

## 목적과 산출물

Validation 실험에 앞서 교육용 앱 두 개의 **출처가 확인되는 공격 후보**를 독립 SQLite DB에 적재한다. 기본 산출물은 `result/test-runs/validation-candidates/CandidateInventory.db`이며 `result/`는 Git에서 제외된다. 별도 정답지는 `result/test-runs/validation-candidates/CandidateAnswerKey.db`에 생성한다. 재생성에 필요한 스크립트와 출처 스냅샷은 저장소에 둔다.

현재 DB는 `attack_candidates`와 `inventory_metadata` 테이블로 구성된다. 후보는 공식 챌린지 또는 원본 코드가 주장하는 테스트 지점이다. 실행 요청, 성공 증거, 재현 명세가 없으므로 기존 Attack `findings` 및 Validation `validation_cases`와 동일하게 취급하지 않는다. Validation의 실행 입력으로 승격할 때는 해당 스캔의 Recon endpoint, Attack attempt/request/evidence, 재현 명세를 실제 실행 결과로 만들어 연결해야 한다.

## 고정 출처

| 대상 | 고정 버전 | 사용한 공식 자료 | 로컬 대조 |
| --- | --- | --- | --- |
| OWASP Juice Shop | Docker image `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`, v20.2.0 | [공식 `challenges.yml`](https://github.com/juice-shop/juice-shop/blob/v20.2.0/data/static/challenges.yml), SHA-256 `8efa070380ab8f39783eb92cbaaf9df67bcee0f1715eee98a06fb1176051c2b7` | 실행 중 앱의 `/api/Challenges` 116개와 key/name 일치 |
| Commando-X VulnBank | commit `5e5ea5425fcf309373a0655dd111ecfb45037cbf` | [README](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/README.md), [app.py](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/app.py), [auth.py](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/auth.py), [merchant_payments.py](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/merchant_payments.py), [transaction_graphql.py](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/transaction_graphql.py) | 로컬 checkout의 commit과 5개 파일 SHA-256 고정 |

Juice Shop 원본 스냅샷은 `resources/lab/juice-shop-v20.2.0-challenges.yml`, 보호 라우트 검토용 서버 코드는 `resources/lab/juice-shop-v20.2.0-server.ts`(SHA-256 `1774fac7f05f9f78fad0b4f82a10eaf0d2ef5b2522ddbe75133e65e423c0a90b`), 코드만으로 자동 추출되지 않는 VulnBank 항목은 `resources/lab/vuln-bank-curated.json`에 보관한다. DB 각 행에는 주장 출처 URL과 줄 번호, 파일 해시, 버전이 들어간다. VulnBank 행에는 해당 라우트 등록 위치인 `route_source_url`도 들어간다. 같은 Python 파일의 직접 주장에는 출처 줄이 해당 라우트 함수 내부에 있는지 검사하고, 공용 함수 주장에는 라우트에서 그 함수까지의 호출 연결을 검사한다. README 항목은 수동으로 대응시킨 출처 주장이다.

## 적재 현황 (2026-09-24)

| 대상 | 후보 수 | 경로 상태 | 평가 상태 |
| --- | ---: | --- | --- |
| Juice Shop | 120 | 공식 챌린지 116개는 경로 매핑 필요; 보호 라우트 가설 4개는 경로 지정 | 96 `UNASSESSED`, Docker 비활성 18 `OUT_OF_TEST_SCOPE`, Miscellaneous 6 `MANUAL_ONLY` |
| VulnBank | 117 | 원래 후보 113개에 범위가 좁은 반례 가설 4개 추가 | 107 `UNASSESSED`, 현재 Scope에서 금지한 race/rate-limit/GraphQL complexity 10 `OUT_OF_TEST_SCOPE` |

원래 VulnBank 후보 113개는 원본 코드 주석 91개, 코드에서 직접 확인한 항목 16개, README 주장 6개다. 같은 메서드·경로·취약점 분류는 중복 적재하지 않는다. Flask가 정수로 변환하는 경로 매개변수만 SQL에 쓰는 두 라우트는 원본의 SQL injection 주석과 달리 양성 후보에서 제외하고, 범위가 한정된 검증 가설로만 추가했다. 코드 주석은 확인할 위치를 제공하지만 동적 재현을 증명하지는 않는다. 특히 실행 중 앱에서 실제 작동 여부, 계정 요건, 취약점 영향은 이후 별도 평가가 필요하다. 후보 개수를 TP 또는 recall 분모로 쓰지 않는다.

## 반례 후보와 별도 정답지

`resources/lab/validation-control-candidates.json`에는 Juice Shop 4개, VulnBank 4개의 **검증 가설**을 정의한다. 이 파일과 후보 DB에는 기대 판정이 없다. 후보 ID도 판정을 암시하지 않는다. 공식 서버 코드 또는 고정 VulnBank 코드에서 라우트와 근거 줄을 찾지 못하면 빌드를 중단한다.

`resources/lab/validation-answer-key.json`에서만 기대 판정과 정확한 요청 조건, 근거 수준, 관찰한 HTTP 상태, 한계를 정의한다. 빌드 결과 `CandidateAnswerKey.db`에는 후보 DB에 실제로 있는 ID만 적재한다. 현재 판정 가능한 부분집합은 **`NOT_VULNERABLE` 8개와 `VULNERABLE` 2개**다. 나머지 227개는 미판정이며 자동으로 양성으로 간주하지 않는다.

이 정답지는 Validation 목표 상태도 기록한다. 증거 조건을 충족한 취약 후보의 목표는 `CONFIRMED`, 비취약 후보의 목표는 `DISPROVEN`이다. 이것은 HTTP 상태 코드 하나만으로 반드시 나와야 하는 상태가 아니다. `proof_requirement`를 충족하지 못해 `INCONCLUSIVE`, `BLOCKED`, `UNDERPOWERED` 등이 나오면 오판으로 세지 않고 미해결로 분류한다. 반대쪽 확정 상태(`NOT_VULNERABLE`→`CONFIRMED`, `VULNERABLE`→`DISPROVEN`)만 잘못된 판정으로 센다.

| 앱 | 비취약 판정의 범위 | 근거 |
| --- | --- | --- |
| Juice Shop | 인증 헤더 없는 `GET /api/Users`, `/api/Feedbacks/1`, `/api/PrivacyRequests`, `/api/Complaints`에서 해당 데이터가 반환되는가 | [공식 v20.2.0 `server.ts`](https://github.com/juice-shop/juice-shop/blob/v20.2.0/server.ts) 보호 라우트 + 로컬 HTTP 401 4건 |
| VulnBank | `category_id`, `card_id` 정수 경로 값으로 문자열 SQL 페이로드가 SQL 질의에 도달하는가 | [고정 `app.py`](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/app.py) 라우트·질의 + 로컬 HTTP 404 2건 |
| VulnBank | 정상 인증된 merchant A가 merchant B의 결제를 ID 또는 일반 목록 API로 읽을 수 있는가 | [고정 `merchant_payments.py`](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/merchant_payments.py)의 merchant 소유권 조건 검토. 두 계정으로 실행 검증은 아직 하지 않음 |

양성 판정 2개는 VulnBank의 `/debug/users` 데이터 노출과 `/api/v1/payments/merchant_id/<int:merchant_id>` 소유권 누락이다. 전자는 코드 근거와 로컬 HTTP 200을 확인했고, 후자는 코드 근거만 검토했다. `NOT_VULNERABLE`은 **정답지 `scope` 필드에 적힌 요청 조건에 한정**한다. 같은 라우트의 다른 취약점이나 인증 우회를 배제하는 판정이 아니다. 정답 DB를 Validation 실행 입력에 넣지 말고, 실제 요청·응답을 기록한 뒤 결과 채점에만 사용한다.

## 재생성

먼저 [로컬 기능 테스트 환경](LOCAL_FUNCTIONAL_LAB.md)에 따라 고정 VulnBank checkout을 `result/lab/vuln-bank`에 준비한다.

```bash
.venv/bin/python scripts/build_validation_candidates.py
```

실행 중인 Juice Shop에서 읽은 응답 JSON 파일이 있다면 `--challenge-api-snapshot <path>`로 공식 스냅샷과 key/name을 대조할 수 있다. 빌드 스크립트는 요청을 보내지 않는다. 두 DB를 임시 위치에서 모두 검사한 뒤 교체하며, 정답 DB의 `answer_metadata.inventory_sha256`에는 대응하는 후보 DB 해시가 들어간다. 소스 버전이나 파일 해시가 다르면 적재를 중단한다.

로컬 HTTP 관찰 7건을 다시 확인하려면 두 교육용 앱이 실행 중일 때 다음 명령을 쓴다. 실행 중인 Docker 컨테이너의 이미지 ID와 VulnBank checkout commit·파일 해시를 고정 출처와 대조한다. 보고서에는 요청 경로·시각·응답 코드·본문 해시와 길이, 실행 환경 신원을 저장하고 응답 본문은 저장하지 않는다. 리다이렉트는 따라가지 않는다.

```bash
.venv/bin/python scripts/probe_validation_controls.py
```

결과는 `result/test-runs/validation-candidates/LocalControlObservations.json`에 저장한다. 이 관찰은 정답지의 HTTP 코드와 비교하지만, 코드 근거만 있는 merchant 간 접근 판정 2건은 실행하지 않는다.

## Validation 테스트 입력과 채점 준비

다음 명령은 관찰 7건으로 별도 `validation-lab/Pipeline.db`, `TargetPolicy.json`, `CandidateFindingMap.json`을 만든다. 생성 시 실행 환경 신원을 다시 확인하고 같은 URL로 7건을 재요청하여 저장된 응답 상태·본문 해시·길이를 대조한다. 승인된 로컬 `result/Scope/lab-aidast-invalid/{juice-shop,vuln-bank}/Scope.md`와 `Approval.json`을 확인해 두 스캔에 묶는다. TargetPolicy의 속도·동시성·시간 제한은 그 Scope 이하로 설정한다. 후보별 재현 명세와 Attack 요청의 관찰값을 연결하고, `CandidateIntegrityGate`를 모두 통과해야 산출물을 설치한다. 기존 `validation-lab` 디렉터리가 있으면 덮어쓰지 않는다.

```bash
.venv/bin/python scripts/prepare_validation_lab.py
```

이 DB의 Attack `confirmed` 시도 7건은 **오탐을 시험하기 위해 의도적으로 만든 합성 주장**이다. 실제 공격 성공으로 보고하거나 다른 스캔 결과에 합치지 않는다. Validation의 기존 무결성 계약이 confirmed 시도를 요구하므로, 테스트 번들에만 합성 표시와 원래 관찰된 401·404·200 응답을 함께 기록한다. 정답 판정은 이 DB와 매핑 파일에 없으며 `CandidateAnswerKey.db`에만 있다. HTTP 재생 범위는 `127.0.0.1:3001`과 `127.0.0.1:5001`의 `GET`으로 제한하며, 허용 경로도 후보에 필요한 라우트로 좁혔다.

두 실습 앱이 같은 고정 버전으로 실행 중이면, 프로젝트의 기존 Validation 명령을 앱별 스캔에 적용할 수 있다. 실제 실행은 재생 요청을 만들고 Validation 에이전트를 호출한다.

```bash
.venv/bin/aidast validate run result/test-runs/validation-candidates/validation-lab/Pipeline.db --scan-id validation-lab-juice-shop --policy result/test-runs/validation-candidates/validation-lab/TargetPolicy.json
.venv/bin/aidast validate run result/test-runs/validation-candidates/validation-lab/Pipeline.db --scan-id validation-lab-vuln-bank --policy result/test-runs/validation-candidates/validation-lab/TargetPolicy.json
.venv/bin/python scripts/score_validation_lab.py
```

채점 결과는 `validation-lab/ValidationScore.json`에 저장한다. 미실행 사례는 `PENDING`, 두 merchant 신원과 서로 다른 소유 결제 데이터가 필요한 3건은 `NEEDS_PREREQUISITES`다. 이 3건에는 실측 요청이나 확정된 Validation 사례를 만들어 넣지 않았다. 정답 상태와 일치하더라도 현재 단계의 대조군·target 시도·인용 증거·명시적 비취약 근거 또는 영향 점수가 없으면 `PASS`가 아니라 `UNSUPPORTED_DECISION`이다. 현재 기본 HTTP 재생 어댑터는 계약 평가에서 `explicit_non_exploit`을 자동 산출하지 않으므로, 비취약 사례가 재현되지 않았다는 사실만으로 `DISPROVEN`에 도달할 것으로 가정하면 안 된다.

## 실제 첫 실행 결과

2026-09-24에 7건을 실제 실행했다. 양성 1건이 인용된 증거와 함께 `CONFIRMED`되어 `PASS`, 비취약 반례 6건은 `BLOCKED` 또는 `INCONCLUSIVE`여서 `UNRESOLVED`였다. 보류된 merchant 3건은 `NEEDS_PREREQUISITES`다. 세부 요청·대조군·판정 원인과 수정 내역은 [Validation 실습 첫 실행 결과](../test-results/09.24/validation/VALIDATION_LAB_FIRST_RUN.md)에 기록했다. 이후 출처가 고정된 부정 증거를 별도 실습 어댑터로 공급한 재실행에서는 [7건 모두 `PASS`](../test-results/09.24/validation/VALIDATION_LAB_FOLLOWUP.md)했다.

확인 예시:

```bash
.venv/bin/python - <<'PY'
import sqlite3
with sqlite3.connect('result/test-runs/validation-candidates/CandidateInventory.db') as db:
    for row in db.execute('SELECT project, evaluation_status, COUNT(*) FROM attack_candidates GROUP BY project, evaluation_status'):
        print(row)
    print(db.execute('PRAGMA integrity_check').fetchone()[0])
PY
```

## Validation 입력으로 연결할 때

1. 후보의 `endpoint_template`, `method`, `vuln_class`, `source_url`을 검토한다. Juice Shop은 공식 챌린지 정보만으로 경로를 추정하지 않았으므로 먼저 경로와 메서드를 공식 코드 및 실제 Recon 결과에 매핑한다.
2. 로컬 Scope가 허용하고 자격 증명·Runtime이 준비된 후보만 실제 Attack 단계에서 재현한다. `OUT_OF_TEST_SCOPE`와 `MANUAL_ONLY`를 자동 실행 대상으로 사용하지 않는다.
3. 실제 Attack 요청·응답·attempt를 기록하고 성공 근거가 확인된 경우에만 기존 `findings` 및 `finding_reproduction_specs`에 연결한다. 그 후 Validation의 무결성 게이트를 통과하는지 검사한다.

현재 단계에서는 후보 수집·출처 검증, 7건의 격리 실행 입력과 실습 전용 부정 증거 어댑터를 통한 재실행까지 완료했다. 일반 HTTP 재생에는 여전히 독립적인 부정 증거 공급이 필요하다.
