# Juice Shop Swagger UI 반영 후 Recon 수집률 (2026-09-26)

## 조건

- 대상: 로컬 OWASP Juice Shop 20.2.0, `http://127.0.0.1:3001/`. Docker 이미지 digest는 `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`이다.
- 비교 기준: `result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26/`의 완료된 인증 Recon. 동일한 승인 Scope, `primary` 인증 세션, 고정 TargetPolicy SHA-256 `4e5b13b7b5cbbf436a34ee9de36602fbbd7529a7b44950caaa5c6aa3695c8462`를 사용했다.
- 설정: 요청 상한 1,000, 0.5 RPS, 동시성 1, 최대 깊이 2, 요청 timeout 15초, ffuf 루트당 최대 150초. 워드리스트 SHA-256은 `cd774e12b54e075ac7c34b95b9f2ad908461e0ae43c57fc82976020575adb059`이다.
- 프로젝트 HEAD는 `226c6c5`이고 실행 당시 Recon 코드에는 커밋되지 않은 변경이 있었다. `api_secondary_discovery.py` SHA-256은 `d4ecbd5c84937e6651d9122fe5937fe42d85d689dca44019a4ea25b336990cca`, `endpoint_discovery.py`는 `c6e26e4756be1201ccab0a7976153fdf98e482bfb09778062dfbd2c5044a1e31`, `playwright_driver.py`는 `fc13cd63b7c1e208def91ce8984a4ea9a489a0685f0dd1f0434a3e687e55a0d3`이다. 현재 작업 트리에는 Swagger UI와 인증 Runtime 관련 변경이 함께 존재하므로 단일 코드 변경의 인과 효과는 이 비교만으로 분리할 수 없다.
- 비교 실험용 고정 정책 래퍼로 CLI Recon만 실행했다. GUI 전체 파이프라인, Attack, Chaining, Validation은 실행하지 않았다.

실행 명령:

```bash
mkdir -p result/test-runs/09.26/juice-openapi-1000
RECON_TEST_RUN_ROOT=result/test-runs/09.26/juice-openapi-1000 \
  PYTHONUNBUFFERED=1 \
  bash docs/test-results/09.24/run-recon-retest-pinned-policy-2026-09-26.sh \
  > result/test-runs/09.26/juice-openapi-1000/run.log 2>&1
```

완료 scan ID는 `scan_f0ef760c69064abf97a165a7f0c9b801`이다. `Recon.db`의 상태는 `completed`이고 `PRAGMA foreign_key_check` 결과는 비어 있다. 원본 DB, Surface, Scope 복사본, 로그는 위 새 결과 폴더에 보존했다.

## 결과

| 지표 | 직전 정상 실행 | 이번 실행 |
| --- | ---: | ---: |
| OpenAPI 명세 확인 | 0 | 1 (`/api-docs`의 Swagger UI 내장 명세) |
| ZAP이 보고한 API 2차 후보 | 0 | 2 |
| 저장된 HTTP transaction | 425 | 508 |
| 정답 GET 경로의 실제 응답 증거 | **25/71 (35.2%)** | **25/71 (35.2%)** |
| 최종 Surface의 정답 GET 경로 | **25/71 (35.2%)** | **25/71 (35.2%)** |

[GET 응답 증거 O/X](GET_ROUTE_MATRIX.md)와 [Surface O/X](SURFACE_ROUTE_MATRIX.md)에 71개 정답 경로 전체를 비교했다. 두 실행에서 O/X가 바뀐 GET 경로는 없다. 정답지는 Juice Shop의 명시적 애플리케이션 GET route 71개를 기준으로 하며, 모든 route가 이 인증 세션에서 접근 가능하다는 뜻은 아니다.

이번 실행은 `/api-docs`에서 명세를 확인하고 ZAP에 전달했다. 공식 Juice Shop `swagger.yml`에는 서버 경로 `/b2b/v2`와 `POST /orders` 한 작업만 있으므로, 이 명세가 71개 GET 기준 경로를 직접 늘리지는 않는다. Recon의 현재 능동 요청 허용 메서드도 GET, HEAD, OPTIONS이고 GraphQL 프로브는 비활성화돼 있다.

ZAP이 신규 후보로 보고한 `GET /b2b`와 `GET /b2b/v2`에는 Recon DB의 실제 HTTP transaction이 연결돼 있지 않다. 별도 읽기 전용 GET에서 `/b2b`는 HTML 200, `/b2b/v2`는 HTML 401을 반환했다. 서버 코드는 `/b2b/v2`에 인증 미들웨어를 두고 `/b2b/v2/orders`에 POST 작업을 등록한다. 따라서 이 두 후보를 검증된 GET 엔드포인트나 수집률 향상으로 계산하지 않았다. ZAP 로그에는 경고가 있었지만 상세 원인은 기록되지 않았다. 명세에서 가져온 경로와 실제 응답으로 확인된 경로를 구분하는 후속 보완이 필요하다.

평가기 명령:

```bash
.venv/bin/python docs/test-results/09.24/evaluate_recon_get_routes.py \
  --ground-truth docs/test-results/09.24/JUICE_SHOP_GET_GROUND_TRUTH.json \
  --run baseline=result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26/Recon.db \
  --run current=result/test-runs/09.26/juice-openapi-1000/Recon.db \
  --surface-run baseline=result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26/Surface.json \
  --surface-run current=result/test-runs/09.26/juice-openapi-1000/Surface.json \
  --output docs/test-results/09.26/recon-openapi/GET_ROUTE_MATRIX.md \
  --surface-output docs/test-results/09.26/recon-openapi/SURFACE_ROUTE_MATRIX.md
```
