# mitmproxy 관찰 데이터 — 인계 노트

정찰 파이프라인(katana + ffuf 기반)은 돌아가는 상태고, 여기에 Playwright 로그인 세션 동안의 실제 트래픽을 mitmproxy로 관찰해서 더하기로 했다. 이 문서는 그 부분 맡을 사람을 위한 정리.

## 지금 상태 — 뼈대만 있고 핵심 로직은 비어있음

- `src/aidast/recon/tools/mitm_addon.py` — mitmdump용 addon 틀. `response()`가 `NotImplementedError` — flow에서 뭘 뽑아서 어떻게 남길지 구현 필요.
- `src/aidast/recon/tools/mitm_ingest.py` — `load_flows()`(로그 파일 읽기)만 동작. `flows_to_raw_endpoints()`, `ingest_flows_to_db()`는 둘 다 `NotImplementedError` — 구현 필요.
- `src/aidast/recon/db.py`의 `http_exchanges` 테이블 + `insert_http_exchange()` — 스키마/헬퍼는 만들어놨음, 그대로 쓰면 됨.
- `src/aidast/recon/judgment.py`의 `assess_observation_gap()` — 함수 시그니처와 의도만 적어놨고 본문은 `NotImplementedError`.
- `src/aidast/recon/tools/login.py`에 `proxy` 파라미터 추가 — `login_and_capture_session(..., proxy="http://127.0.0.1:8080")`로 부르면 로그인 트래픽이 mitmproxy를 거쳐서 나간다. 이건 동작함.
- `scripts/demo_mitm_login.py` — 로그인 → flow 읽기 → DB 적재로 이어지는 흐름을 보여주는 예시. 위 미구현 함수들을 호출하는 지점에서 멈춘다.

각 파일 상단에 뭘 구현해야 하는지 TODO로 적어놨음. 완성되면 아래처럼 돌아가는 게 목표:

```
# 터미널 1
mitmdump -s src/aidast/recon/tools/mitm_addon.py --set flow_log=mitm_flows.jsonl -p 8080

# 터미널 2
docker run --rm -p 3000:3000 bkimminich/juice-shop

# Juice Shop에서 /#/register로 테스트 계정 만든 다음
JUICE_EMAIL=... JUICE_PASSWORD=... uv run python scripts/demo_mitm_login.py
```

## 왜 이렇게 갈랐냐면

addon은 mitmdump가 띄우는 별도 프로세스에서 돈다. 우리 메인 스크립트랑 같은 프로세스가 아니라서, 거기서 바로 SQLite에 쓰면 두 프로세스가 같은 DB 파일에 동시에 쓰는 상황이 생긴다. 그래서 일단 JSONL로만 남기고, DB 적재는 메인 스크립트 쪽(`mitm_ingest.py`)에서 따로 하는 걸로 나눴다.

## 아직 안 정한 것 (여기서부터 맡을 부분)

**로그인만 하고 끝나면 볼 게 없다.** 지금 `login_and_capture_session()`은 로그인 폼 채우고 제출하는 게 끝이다. mitmproxy가 관찰할 트래픽 자체가 별로 없다는 뜻 — 로그인 이후에 페이지 몇 개 더 돌아다니게 하든, 상품 검색이나 장바구니 담기 같은 시나리오를 몇 개 태우든, 최소한의 상호작용을 추가해야 이 기능이 의미가 생긴다. 어디까지 시킬지부터 정해야 함.

**auth_required 판단.** `http_exchanges.is_authenticated`는 지금 항상 0으로 들어간다. 제일 간단한 방법은 로그인 완료 시각 기준으로 그 이후 flow만 인증된 걸로 치는 건데, 세션 쿠키를 이미 갖고 재방문하는 경우까지 생각하면 이걸로 충분한지는 모르겠다.

**parameters 테이블.** query string이나 요청 바디에서 실제 파라미터 이름/값을 뽑아서 넣는 부분이 아직 없다. `judgment.py`의 `PARAM_PATTERN`(숫자/UUID 감지용)을 재사용하면 될 것 같은데 손은 안 댔음.

**body 저장 여부.** 지금은 request/response body를 아예 안 남긴다. 로그인 트래픽 그대로 남기면 세션 토큰이나 입력값이 DB에 박히기 때문. 나중에 body가 필요해지면 민감한 값 마스킹부터 정하고 컬럼 추가할 것.

**Gap Ratio를 뭘로 쓸지.** `assess_observation_gap()`은 만들어놨는데, 기존 katana 기반 `assess_gap_ratio()`를 대체하는 건지 같이 쓰는 건지는 안 정했다. 개인적으로는 katana 쪽은 "크롤러 내부 비교"고 이건 "진짜 트래픽 vs 크롤러" 비교라 성격이 달라서 둘 다 남기고 따로 보는 게 나을 것 같은데, 얘기해보고 정하면 될 듯.

**mitmproxy 자체를 프로젝트 의존성으로 넣을지.** `pyproject.toml`에는 아직 안 넣었다. katana/ffuf처럼 시스템에 따로 설치하는 외부 도구 취급을 했는데, `pip install mitmproxy`로 가상환경에 넣는 쪽이 나을 수도 있음.

## 참고

- 로그인 폼 셀렉터(`#email`, `#password`, `#loginButton`)는 Juice Shop 전용으로 박혀 있다. 다른 타겟 붙일 일 있으면 이 부분부터 손봐야 함.
- executor.py 쪽에 아직 mitmproxy 관찰을 자동으로 붙이는 배선은 없다. 지금은 `demo_mitm_login.py`로 따로 돌려보는 것까지만 되고, 정식 파이프라인(`ReconExecutor`)에 넣는 건 다음 단계.
