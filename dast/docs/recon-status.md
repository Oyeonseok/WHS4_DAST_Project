# 정찰 파이프라인 현황

Codex 없이 돌아가는 정찰 MVP 상태 정리. Juice Shop(`http://localhost:3000`) 대상으로 실제로 돌려보면서 잡은 문제들 위주로 적어놨다.

## 구조

```
ReconCoordinator (기존)  ->  Task 목록 생성, Codex 불필요
ReconExecutor (신규)     ->  Task를 순서대로 실행
  ├─ HTTP_PROBE          urllib로 살아있는지만 확인
  ├─ ORIGIN_DISCOVERY    정적 HTML 시그니처로 SPA 여부 1차 추정
  └─ ENDPOINT_DISCOVERY  아래 참고
```

`scripts/demo_juiceshop.py`가 Codex 없이 Scope/Plan을 직접 만들어서 이 전체를 한 번에 돌리는 진입점. `FFUF_WORDLIST`, `JUICE_EMAIL`/`JUICE_PASSWORD` 환경변수로 옵션 켜고 끔.

## ENDPOINT_DISCOVERY 실행 순서

여러 번 회의하면서 정리된 최종 순서:

1. katana를 standard/headless 두 모드로 다 돌린다
2. 그 둘을 합쳐서 "전체"로 두고, headless에만 나온 것을 분자로 비율(Gap Ratio)을 구한다
3. 비율이 임계값(30%) 넘으면 — SPA 성격 강하다고 판단, `origins.spa_detected`가 틀려있으면 정정
4. 그 다음에야 ffuf(브루트포스)를 돌려서 최종 결과에 합친다

ffuf를 Gap Ratio 계산에서 빼놓은 이유: ffuf는 워드리스트를 무작위로 찔러보는 방식이라 katana의 "링크 추적 vs JS 렌더링" 비교랑 성격이 다르다. 섞으면 ffuf가 많이 찾을수록 비율이 오염된다(실제로 한 번 4700건 넘게 flood나서 비율이 100%→1%로 튄 적 있음). ffuf에 `-ac`(자동보정) 옵션도 걸어놔서 SPA의 soft-404 패턴 때문에 워드리스트 전체가 허위로 매치되는 것도 막아놨다.

origin_discovery의 정적 SPA 판단(`spa_detected`)은 더 이상 실행 분기에 안 쓴다. Juice Shop 자체가 Angular라 실제론 SPA인데 정적 HTML만 보고는 "아니다"로 잘못 판단했던 적이 있어서 — JS가 만드는 마커(`ng-version` 등)는 브라우저가 부트스트랩한 다음에야 생기니까 urllib으로는 애초에 볼 수가 없다. 그래서 katana 두 모드를 실측으로 비교하는 쪽으로 바꿨고, 정적 판단은 참고 기록으로만 남긴다.

## 로그인 세션

`tools/login.py` — Playwright로 로그인 폼 채우고 제출한 다음 쿠키 + localStorage를 캡처한다. Juice Shop은 JWT를 쿠키가 아니라 로그인 후 localStorage에 저장해서(Angular 인터셉터가 Authorization 헤더로 붙이는 방식), 쿠키만 봐서는 인증이 안 되고 localStorage까지 같이 읽어야 했다. 캡처한 세션은 katana/ffuf 커맨드에 `-H` 헤더로 그대로 넘겨서 로그인된 상태로 크롤링하게 만든다.

로그인 폼 셀렉터는 Juice Shop 전용으로 박혀있다(`#email`, `#password`, `#loginButton`). 다른 타겟엔 못 씀.

## 알려진 문제 / 안 채워진 것

- **auth_required, parameters 테이블** — 둘 다 비어있다. katana/ffuf는 URL 문자열만 다루기 때문에 실제 요청 헤더나 파라미터 정보가 없다. (mitmproxy 붙이면 여기서 채울 수 있을 것 — `docs/observation-mitmproxy.md` 참고)
- **content_type** — katana는 항상 None. `-json` 출력 모드로 안 바꾸고 plain text로만 받고 있어서 그렇다. ffuf는 실제 응답을 받으니 값이 채워진다.
- **subfinder** — 코드는 있는데(`tools/asset_dns_port.py`) 한 번도 안 돌려봄. Juice Shop이 URL 스코프라 ASSET_DISCOVERY 자체가 스킵됨. 더 큰 문제는 subfinder가 서브도메인을 찾아도 그걸로 새 Task를 만드는 로직이 없다는 것 — Task 목록이 subfinder 실행 전에 이미 확정되기 때문. 발견만 하고 활용을 안 함.
- **httpx** — 안 쓰고 `urllib` 기반 최소 구현(`tools/http_probe.py`)으로 대체했다. 단일 URL 확인엔 충분한데 기술스택 탐지, title, 여러 호스트 동시 처리 같은 httpx 원래 기능은 없다.
- **Hunt-Dispatch** — 코드 자체가 없음. 정찰 다음 단계라 이번 스코프 밖.
- **자동 테스트 없음** — `tests/`는 Codex 이전 단계(Scope, Task 생성)만 커버. 여기 새로 짠 것들(db.py, executor.py, judgment.py 등)은 실행해보고 눈으로 확인하는 것 말고 검증된 게 없다.
- **재실행 시 DB 누적** — `_ensure_asset()`이 기존 레코드를 확인 안 하고 매번 새로 만든다. `demo_juiceshop.py`는 실행 전에 DB를 통째로 지우는 걸로 우회해놨는데, 여러 스캔을 이력으로 남기려면 이걸로는 안 됨.
- **WAL 모드 이슈** — WSL에서 Windows 드라이브(`/mnt/c/...`) 마운트 경로는 SQLite WAL이 필요로 하는 파일 락을 지원 안 해서 DB 생성 자체가 깨졌었다. 지금은 기본 저널 모드(DELETE)로 바꿔놨음.

## 실행 방법

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop

cd dast
FFUF_WORDLIST=/path/to/wordlist.txt \
JUICE_EMAIL=test@test.com JUICE_PASSWORD=Test1234! \
uv run python scripts/demo_juiceshop.py
```

katana/ffuf 없이도 돌아간다(둘 다 없으면 그냥 건너뛰고 경고만 찍음). `recon_juiceshop.db`, `Surface.json` 생김.
