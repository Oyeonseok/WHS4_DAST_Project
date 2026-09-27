# feroxbuster 대체 가능성: 로컬 Juice Shop GET 비교 (2026-09-27)

`feroxbuster`가 없어서 Homebrew 공식 Formula로 2.13.1을 설치했다. [Homebrew Formula](https://formulae.brew.sh/formula/feroxbuster)와 [공식 릴리스](https://github.com/epi052/feroxbuster/releases)를 확인했다. 이 실험은 Recon 제품 코드에 feroxbuster를 연결하지 않는다.

대상은 승인된 `http://127.0.0.1:3001/` 한 곳이다. 이전 ffuf 워드리스트의 **앞 50개 단어**만 루트 경로에 사용했다. 세 실행 모두 인증 헤더 없이 GET만 보냈고, 재귀·링크 추출·리다이렉트 추적을 끄고 도구 스레드는 1개로 제한했다. 실험 프록시가 TargetPolicy의 호스트·포트·경로·GET 허용을 검사하고, 대상 요청을 최소 2초 간격(0.5 RPS)으로 전달하며 **도구 실행당 최대 100회**를 강제한다. 세 실행의 이론상 상한은 300회로 승인 정책의 1,000회보다 낮고, 실제 전달 합계는 **166회**였다. feroxbuster 자체 `--rate-limit 1`은 1 RPS이므로 정책 속도 제한은 실험 프록시가 맡았다. 실행 스크립트는 [compare_local_get.py](compare_local_get.py)이고 원본 결과는 `result/test-runs/09.27/feroxbuster-get-comparison/`에 있다.

| 실행 | 종료 코드 | 대상 전달 요청 | 최소 기록 간격 | 도구가 출력한 응답 후보 |
| --- | ---: | ---: | ---: | ---: |
| feroxbuster 기본 필터 | 0 | 55 | 2.000초 | 51건 |
| ffuf `-ac` | 0 | 56 | 2.002초 | 1건 |
| feroxbuster `--filter-size 9393` | 0 | 55 | 2.000초 | 1건 |

feroxbuster 기본 출력의 51건 중 50건은 크기가 같은 200 HTML 응답이다. Juice Shop SPA fallback 때문에 존재하지 않는 경로도 200을 반환해, 이 결과를 실제 엔드포인트로 세면 오탐이다. 나머지 한 건은 `/api`의 500 응답이다. ffuf 자동 보정과 feroxbuster의 9,393바이트 크기 필터를 적용한 출력은 모두 `/api` 한 건이었다. `/api`는 기존 71개 명시적 GET 정답 경로에 없어서 **세 실행 모두 GET 수집률 증가가 0개**다.

이 결과는 **도구 실행과 정책 속도 준수는 가능하지만, 현재 설정에서 ffuf보다 GET 수집이 늘어난다는 증거는 없다**는 뜻이다. feroxbuster의 정적 크기 필터 값은 Juice Shop 현재 SPA 응답에 의존하므로 범용 설정으로 쓰면 안 된다. 향후 교체 실험에는 응답 지문을 이용한 동적 fallback 분리, 인증 세션 전달, 동일한 여러 루트와 전체 워드리스트, 결과를 실제 HTTP 응답·Surface에 연결하는 평가가 필요하다.

실험 프록시가 전달한 요청 수에는 도구 종료 시 연결이 끊겨 응답 기록이 완성되지 않은 요청 한 건이 포함될 수 있다. 최소 간격은 완성된 요청 로그 기준이다.
