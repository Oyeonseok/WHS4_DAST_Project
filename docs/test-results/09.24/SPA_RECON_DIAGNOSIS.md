# Juice Shop SPA Recon 원인 점검 (2026-09-24)

## 현재 구현과 참고 자료

현재 Recon에는 Playwright의 브라우저 HTTP 요청 관측, SPA hash 화면 확인, 동일 origin JavaScript에서 API 후보를 추출하는 `adaptive_js`, ffuf의 `-ac` 보정이 있다. JavaScript 후보 단계와 테스트는 2026-09-23 commit `69a8c2686d7c2289ba30478ec41a80d376ea0508`에서 추가됐다. 저장소 코드·의존성·commit 기록에서 `insane-search` 직접 사용 또는 출처 표기는 발견되지 않았다. 따라서 [insane-search README](https://github.com/fivetaku/insane-search/blob/main/README.ko.md)와 비슷한 브라우저 네트워크 관측 아이디어는 확인되지만, 해당 프로젝트의 코드를 가져왔거나 그 문서를 직접 참고했다는 사실은 확인할 수 없다. 이 README의 주목적은 공개 페이지 콘텐츠 읽기이며, 여기서 평가하는 인증된 애플리케이션의 route 전수 탐색과 범위가 다르다.

## 관측된 병목

1. **ffuf는 동작하지만 입력 대부분을 끝까지 시도하지 못했다.** 11개 smoke 목록의 300 요청 상한 실행은 정답 GET route를 9개에서 12개로 늘렸다. SecLists API 목록 174개 × root 4개 실험의 실제 GET 요청 관측은 재평가 후 10/71이다. `-maxtime 150`초/root, 0.5 RPS와 공통 요청 예산 아래서 DB에 남은 wordlist 형태의 경로는 root 순서대로 74·73·50·0개였다. `profile`은 목록 106번째, `users`는 158번째라 이 구간 밖이었다.
2. **ffuf의 후보 26개 중 25개는 대상 경로가 아니다.** `endpoint_observations.evidence_json`의 상태는 403이 25개, 500이 1개다. 403 경로 `/rest/connect`~`/rest/group`은 대상 `http_transactions`가 없으며, 정책 프록시가 예산 초과 요청에 반환하는 403이다. 남은 `/api` 500도 71개 정답 GET route에 포함되지 않는다. ffuf 결과를 그대로 endpoint 수로 세면 수집률이 왜곡된다.
3. **SPA JavaScript 후보 단계가 4번 모두 0개를 채택했다.** 호출은 됐고 입력 seed의 API path 수는 8·8·8·9개로 임계값 10보다 낮았다. 즉 임계값 때문에 건너뛴 것이 아니다. 현재 정규식은 작은따옴표·큰따옴표 문자열만 찾는다. 실행 이미지의 공개 `main.js`(1,207,722바이트, `result/test-runs/09.24/seclists-api-500/analysis-input/main.js`, SHA-256 `1fbe46da9b367d28f7c3b80ef6648c593ac18a18c40edc115d0af0639f967aa7`)에 이 정규식의 일치는 0개다. 같은 파일의 백틱 문자열에는 서로 다른 `/api`·`/rest` 경로 42개가 있고, 그중 26개가 71개 GET 정답지의 path와 일치한다. **문자열 일치는 요청 성공이나 GET 호출 증거가 아니므로** 검증 전에는 발견 endpoint로 세지 않는다.
4. **후보 검증의 비교용 요청도 이 대상에서 실패한다.** `/api/__aidast_missing_control__`와 `/rest/__aidast_missing_control__`는 300·500 상한 실행에서 모두 HTTP 500이었다. 구현은 비교용 응답이 500 이상이면 버리고, 비교 기준이 없는 prefix의 모든 후보를 탈락시킨다. 150 상한 실행에서는 이 요청 자체가 저장되지 않았다. 백틱 파싱만 늘려도 현재 검증 조건에서는 Juice Shop 후보가 채택되지 않는다.
5. **차단된 후보가 정규화를 오염시켰다.** SecLists 실행에서 실제 200 응답이 있는 `/rest/languages`가 `normalized_path=/rest/:param`으로 저장되고 `source_tools`에 `ffuf`까지 합쳐졌다. 해당 wordlist에는 `languages`가 없다. 초기 O/X 평가는 endpoint 대표 `path`를 써서 병합된 다른 HTTP 요청을 놓쳤다. 수정된 평가는 실제 transaction URL을 사용한다. Recon의 Surface 정규화는 별도로 수정해야 한다.

## 리팩토링 우선순위

1. 정책 프록시가 만든 차단 응답을 식별 가능한 신호로 표시하고 ffuf 후보에서 제거한다. 실제 대상의 403은 유효한 접근 제한 경로일 수 있으므로 상태 코드 403 전체를 버리는 방식은 피한다.
2. JavaScript 후보 추출에 백틱과 경로 조합을 포함하고, 후보의 HTTP method·source script를 보존한다. SPA 브라우저 네트워크 관측에서 확인된 API 호출과 정적 문자열 후보는 서로 다른 증거 수준으로 기록한다.
3. 비교용 존재하지 않는 경로가 500을 돌려주는 경우에도 대상의 응답 형태에 맞춰 후보를 검증한다. 검증 실패는 `unknown`으로 남기고, 성공한 후보로 자동 승격하지 않는다.
4. 실제 대상 응답이 없는 ffuf 후보를 동적 path 학습과 source 병합에서 제외한다. 원본 path와 각 HTTP 관측의 provenance는 유지한다.
5. 같은 root·wordlist·요청 예산을 고정해 변경 전후를 다시 실행한다. route O/X와 별도로 **실제 시도한 wordlist 조합 수**, 예산 보류 수, 거짓 후보 수를 기록한다.

정답지 71개에는 인증 상태에서 탐색하기 어려운 경로와 parameter route 20개가 포함된다. 따라서 9/71은 고정 route 목록 대비 관측 비율이며, 인증 세션에서 접근 가능한 route만의 recall은 아니다.
