# Juice Shop Recon용 SecLists wordlist 선정

SecLists는 커뮤니티가 관리하는 wordlist 저장소다. 기존 `common-api-endpoints-mazen160.txt`도 해당 저장소의 파일이지만, 174개의 일반 API 단어 목록이므로 Juice Shop의 웹 경로와 중첩 API 경로를 평가하는 주 목록으로는 좁다. 아래 세 파일은 모두 같은 고정 커밋 `8420764ea28d5cdc1a8bbb8311736a2235be28c4`에서 받았다. 원본 파일은 `wordlists/` 아래에 수정 없이 보관했다.

| 파일 | 줄 수 | SHA-256 | 71개 GET 정답 경로와 단순 경로 일치 |
| --- | ---: | --- | ---: |
| [기존 API 단어 목록](wordlists/common-api-endpoints-mazen160.txt) | 174 | `cd774e12b54e075ac7c34b95b9f2ad908461e0ae43c57fc82976020575adb059` | 1 |
| [SecLists API endpoint 목록](wordlists/api-endpoints.txt) | 295 | `7860e451bec345a022018a4f76c820d2e7e130df480e31b80dc35dda06762a46` | 0 |
| [SecLists common 웹 경로 목록](wordlists/common.txt) | 4,752 | `47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a` | 10 |

원본: [기존 API 단어 목록](https://github.com/danielmiessler/SecLists/blob/8420764ea28d5cdc1a8bbb8311736a2235be28c4/Discovery/Web-Content/common-api-endpoints-mazen160.txt), [API endpoint 목록](https://github.com/danielmiessler/SecLists/blob/8420764ea28d5cdc1a8bbb8311736a2235be28c4/Discovery/Web-Content/api/api-endpoints.txt), [common 웹 경로 목록](https://github.com/danielmiessler/SecLists/blob/8420764ea28d5cdc1a8bbb8311736a2235be28c4/Discovery/Web-Content/common.txt). SecLists의 [Web-Content README](https://github.com/danielmiessler/SecLists/blob/8420764ea28d5cdc1a8bbb8311736a2235be28c4/Discovery/Web-Content/README.md)는 웹 경로·파일 탐색용 목록의 용도를 설명한다.

단순 일치는 목록의 각 항목을 root `/`에 붙여 비교하고, 일반 단어 목록 두 개는 `/api/`, `/rest/`에도 붙여 비교한 값이다. 실행 결과나 HTTP 유효성 점수가 아니다. `:id` 같은 동적 route도 채우지 않았고, GET 정답지만 비교했다. 이 분석은 **목록 선정의 진단**으로만 사용해야 하며, 정답지에 맞춰 항목을 발췌해 실제 수집률 실험에 사용하면 평가에 정답 누출이 생긴다.

현재 Recon은 ffuf에 `-maxtime 150`초/root와 0.5 RPS를 적용한다. 상한 1,000건 실험에서도 각 root의 74~75번째 항목까지만 도달했다. `common.txt`의 일치 항목 중 가장 앞선 `/.well-known/security.txt`도 89번째이고, `/profile`은 3,328번째다. 따라서 파일만 교체하면 추가 수집 여부를 공정하게 판단할 수 없다. 4,752줄 전체를 0.5 RPS로 한 root에 요청하는 이론적 최소 시간은 약 2시간 38분이며, 네 root는 약 10시간 34분이다. 실제 실행에는 보정 요청과 후속 탐색도 든다.

**다음 비교 실험의 주 목록은 수정하지 않은 `common.txt`로 고정한다.** 실행 전 ffuf의 root 선택, 요청 예산, per-root 시간 제한을 목록 크기에 맞게 설계하고, 실제 시도한 항목 수와 대상 HTTP 응답으로 수집률을 평가한다. `api/api-endpoints.txt`는 일반 API 발견 보조 목록으로만 보관한다.
