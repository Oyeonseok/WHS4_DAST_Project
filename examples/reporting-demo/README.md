# 보고서 예시 산출물

**합성 예시입니다. 실제 대상에 요청을 보내거나 취약점을 발견한 결과가 아닙니다.**

가상의 청구서 API에서 Account B가 Account A의 청구서 한 건을 읽는 상황을 구성했습니다.
소유자 요청 200, 다른 계정 요청 200, 존재하지 않는 청구서 대조 요청 404는 모두 생성한 fixture 관측입니다.
Severity와 Bugcrowd 분류도 설명용 예시이며 실제 프로그램의 평가나 최신 VRT 검증 결과가 아닙니다.

현재 구현한 보고서 서비스로 출처가 결합된 임시 초안을 만들고, 프로그램 요구사항을 설정한 뒤 자동 검사를 통과해 내보냈습니다.
원본 DB·초안은 임시 자료이며 이 예시 묶음에는 정제한 공개 산출물만 넣었습니다.

| 플랫폼 | 보고서 본문 | 다운로드 |
| --- | --- | --- |
| HackerOne | [Report.md](hackerone/Report.md) | [제출 ZIP](hackerone/hackerone-submission.zip) |
| Intigriti | [Report.md](intigriti/Report.md) | [제출 ZIP](intigriti/intigriti-submission.zip) |
| Bugcrowd | [Report.md](bugcrowd/Report.md) | [제출 ZIP](bugcrowd/bugcrowd-submission.zip) |

각 폴더에는 다음 파일이 있습니다.

- `Report.md`: 플랫폼별 영문 보고서 본문. 합성 예시 표시, 재현 단계, 기대·실제 결과, 한정된 영향과 개선 방안.
- `Submission.json`: 플랫폼 제출 필드와 예시 프로그램 요구사항.
- `Evidence/evidence-001.json` ~ `003.json`: 소유자·다른 계정·존재하지 않는 청구서의 마스킹된 증거 메타데이터.
- `Manifest.json`: 내보내기 revision, 공개 파일 크기와 SHA-256, 마스킹 정책과 검사 참고사항.
- `Checks.json`: 자동 검사 통과 상태, 마스킹 건수, 산출물 검증 결과. 이 설명 파일은 플랫폼 제출 ZIP 바깥에 있습니다.

세 플랫폼 모두 증거 파일의 순서는 다음과 같습니다.

| 파일 | 관측 | 테스트 계정 | 합성 상태 코드 |
| --- | --- | --- | --- |
| `evidence-001.json` | 다른 계정의 청구서 읽기 | Account B | 200 |
| `evidence-002.json` | 존재하지 않는 청구서 대조 | Account B | 404 |
| `evidence-003.json` | 소유자 자신의 청구서 읽기 | Account A | 200 |

동일한 문자열 신원은 보고서와 증거에서 같은 `[EMAIL_n]`·`[TOKEN_n]`으로 치환됩니다. Account A/B 구분은 유지됩니다.
Authorization, Cookie, 이메일과 문자열 사용자 ID의 가상 원문이 ZIP에서 제거됐고, manifest 해시와 원본 불변성을 확인했습니다.
플랫폼마다 같은 시나리오를 독립적으로 생성했으므로 보고서 ID와 revision은 다릅니다.

증거는 **텍스트 메타데이터**입니다. 원시 HTTP 본문·스크린샷·PoC 영상은 포함하지 않습니다.
`ready: true`는 구조·출처·필수 항목 검사를 통과했다는 뜻이며 이 합성 예시의 실제 취약성을 증명하지 않습니다.
전체 예시 ZIP은 `report-examples.zip`, 플랫폼별 검사 요약은 [Verification.json](Verification.json)에 있습니다.
