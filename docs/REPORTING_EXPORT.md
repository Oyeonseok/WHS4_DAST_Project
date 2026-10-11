# 보고서 검사와 제출용 패키지

보고서 초안은 기존 `Report.db`, `Report.json`, `Report.md`에 보존됩니다. 제출용 내보내기는 현재 Validation 판정과 스코프, 증거 연결, 플랫폼 필수 필드 및 민감정보 처리를 다시 검사합니다. 자동 검사를 통과하면 별도 승인 없이 ZIP을 내려받을 수 있습니다.

첫 버전은 텍스트 보고서와 저장된 증거 **메타데이터**를 처리합니다. 이미 수집 단계에서 제외한 HTTP 본문이나 인증정보를 복원하지 않습니다. 선택적으로 정제된 저장 증거를 설명하는 WebM 영상을 자동 생성할 수 있습니다. [PoC 증거 재생 영상](REPORTING_POC_VIDEO.md)을 참고하세요. 대상 화면의 연속 녹화와 원시 스크린샷 마스킹은 지원하지 않습니다.

## 대시보드

Reports에서 보고서를 열면 플랫폼별 제출 필드, 정제된 증거, 민감정보 처리 건수와 자동 검사 결과를 볼 수 있습니다. 프로그램 요구사항에는 확인한 프로그램 지침의 URL 또는 설명, 필수 필드, 추가 필드와 선택적인 Markdown 양식을 입력합니다. “프로그램 요구사항 확인”은 사용할 양식을 설정하는 항목입니다. 보고서 최종 승인 단계는 없습니다.

프로그램 요구사항을 저장하면 검사를 다시 실행합니다. 누락 항목이 없으면 **제출용 ZIP 내보내기**가 활성화됩니다. 검사 이후 판정·증거·양식이 바뀌면 서버는 이전 검사 결과를 거부하므로 새로 검사해야 합니다.

## CLI

먼저 프로그램 요구사항을 JSON으로 저장합니다. 예를 들어 severity를 필수로 요구하는 HackerOne 프로그램이라면:

```json
{
  "verified": true,
  "source": "https://hackerone.com/example-program",
  "severity_required": true,
  "required_fields": ["summary", "steps_to_reproduce", "impact"],
  "additional_fields": {},
  "report_template": null,
  "impact_template": null
}
```

```bash
aidast report check result/ReportRun/<scan_id>/<case_id>/Report.db \
  --requirements program-requirements.json

aidast report export result/ReportRun/<scan_id>/<case_id>/Report.db \
  --output submission.zip
```

`check`는 검사 결과 JSON을 출력하고 통과 시 0, 차단 시 1을 반환합니다. `export`는 매번 같은 검사를 다시 수행합니다. `--revision <revision_sha256>`를 지정하면 이전에 확인한 버전과 같은지도 검사합니다. 내보내기는 기존 파일을 덮어쓰지 않습니다.

현재 출처 검증을 제공하는 case 기반 Report.db v2가 내보내기 대상입니다. 이전 보고서는 기존 미리보기·초안 조회를 유지하며, 현재 Validation에서 다시 생성한 보고서로 최종 내보내기를 진행합니다.

## 플랫폼 필드와 프로그램 양식

- HackerOne: `title`, `asset`, `weakness`, `summary`, `steps_to_reproduce`, `impact`, 프로그램별 `severity`와 추가 필드.
- Intigriti: `title`, `asset`, `vulnerability_type`, `endpoint`, `description`, `steps_to_reproduce`, `impact`, `severity`/`cvss_vector`.
- Bugcrowd: `title`, `target`, `vrt_category`, `technical_severity`, `description`, `steps_to_reproduce`, `demonstrated_impact`.

`required_fields`는 값이 있어야 하는 제출 필드 이름 목록입니다. `additional_fields`는 프로그램에서 추가로 요구하는 항목의 이름과 값입니다. 이름에는 `test_account`처럼 영문 소문자·숫자·밑줄을 사용합니다. 표준 필드를 추가 필드로 덮어쓸 수 없습니다. Severity나 VRT를 판단할 근거가 없으면 초안 생성 단계의 분류를 보강해야 합니다. 검사기가 분류를 만들어 넣지 않습니다.

`report_template`과 `impact_template`은 `{summary}`, `{steps_to_reproduce}`, `{impact}`처럼 제출 필드를 참조합니다. 선택한 플랫폼에서 제공하지 않는 이름이나 비어 있는 필드를 사용하면 내보내기가 차단됩니다. 프로그램에 별도 양식이 없다면 기본 플랫폼 양식을 사용할 수 있습니다.

## HTTP API

```text
GET  /api/v1/reports/{report_id}/submission
POST /api/v1/reports/{report_id}/requirements
GET  /api/v1/reports/{report_id}/export?revision={revision_sha256}
```

요구사항 저장은 JSON 본문과 same-origin 요청을 요구합니다. 내보내기가 차단되거나 검사 버전이 달라지면 409를 반환합니다. 검사 결과는 `ready`, `revision_sha256`, `checks`, `fields`, `evidence`, `redactions`를 제공합니다.

요구사항 JSON은 128 KiB까지 받습니다. 생성 본문과 전체 증거 메타데이터는 각각 2,000,000 바이트, 증거는 최대 2,048개, 전체 제출 패키지는 압축 전 8,000,000 바이트로 제한합니다. 반복된 템플릿 확장도 이 제한을 적용하며 초과 시 내용을 잘라 내보내지 않고 차단합니다.

## 원본 보존과 마스킹

원본 초안과 증거를 변경하지 않고 제출용 사본에서 인증 헤더, 쿠키, 비밀번호·토큰·API key와 알려진 개인정보를 정제합니다. 같은 민감값은 한 사본 안에서 같은 자리표시자로 치환해 계정별 차이를 보존합니다. ZIP에는 정제한 본문·제출 필드·증거 메타데이터와 공개용 manifest만 포함합니다. 로컬 데이터베이스, 원본 경로, 원문 비밀값이나 치환표는 포함하지 않습니다.

문자열 식별자의 자리표시자는 보고서 작성과 내보내기 사이에도 유지됩니다. 마스킹된 요구사항에서 다른 항목만 수정하면 기존 민감값은 비공개 저장 자료에 유지합니다. 숫자 등 비문자형 민감 필드는 `[REDACTED]`로 처리하므로 그 필드의 계정별 차이는 보존하지 않습니다.

검사는 저장 자료를 사용합니다. 대상 서버에 새로운 재현 요청을 보내지 않습니다. 필드가 채워졌다는 사실만으로 취약점 영향이나 모든 문장의 의미가 증명됐다고 판정하지 않으며, 이름이 없는 임의의 비밀값을 모두 탐지한다고 보장하지 않습니다.
