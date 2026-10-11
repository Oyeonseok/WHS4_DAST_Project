# 플랫폼 미지정 대상의 기본 보고서

## 원인과 변경

통합 실행은 프로그램 URL에서 HackerOne·Bugcrowd·Intigriti를 식별하지 못하면
보고서 단계를 건너뛰었다. 보고서 스키마와 대시보드도 이 세 형식만 허용했다.

미지정·미식별 플랫폼은 이제 `generic` 형식을 사용한다. 별도 작성 지침과
기본 Markdown 형식으로 대상, 취약점, 요약, 재현 절차, 기대·실제 결과, 영향,
개선 권고를 기록한다. 특정 대상 이름이나 경로에 따른 예외는 없다.
대시보드는 일반 보고서를 표시하며 플랫폼 규칙 확인 없이 마스킹된 ZIP을
다운로드할 수 있다. 추가 필수 필드·심각도 요구사항은 설정했을 때 적용한다.

현재 완료된 `CONFIRMED` case, Scope 적격성, 근거 인용과 해시, 마스킹,
최신 revision 검사는 유지한다. 확정된 case가 없으면 보고서를 생성하지 않는다.
기존 플랫폼의 작성 지침·템플릿·발행 스키마는 보존해 이전 보고서 재실행도 지원한다.

## 검증

- 보고서·CLI·대시보드 관련 백엔드: 242 tests + 106 subtests 통과.
- Node 24.18.0 UI 테스트: 110개 통과.
- UI i18n 검사·TypeScript 검사·Vite production build 통과.
- 기본 보고서 생성 → 대시보드 조회 → 요구사항 검사 → 실제 ZIP 응답을 ASGI로 검증.
- 두 AI 작성 어댑터의 일반 보고서 skill staging을 검증.
- 기존 세 플랫폼의 이전 스키마 재실행 및 산출물 바이트 유지, 스키마 변조 거부 검증.

AI 응답은 테스트 작성기로 대체했다. 실제 Juice Shop 재스캔이나 실제 모델의
보고서 작성 품질 검증은 이번 변경에서 수행하지 않았다.

## 적용

실행 중인 대시보드 백엔드를 다시 시작한 뒤 새 통합 스캔에 적용된다.
기존 완료 스캔에는 자동 소급 생성하지 않는다. 기존 확정 case는 다음과 같이 생성한다.

```bash
aidast report run result/AttackRuns/<platform>/<program>/<scan_id>/Pipeline.db \
  --case-id <case_id> \
  --platform generic \
  --output-dir result/ReportRun/<scan_id>/<case_id>
```

기존 미커밋 Recon·정책·런타임 변경은 보존했다.
