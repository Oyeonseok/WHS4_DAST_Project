# 자동 PoC 설명 영상 검증 — 2026-09-28

저장된 마스킹 증거를 `evidence_replay` WebM으로 자동 구성하고, 자동 검사 후 제출 ZIP에 첨부한다. 대시보드 기본 영상 포함, 생성·미리보기, CLI `report export --poc`를 제공한다. 실시간 대상 화면 녹화 기능은 이번 범위에 포함하지 않았다.

## 검증 결과

- 현재 작업 폴더의 reporting/Validation browser/web dashboard 회귀: **218 passed, 100 subtests passed**, 20.24초.
- 현재 작업 폴더 WebUI: **100 passed**, `npm run build`의 i18n·TypeScript·Vite 검사 통과.
- 백엔드 집중 검사: **89 passed**. 출처 변경, ZIP 압축 중 변경, 캐시·메타데이터 변조, 심볼릭 링크, 동시 생성, 시간·크기 제한과 기존 텍스트 ZIP 호환성을 검사했다.
- 실제 Chromium + Playwright FFmpeg: 합성 청구서 관측 3개에서 **10장면, 50초, 1280×720, VP8 WebM 321,285바이트** 생성. 전체 프레임 디코딩, ZIP SHA-256, 원본 불변성과 가상 인증정보·이메일 마스킹 확인.
- 실제 Chromium에서 긴 영문 및 CJK 문장이 화면 밖으로 잘릴 때 생성 차단 확인.
- 실제 React 컴포넌트와 합성 API 응답: 영상 포함 기본값, 자동 생성 요청, ZIP 다운로드, 50초 영상 미리보기, 요구사항 수정 시 미리보기 제거·내보내기 차단 확인.
- 작업별 리뷰 및 전체 리뷰 완료. ZIP 압축 완료 후 revision 재검사와 PoC 상태 문자열 검증 보완을 재검토했다. 미해결 리뷰 지적 없음.

## 산출물

- [영상](../../../examples/report-poc-video/PoC/Video.webm)
- [영상 포함 제출 ZIP](../../../examples/report-poc-video/hackerone-with-poc.zip)
- [예시 설명 및 검증 자료](../../../examples/report-poc-video/README.md)
- [사용 안내](../../REPORTING_POC_VIDEO.md)

합성 예시는 실제 대상에 요청하거나 취약점을 확인한 결과가 아니다. 영상은 저장 증거 설명이며 기존 패턴 마스킹 한계를 그대로 적용한다. 검증 과정에서 기존 Scope·Recon 작업과 승인·실행 자료는 보존했다.
