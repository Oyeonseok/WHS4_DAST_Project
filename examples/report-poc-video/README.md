# 자동 PoC 영상 예시

**합성 예시입니다. 실제 서비스에 요청하거나 취약점을 발견한 결과가 아닙니다.**

가상 청구서 API의 소유자·다른 계정·없는 기록 비교 증거를 실제 보고서 서비스로 마스킹하고,
Chromium에서 장면을 렌더링한 뒤 VP8 WebM 영상으로 자동 인코딩했습니다.
영상은 저장된 증거의 설명이며 실제 대상 화면 녹화나 실시간 재현 영상이 아닙니다.

- [설명 영상](PoC/Video.webm)
- [첫 장면 미리보기](Preview.png)
- [영상 포함 제출 ZIP](hackerone-with-poc.zip)
- [스토리보드](PoC/Storyboard.json)
- [영상 출처·무결성 메타데이터](PoC/Metadata.json)
- [검증 결과](Verification.json)

전체 영상 디코딩, ZIP 해시, 출처 revision, 가상 인증정보·이메일 마스킹과 원본 불변성을 검사했습니다.
이 예시의 200/404 응답과 영향은 모두 합성 fixture 관측입니다.
