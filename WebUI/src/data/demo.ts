import type { Snapshot } from '../lib/events';

export const DEMO_SCAN = 'demo_local_042';
export function demoSnapshot(): Snapshot {
  return {
    version: 1, scan_id: DEMO_SCAN, last_event_id: 7, status: 'running', stage: 'Attack', progress: 62, requests: 391, budget: 2000, endpoints: 218,
    findings: [
      { id: 'F-0042', title: '테스트 계정별 객체 접근 결과가 다름', severity: 'HIGH', status: 'unreviewed', endpoint: 'GET /api/accounts/{id}', cwe: 'CWE-639' },
      { id: 'F-0041', title: '검색 응답에 입력값이 반사됨', severity: 'MEDIUM', status: 'unreviewed', endpoint: 'GET /search', cwe: 'CWE-79' },
      { id: 'F-0040', title: '응답 헤더에 서버 버전이 노출됨', severity: 'LOW', status: 'confirmed', endpoint: 'GET /health', cwe: 'CWE-200' },
      { id: 'F-0039', title: '응답 보안 헤더가 누락됨', severity: 'INFO', status: 'rejected', endpoint: 'GET /', cwe: 'CWE-693' },
    ],
    logs: [
      { id: 1, time: '2026-09-20T05:28:00Z', stage: 'Scope', level: 'success', message: '데모 스코프와 승인 해시가 일치합니다. 합성 실습 환경만 사용합니다.' },
      { id: 2, time: '2026-09-20T05:28:04Z', stage: 'Recon', level: 'success', message: '데모 자산 목록 확정 · Recon.db 경로 218개' },
      { id: 3, time: '2026-09-20T05:28:09Z', stage: 'Recon', level: 'info', message: 'Handoff.json 출처 검증 완료 · Pipeline.db 생성' },
      { id: 4, time: '2026-09-20T05:28:12Z', stage: 'Attack', level: 'info', message: '접근 제어 템플릿 묶음 시작 · 작업 136개 중 84개' },
      { id: 5, time: '2026-09-20T05:28:18Z', stage: 'Attack', level: 'warning', message: '응답 차이를 탐지했습니다. 검증이 필요한 후보입니다.' },
      { id: 6, time: '2026-09-20T05:28:21Z', stage: 'Attack', level: 'success', message: '민감정보를 제거한 증거 쌍 저장 · 인증정보 참조 제외' },
      { id: 7, time: '2026-09-20T05:28:24Z', stage: 'Attack', level: 'info', message: 'F-0042를 검토 대기열에 추가 · 매처 결과만으로 판정하지 않음' },
    ],
  };
}
