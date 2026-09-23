import type { Language } from './i18n';

export type ActivityMessage = {
  message: string;
  message_code?: string | null;
  message_params?: Record<string, string | number>;
};

const auditLabels: Record<string, string> = {
  'stage.started': '단계 시작',
  'stage.resumed': '단계 재개',
  'stage.completed': '단계 완료',
  'stage.failed': '단계 실패',
  'task.created': '작업 생성',
  'task.cancelled': '작업 취소',
  'credential_reference.created': '인증정보 참조 생성',
  'scope.verified': '스코프 검증',
  'pipeline.materialized': '파이프라인 생성',
  'request.authorized': '요청 승인',
  'finding.created': '취약점 후보 생성',
  'recon.activity': '정찰 도구 활동',
};

const reconPhaseLabels: Record<string, string> = {
  subfinder: 'Subfinder 하위 도메인 탐색', dnsx: 'dnsx DNS 확인',
  naabu: 'naabu 포트 탐색', nmap: 'nmap 포트 확인',
  asset_discovery: '자산 탐색', dns_resolution: 'DNS 확인', host_port_discovery: '호스트·포트 탐색',
  http_probe: 'HTTP 확인', origin_discovery: '웹 원점 확인', endpoint_discovery: '엔드포인트 수집',
  playwright_bootstrap: 'Playwright 브라우저·세션 준비', playwright_priority: 'Playwright 우선 페이지/API 관측',
  katana_standard: 'Katana 일반 크롤링', katana_headless: 'Katana 브라우저 크롤링',
  playwright_interaction: 'Playwright 화면 상호작용', ffuf: 'ffuf 경로 탐색',
  api_secondary: 'API 명세·GraphQL 추가 탐색', openapi_detection: 'OpenAPI 명세 확인',
  graphql_detection: 'GraphQL 엔드포인트 확인', zap_openapi: 'ZAP OpenAPI 탐색',
  zap_graphql: 'ZAP GraphQL 탐색', mitm_capture: 'mitmproxy 요청 캡처',
};
const reconStateLabels: Record<string, string> = {
  started: '시작', finished: '종료', skipped: '건너뜀', failed: '실패', planned: '작업 범위 결정',
};

export function reconActivityLabel(params: Record<string, string | number>): string {
  const phase = reconPhaseLabels[String(params.phase)] ?? '정찰 작업';
  const state = reconStateLabels[String(params.state)] ?? '상태 변경';
  const root = typeof params.index === 'number' && typeof params.total === 'number'
    ? ` · 대상 ${params.index}/${params.total}` : '';
  const count = typeof params.count === 'number' ? ` · 결과 ${params.count}건` : '';
  const roots = typeof params.root_count === 'number' ? ` · 탐색 경로 ${params.root_count}개` : '';
  const captured = typeof params.allowed_count === 'number'
    ? ` · 허용 ${params.allowed_count}건, 차단 ${Number(params.blocked_count) || 0}건` : '';
  const duplicates = typeof params.duplicate_count === 'number' && params.duplicate_count > 0
    ? ` · 이미 본 화면 ${params.duplicate_count}개 건너뜀` : '';
  const reason = { time_limit: '시간 상한 도달', action_limit: '동작 상한 도달', page_limit: '페이지 상한 도달' }[String(params.reason)] ?? '';
  return `${phase} ${state}${root}${count}${roots}${captured}${duplicates}${reason ? ` · ${reason}` : ''}`;
}

const koreanMessages: Record<string, (params: Record<string, string | number>) => string> = {
  'pipeline.accepted': () => '승인 확인 후 스캔 요청을 접수했습니다.',
  'pipeline.start_failed': () => '스캔 프로세스를 시작하지 못했습니다.',
  'pipeline.started': () => 'AI DAST 파이프라인을 시작했습니다.',
  'pipeline.completed': () => 'AI DAST 파이프라인이 완료되었습니다.',
  'pipeline.failed': () => 'AI DAST 파이프라인이 오류로 종료되었습니다.',
  'pipeline.resumed': () => '실패한 단계부터 스캔을 다시 시작했습니다.',
  'pipeline.resume_completed': () => '재실행한 스캔이 완료되었습니다.',
  'pipeline.resume_failed': () => '재실행한 스캔이 오류로 종료되었습니다.',
  'pipeline.stop_requested': () => '운영자가 스캔 중단을 요청했습니다.',
  'pipeline.stopped': () => '운영자가 스캔을 중단했습니다.',
  'pipeline.stop_persist_failed': () => '프로세스는 종료됐지만 저장된 스캔 상태를 갱신하지 못했습니다.',
  'pipeline.cancel_requested': () => '운영자가 스캔 취소를 요청했습니다.',
  'pipeline.cancelled': () => '스캔이 취소됐습니다.',
  'pipeline.cancel_persist_failed': () => '프로세스는 종료됐지만 저장된 스캔 상태를 취소됨으로 갱신하지 못했습니다.',
  'pipeline.paused': () => '스캔 실행이 일시정지됐습니다.',
  'pipeline.continued': () => '일시정지한 스캔 실행을 계속합니다.',
  'pipeline.audit_event': params => `파이프라인 이벤트 · ${auditLabels[String(params.event_type)] ?? '상태 변경'}`,
  'recon.activity': params => reconActivityLabel(params),
  'scope.started': () => '스코프 수집을 시작했습니다.',
  'scope.interrupted': () => '대시보드 재시작으로 스코프 수집이 중단되었습니다.',
  'scope.already_approved': () => '검증된 승인 스코프가 이미 있습니다.',
  'scope.browser_ready': () => '프로그램 페이지에 자동 접근하지 못했습니다. 열린 브라우저에서 로그인이나 접근 확인을 마친 뒤 계속을 누르세요.',
  'scope.browser_confirmed': () => '브라우저 접근 확인을 받았습니다. 등록된 프로그램 페이지로 이동해 캡처합니다.',
  'scope.browser_progress': () => '브라우저에서 프로그램 정책 화면을 수집하고 있습니다.',
  'scope.page_read_started': () => '프로그램 정책 화면 읽기를 시작합니다.',
  'scope.page_read_completed': params => `프로그램 정책 화면 읽기를 완료했습니다. 텍스트 ${Number(params.characters) || 0}자를 수집했습니다.`,
  'scope.analysis_started': () => 'Scope Agent가 In-Scope, Out-of-Scope와 정책 제약을 읽고 분석합니다.',
  'scope.analysis_completed': params => `In-Scope ${Number(params.in_scope) || 0}개와 Out-of-Scope ${Number(params.out_of_scope) || 0}개를 읽고 분류했습니다.`,
  'scope.collection_started': () => 'Scope Agent가 프로그램 화면 수집과 정책 분석을 시작합니다.',
  'scope.collection_completed': params => `프로그램 화면 수집과 정책 분석을 마쳤습니다. 텍스트 ${Number(params.characters) || 0}자, In-Scope ${Number(params.in_scope) || 0}개, Out-of-Scope ${Number(params.out_of_scope) || 0}개를 추출했습니다.`,
  'scope.verification_started': () => '수집한 범위와 원문 근거가 일치하는지 검증합니다.',
  'scope.verification_completed': () => '수집한 범위와 원문 근거 검증을 완료했습니다.',
  'scope.draft_started': () => '검증된 내용으로 스코프 초안 저장을 시작합니다.',
  'scope.draft_completed': () => '스코프 초안 저장을 완료했습니다.',
  'scope.paused': () => '스코프 수집을 일시정지했습니다.',
  'scope.continued': () => '일시정지한 스코프 수집을 계속합니다.',
  'scope.cancel_requested': () => '스코프 수집 취소를 요청했습니다.',
  'scope.cancelled': () => '스코프 수집이 취소됐습니다.',
  'scope.review_required': params => `스코프 초안이 검토를 기다립니다. 허용 범위 ${Number(params.in_scope) || 0}개, 제외 범위 ${Number(params.out_of_scope) || 0}개입니다.`,
  'scope.approved': () => '스코프 초안을 승인하고 무결성이 결합된 산출물을 게시했습니다.',
  'scope.rejected': () => '운영자가 스코프 초안을 거절했습니다. 승인 산출물은 생성하지 않았습니다.',
  'scope.failed': params => params.reason ? `스코프 수집 실패: ${String(params.reason)}` : '스코프 수집에 실패했습니다. 자세한 원인은 서버 로그를 확인하세요.',
};

const legacyCodes: Record<string, string> = {
  'Scan request accepted after approval verification.': 'pipeline.accepted',
  'Scan process could not be started.': 'pipeline.start_failed',
  'AI DAST pipeline process started.': 'pipeline.started',
  'AI DAST pipeline completed.': 'pipeline.completed',
  'AI DAST pipeline exited with an error.': 'pipeline.failed',
  'A verified approved Scope already exists.': 'scope.already_approved',
  'Scope collection started.': 'scope.started',
  'Scope login browser opened. Complete the platform login/MFA, return to the exact program page, and open its scope view.': 'scope.browser_ready',
  'Browser opened. Complete login/MFA, return to the exact Scope view, then confirm in the dashboard.': 'scope.browser_ready',
  'Browser login confirmation received; capturing the exact program page.': 'scope.browser_confirmed',
  'Scope draft approved and integrity-bound artifacts published.': 'scope.approved',
  'Scope draft rejected by the operator; no approval artifacts were published.': 'scope.rejected',
};

export function localizeActivityMessage(language: Language, event: ActivityMessage): string {
  if (language === 'en') return event.message;
  const code = event.message_code || legacyCodes[event.message];
  if (code === 'scope.browser_progress' && /[가-힣]/.test(event.message)) return event.message;
  if (code && koreanMessages[code]) return koreanMessages[code](event.message_params || {});
  const oldDraft = /^Scope draft ready for explicit Yes\/No review: (\d+) in-scope and (\d+) out-of-scope assets\.$/.exec(event.message);
  if (oldDraft) return koreanMessages['scope.review_required']({ in_scope: Number(oldDraft[1]), out_of_scope: Number(oldDraft[2]) });
  if (event.message.startsWith('Scope collection failed:')) return koreanMessages['scope.failed']({});
  if (event.message.startsWith('Pipeline event · ')) {
    const legacyType = event.message.slice('Pipeline event · '.length).replaceAll(' · ', '.').replaceAll(' ', '_');
    return koreanMessages['pipeline.audit_event']({ event_type: legacyType });
  }
  if (/[가-힣]/.test(event.message)) return event.message;
  return '활동이 기록되었습니다. 자세한 내용은 서버 로그를 확인하세요.';
}

export function localizeAuditEventType(language: Language, eventType: string): string {
  return language === 'ko' ? auditLabels[eventType] ?? '상태 변경' : eventType;
}
