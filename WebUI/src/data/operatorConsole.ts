export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type FindingStatus = '미조치' | '조치 중' | '해결됨' | '위험 수용' | '오탐';
export type ScanStatus = '대기 중' | '실행 중' | '완료' | '실패' | '중단';
export type Project = { id: string; name: string };
export type Asset = { id: string; projectId: string; name: string; baseUrl: string; kind: string };
export type Scan = { id: string; assetId: string; status: ScanStatus; stage: string; progress: number; startedAt: string; finishedAt?: string; scope: string; excluded: string[]; rate: number; urls: string[]; logs: string[] };
export type Finding = { id: string; assetId: string; scanId: string; title: string; severity: Severity; status: FindingStatus; url: string; parameter: string; cwe: string; firstSeen: string; lastSeen: string; resolvedAt?: string; description: string; evidence: string; remediation: string; request: string; response: string };

const ago = (days: number, hours = 0) => new Date(Date.now() - (days * 24 + hours) * 3_600_000).toISOString();
export const projects: Project[] = [{ id: 'p-web', name: '예시 웹 서비스' }, { id: 'p-portal', name: '예시 고객 포털' }];
export const assets: Asset[] = [
  { id: 'a-main', projectId: 'p-web', name: '메인 서비스', baseUrl: 'https://app.example.com', kind: '웹 애플리케이션' },
  { id: 'a-api', projectId: 'p-web', name: '공개 API', baseUrl: 'https://api.example.com', kind: 'API' },
  { id: 'a-docs', projectId: 'p-web', name: '문서 사이트', baseUrl: 'https://docs.example.com', kind: '웹사이트' },
  { id: 'a-portal', projectId: 'p-portal', name: '고객 포털', baseUrl: 'https://portal.example.com', kind: '웹 애플리케이션' },
  { id: 'a-admin', projectId: 'p-portal', name: '관리자 콘솔', baseUrl: 'https://admin.example.com', kind: '웹 애플리케이션' },
];
export const initialScans: Scan[] = [
  { id: 'SCAN-1048', assetId: 'a-main', status: '실행 중', stage: '취약점 검사', progress: 68, startedAt: ago(0, 1), scope: '/app/*', excluded: ['/logout'], rate: 5, urls: ['/app', '/app/profile', '/app/search'], logs: ['탐색 완료 · 24개 URL', '크롤링 완료 · 18개 응답', '취약점 검사 진행 중 · 68%'] },
  { id: 'SCAN-1047', assetId: 'a-portal', status: '실행 중', stage: '크롤링', progress: 34, startedAt: ago(0, 2), scope: '/*', excluded: ['/signout'], rate: 3, urls: ['/', '/account', '/tickets'], logs: ['탐색 완료 · 12개 URL', '크롤링 진행 중 · 34%'] },
  { id: 'SCAN-1046', assetId: 'a-api', status: '완료', stage: '완료', progress: 100, startedAt: ago(1), finishedAt: ago(1, -1), scope: '/v1/*', excluded: [], rate: 4, urls: ['/v1/users', '/v1/orders', '/v1/health'], logs: ['탐색 완료 · 9개 URL', '크롤링 완료 · 9개 응답', '취약점 검사 완료'] },
  { id: 'SCAN-1045', assetId: 'a-admin', status: '완료', stage: '완료', progress: 100, startedAt: ago(3), finishedAt: ago(3, -2), scope: '/*', excluded: ['/logout'], rate: 2, urls: ['/login', '/settings', '/users'], logs: ['탐색 완료 · 11개 URL', '크롤링 완료 · 10개 응답', '취약점 검사 완료'] },
  { id: 'SCAN-1044', assetId: 'a-main', status: '완료', stage: '완료', progress: 100, startedAt: ago(8), finishedAt: ago(8, -2), scope: '/app/*', excluded: [], rate: 5, urls: ['/app', '/app/search'], logs: ['탐색 완료', '크롤링 완료', '취약점 검사 완료'] },
  { id: 'SCAN-1043', assetId: 'a-docs', status: '실패', stage: '크롤링', progress: 26, startedAt: ago(12), finishedAt: ago(12, -1), scope: '/*', excluded: [], rate: 3, urls: ['/', '/guide'], logs: ['탐색 완료', '예시 오류: 연결 시간 초과'] },
  { id: 'SCAN-1042', assetId: 'a-portal', status: '중단', stage: '취약점 검사', progress: 71, startedAt: ago(37), finishedAt: ago(37, -2), scope: '/*', excluded: [], rate: 3, urls: ['/', '/account'], logs: ['탐색 완료', '운영자가 중단한 예시 기록'] },
];

const sampleRequest = (host: string, path: string) => `GET ${path} HTTP/1.1\nHost: ${host}\nAccept: application/json\nAuthorization: Bearer [REDACTED]\nCookie: session=[REDACTED]`;
const sampleResponse = 'HTTP/1.1 200 OK\nContent-Type: application/json\nSet-Cookie: session=[REDACTED]; HttpOnly\n\n{"example":"redacted demonstration response"}';
const rawFindings: Array<[string,string,string,Severity,FindingStatus,string,string,string,number,number,number?]> = [
  ['F-201','a-main','SCAN-1048','High','미조치','검색 결과의 반사형 XSS','/app/search?q=example','q',0,0],
  ['F-202','a-api','SCAN-1046','Critical','조치 중','객체 접근 제어 누락','/v1/orders/12345','orderId',1,1],
  ['F-203','a-portal','SCAN-1047','Medium','미조치','보안 헤더 누락','/account','',0,0],
  ['F-204','a-admin','SCAN-1045','High','미조치','관리 페이지 권한 검증 미흡','/users/42','userId',3,3],
  ['F-205','a-main','SCAN-1044','Low','해결됨','서버 버전 정보 노출','/app/health','',8,3,3],
  ['F-206','a-docs','SCAN-1043','Info','위험 수용','공개 문서의 내부 경로 참조','/guide/configuration','',12,12],
  ['F-207','a-api','SCAN-1046','Medium','미조치','과도한 오류 정보 노출','/v1/users?debug=1','debug',1,1],
  ['F-208','a-portal','SCAN-1047','High','미조치','세션 만료 처리 미흡','/account/session','',0,0],
  ['F-209','a-main','SCAN-1044','Medium','해결됨','안전하지 않은 리다이렉트','/app/redirect?next=example','next',9,4,4],
  ['F-210','a-admin','SCAN-1045','Low','오탐','캐시 제어 헤더 후보','/settings','',3,3],
  ['F-211','a-api','SCAN-1046','High','미조치','요청 제한 누락','/v1/search','query',1,1],
  ['F-212','a-portal','SCAN-1042','Medium','해결됨','오래된 CSP 정책','/dashboard','',37,15,15],
  ['F-213','a-main','SCAN-1044','Low','미조치','클릭재킹 방어 헤더 누락','/app/profile','',8,8],
  ['F-214','a-admin','SCAN-1045','Critical','위험 수용','예시 관리자 경로 노출','/internal/console','',3,3],
  ['F-215','a-docs','SCAN-1043','Info','미조치','기술 스택 버전 표시','/about','',12,12],
  ['F-216','a-main','SCAN-1044','Medium','해결됨','오류 메시지에 경로 표시','/app/upload','',65,48,48],
];
export const initialFindings: Finding[] = rawFindings.map(([id,assetId,scanId,severity,status,title,path,parameter,first,last,resolved]) => {
  const asset = assets.find(item => item.id === assetId)!;
  return { id, assetId, scanId, title, severity, status, url: `${asset.baseUrl}${path}`, parameter, cwe: severity === 'Info' ? 'CWE-200' : severity === 'Critical' ? 'CWE-862' : severity === 'High' ? 'CWE-79' : 'CWE-693', firstSeen: ago(first), lastSeen: ago(last), resolvedAt: resolved === undefined ? undefined : ago(resolved), description: `${asset.name}의 ${path}에서 확인된 설명용 탐지 결과입니다. 실제 취약점 판정이나 점검 결과가 아닙니다.`, evidence: `예시 근거 · ${scanId}의 ${path} 응답에서 해당 탐지 조건이 관찰된 것으로 구성한 목 데이터입니다.`, remediation: '서버 측 검증 및 접근 제어를 점검하고, 수정 후 동일 조건으로 재검증하세요.', request: sampleRequest(new URL(asset.baseUrl).host,path), response: sampleResponse };
});

export const unresolved = (finding: Finding) => finding.status === '미조치' || finding.status === '조치 중' || finding.status === '위험 수용';
export const assetOf = (id: string) => assets.find(asset => asset.id === id);
export const severityOrder: Severity[] = ['Critical','High','Medium','Low','Info'];
export const statuses: FindingStatus[] = ['미조치','조치 중','해결됨','위험 수용','오탐'];
export const withinDays = (date: string, days: number) => Date.now() - new Date(date).getTime() <= days * 86_400_000;
export function recentScan(assetId: string, scans: Scan[]) { return scans.filter(scan => scan.assetId === assetId).sort((a,b) => b.startedAt.localeCompare(a.startedAt))[0]; }
export function projectAssets(projectId: string) { return projectId === 'all' ? assets : assets.filter(asset => asset.projectId === projectId); }
export function projectScans(projectId: string, scans: Scan[]) { const ids = new Set(projectAssets(projectId).map(asset => asset.id)); return scans.filter(scan => ids.has(scan.assetId)); }
export function projectFindings(projectId: string, findings: Finding[]) { const ids = new Set(projectAssets(projectId).map(asset => asset.id)); return findings.filter(finding => ids.has(finding.assetId)); }
export function trend(findings: Finding[], days: number) {
  const buckets = days === 7 ? 7 : days === 30 ? 10 : 12;
  const size = days / buckets;
  return Array.from({ length: buckets }, (_, index) => {
    const upper = days - index * size;
    const lower = upper - size;
    const age = (date: string) => (Date.now() - new Date(date).getTime()) / 86_400_000;
    return { label: days === 7 ? `${Math.round(upper)}일 전` : `${Math.round(lower)}–${Math.round(upper)}일`, newCount: findings.filter(f => age(f.firstSeen) >= lower && age(f.firstSeen) < upper).length, resolvedCount: findings.filter(f => f.resolvedAt && age(f.resolvedAt) >= lower && age(f.resolvedAt) < upper).length };
  });
}
