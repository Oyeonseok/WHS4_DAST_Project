import { useEffect, useReducer, useRef, useState, type ReactNode } from 'react';
import { DEMO_SCAN } from './data/demo';
import { transportMode, useScanSocket } from './hooks/useScanSocket';
import {
  formatActivityElapsed,
  initialScopeActivityState,
  isScopeActivityActive,
  mergeActivityLogs,
  reduceScopeActivity,
  startScopeElapsedClock,
  startScopeJobPolling,
  shouldPollScopeJob,
  type ScopeActivityEvent,
} from './lib/activity';
import { displayStageStatus, stages, type Finding, type ReportDraftStatus, type Snapshot } from './lib/events';
import { localizeActivityMessage, localizeAuditEventType } from './lib/activityMessages';
import { initialLanguage, translate, type Language } from './lib/i18n';
import {
  resolveExecutionLimits,
  type ExecutionProfileId,
  type ScopeExecutionRequirements,
} from './lib/scan';
import { scopeCollectionRequest } from './lib/scope';

const pages = ['Overview', 'Scopes / Programs', 'Scans', 'Findings', 'Validation', 'Reports', 'Audit log', 'Settings'] as const;
type Page = typeof pages[number];
type ScanSummary = { scan_id: string; status: Snapshot['status']; started_at: string; finished_at: string | null; targets?: string[] };
type AttackTask = { task_id: string; skill_name: string; status: string; selection_reasons: string[]; observed_urls: { method: string; url: string; hint: string }[]; attempt_count: number; recent_attempts: { method: string; url: string | null; outcome: string }[] };
type AttackTaskSnapshot = { scan_id: string; stage_run_id: string | null; stage_status?: string; tasks: AttackTask[]; attempt_count: number };
type ScopeTarget = { asset_type: string; asset: string; description: string; maximum_severity: string };
type ApprovedScope = { scope_id: string; program_id: string; program_name: string; platform: string; targets: ScopeTarget[]; identity_header: 'hackerone' | 'intigriti' | null; approved_by: string; execution_requirements: ScopeExecutionRequirements };
type ScopeStatus = 'scope_required' | 'collecting' | 'awaiting_browser' | 'paused' | 'cancelling' | 'cancelled' | 'review_required' | 'approved' | 'rejected' | 'failed';
type RegisteredProgram = { id: string; platform: string; program: string; visibility: 'public' | 'private'; scope_status: ScopeStatus; scope_job_id?: string; scope_error?: string | null; scope_updated_at?: string; created_at: string };
type ScopeDraftAsset = ScopeTarget & { eligibility: string };
type ScopeDraft = { scope_id: string; created_at: string; source_url: string; program_name: string; program_description: string; in_scope_assets: ScopeDraftAsset[]; out_of_scope_assets: ScopeDraftAsset[]; allowed_activities: string[]; prohibited_activities: string[]; submission_requirements: string[]; operational_constraints: string[]; safe_harbor: string; ambiguities: string[]; source_evidence: { section: string; quote: string }[] };
type ScopeApproval = { approved_by: string; approved_at: string };
type AuditEntry = { id: string; event_type: string; stage: string; created_at: string };
type ReportSummary = { report_id: string; scan_id: string; case_id: string; platform: string; title: string; created_at: string };
type ThemeChoice = 'system' | 'dark' | 'light';
const scopeStatusLabel: Record<ScopeStatus, string> = { scope_required: 'Scope required', collecting: 'Collecting', awaiting_browser: 'Login required', paused: 'Paused', cancelling: 'Cancelling', cancelled: 'Cancelled', review_required: 'Review Yes / No', approved: 'Approved', rejected: 'Rejected', failed: 'Failed' };
const scopeStatusTone = (status: ScopeStatus) => status === 'approved' ? 'success' : status === 'failed' || status === 'rejected' ? 'critical' : status === 'cancelled' ? '' : 'warning';
const THEME_KEY = 'aidast-theme';
const attackSkillLabels: Record<string, string> = {
  'hunt-auth-bypass': '인증 우회 점검',
  'hunt-cors': 'CORS 설정 점검',
  'hunt-session': '세션 관리 점검',
};
const attackReasonLabels: Record<string, string> = {
  'authentication endpoint': '인증 관련 엔드포인트 발견',
  'authenticated endpoint': '인증이 필요한 엔드포인트 발견',
  'CORS response signal': 'CORS 관련 응답 헤더 발견',
  'session response signal': '세션 관련 응답 헤더 발견',
  'session endpoint': '세션 관련 엔드포인트 발견',
};
const attackTaskStatusLabels: Record<string, string> = { pending: '대기', running: '진행 중', completed: '완료', skipped: '건너뜀', failed: '실패', cancelled: '취소' };
const attackOutcomeLabels: Record<string, string> = { negative: '취약점 징후 없음', confirmed: '확인됨', lead: '추가 확인 필요', inconclusive: '판단 보류', blocked: '차단됨', error: '오류' };
function savedTheme(): ThemeChoice {
  const value = localStorage.getItem(THEME_KEY);
  return value === 'dark' || value === 'light' || value === 'system' ? value : 'system';
}
const slugs = ['overview', 'scopes', 'scans', 'findings', 'validation', 'reports', 'audit', 'settings'];
const symbols = ['overview', 'scope', 'scan', 'shield', 'check', 'report', 'logs', 'settings'];
function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    scope: <><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/></>,
    scan: <><path d="M4 8V4h4M16 4h4v4M20 16v4h-4M8 20H4v-4M7 12h10M12 7v10"/></>,
    shield: <><path d="m12 3 8 4v5c0 5-5 8-8 9-3-1-8-4-8-9V7z"/><path d="M12 8v5M12 16h.01"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    report: <><path d="M6 3h9l4 4v14H6zM14 3v5h5M9 12h7M9 16h7"/></>,
    logs: <><path d="M4 5h16M4 12h16M4 19h16M8 3v4M15 10v4M10 17v4"/></>,
    settings: <><circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/></>,
    arrow: <path d="M4 12h16m-6-6 6 6-6 6"/>,
    search: <><circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
    pulse: <path d="M2 12h5l3-8 4 16 3-8h5"/>,
    plus: <path d="M12 5v14M5 12h14"/>,
    terminal: <><path d="m4 6 6 6-6 6M13 18h7"/></>,
    sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></>,
    moon: <path d="M20 15.2A8 8 0 0 1 8.8 4 8.5 8.5 0 1 0 20 15.2z"/>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.shield}</svg>;
}
function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) { return <span className={`badge ${tone}`}>{children}</span>; }
function Panel({ title, subtitle, action, children, className = '' }: { title: string; subtitle?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><div className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>{children}</section>;
}
function VerifiedScopeDetails({ draft, approval, language, onScan }: { draft: ScopeDraft; approval: ScopeApproval; language: Language; onScan: () => void }) {
  const tr = (label: string) => translate(language, label);
  const groups = [
    ['Allowed', draft.allowed_activities], ['Prohibited', draft.prohibited_activities],
    ['Submission requirements', draft.submission_requirements], ['Operational constraints', draft.operational_constraints],
    ['Ambiguities to verify', draft.ambiguities],
  ] as const;
  return <div className="scope-workflow">
    <div className="scope-review-heading"><div><span>{tr('APPROVED SCOPE')}</span><h3>{draft.program_name}</h3></div><code>{draft.scope_id}</code></div>
    <div className="scope-catalog-meta"><p>{draft.program_description}</p><p>{tr('Collected from')}: {draft.source_url}</p><p>{tr('Approved by')} {approval.approved_by} · {new Date(approval.approved_at).toLocaleString(language === 'ko' ? 'ko-KR' : undefined)}</p></div>
    {([['In scope', draft.in_scope_assets], ['Out of scope', draft.out_of_scope_assets]] as const).map(([title, assets]) => <details className="scope-review-section" key={title} open={title === 'In scope'}><summary>{tr(title)} <span>{assets.length}</span></summary><div className="scope-asset-list">{assets.map((asset, index) => <div key={`${asset.asset}:${index}`}><Badge tone={title === 'In scope' ? 'success' : 'critical'}>{asset.asset_type}</Badge><div><strong className="mono">{asset.asset}</strong><p>{asset.description || asset.eligibility || tr('No additional description.')}</p></div><small>{asset.maximum_severity || tr('Policy limit')}</small></div>)}</div></details>)}
    <div className="scope-rule-grid">{groups.map(([title, items]) => <details className="scope-rule-item" key={title}><summary>{tr(title)} <span>{items.length}</span></summary><ul>{items.length ? items.map((item, index) => <li key={index}>{item}</li>) : <li>{tr('None extracted.')}</li>}</ul></details>)}</div>
    <details className="scope-evidence"><summary>{tr('Source evidence and safe harbor')} <span>{draft.source_evidence.length}</span></summary><div className="scope-evidence-section"><strong>{tr('Safe harbor')}</strong><p>{draft.safe_harbor || tr('No safe-harbor text was extracted.')}</p></div><div className="scope-evidence-section"><strong>{tr('Source evidence')}</strong>{draft.source_evidence.map((item, index) => <blockquote key={index}><strong>{item.section}</strong>{item.quote}</blockquote>)}</div></details>
    <div className="button-row"><button className="primary-button" onClick={onScan}>{language === 'ko' ? '이 Scope로 새 스캔' : 'New scan with this Scope'} <Icon name="arrow" size={14}/></button></div>
  </div>;
}
function Empty({ title, children }: { title: string; children: ReactNode }) { return <div className="empty"><Icon name="lock" size={26}/><h3>{title}</h3><p>{children}</p></div>; }
function Pipeline({ snapshot, language, reportDraft }: { snapshot: Snapshot; language: Language; reportDraft: ReportDraftStatus }) {
  const labels: Record<string, string> = { completed: '완료', skipped: '건너뜀', failed: '실패', blocked: '차단', pending: '대기', running: '진행 중', not_created: '미작성', unknown: '확인 중' };
  return <ol className="pipeline" aria-label={translate(language, 'Scan workflow')}>{stages.map((stage, index) => {
    const status = displayStageStatus(snapshot, stage, reportDraft);
    const done = status === 'completed';
    return <li key={stage} className={done ? 'done' : status === 'running' ? 'current' : status === 'skipped' ? 'skipped' : ''}>
      <span className="stage-number">{done ? <Icon name="check" size={13}/> : String(index + 1).padStart(2,'0')}</span>
      <strong>{translate(language, stage)}</strong>
      <small>{status === 'running' && stage === snapshot.stage ? `${snapshot.progress}% · ${labels[status]}` : labels[status] || status}</small>
    </li>;
  })}</ol>;
}
function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'text/markdown;charset=utf-8' }));
  const a = document.createElement('a'); a.href = url; a.download = name; a.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const sampleReport = '# 데모 — 로컬 보고서 초안\n\n합성 픽스처만 사용했습니다. 실제 프로그램이나 대상은 테스트하지 않았습니다.\n\n## 취약점 F-0040\n응답 헤더의 서버 버전 노출(CWE-200)\n심각도: 낮음 · 픽스처 검토 상태: 확정\n\n## 재현\n합성 GET /health 픽스처에 서버 버전 헤더가 포함됩니다.\n반복 픽스처와 대조군 픽스처를 비교했습니다.\n\n## 영향\n격리된 데모 환경에서 제한적인 정보 노출이 발생합니다.\n실제 운영 환경에 대한 영향은 주장하지 않습니다.\n\n## 조치 방법\n불필요한 서버 버전 헤더를 제거합니다.\n\n이 로컬 초안은 어떤 플랫폼에도 제출되지 않았습니다.\n';

export default function App() {
  const getPage = () => pages[Math.max(0, slugs.indexOf(location.hash.slice(1)))];
  const [page, setPage] = useState<Page>(getPage);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('All severities');
  const [privateVisible, setPrivateVisible] = useState(false);
  const [modal, setModal] = useState<'new' | 'scan-progress' | 'scope' | 'scope-workflow' | 'verified-scope' | 'finding' | 'report' | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [level, setLevel] = useState('All levels');
  const [stageFilter, setStageFilter] = useState('All stages');
  const [logSearch, setLogSearch] = useState('');
  const [paused, setPaused] = useState(false);
  const [compact, setCompact] = useState(false);
  const [collapsed, setCollapsed] = useState(() => window.matchMedia('(max-width: 900px)').matches);
  const [theme, setTheme] = useState<ThemeChoice>(savedTheme);
  const [resolvedTheme, setResolvedTheme] = useState<'dark' | 'light'>('dark');
  const [language, setLanguage] = useState<Language>(initialLanguage);
  const dialog = useRef<HTMLDialogElement>(null);
  const navigation = useRef<HTMLElement>(null);
  const stream = useRef<HTMLDivElement>(null);
  const demo = transportMode === 'demo';
  const configuredScanId = demo ? DEMO_SCAN : import.meta.env.VITE_SCAN_ID || '';
  const [scanId, setScanId] = useState<string>(configuredScanId);
  const [scanOptions, setScanOptions] = useState<ScanSummary[]>([]);
  const [scopes, setScopes] = useState<ApprovedScope[]>([]);
  const [catalogScopeId, setCatalogScopeId] = useState('');
  const [catalogScopeDraft, setCatalogScopeDraft] = useState<ScopeDraft | null>(null);
  const [catalogScopeApproval, setCatalogScopeApproval] = useState<ScopeApproval | null>(null);
  const [catalogScopeError, setCatalogScopeError] = useState('');
  const [catalogScopeSummaryOnly, setCatalogScopeSummaryOnly] = useState(false);
  const [registeredPrograms, setRegisteredPrograms] = useState<RegisteredProgram[]>([]);
  const [scopeProgramUrl, setScopeProgramUrl] = useState('');
  const [scopeVisibility, setScopeVisibility] = useState<'public' | 'private'>('public');
  const [scopeSubmitting, setScopeSubmitting] = useState(false);
  const [scopeError, setScopeError] = useState('');
  const [workflowProgram, setWorkflowProgram] = useState<RegisteredProgram | null>(null);
  const [scopeActivity, dispatchScopeActivity] = useReducer(reduceScopeActivity, initialScopeActivityState);
  const scopeEvents = scopeActivity.events;
  const scopePolling = scopeActivity.polling;
  const [scopeClock, setScopeClock] = useState(() => Date.now());
  const [scanClock, setScanClock] = useState(() => Date.now());
  const [scopeDraft, setScopeDraft] = useState<ScopeDraft | null>(null);
  const [scopeApproval, setScopeApproval] = useState<ScopeApproval | null>(null);
  const [scopeReviewer, setScopeReviewer] = useState('');
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [scopeActionBusy, setScopeActionBusy] = useState(false);
  const [scopeWorkflowError, setScopeWorkflowError] = useState('');
  const [scopeId, setScopeId] = useState('');
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [scanProfile, setScanProfile] = useState<ExecutionProfileId>('safe-recon');
  const [maxRequests, setMaxRequests] = useState(500);
  const [maxRps, setMaxRps] = useState(0.5);
  const [maxConcurrency, setMaxConcurrency] = useState(2);
  const [timeoutSeconds, setTimeoutSeconds] = useState(15);
  const [maxDepth, setMaxDepth] = useState(2);
  const [platformHandle, setPlatformHandle] = useState('');
  const [loginMode, setLoginMode] = useState<'none' | 'runtime-browser'>('none');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState('');
  const [repeatSource, setRepeatSource] = useState<{ scanId: string; scopeId: string; targets: string[] } | null>(null);
  const [resuming, setResuming] = useState(false);
  const [resumeError, setResumeError] = useState('');
  const [cancelRequest, setCancelRequest] = useState<{ scanId: string; phase: 'requesting' | 'cancelling' } | null>(null);
  const [cancelError, setCancelError] = useState('');
  const [pauseBusy, setPauseBusy] = useState<'pause' | 'continue' | null>(null);
  const [pauseError, setPauseError] = useState('');
  const [attackTaskSnapshot, setAttackTaskSnapshot] = useState<AttackTaskSnapshot | null>(null);
  const [attackTaskError, setAttackTaskError] = useState('');
  const [attackTaskRevision, setAttackTaskRevision] = useState(0);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditError, setAuditError] = useState('');
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [reportError, setReportError] = useState('');
  const [reportScanId, setReportScanId] = useState<string | null>(null);
  const [reportPreview, setReportPreview] = useState(sampleReport);
  const [selectedReport, setSelectedReport] = useState<ReportSummary | null>(null);
  const [resultRoot, setResultRoot] = useState(demo ? 'Synthetic demo data (memory)' : '');
  const { snapshot, state, error, refresh } = useScanSocket(scanId);
  const cancelling = cancelRequest?.scanId === scanId;
  const cancelPhase = cancelling ? cancelRequest.phase : null;
  const scopeActive = isScopeActivityActive(workflowProgram?.scope_status);
  const scopeWorkLabel = workflowProgram?.scope_status === 'paused' ? '일시정지'
    : workflowProgram?.scope_status === 'cancelling' ? '취소 중' : '작업 중';
  const scopeStartedAt = scopeEvents[0]?.occurred_at || workflowProgram?.scope_updated_at;
  const scopeElapsedSeconds = scopeActive && scopeStartedAt
    ? Math.max(0, Math.floor((scopeClock - Date.parse(scopeStartedAt)) / 1000))
    : 0;
  const scopeElapsedLabel = formatActivityElapsed(scopeElapsedSeconds);
  const scanSummary = scanOptions.find(item => item.scan_id === scanId);
  const scanTargets = scanSummary?.targets || [];
  const scanTargetLabel = scanTargets.length
    ? `${scanTargets.slice(0, 2).join(', ')}${scanTargets.length > 2 ? ` 외 ${scanTargets.length - 2}개` : ''}`
    : snapshot?.program_name || scanId;
  const scanElapsedSeconds = scanSummary
    ? Math.max(0, Math.floor(((scanSummary.finished_at ? Date.parse(scanSummary.finished_at) : scanClock) - Date.parse(scanSummary.started_at)) / 1000))
    : 0;
  const reportDraftStatus: ReportDraftStatus = reportScanId === scanId
    ? reports.some(item => item.scan_id === scanId) ? 'present' : 'absent'
    : reportError ? 'unavailable' : 'loading';
  useEffect(() => {
    if (workflowProgram) {
      dispatchScopeActivity({ type: 'program-status', status: workflowProgram.scope_status });
    }
  }, [workflowProgram?.scope_status]);
  const tr = (text: string) => translate(language, text);
  const pageLabel = (value: Page) => tr(value);
  const go = (destination: Page) => { location.hash = slugs[pages.indexOf(destination)]; setPage(destination); setSearch(''); };
  const refreshRegisteredPrograms = async (signal?: AbortSignal) => {
    if (demo) return;
    const base = import.meta.env.VITE_API_BASE_URL || location.origin;
    const response = await fetch(new URL('/api/v1/programs', base), { signal, credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) return;
    const body = await response.json() as { programs?: RegisteredProgram[] };
    if (!Array.isArray(body.programs)) return;
    setRegisteredPrograms(body.programs);
    setWorkflowProgram(current => current ? body.programs!.find(item => item.id === current.id) || current : null);
  };
  useEffect(() => { const changed = () => { setPage(getPage()); setSearch(''); }; window.addEventListener('hashchange', changed); return () => window.removeEventListener('hashchange', changed); }, []);
  useEffect(() => {
    if (!window.matchMedia('(max-width: 660px)').matches) return;
    navigation.current?.querySelector<HTMLElement>('.nav-item.active')?.scrollIntoView({ block: 'nearest', inline: 'center' });
  }, [page]);
  useEffect(() => {
    if (!scopeActive) return;
    const clock = startScopeElapsedClock({ onTick: setScopeClock });
    return clock.stop;
  }, [scopeActive, workflowProgram?.scope_job_id]);
  useEffect(() => {
    if (modal !== 'scan-progress' || snapshot?.status !== 'running') return;
    setScanClock(Date.now());
    const timer = window.setInterval(() => setScanClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [modal, snapshot?.status]);
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const apply = () => {
      const resolved = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme;
      document.documentElement.dataset.theme = resolved;
      document.documentElement.style.colorScheme = resolved;
      document.querySelector('meta[name="theme-color"]')?.setAttribute('content', resolved === 'dark' ? '#101419' : '#f4f7f5');
      setResolvedTheme(resolved);
    };
    localStorage.setItem(THEME_KEY, theme);
    apply();
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [theme]);
  useEffect(() => {
    localStorage.setItem('aidast-language', language);
    document.documentElement.lang = language;
  }, [language]);
  useEffect(() => {
    if (demo) return;
    const abort = new AbortController();
    void (async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL('/api/v1/health', base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        const body = await response.json() as { result_root?: string };
        if (response.ok && typeof body.result_root === 'string') setResultRoot(body.result_root);
      } catch { /* Connection status is displayed separately. */ }
    })();
    return () => abort.abort();
  }, [demo]);
  useEffect(() => {
    if (demo || !scanId || (modal !== 'scan-progress' && page !== 'Scans')) return;
    if (!snapshot || snapshot.scan_id !== scanId) return;
    if (snapshot.stage === 'Scope' || snapshot.stage === 'Recon') {
      setAttackTaskSnapshot({ scan_id: scanId, stage_run_id: null, tasks: [], attempt_count: 0 });
      setAttackTaskError('');
      return;
    }
    const abort = new AbortController();
    const load = async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/attack-tasks`, base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        if (!response.ok) throw new Error(`공격 작업 조회 실패 (${response.status})`);
        const body = await response.json() as AttackTaskSnapshot;
        if (!abort.signal.aborted && body.scan_id === scanId && Array.isArray(body.tasks)) {
          setAttackTaskSnapshot(body); setAttackTaskError('');
        }
      } catch (e) {
        if (!abort.signal.aborted) setAttackTaskError(e instanceof Error ? e.message : '공격 작업을 불러올 수 없습니다.');
      }
    };
    void load();
    const timer = snapshot?.status === 'running' ? window.setInterval(() => void load(), 3000) : undefined;
    return () => { abort.abort(); if (timer !== undefined) window.clearInterval(timer); };
  }, [demo, scanId, modal, page, snapshot?.status, snapshot?.stage, attackTaskRevision]);
  useEffect(() => {
    if (demo) return;
    const abort = new AbortController();
    const load = async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL('/api/v1/scans', base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        if (!response.ok) return;
        const body: unknown = await response.json();
        if (!body || typeof body !== 'object' || !Array.isArray((body as { scans?: unknown }).scans)) return;
        const scans = (body as { scans: unknown[] }).scans.filter((item): item is ScanSummary => {
          if (!item || typeof item !== 'object') return false;
          const row = item as Record<string, unknown>;
          return typeof row.scan_id === 'string' && row.scan_id.length > 0 && row.scan_id.length <= 128 && typeof row.status === 'string' && typeof row.started_at === 'string' && (row.finished_at === null || typeof row.finished_at === 'string') && (row.targets === undefined || (Array.isArray(row.targets) && row.targets.every(target => typeof target === 'string' && target.length <= 256)));
        });
        setScanOptions(scans);
        setScanId(current => scans.some(item => item.scan_id === current) ? current : scans[0]?.scan_id || current);
      } catch { /* The snapshot hook owns visible connection errors. */ }
    };
    void load();
    return () => abort.abort();
  }, [demo]);
  useEffect(() => {
    if (demo) return;
    const abort = new AbortController();
    const load = () => void refreshRegisteredPrograms(abort.signal).catch(() => { /* Mutations surface errors in the workflow dialog. */ });
    load();
    const timer = page === 'Scopes / Programs' ? window.setInterval(load, 1500) : undefined;
    return () => { abort.abort(); if (timer !== undefined) window.clearInterval(timer); };
  }, [demo, page]);
  useEffect(() => {
    const programId = workflowProgram?.id;
    if (demo || !shouldPollScopeJob({
      hasJob: !!workflowProgram?.scope_job_id,
      polling: scopePolling,
      dialogOpen: modal === 'scope-workflow',
    }) || !programId) return;
    const poller = startScopeJobPolling({
      repeat: scopePolling,
      load: async signal => {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(programId)}/scope-job?after=0`, base), { signal, credentials: 'same-origin', cache: 'no-store' });
        const body = await response.json() as { job?: Partial<RegisteredProgram>; events?: ScopeActivityEvent[]; detail?: string };
        if (!response.ok || !body.job) throw new Error(body.detail || `Scope status returned ${response.status}`);
        let draft: ScopeDraft | undefined;
        if (body.job.scope_status === 'review_required' && modal === 'scope-workflow') {
          const draftResponse = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(programId)}/scope-draft`, base), { signal, credentials: 'same-origin', cache: 'no-store' });
          const draftBody = await draftResponse.json() as { draft?: ScopeDraft; detail?: string };
          if (!draftResponse.ok || !draftBody.draft) throw new Error(draftBody.detail || `Scope draft returned ${draftResponse.status}`);
          draft = draftBody.draft;
        }
        return {
          status: body.job.scope_status,
          payload: { job: body.job, events: Array.isArray(body.events) ? body.events : [], draft },
        };
      },
      onResponse: result => {
        setWorkflowProgram(current => current ? { ...current, ...result.payload.job } : current);
        dispatchScopeActivity({ type: 'job-response', status: result.status, events: result.payload.events });
        if (result.payload.draft) setScopeDraft(result.payload.draft);
      },
      onError: error => setScopeWorkflowError(error instanceof Error ? error.message : 'Scope status could not be loaded.'),
    });
    return poller.stop;
  }, [demo, modal, scopePolling, workflowProgram?.id, workflowProgram?.scope_job_id]);
  useEffect(() => {
    if (demo || modal !== 'scope-workflow' || workflowProgram?.scope_status !== 'approved') return;
    const abort = new AbortController();
    void (async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/approved-scope`, base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        const body = await response.json() as { scope?: ScopeDraft; approval?: ScopeApproval; detail?: string };
        if (!response.ok || !body.scope || !body.approval) throw new Error(body.detail || `Approved Scope returned ${response.status}`);
        setScopeDraft(body.scope);
        setScopeApproval(body.approval);
        setScopeWorkflowError('');
      } catch (error) { if (!abort.signal.aborted) setScopeWorkflowError(error instanceof Error ? error.message : '승인된 Scope를 불러오지 못했습니다.'); }
    })();
    return () => abort.abort();
  }, [demo, modal, workflowProgram?.id, workflowProgram?.scope_status]);
  useEffect(() => { if (modal && !dialog.current?.open) dialog.current?.showModal(); else if (!modal && dialog.current?.open) dialog.current.close(); }, [modal]);
  useEffect(() => {
    if (demo || page !== 'Audit log' || !scanId) return;
    const abort = new AbortController();
    setAuditError('');
    void (async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/audit`, base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        const body = await response.json() as { events?: AuditEntry[]; detail?: string };
        if (!response.ok || !Array.isArray(body.events)) throw new Error(body.detail || `Audit request returned ${response.status}`);
        setAuditEntries(body.events);
      } catch (e) { if (!abort.signal.aborted) setAuditError(e instanceof Error ? e.message : 'The audit log could not be loaded.'); }
    })();
    return () => abort.abort();
  }, [demo, page, scanId]);
  useEffect(() => {
    if (demo || (!scanId && page !== 'Reports')) return;
    const abort = new AbortController();
    setReportError('');
    setReportScanId(null);
    void (async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const url = new URL('/api/v1/reports', base);
        if (scanId) url.searchParams.set('scan_id', scanId);
        const response = await fetch(url, { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        const body = await response.json() as { reports?: ReportSummary[]; detail?: string };
        if (!response.ok || !Array.isArray(body.reports)) throw new Error(body.detail || `Report request returned ${response.status}`);
        setReports(body.reports);
        setReportScanId(scanId || null);
      } catch (e) { if (!abort.signal.aborted) setReportError(e instanceof Error ? e.message : 'Reports could not be loaded.'); }
    })();
    return () => abort.abort();
  }, [demo, page, scanId]);
  useEffect(() => {
    if (demo || (modal !== null && modal !== 'new')) return;
    const abort = new AbortController();
    setLaunchError('');
    void (async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL('/api/v1/scopes', base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        if (!response.ok) throw new Error(`Approved scope request returned ${response.status}`);
        const body = await response.json() as { scopes?: ApprovedScope[] };
        const loaded = Array.isArray(body.scopes) ? body.scopes : [];
        setScopes(loaded);
        setScopeId(current => loaded.some(item => item.scope_id === current) ? current : repeatSource ? '' : loaded[0]?.scope_id || '');
        if (repeatSource) {
          const approved = loaded.find(item => item.scope_id === repeatSource.scopeId);
          setSelectedTargets(approved ? repeatSource.targets.filter(target => approved.targets.some(item => item.asset === target)) : []);
        }
      } catch (e) { if (!abort.signal.aborted) setLaunchError(e instanceof Error ? e.message : 'Approved scopes could not be loaded.'); }
    })();
    return () => abort.abort();
  }, [modal, demo, repeatSource]);
  useEffect(() => {
    if (modal !== 'verified-scope' || !catalogScopeId) return;
    const abort = new AbortController();
    setCatalogScopeDraft(null);
    setCatalogScopeApproval(null);
    setCatalogScopeError('');
    setCatalogScopeSummaryOnly(false);
    void (async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL(`/api/v1/scopes/${encodeURIComponent(catalogScopeId)}`, base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        const body = await response.json() as { scope?: ScopeDraft; approval?: ScopeApproval; detail?: string };
        if (response.status === 404 && body.detail === 'Not Found') {
          setCatalogScopeSummaryOnly(true);
          return;
        }
        if (!response.ok || !body.scope || !body.approval) throw new Error(body.detail || `Scope detail returned ${response.status}`);
        setCatalogScopeDraft(body.scope);
        setCatalogScopeApproval(body.approval);
      } catch (error) { if (!abort.signal.aborted) setCatalogScopeError(error instanceof Error ? error.message : 'Scope details could not be loaded.'); }
    })();
    return () => abort.abort();
  }, [modal, catalogScopeId]);
  const selectedScope = scopes.find(item => item.scope_id === scopeId);
  const selectedLimits = selectedScope
    ? resolveExecutionLimits(selectedScope.execution_requirements, scanProfile)
    : null;
  const requestInterval = maxRps > 0 && maxRps < 1
    ? Number((1 / maxRps).toFixed(1))
    : null;
  useEffect(() => {
    if (!selectedLimits) return;
    setMaxRequests(selectedLimits.max_requests);
    setMaxRps(selectedLimits.requests_per_second);
    setMaxConcurrency(selectedLimits.concurrency);
    setTimeoutSeconds(selectedLimits.timeout_seconds);
    setMaxDepth(selectedLimits.max_depth);
  }, [selectedScope?.scope_id, scanProfile]);
  const registerProgram = async () => {
    if (!scopeProgramUrl.trim()) return;
    setScopeSubmitting(true); setScopeError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL('/api/v1/programs', base), {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ program_url: scopeProgramUrl.trim(), visibility: scopeVisibility }),
      });
      const body = await response.json() as { program?: RegisteredProgram; detail?: string };
      if (!response.ok || !body.program) throw new Error(body.detail || `Program registration returned ${response.status}`);
      setRegisteredPrograms(current => [body.program!, ...current.filter(item => item.id !== body.program!.id)]);
      setScopeProgramUrl(''); setModal(null); go('Scopes / Programs');
    } catch (e) { setScopeError(e instanceof Error ? e.message : 'The program could not be registered.'); }
    finally { setScopeSubmitting(false); }
  };
  const openScopeWorkflow = (item: RegisteredProgram) => {
    setWorkflowProgram(item); dispatchScopeActivity({ type: 'job-selected', status: item.scope_status }); setScopeDraft(null); setScopeApproval(null); setScopeReviewer(''); setScopeConfirmed(false); setScopeWorkflowError(''); setModal('scope-workflow');
  };
  const startScopeCollection = async () => {
    if (!workflowProgram) return;
    setScopeActionBusy(true); setScopeWorkflowError(''); dispatchScopeActivity({ type: 'reset' }); setScopeDraft(null); setScopeApproval(null);
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/scope-collection`, base), {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scopeCollectionRequest),
      });
      const body = await response.json() as { job?: Partial<RegisteredProgram>; detail?: string };
      if (!response.ok || !body.job) throw new Error(body.detail || `Scope collection returned ${response.status}`);
      setWorkflowProgram(current => current ? { ...current, ...body.job } : current);
      dispatchScopeActivity({ type: 'collection-started' });
      await refreshRegisteredPrograms();
    } catch (e) { setScopeWorkflowError(e instanceof Error ? e.message : 'Scope collection could not start.'); }
    finally { setScopeActionBusy(false); }
  };
  const confirmScopeBrowser = async () => {
    if (!workflowProgram) return;
    setScopeActionBusy(true); setScopeWorkflowError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/scope-browser-ready`, base), { method: 'POST', credentials: 'same-origin' });
      const body = await response.json() as { job?: Partial<RegisteredProgram>; detail?: string };
      if (!response.ok || !body.job) throw new Error(body.detail || `Browser confirmation returned ${response.status}`);
      setWorkflowProgram(current => current ? { ...current, ...body.job } : current);
      dispatchScopeActivity({ type: 'external-mutation' });
    } catch (e) { setScopeWorkflowError(e instanceof Error ? e.message : 'Browser confirmation failed.'); }
    finally { setScopeActionBusy(false); }
  };
  const controlScope = async (action: 'pause' | 'continue' | 'cancel') => {
    if (!workflowProgram || scopeActionBusy) return;
    setScopeActionBusy(true); setScopeWorkflowError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/scope-${action}`, base), { method: 'POST', credentials: 'same-origin' });
      const body = await response.json() as { job?: Partial<RegisteredProgram>; detail?: string };
      if (!response.ok || !body.job) throw new Error(body.detail || `Scope ${action} returned ${response.status}`);
      setWorkflowProgram(current => current ? { ...current, ...body.job } : current);
      dispatchScopeActivity({ type: 'external-mutation' });
      await refreshRegisteredPrograms();
    } catch (e) { setScopeWorkflowError(e instanceof Error ? e.message : `Scope ${action} failed.`); }
    finally { setScopeActionBusy(false); }
  };
  const decideScope = async (decision: 'yes' | 'no') => {
    if (!workflowProgram) return;
    setScopeActionBusy(true); setScopeWorkflowError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/scope-decision`, base), {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision, approved_by: decision === 'yes' ? scopeReviewer.trim() : null, confirmation: decision === 'yes' && scopeConfirmed }),
      });
      const body = await response.json() as { job?: Partial<RegisteredProgram>; detail?: string };
      if (!response.ok || !body.job) throw new Error(body.detail || `Scope decision returned ${response.status}`);
      setWorkflowProgram(current => current ? { ...current, ...body.job } : current);
      dispatchScopeActivity({ type: 'external-mutation' });
      setScopeDraft(null); setScopeConfirmed(false);
      await refreshRegisteredPrograms();
    } catch (e) { setScopeWorkflowError(e instanceof Error ? e.message : 'Scope decision failed.'); }
    finally { setScopeActionBusy(false); }
  };
  const closeDialog = () => {
    if (modal === 'scope-workflow') dispatchScopeActivity({ type: 'dialog-closed' });
    setModal(null);
  };
  const startScan = async () => {
    if (!selectedScope || !selectedTargets.length || !selectedTargets.every(target => selectedScope.targets.some(item => item.asset === target)) || !authorizationConfirmed) return;
    setLaunching(true); setLaunchError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL('/api/v1/scans', base), {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_id: selectedScope.scope_id, targets: selectedTargets, profile: scanProfile,
          max_requests: maxRequests, max_rps: maxRps, max_concurrency: maxConcurrency,
          timeout_seconds: timeoutSeconds, max_depth: maxDepth,
          login_mode: loginMode, authorization_confirmed: true,
          hackerone_username: selectedScope.identity_header === 'hackerone' ? platformHandle : null,
          intigriti_username: selectedScope.identity_header === 'intigriti' ? platformHandle : null,
        }),
      });
      const body = await response.json() as { scan_id?: string; status?: Snapshot['status']; started_at?: string; detail?: string };
      if (!response.ok || !body.scan_id) throw new Error(body.detail || `Scan start returned ${response.status}`);
      const created: ScanSummary = { scan_id: body.scan_id, status: body.status || 'running', started_at: body.started_at || new Date().toISOString(), finished_at: null, targets: selectedTargets };
      setScanOptions(current => [created, ...current.filter(item => item.scan_id !== created.scan_id)]);
      setScanId(created.scan_id); setRepeatSource(null); go('Scans'); setModal('scan-progress');
    } catch (e) { setLaunchError(e instanceof Error ? e.message : 'The scan could not be started.'); }
    finally { setLaunching(false); }
  };
  const resumeScan = async () => {
    if (demo || !scanId || resuming) return;
    setResuming(true); setResumeError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/resume`, base), {
        method: 'POST', credentials: 'same-origin',
      });
      const body = await response.json() as { status?: string; detail?: string };
      if (!response.ok || body.status !== 'running') throw new Error(body.detail || `재실행 요청 실패 (${response.status})`);
      setScanOptions(current => current.map(item => item.scan_id === scanId ? { ...item, status: 'running', finished_at: null } : item));
      setModal('scan-progress');
      refresh();
    } catch (e) { setResumeError(e instanceof Error ? e.message : '스캔을 재실행할 수 없습니다.'); }
    finally { setResuming(false); }
  };
  const cancelScan = async () => {
    if (demo || !scanId || cancelling || !['running', 'paused'].includes(snapshot?.status || '')) return;
    if (!window.confirm('현재 스캔을 취소할까요? 실행 프로세스가 종료되며, 다시 검사하려면 새 스캔을 시작해야 합니다.')) return;
    setCancelRequest({ scanId, phase: 'requesting' }); setCancelError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/cancel`, base), {
        method: 'POST', credentials: 'same-origin',
      });
      const body = await response.json() as { status?: string; detail?: string };
      if (response.status === 404) throw new Error('현재 대시보드 서버에는 스캔 취소 기능이 적용되지 않았습니다.');
      if (response.status === 409 && body.detail?.includes('no isolated active process')) throw new Error('이 스캔의 실행 프로세스를 확인할 수 없습니다. 스캔 상태를 새로고침하세요.');
      if (!response.ok || body.status !== 'cancelling') throw new Error(body.detail || `스캔 취소 요청 실패 (${response.status})`);
      setCancelRequest({ scanId, phase: 'cancelling' });
      refresh();
    } catch (e) {
      setCancelError(e instanceof Error ? e.message : '스캔을 취소할 수 없습니다.');
      setCancelRequest(null);
      setModal('scan-progress');
    }
  };
  const changePause = async (next: 'pause' | 'continue') => {
    if (demo || !scanId || pauseBusy || cancelling || snapshot?.status !== (next === 'pause' ? 'running' : 'paused')) return;
    setPauseBusy(next); setPauseError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/${next}`, base), {
        method: 'POST', credentials: 'same-origin',
      });
      const body = await response.json() as { status?: string; detail?: string };
      if (!response.ok || body.status !== (next === 'pause' ? 'paused' : 'running')) throw new Error(body.detail || `스캔 ${next === 'pause' ? '일시정지' : '계속'} 실패 (${response.status})`);
      setScanOptions(current => current.map(item => item.scan_id === scanId ? { ...item, status: body.status as Snapshot['status'] } : item));
      refresh();
    } catch (e) {
      setPauseError(e instanceof Error ? e.message : '스캔 상태를 변경할 수 없습니다.');
      setModal('scan-progress');
    } finally { setPauseBusy(null); }
  };
  useEffect(() => {
    if (!cancelRequest || snapshot?.scan_id !== cancelRequest.scanId) return;
    if (snapshot.status === 'cancelled') {
      setScanOptions(current => current.map(item => item.scan_id === snapshot.scan_id ? { ...item, status: 'cancelled' } : item));
      setCancelRequest(null);
    } else if (snapshot.status === 'completed' || snapshot.status === 'failed') {
      setCancelError('취소가 확인되기 전에 스캔이 종료됐습니다. 현재 결과 상태를 확인하세요.');
      setCancelRequest(null);
    } else if (snapshot.logs.some(log => log.message_code === 'pipeline.cancel_persist_failed')) {
      setCancelError('실행 프로세스는 종료됐지만 저장된 스캔 상태를 취소됨으로 갱신하지 못했습니다. 활동 기록을 확인하세요.');
      setCancelRequest(null);
    }
  }, [cancelRequest, snapshot]);
  const activityLogs = mergeActivityLogs(snapshot?.logs || [], scopeEvents);
  const hasActivity = activityLogs.length > 0 || scopeActive;
  const visibleLogs = activityLogs.filter(log => {
    const sourceLabel = log.source === 'scope' ? '스코프 수집' : `스캔 ${tr(log.stage)}`;
    return (level === 'All levels' || log.level === level)
      && (stageFilter === 'All stages' || log.stage === stageFilter)
      && `${localizeActivityMessage(language, log)} ${log.stage} ${sourceLabel}`.toLowerCase().includes(logSearch.toLowerCase());
  });
  const showScopeWorking = scopeActive
    && (level === 'All levels' || level === 'info')
    && (stageFilter === 'All stages' || stageFilter === 'Scope')
    && `스코프 수집 ${scopeWorkLabel} ${scopeElapsedLabel}`.includes(logSearch);
  useEffect(() => { if (!paused && stream.current) stream.current.scrollTop = stream.current.scrollHeight; }, [activityLogs.at(-1)?.key, scopeClock, paused, logSearch, level, stageFilter, collapsed]);
  const findings = snapshot?.findings || [];
  const shownFindings = findings.filter(f => `${f.id} ${f.title} ${f.endpoint}`.toLowerCase().includes(search.toLowerCase()) && (severity === 'All severities' || f.severity === severity));
  const reviewCount = findings.filter(f => f.status === 'unreviewed').length;
  const approvedScopeCount = demo ? 0 : scopes.length;
  const totalProgramCount = registeredPrograms.length;
  const visiblePrograms = registeredPrograms.filter(item => `${item.visibility === 'private' && !privateVisible ? 'Private program' : item.program} ${item.platform}`.toLowerCase().includes(search.toLowerCase()));
  const inspect = (f: Finding) => { setSelectedFinding(f); setModal('finding'); };
  const openNewScan = () => {
    setRepeatSource(null);
    setSelectedTargets([]);
    setPlatformHandle('');
    setAuthorizationConfirmed(false);
    setLaunchError('');
    setModal('new');
  };
  const openRepeatScan = () => {
    if (!snapshot || snapshot.status !== 'completed') return;
    const source = { scanId: snapshot.scan_id, scopeId: snapshot.scope_id || '', targets: scanTargets };
    setRepeatSource(source);
    setScopeId(source.scopeId);
    const approved = scopes.find(item => item.scope_id === source.scopeId);
    setSelectedTargets(approved ? source.targets.filter(target => approved.targets.some(item => item.asset === target)) : []);
    setPlatformHandle('');
    setAuthorizationConfirmed(false);
    setLaunchError('');
    setModal('new');
  };
  const openReport = async (item: ReportSummary) => {
    setReportError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/reports/${encodeURIComponent(item.report_id)}`, base), { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error(`Report preview returned ${response.status}`);
      setSelectedReport(item); setReportPreview(await response.text()); setModal('report');
    } catch (e) { setReportError(e instanceof Error ? e.message : 'The report preview could not be loaded.'); }
  };
  const findingTable = (rows: Finding[]) => <div className="table-wrap"><table><thead><tr><th>{tr('Severity')}</th><th>{tr('Finding')}</th><th>{tr('Review status')}</th><th><span className="sr-only">{tr('Details')}</span></th></tr></thead><tbody>{rows.map(f => <tr key={f.id}><td><Badge tone={f.severity.toLowerCase()}>{tr(f.severity)}</Badge></td><td><button className="text-button finding-title" onClick={() => inspect(f)}>{f.title}</button><small className="mono">{f.id} <span>·</span> {f.endpoint}</small></td><td><Badge tone={f.status === 'confirmed' ? 'success' : ''}>{tr(f.status)}</Badge></td><td><button className="icon-button" aria-label={`${tr('Details')} ${f.id}`} onClick={() => inspect(f)}><Icon name="arrow" size={16}/></button></td></tr>)}</tbody></table>{rows.length === 0 && <p className="table-empty">{tr('No findings match this view.')}</p>}</div>;
  const currentAttackTasks = attackTaskSnapshot?.scan_id === scanId ? attackTaskSnapshot : null;
  const attackTasksContent = <section className="scan-attack-tasks" aria-label="공격 작업과 선택 근거">
    <div className="scan-attack-tasks-heading"><h3>공격 작업 <small>{currentAttackTasks?.tasks.length ?? 0}개 · 기록된 시도 {currentAttackTasks?.attempt_count ?? 0}건</small></h3></div>
    <p className="scan-attack-tasks-note">관찰 URL은 정찰 결과에서 작업 선택의 근거가 된 주소입니다. 실제 공격 요청 대상은 시도 기록이 생기면 별도로 표시됩니다. URL의 쿼리 값과 응답 헤더 값은 표시하지 않습니다.</p>
    {attackTaskError && <p className="form-error" role="alert">{attackTaskError}</p>}
    {currentAttackTasks?.tasks.map(task => <article className="scan-attack-task" key={task.task_id}>
      <div className="scan-attack-task-title"><strong>{attackSkillLabels[task.skill_name] || task.skill_name}</strong><Badge tone={task.status === 'failed' ? 'critical' : task.status === 'completed' ? 'success' : 'warning'}>{attackTaskStatusLabels[task.status] || task.status}</Badge></div>
      <small className="mono">{task.skill_name} · {task.task_id}</small>
      <p><b>선택 힌트</b> {task.selection_reasons.map(reason => attackReasonLabels[reason] || reason).join(', ') || '기록 없음'}</p>
      <div><b>관련 정찰 URL</b>{task.observed_urls.length ? <ul>{task.observed_urls.map((item, index) => <li key={`${item.url}-${index}`}><code>{item.method} {item.url}</code><span>{item.hint}</span></li>)}</ul> : <p>이 작업에 연결된 URL 근거가 없습니다. 선택 힌트를 재검토하세요.</p>}</div>
      <div><b>실제 시도</b> {task.attempt_count}건{task.recent_attempts.length > 0 && <ul>{task.recent_attempts.map((item, index) => <li key={index}><code>{item.method} {item.url || 'URL 기록 없음'}</code><span>{attackOutcomeLabels[item.outcome] || item.outcome}</span></li>)}</ul>}</div>
    </article>)}
    {currentAttackTasks && currentAttackTasks.tasks.length === 0 && <p className="scan-progress-empty">{snapshot?.stage === 'Scope' || snapshot?.stage === 'Recon' ? '정찰이 끝나면 공격 작업이 생성됩니다.' : '아직 생성된 공격 작업이 없습니다.'}</p>}
    {!currentAttackTasks && !attackTaskError && <p className="scan-progress-empty">공격 작업을 불러오는 중입니다.</p>}
  </section>;
  const reconActivity = snapshot?.logs.filter(log => log.message_code === 'recon.activity') ?? [];
  const latestReconActivity = reconActivity.at(-1);
  const scanControls = !demo && (snapshot?.status === 'running' || snapshot?.status === 'paused') ? <>
    <button className="secondary-button" onClick={() => void changePause(snapshot.status === 'running' ? 'pause' : 'continue')} disabled={!!pauseBusy || cancelling}>{pauseBusy === 'pause' ? '일시정지 처리 중…' : pauseBusy === 'continue' ? '계속 처리 중…' : snapshot.status === 'running' ? '일시정지' : '계속'}</button>
    <button className="secondary-button" onClick={() => void cancelScan()} disabled={cancelling || !!pauseBusy}>{cancelPhase === 'requesting' ? '취소 요청 전달 중…' : cancelling ? '취소 확인 중…' : '스캔 취소'}</button>
  </> : null;
  const scanPanel = <Panel title={demo ? tr('Local lab · API assessment') : scanTargetLabel} subtitle={demo ? tr('Synthetic fixture · isolated from program inventory') : `${snapshot?.program_name ? `${snapshot.program_name} · ` : ''}${scanId}`} action={<div className="scan-panel-actions"><Badge tone={snapshot?.status === 'failed' ? 'critical' : snapshot?.status === 'completed' ? 'success' : 'warning'}><span className="dot"/>{cancelling ? '취소 처리 중' : tr(snapshot?.status || state)}</Badge>{scanControls}{!demo && snapshot?.status === 'failed' && <button className="secondary-button" onClick={resumeScan} disabled={resuming}>{resuming ? '재실행 요청 중…' : '실패 단계부터 재실행'}</button>}{!demo && (snapshot?.status === 'completed' || snapshot?.status === 'cancelled') && <button className="secondary-button" onClick={openRepeatScan}>정찰부터 다시 스캔</button>}{!demo && scanId && <button className="secondary-button" onClick={() => setModal('scan-progress')}>진행 창 열기</button>}</div>}>
    {snapshot ? <><Pipeline snapshot={snapshot} language={language} reportDraft={reportDraftStatus}/>{cancelling && <p className="scan-stop-status" role="status">{cancelPhase === 'requesting' ? '취소 요청을 서버에 전달하고 있습니다.' : '취소 요청을 접수했습니다. 실행 프로세스 종료와 저장된 상태 갱신을 확인하고 있습니다.'}</p>}{snapshot.status === 'paused' && !cancelling && <p className="scan-stop-status" role="status">스캔 일시정지 중 · 같은 실행을 이어가려면 ‘계속’을 누르세요.</p>}{snapshot.status === 'cancelled' && <p className="scan-stop-status is-done" role="status">스캔 취소 완료 · 실행 프로세스가 종료됐고 스캔 상태가 취소됨으로 저장됐습니다.</p>}<div className="scan-stats"><div><span>{tr('Scan ID')}</span><strong className="mono">{snapshot.scan_id}</strong></div><div><span>{tr('Endpoints')}</span><strong>{snapshot.endpoints}</strong></div><div><span>{tr('Request budget')}</span><strong>{snapshot.requests} <small>/ {snapshot.budget.toLocaleString()}</small></strong></div><div className="progress-stat"><span>{tr(snapshot.stage)} {tr('progress')} <b>{snapshot.progress}%</b></span><progress max="100" value={snapshot.progress} aria-label={`${tr(snapshot.stage)} ${tr('progress')}`}/></div></div>{snapshot.service_endpoints !== undefined && <p className="scan-recon-summary"><strong>서비스 URL 후보</strong> {snapshot.service_endpoints}개 <span>· 실제 HTTP 응답 관측 {snapshot.live_endpoints ?? 0}개</span></p>}{snapshot.stage === 'Recon' && <p className="scan-recon-summary"><strong>최근 정찰 작업</strong> {latestReconActivity ? localizeActivityMessage(language, latestReconActivity) : '이 실행에는 도구별 정찰 기록이 아직 없습니다.'}</p>}{resumeError && <p className="form-error" role="alert">{resumeError}</p>}{pauseError && <p className="form-error" role="alert">{pauseError}</p>}{cancelError && <p className="form-error" role="alert">{cancelError}</p>}</> : <Empty title={tr(state === 'offline' ? 'Backend unavailable' : state === 'idle' ? 'No scan selected' : 'Loading scan snapshot')}>{tr(state === 'idle' ? 'Start a scan from an approved Scope to show its snapshot and activity here.' : 'Connect the REST snapshot endpoint to display scan state. Demo data is never substituted in live mode.')}</Empty>}
  </Panel>;
  const scanProgressContent = <div className="scan-progress-dialog">
    {cancelError && <p className="scan-progress-failed" role="alert"><strong>스캔 취소 실패 · </strong>{cancelError}</p>}
    {pauseError && <p className="scan-progress-failed" role="alert"><strong>일시정지 상태 변경 실패 · </strong>{pauseError}</p>}
    <div className="scan-progress-overview">
      <div><span>스캔 대상</span><strong>{scanTargetLabel || '불러오는 중'}</strong><small>{snapshot?.program_name} <span className="mono">· {scanId}</span></small></div>
      <Badge tone={snapshot?.status === 'failed' ? 'critical' : snapshot?.status === 'completed' ? 'success' : 'warning'}>{cancelling ? '취소 처리 중' : tr(snapshot?.status || state)}</Badge>
    </div>
    <div className="scan-progress-stats"><div><span>현재 단계</span><strong>{tr(snapshot?.stage || 'Waiting')}</strong></div><div><span>단계 진행률</span><strong>{snapshot?.progress ?? 0}%</strong></div><div><span>경과 시간</span><strong role="timer">{formatActivityElapsed(scanElapsedSeconds)}</strong></div><div><span>요청 수 / 예산</span><strong>{snapshot?.requests ?? 0} / {snapshot?.budget ?? '—'}</strong></div></div>
    {snapshot?.service_endpoints !== undefined && <p className="scan-recon-summary"><strong>정찰 URL</strong> 전체 {snapshot.endpoints}개 · 서비스 후보 {snapshot.service_endpoints}개 · 실제 HTTP 응답 관측 {snapshot.live_endpoints ?? 0}개</p>}
    <progress aria-label="스캔 단계 진행률" max="100" value={snapshot?.progress ?? 0}/>
    {cancelling && <p className="scan-stop-status" role="status">{cancelPhase === 'requesting' ? '취소 요청을 서버에 전달하고 있습니다.' : '취소 요청 접수됨 · 실행 프로세스 종료와 저장된 상태 갱신을 확인하는 중입니다.'}</p>}
    {snapshot?.status === 'running' && !cancelling && <p className="scan-progress-working" role="status"><span className="dot"/> {tr(snapshot.stage)} 단계 작업 중 · {formatActivityElapsed(scanElapsedSeconds)}{snapshot.progress === 0 ? ' · 다음 진행 이벤트를 기다리고 있습니다.' : ''}</p>}
    {snapshot?.status === 'paused' && !cancelling && <p className="scan-stop-status" role="status">스캔 일시정지 중 · 작업을 멈춘 상태입니다. 같은 실행을 이어가려면 ‘계속’을 누르세요.</p>}
    {snapshot?.status === 'failed' && <p className="scan-progress-failed" role="alert">{tr(snapshot.stage)} 단계에서 스캔이 실패했습니다. 완료된 정찰 결과를 재사용하고, 실패한 단계의 작업을 새로 생성해 실행합니다. 아래 활동 기록에서 마지막 오류를 확인하세요.</p>}
    {snapshot?.status === 'cancelled' && <p className="scan-stop-status is-done" role="status">스캔 취소 완료 · 실행 프로세스가 종료됐고 스캔 상태가 취소됨으로 저장됐습니다. 다시 검사하려면 새 스캔을 시작하세요.</p>}
    {resumeError && <p className="form-error" role="alert">{resumeError}</p>}
    {error && <p className="form-error" role="alert">{tr(error)}</p>}
    {(snapshot?.stage === 'Recon' || reconActivity.length > 0) && <section className="scan-recon-activity" aria-label="정찰 작업">
      <h3>정찰 작업 <small>{reconActivity.length}개 기록</small></h3>
      {latestReconActivity && <p className="scan-recon-current"><strong>최근 작업</strong> {localizeActivityMessage(language, latestReconActivity)}</p>}
      {reconActivity.length > 0 ? <div className="scan-recon-timeline">{reconActivity.slice(-30).reverse().map(log => <article key={log.id} className={log.level}><time dateTime={log.time}>{new Date(log.time).toLocaleTimeString('ko-KR',{hour12:false})}</time><span>{localizeActivityMessage(language, log)}</span></article>)}</div> : <p className="scan-progress-empty">이 실행에는 도구별 정찰 기록이 없습니다. 새 기록이 도착하면 여기에 표시됩니다.</p>}
    </section>}
    {!demo && attackTasksContent}
    <div className="scan-progress-log"><h3>스캔 활동 <small>{snapshot?.logs.length ?? 0}개 기록</small></h3><div>{snapshot?.logs.slice(-50).map(log => <article key={log.id} className={log.level}><time dateTime={log.time}>{new Date(log.time).toLocaleTimeString('ko-KR',{hour12:false})}</time><span>{tr(log.stage)}</span><p>{localizeActivityMessage(language, log)}</p></article>)}{!snapshot?.logs.length && <p className="scan-progress-empty">스캔 상태를 불러오는 중입니다. 기록이 도착하면 여기에 표시됩니다.</p>}</div></div>
    <div className="button-row"><button className="secondary-button" onClick={() => { refresh(); setAttackTaskRevision(value => value + 1); }}>상태 새로고침</button>{scanControls}{!demo && snapshot?.status === 'failed' && <button className="primary-button" onClick={resumeScan} disabled={resuming}>{resuming ? '재실행 요청 중…' : '실패 단계부터 재실행'}</button>}{!demo && (snapshot?.status === 'completed' || snapshot?.status === 'cancelled') && <button className="primary-button" onClick={openRepeatScan}>정찰부터 다시 스캔</button>}<button className="secondary-button" onClick={closeDialog}>스캔 화면에서 계속 보기</button></div>
  </div>;
  const scanFromScope = (id: string) => {
    setScopeId(id);
    setSelectedTargets([]);
    setPlatformHandle('');
    setAuthorizationConfirmed(false);
    setLaunchError('');
    go('Scans');
    setModal('new');
  };
  const verifiedScopesPanel = <Panel title={language === 'ko' ? '검증된 Scope' : 'Verified Scopes'} subtitle={language === 'ko' ? '저장된 승인 산출물 · 프로그램 대기열과 별도로 표시됩니다' : 'Stored approved artifacts · separate from the program queue'}>
    {launchError && <p className="form-error scope-list-error" role="alert">{launchError}</p>}
    {scopes.length ? <div className="verified-scope-list">{scopes.map(scope => <article className="verified-scope-row" key={scope.scope_id}>
      <div className="verified-scope-info"><strong>{scope.program_name}</strong><p>{scope.platform} · {scope.targets.length}{language === 'ko' ? '개 실행 대상' : ' executable targets'}</p><small className="mono">{scope.scope_id}</small></div>
      <div className="verified-scope-actions"><Badge tone="success">{language === 'ko' ? '승인 검증됨' : 'Verified'}</Badge><button className="secondary-button" onClick={() => { setCatalogScopeId(scope.scope_id); setModal('verified-scope'); }}>{language === 'ko' ? '내용 보기' : 'View Scope'}</button><button className="primary-button" onClick={() => scanFromScope(scope.scope_id)}>{language === 'ko' ? '새 스캔' : 'New scan'}</button></div>
    </article>)}</div> : !launchError && <p className="table-empty">{language === 'ko' ? '검증된 Scope가 없습니다.' : 'No verified Scopes are available.'}</p>}
  </Panel>;
  const catalogScopeSummary = scopes.find(scope => scope.scope_id === catalogScopeId);
  const catalogScopeSummaryContent = catalogScopeSummary && <div className="scope-workflow">
    <div className="notice"><Icon name="scope"/><div><strong>{language === 'ko' ? '현재 서버에서 요약 정보만 확인할 수 있습니다.' : 'Only the Scope summary is available from this server.'}</strong><p>{language === 'ko' ? '대시보드 백엔드를 재시작하면 승인 정책 전체를 볼 수 있습니다.' : 'Restart the dashboard backend to view the complete approved policy.'}</p></div></div>
    <div className="scope-review-heading"><div><span>{tr('APPROVED SCOPE')}</span><h3>{catalogScopeSummary.program_name}</h3></div><code>{catalogScopeSummary.scope_id}</code></div>
    <div className="scope-catalog-meta"><p>{catalogScopeSummary.platform} · {tr('Approved by')} {catalogScopeSummary.approved_by}</p></div>
    <div className="scope-review-section"><div className="scope-asset-list">{catalogScopeSummary.targets.map((target, index) => <div key={`${target.asset}:${index}`}><Badge tone="success">{target.asset_type}</Badge><div><strong className="mono">{target.asset}</strong><p>{target.description}</p></div><small>{target.maximum_severity}</small></div>)}</div></div>
    <div className="button-row"><button className="primary-button" onClick={() => scanFromScope(catalogScopeSummary.scope_id)}>{language === 'ko' ? '이 Scope로 새 스캔' : 'New scan with this Scope'} <Icon name="arrow" size={14}/></button></div>
  </div>;
  const requiredHeader = selectedScope?.execution_requirements.required_header;
  const handleRequired = !!requiredHeader;
  const limitsValid = !!selectedLimits
    && maxRequests >= 1 && maxRequests <= selectedLimits.max_requests
    && maxRps > 0 && maxRps <= selectedLimits.requests_per_second
    && maxConcurrency >= 1 && maxConcurrency <= selectedLimits.concurrency
    && timeoutSeconds >= 1 && timeoutSeconds <= selectedLimits.timeout_seconds
    && maxDepth >= 0 && maxDepth <= selectedLimits.max_depth;
  const canLaunch = !demo && !!selectedScope && selectedTargets.length > 0
    && selectedTargets.every(target => selectedScope.targets.some(item => item.asset === target))
    && authorizationConfirmed && limitsValid
    && (!handleRequired || !!platformHandle.trim()) && !launching;
  const journeySteps = [
    { title: '프로그램 등록', description: '버그바운티 프로그램 URL과 공개 여부를 등록합니다.' },
    { title: '스코프 승인', description: '정책과 대상 자산을 원문과 대조한 뒤 승인합니다.' },
    { title: '스캔 실행', description: '승인된 대상과 정책 제한을 확인하고 스캔을 시작합니다.' },
    { title: '검증과 보고서', description: '후보를 재현하고 증거를 검토해 로컬 초안을 만듭니다.' },
  ];
  const journeyIndex = demo ? 3 : totalProgramCount === 0 ? 0 : approvedScopeCount === 0 ? 1 : !snapshot ? 2 : 3;
  const journeyAction = demo
    ? { label: '데모 스캔 살펴보기', run: () => go('Scans') }
    : journeyIndex === 0
      ? { label: '프로그램 등록', run: () => { setScopeError(''); setModal('scope'); } }
      : journeyIndex === 1
        ? { label: '스코프 검토하기', run: () => go('Scopes / Programs') }
        : journeyIndex === 2
          ? { label: '새 스캔 설정', run: openNewScan }
          : { label: reviewCount ? '검증 대기열 열기' : '스캔 화면 열기', run: () => go(reviewCount ? 'Validation' : 'Scans') };
  const newScanContent = <div className="scan-form">
    <div className="notice"><Icon name="lock"/><div><strong>{tr('Approved Scope only')}</strong><p>{tr('The backend re-verifies approval integrity and the Python orchestrator enforces TargetPolicy and request budgets.')}</p></div></div>
    {demo ? <p className="form-error">{tr('Switch to the live local dashboard to start a scan.')}</p> : <>
      {repeatSource && <div className="notice" role="status"><Icon name="scope"/><div><strong>정찰부터 새 스캔</strong><p>기존 스캔 {repeatSource.scanId}의 결과는 유지됩니다. 새 스캔 ID를 만들고 Scope·대상·실행 제한·로그인 방식을 확인한 뒤 정찰부터 다시 시작합니다. 이전 실행 설정은 저장되지 않아 현재 승인된 Scope와 프로필 기본값을 사용합니다.</p></div></div>}
      {repeatSource && !scopes.some(scope => scope.scope_id === repeatSource.scopeId) && <p className="form-error" role="alert">기존 스캔의 승인된 Scope를 찾을 수 없습니다. 새로 승인된 Scope를 직접 선택하고 대상을 확인하세요.</p>}
      {repeatSource && selectedScope?.scope_id === repeatSource.scopeId && repeatSource.targets.some(target => !selectedScope.targets.some(item => item.asset === target)) && <p className="form-error" role="alert">이전 스캔의 일부 대상은 현재 승인된 Scope에 없어 선택하지 않았습니다. 대상 목록을 확인하세요.</p>}
      <label className="form-field"><span>{tr('Verified Scope')}</span><select aria-label={tr('Approved program')} value={scopeId} onChange={event => { setScopeId(event.target.value); setSelectedTargets([]); setPlatformHandle(''); }}><option value="">{tr('Select a recent approved scope')}</option>{scopes.map(scope => <option key={scope.scope_id} value={scope.scope_id}>{scope.program_name} · {scope.platform}</option>)}</select></label>
      {selectedScope && <>
        <fieldset className="target-fieldset"><legend>{tr('Targets')} <small>{selectedTargets.length}{tr('selected')}</small></legend><div className="target-actions"><button type="button" className="text-button" onClick={() => setSelectedTargets(selectedScope.targets.map(item => item.asset))}>{tr('Select all')}</button><button type="button" className="text-button" onClick={() => setSelectedTargets([])}>{tr('Clear')}</button></div><div className="target-list">{selectedScope.targets.map(target => <label key={`${target.asset_type}:${target.asset}`}><input type="checkbox" checked={selectedTargets.includes(target.asset)} onChange={() => setSelectedTargets(current => current.includes(target.asset) ? current.filter(item => item !== target.asset) : [...current, target.asset])}/><span><strong>{target.asset}</strong><small>{target.asset_type} · 최대 {tr(target.maximum_severity || 'program policy')}</small></span></label>)}</div></fieldset>
        {selectedTargets.length > 0 && selectedLimits && <section className="execution-requirements"><div className="execution-requirements-heading"><div><h3>{tr('Execution requirements')}</h3><p>{tr("Derived from this Scope's policy and the selected safe profile.")}</p></div><div className="stage-badges"><Badge>{tr('Recon')}</Badge><Badge>{tr('Attack')}</Badge><Badge>{tr('Validation')}</Badge></div></div><div className="requirements-summary"><div><span>{tr('Policy request-rate ceiling')}</span><strong>{selectedScope.execution_requirements.scope_max_requests_per_second ? `${selectedScope.execution_requirements.scope_max_requests_per_second} ${tr('requests per second unit')}` : tr('Not specified by policy')}</strong></div><div><span>{tr('Required request header')}</span><strong className="mono">{selectedScope.execution_requirements.required_header?.name || tr('None')}</strong></div></div>{selectedScope.execution_requirements.operational_constraints.length > 0 && <div className="operational-constraints"><h3>{tr('Operational constraints')}</h3><ul>{selectedScope.execution_requirements.operational_constraints.map(item => <li key={item}>{item}</li>)}</ul></div>}<p className="requirements-note">{tr('TargetPolicy is regenerated at launch and may lower these limits further.')}</p></section>}
        <div className="form-grid"><label className="form-field"><span>{tr('Execution profile')}</span><select value={scanProfile} onChange={event => setScanProfile(event.target.value as ExecutionProfileId)}><option value="safe-recon">{tr('Safe recon')}</option><option value="focused-discovery">{tr('Focused discovery')}</option></select></label><label className="form-field"><span>{tr('Request budget')} <small>≤ {selectedLimits?.max_requests.toLocaleString()}</small></span><input type="number" min="1" max={selectedLimits?.max_requests} value={maxRequests} onChange={event => setMaxRequests(Number(event.target.value))}/></label></div>
        <div className="form-grid"><label className="form-field"><span>{tr('Requests per second')} <small>≤ {selectedLimits?.requests_per_second}</small></span><input type="number" min="0.1" step="0.1" max={selectedLimits?.requests_per_second} value={maxRps} onChange={event => setMaxRps(Number(event.target.value))}/></label><label className="form-field"><span>{tr('Concurrency')} <small>≤ {selectedLimits?.concurrency}</small></span><input type="number" min="1" max={selectedLimits?.concurrency} value={maxConcurrency} onChange={event => setMaxConcurrency(Number(event.target.value))}/></label></div>
        <div className="scan-rate-summary" aria-live="polite"><span>{tr('This scan per-target request-rate cap')}</span><strong>{maxRps > 0 ? `${maxRps} ${tr('requests per second unit')}` : tr('Enter a valid request rate')}</strong>{requestInterval !== null && <small>{language === 'ko' ? `평균 ${requestInterval}초에 1회 요청` : `Average one request every ${requestInterval} seconds`}</small>}<p>{tr('Concurrency limits parallel work; it does not multiply the request-rate setting.')} {tr('The generated TargetPolicy may lower this setting further.')}</p></div>
        <div className="form-grid"><label className="form-field"><span>{tr('Timeout seconds')} <small>≤ {selectedLimits?.timeout_seconds}</small></span><input type="number" min="1" max={selectedLimits?.timeout_seconds} value={timeoutSeconds} onChange={event => setTimeoutSeconds(Number(event.target.value))}/></label><label className="form-field"><span>{tr('Maximum depth')} <small>≤ {selectedLimits?.max_depth}</small></span><input type="number" min="0" max={selectedLimits?.max_depth} value={maxDepth} onChange={event => setMaxDepth(Number(event.target.value))}/></label></div>
        <div className="form-grid"><label className="form-field"><span>{tr('Login behavior')}</span><select value={loginMode} onChange={event => setLoginMode(event.target.value as 'none' | 'runtime-browser')}><option value="none">{tr('No login prompt')}</option><option value="runtime-browser">{tr('Open runtime browser')}</option></select></label>{requiredHeader && <label className="form-field"><span className="mono">{requiredHeader.name} <small>{tr('required for every request')}</small></span><input value={platformHandle} onChange={event => setPlatformHandle(event.target.value)} autoComplete="off" maxLength={64} placeholder={tr('Enter the platform username sent in this header')}/></label>}</div>
      </>}
      {launchError && <p className="form-error" role="alert">{launchError}</p>}
      {!scopes.length && !launchError && <p className="form-empty">{tr('Loading verified scopes…')}</p>}
      <div className="dialog-action-dock">{selectedScope && <label className="confirm-field"><input type="checkbox" checked={authorizationConfirmed} onChange={event => setAuthorizationConfirmed(event.target.checked)}/><span>{tr('I confirm these selected targets are currently authorized and accept the policy-derived execution requirements shown above.')}</span></label>}<div className="button-row"><button className="secondary-button" onClick={() => { setModal(null); go('Scopes / Programs'); }}>{tr('Review programs')}</button><button className="primary-button" disabled={!canLaunch} onClick={() => void startScan()}>{tr(launching ? 'Starting…' : 'Start scan')} <Icon name="arrow" size={14}/></button></div></div>
    </>}
  </div>;
  const scopeIntakeContent = <div className="scope-intake-form">
    <div className="notice"><Icon name="scope"/><div><strong>{tr('Register before collecting Scope')}</strong><p>{tr('Add the bug bounty program here. Scope extraction, evidence review, and approval stay separate from scan execution.')}</p></div></div>
    <label className="form-field"><span>{tr('Program URL')}</span><input type="url" value={scopeProgramUrl} onChange={event => setScopeProgramUrl(event.target.value)} placeholder="https://hackerone.com/program-handle" autoComplete="off"/></label>
    <fieldset className="visibility-options"><legend>{tr('Program visibility')}</legend><label><input type="radio" name="scope-visibility" value="public" checked={scopeVisibility === 'public'} onChange={() => setScopeVisibility('public')}/><span><strong>{tr('Public')}</strong><small>{tr('Program name may be shown in the workspace.')}</small></span></label><label><input type="radio" name="scope-visibility" value="private" checked={scopeVisibility === 'private'} onChange={() => setScopeVisibility('private')}/><span><strong>{tr('Private')}</strong><small>{tr('Name and URL remain masked in normal dashboard views.')}</small></span></label></fieldset>
    {scopeError && <p className="form-error" role="alert">{scopeError}</p>}
    <div className="button-row"><button className="secondary-button" onClick={() => setModal(null)}>{tr('Cancel')}</button><button className="primary-button" disabled={demo || !scopeProgramUrl.trim() || scopeSubmitting} onClick={() => void registerProgram()}>{tr(scopeSubmitting ? 'Registering…' : 'Add to Scope queue')} <Icon name="arrow" size={14}/></button></div>
  </div>;
  const scopeWorkflowContent = workflowProgram && <div className="scope-workflow">
    <div className="workflow-summary"><div><span>{workflowProgram.platform}</span><strong>{workflowProgram.visibility === 'private' && !privateVisible ? tr('Private program') : workflowProgram.program}</strong></div><Badge tone={scopeStatusTone(workflowProgram.scope_status)}>{tr(scopeStatusLabel[workflowProgram.scope_status])}</Badge></div>
    {(workflowProgram.scope_status === 'scope_required' || workflowProgram.scope_status === 'rejected' || workflowProgram.scope_status === 'failed' || workflowProgram.scope_status === 'cancelled') && <>
      <div className="notice"><Icon name="scope"/><div><strong>{tr('Collect a policy snapshot')}</strong><p>{tr('AI DAST opens its own browser. Log in to the bug bounty platform, then continue here. AI DAST will open the registered program page and collect its scope. The result remains an unapproved draft until you review it.')}</p></div></div>
      {workflowProgram.scope_error && <p className="form-error">{tr('Previous attempt:')} {workflowProgram.scope_error}</p>}
      {workflowProgram.scope_status === 'cancelled' && <p role="status">{tr('Scope collection was cancelled. You can start a new collection.')}</p>}
      <div className="button-row"><button className="secondary-button" onClick={closeDialog}>{tr('Cancel')}</button><button className="primary-button" disabled={scopeActionBusy} onClick={() => void startScopeCollection()}>{tr(scopeActionBusy ? 'Starting…' : workflowProgram.scope_status === 'scope_required' ? 'Collect Scope' : 'Collect again')} <Icon name="arrow" size={14}/></button></div>
    </>}
    {(workflowProgram.scope_status === 'collecting' || workflowProgram.scope_status === 'awaiting_browser' || workflowProgram.scope_status === 'paused' || workflowProgram.scope_status === 'cancelling') && <>
      <div className="notice"><Icon name="terminal"/><div><strong>{tr(workflowProgram.scope_status === 'awaiting_browser' ? 'Browser input required' : workflowProgram.scope_status === 'paused' ? 'Scope collection paused' : workflowProgram.scope_status === 'cancelling' ? 'Scope cancellation in progress' : 'Scope collection is running')} <span className="scope-elapsed" role="timer">· {scopeElapsedLabel}</span></strong><p>{tr(workflowProgram.scope_status === 'awaiting_browser' ? 'Check access in the opened local browser, then continue here. Log in only if the site requires it.' : workflowProgram.scope_status === 'paused' ? 'The Scope worker and its browser are paused. Continue to resume the same collection.' : workflowProgram.scope_status === 'cancelling' ? 'The Scope worker is shutting down. The result will show Cancelled after it exits.' : 'The dashboard is collecting and interpreting the program policy. Keep this dialog open to follow progress.')}</p></div></div>
      {workflowProgram.scope_status === 'awaiting_browser' && <button className="primary-button workflow-wide-button" disabled={scopeActionBusy} onClick={() => void confirmScopeBrowser()}>{tr(scopeActionBusy ? 'Continuing…' : 'I finished login · Continue')}</button>}
      <div className="button-row"><button className="secondary-button" disabled={scopeActionBusy || workflowProgram.scope_status === 'cancelling'} onClick={() => void controlScope(workflowProgram.scope_status === 'paused' ? 'continue' : 'pause')}>{tr(workflowProgram.scope_status === 'paused' ? 'Continue Scope' : 'Pause Scope')}</button><button className="secondary-button" disabled={scopeActionBusy || workflowProgram.scope_status === 'cancelling'} onClick={() => void controlScope('cancel')}>{tr(workflowProgram.scope_status === 'cancelling' ? 'Cancelling Scope…' : 'Cancel Scope collection')}</button></div>
    </>}
    {scopeEvents.length > 0 && <div className="scope-event-list" aria-live="polite"><h3>{tr('Collection activity')}{scopeActive && <span className="scope-elapsed" role="timer">{scopeWorkLabel} · {scopeElapsedLabel}</span>}</h3>{scopeEvents.map(event => <div key={`${event.job_id}:${event.event_id}`} className={event.level}><time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleTimeString('ko-KR', { hour12: false })}</time><span>{localizeActivityMessage(language, event)}</span></div>)}</div>}
    {workflowProgram.scope_status === 'approved' && !scopeDraft && !scopeWorkflowError && <p className="form-empty">{tr('Loading approved Scope…')}</p>}
    {(workflowProgram.scope_status === 'review_required' || workflowProgram.scope_status === 'approved') && scopeDraft && <>
      <div className="scope-review-heading"><div><span>{tr(scopeApproval ? 'APPROVED SCOPE' : 'UNAPPROVED DRAFT')}</span><h3>{scopeDraft.program_name}</h3></div><code>{scopeDraft.scope_id}</code></div>
      <details className="scope-meta" open={workflowProgram.scope_status === 'review_required'}><summary>{tr('Collection details')}</summary><div><p>{scopeDraft.program_description}</p><p className="scope-review-meta">{tr('Collected from')}: {scopeDraft.source_url} · {new Date(scopeDraft.created_at).toLocaleString(language === 'ko' ? 'ko-KR' : undefined)}</p>{scopeApproval && <p className="scope-review-meta">{tr('Approved by')} {scopeApproval.approved_by} · {new Date(scopeApproval.approved_at).toLocaleString(language === 'ko' ? 'ko-KR' : undefined)}</p>}</div></details>
      <details className="scope-review-section" open={workflowProgram.scope_status === 'review_required'}><summary>{tr('In scope')} <span>{scopeDraft.in_scope_assets.length}</span></summary><div className="scope-asset-list">{scopeDraft.in_scope_assets.map((asset, index) => <div key={`${asset.asset}:${index}`}><Badge tone="success">{asset.asset_type}</Badge><div><strong className="mono">{asset.asset}</strong><p>{asset.description || asset.eligibility || tr('No additional description.')}</p></div><small>{asset.maximum_severity || tr('Policy limit')}</small></div>)}</div></details>
      <details className="scope-review-section" open={workflowProgram.scope_status === 'review_required'}><summary>{tr('Out of scope')} <span>{scopeDraft.out_of_scope_assets.length}</span></summary><div className="scope-asset-list">{scopeDraft.out_of_scope_assets.map((asset, index) => <div key={`${asset.asset}:${index}`}><Badge tone="critical">{asset.asset_type}</Badge><div><strong className="mono">{asset.asset}</strong><p>{asset.description || asset.eligibility || tr('Excluded by policy.')}</p></div></div>)}</div></details>
      <div className="scope-rule-grid">
        <details className="scope-rule-item" open={workflowProgram.scope_status === 'review_required'}><summary>{tr('Allowed')} <span>{scopeDraft.allowed_activities.length}</span></summary><ul>{scopeDraft.allowed_activities.length ? scopeDraft.allowed_activities.map((item, index) => <li key={index}>{item}</li>) : <li>{tr('None extracted.')}</li>}</ul></details>
        <details className="scope-rule-item" open={workflowProgram.scope_status === 'review_required'}><summary>{tr('Prohibited')} <span>{scopeDraft.prohibited_activities.length}</span></summary><ul>{scopeDraft.prohibited_activities.length ? scopeDraft.prohibited_activities.map((item, index) => <li key={index}>{item}</li>) : <li>{tr('None extracted.')}</li>}</ul></details>
        <details className="scope-rule-item" open={workflowProgram.scope_status === 'review_required'}><summary>{tr('Submission requirements')} <span>{scopeDraft.submission_requirements.length}</span></summary><ul>{scopeDraft.submission_requirements.length ? scopeDraft.submission_requirements.map((item, index) => <li key={index}>{item}</li>) : <li>{tr('None extracted.')}</li>}</ul></details>
        <details className="scope-rule-item" open={workflowProgram.scope_status === 'review_required'}><summary>{tr('Operational constraints')} <span>{scopeDraft.operational_constraints.length}</span></summary><ul>{scopeDraft.operational_constraints.length ? scopeDraft.operational_constraints.map((item, index) => <li key={index}>{item}</li>) : <li>{tr('None extracted.')}</li>}</ul></details>
        <details className="scope-rule-item" open={workflowProgram.scope_status === 'review_required'}><summary>{tr('Ambiguities to verify')} <span>{scopeDraft.ambiguities.length}</span></summary><ul>{scopeDraft.ambiguities.length ? scopeDraft.ambiguities.map((item, index) => <li key={index}>{item}</li>) : <li>{tr('None extracted.')}</li>}</ul></details>
      </div>
      <details className="scope-evidence"><summary>{tr('Source evidence and safe harbor')} <span>{scopeDraft.source_evidence.length}</span></summary><div className="scope-evidence-section"><strong>{tr('Safe harbor')}</strong><p>{tr('Program protections for policy-compliant research; approved Scope still defines permitted targets.')}</p><p>{scopeDraft.safe_harbor || tr('No safe-harbor text was extracted.')}</p></div><div className="scope-evidence-section"><strong>{tr('Source evidence')}</strong><p>{tr('Exact excerpts from the program page supporting the collected assets and rules.')}</p>{scopeDraft.source_evidence.map((item, index) => <blockquote key={index}><strong>{item.section}</strong>{item.quote}</blockquote>)}</div></details>
      {workflowProgram.scope_status === 'review_required' && <div className="scope-decision"><h3>{tr('Is this Scope accurate and authorized?')}</h3><p>{language === 'ko' ? <><strong>Yes</strong>는 무결성이 결합된 Scope 산출물을 게시하고 스캔을 활성화합니다. <strong>No</strong>는 초안을 삭제하고 프로그램을 실행 불가 상태로 유지합니다.</> : <><strong>Yes</strong> publishes integrity-bound Scope artifacts and enables scanning. <strong>No</strong> deletes this draft and keeps the program non-executable.</>}</p><label className="form-field"><span>{tr('Reviewer name')} <small>{tr('required for Yes')}</small></span><input value={scopeReviewer} onChange={event => setScopeReviewer(event.target.value)} maxLength={160} autoComplete="off" placeholder={tr('Local operator or team identity')}/></label><label className="confirm-field"><input type="checkbox" checked={scopeConfirmed} onChange={event => setScopeConfirmed(event.target.checked)}/><span>{tr('I reviewed the listed assets and rules against the source policy and confirm this Scope is authorized.')}</span></label><div className="decision-buttons"><button className="reject-button" disabled={scopeActionBusy} onClick={() => void decideScope('no')}>{tr('No · Reject draft')}</button><button className="primary-button" disabled={scopeActionBusy || !scopeReviewer.trim() || !scopeConfirmed} onClick={() => void decideScope('yes')}>{tr('Yes · Approve Scope')} <Icon name="check" size={14}/></button></div></div>}
    </>}
    {((workflowProgram.scope_status === 'approved' && scopeDraft && scopeApproval) || workflowProgram.scope_status === 'rejected') && <div className={`workflow-result ${workflowProgram.scope_status}`}><Icon name={workflowProgram.scope_status === 'approved' ? 'check' : 'shield'} size={24}/><div><h3>{tr(workflowProgram.scope_status === 'approved' ? 'Scope approved' : 'Draft rejected')}</h3><p>{tr(workflowProgram.scope_status === 'approved' ? 'Integrity-bound artifacts were published. The verified targets are now available in New Scan.' : 'No approval artifact was created and this program remains non-executable.')}</p></div><button className="secondary-button" onClick={() => setModal(null)}>{tr('Done')}</button></div>}
    {scopeWorkflowError && <p className="form-error" role="alert">{scopeWorkflowError}</p>}
  </div>;

  return <div className={`app-shell ${compact ? 'compact-mode' : ''}`}>
    <a className="skip-link" href="#main-content">{tr('Skip to content')}</a>
    <aside className="sidebar"><div className="brand"><div className="brand-mark"><Icon name="shield" size={22}/></div><div><strong>AI DAST<span className="brand-period">.</span></strong><small>{tr('SECURITY WORKSPACE')}</small></div></div>
      <div className="workspace-label"><span className="workspace-avatar">W</span><div>{tr('Local workspace')}<small>AI DAST 프로젝트</small></div></div>
      <nav ref={navigation} aria-label={tr('Main navigation')}><p className="nav-label">{tr('OPERATIONS')}</p>{pages.map((p,i) => <button key={p} aria-label={pageLabel(p)} title={pageLabel(p)} className={`nav-item ${p === 'Settings' ? 'mobile-settings-nav' : ''} ${page === p ? 'active' : ''}`} onClick={() => go(p)} aria-current={page === p ? 'page' : undefined}><Icon name={symbols[i]}/><span>{p === 'Scopes / Programs' ? <><span className="desktop-nav-label">{pageLabel(p)}</span><span className="mobile-nav-label">스코프</span></> : pageLabel(p)}</span>{i === 1 && <em>{totalProgramCount}</em>}{i === 3 && snapshot && <em>{findings.length}</em>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="boundary-note"><Icon name="lock" size={16}/><strong>{tr('Scope comes first.')}</strong><p>{tr('Every request stays inside verified approval and policy boundaries.')}</p></div><button aria-label={tr('Settings')} title={tr('Settings')} className={`nav-item ${page === 'Settings' ? 'active' : ''}`} aria-current={page === 'Settings' ? 'page' : undefined} onClick={() => go('Settings')}><Icon name="settings"/><span>{tr('Settings')}</span></button><div className="operator"><div className="avatar">LO</div><div><strong>{tr('Local operator')}</strong><small>{tr(demo ? 'Demo workspace' : 'Backend session')}</small></div><span className="dot"/></div></div>
    </aside>
      <div className="main-shell"><header className="topbar"><div className="breadcrumb">{tr('Workspace')} <span>/</span> <strong>{pageLabel(page)}</strong></div><div className="top-actions"><span className={`connection ${demo ? 'demo' : state}`} role="status"><span className="dot"/>{tr(demo ? 'Demo environment' : state)}</span><label className="language-select"><span className="sr-only">{tr('Language')}</span><select aria-label={tr('Language')} value={language} onChange={event => setLanguage(event.target.value as Language)}><option value="ko">한국어</option><option value="en">English</option></select></label><button className="icon-button theme-toggle" title={tr(`Switch to ${resolvedTheme === 'dark' ? 'light' : 'dark'} mode`)} aria-label={tr(`Switch to ${resolvedTheme === 'dark' ? 'light' : 'dark'} mode`)} onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}><Icon name={resolvedTheme === 'dark' ? 'sun' : 'moon'} size={16}/></button></div></header>
      <div className="demo-strip"><Icon name={demo ? 'terminal' : 'lock'} size={14}/><span>{tr(demo ? 'DEMO DATA' : 'LOCAL OPERATOR')}<b>·</b>{tr(demo ? 'A synthetic workflow. No network scans or program activity.' : 'Approved-scope scan controls + live REST and WebSocket status.')}</span><button onClick={() => go('Settings')}>{tr('Connection details')} <Icon name="arrow" size={13}/></button></div>
      <div className={`workspace-grid ${collapsed ? 'activity-collapsed' : ''}`}><main id="main-content" tabIndex={-1} className="content-column">
        <div className="page-heading"><div><p className="eyebrow">{tr(page === 'Overview' ? 'YOUR OPERATIONS, AT A GLANCE' : 'AI DAST / WORKSPACE')}</p><h1>{tr(page === 'Overview' ? 'Security overview' : page)}</h1><p>{tr(page === 'Overview' ? 'From approved scope to evidence you can stand behind.' : page === 'Scopes / Programs' ? 'Program inventory is a starting point. Approved scope defines execution.' : page === 'Scans' ? 'One deterministic pipeline. Traceable decisions at every stage.' : page === 'Findings' ? 'Signals become findings. Validation establishes the verdict.' : page === 'Validation' ? 'Reproduction, controls, and evidence before confirmation.' : page === 'Reports' ? 'Reviewable local drafts. Nothing is submitted automatically.' : page === 'Audit log' ? 'Trace the decisions and provenance behind each run.' : 'Connection, privacy, and display preferences.')}</p></div><span className="heading-tag">{demo ? '데모 / 042' : '라이브 / V1'}</span></div>
        {page === 'Scopes / Programs' && <div className="scope-page-actions"><div><strong>{tr('Scope intake')}</strong><p>{tr('Register a bug bounty program before collecting and approving its executable Scope.')}</p></div><button className="primary-button" onClick={() => { setScopeError(''); setModal('scope'); }}><Icon name="plus" size={15}/>{tr('Add program')}</button></div>}
        {page === 'Scans' && <div className="scope-page-actions"><div><strong>{tr('Start scan')}</strong><p>{tr('Choose a verified approved Scope and configure a new scan.')}</p></div><button className="primary-button" onClick={openNewScan}><Icon name="plus" size={15}/>{tr('New scan')}</button></div>}
        {error && !(state === 'idle' && !scanId && (page === 'Overview' || page === 'Scans')) && (page === 'Overview' || page === 'Scans' || page === 'Findings' || page === 'Validation') && <div className="error-banner" role="status"><span>{tr(error)}</span><button onClick={!scanId ? (approvedScopeCount ? openNewScan : () => go('Scopes / Programs')) : refresh}>{!scanId ? (approvedScopeCount ? '승인된 스코프로 스캔 시작' : '스코프 준비하기') : tr('Reload snapshot')}</button></div>}
        {page === 'Overview' && <>
          <section className="operator-next" aria-labelledby="operator-next-title"><div><p className="eyebrow">권장 작업</p><h2 id="operator-next-title">{demo ? '데모 흐름을 따라 기능을 확인하세요' : `${journeyIndex + 1}단계 · ${journeySteps[journeyIndex].title}`}</h2><p>{demo ? '합성 데이터로 스캔·검증·보고서 화면을 안전하게 둘러볼 수 있습니다.' : journeySteps[journeyIndex].description}</p></div><button className="primary-button" onClick={journeyAction.run}>{journeyAction.label}<Icon name="arrow" size={14}/></button><ol className="journey-steps">{journeySteps.map((step, index) => <li key={step.title} className={index < journeyIndex ? 'complete' : index === journeyIndex ? 'current' : 'upcoming'}><span className="journey-marker">{index < journeyIndex ? <Icon name="check" size={13}/> : index + 1}</span><div><strong>{step.title}</strong><small>{index < journeyIndex ? '완료' : index === journeyIndex ? '현재 단계' : '다음 단계'}</small></div></li>)}</ol></section>
          <section className="metrics" aria-label={tr('Workspace metrics')}>{[{ label: tr('Active scans'), value: snapshot?.status === 'running' ? '1' : '0', note: demo ? tr('1 synthetic workflow') : tr('Selected scan'), icon: 'pulse', color: 'green' },{ label: tr('Programs'), value: String(totalProgramCount), note: `승인된 스코프 ${approvedScopeCount}개`, icon: 'scope', color: 'blue' },{ label: tr('Awaiting review'), value: String(reviewCount), note: tr('Candidates, not verdicts'), icon: 'shield', color: 'amber' },{ label: tr('Confirmed findings'), value: String(findings.filter(f => f.status === 'confirmed').length), note: tr(demo ? 'Synthetic evidence only' : 'From backend snapshot'), icon: 'check', color: 'purple' }].map(m => <article className={`metric ${m.color}`} key={m.label}><div><span>{m.label}</span><Icon name={m.icon}/></div><strong>{m.value}</strong><small><span className="mini-line"/>{m.note}</small></article>)}</section>
          <div className="section-caption"><span><span className="dot"/>{tr('IN PROGRESS')}</span><button className="text-button" onClick={() => go('Scans')}>{tr('Open scan workspace')} <Icon name="arrow" size={14}/></button></div>{scanPanel}
          <div className="insight-grid"><Panel title={tr('Finding distribution')} subtitle={tr('Severity across this scan')}><div className="distribution"><div className="donut" style={{ background: findings.length ? `conic-gradient(${['CRITICAL','HIGH','MEDIUM','LOW','INFO'].flatMap((s,i,a) => { const start = a.slice(0,i).reduce((n,x) => n + findings.filter(f => f.severity === x).length,0)/findings.length*100; const end = start+findings.filter(f => f.severity === s).length/findings.length*100; return `${['#e98791','#e4a173','#dfc079','#89a9ce','#929bb3'][i]} ${start}% ${end}%`; }).join(',')})` : undefined }}><div><strong>{findings.length}</strong><span>{tr('findings')}</span></div></div><div className="legend">{['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s => <div key={s}><i className={s.toLowerCase()}/><span>{tr(s)}</span><strong>{findings.filter(f => f.severity === s).length}</strong></div>)}</div></div></Panel>
          <Panel title={tr('Scope readiness')} subtitle={tr('Verified executable Scope artifacts')} action={<Icon name="scope"/>}><div className="readiness-number"><strong>{approvedScopeCount}</strong><Badge tone={approvedScopeCount ? 'success' : 'warning'}>{tr(approvedScopeCount ? 'Integrity verified' : 'Approval required')}</Badge></div><p className="panel-copy">{approvedScopeCount ? `${approvedScopeCount}개의 스코프 산출물이 매니페스트 및 승인 무결성 검증을 통과했습니다.` : tr('Register a program, collect its policy, and explicitly approve the draft before execution.')}</p><div className="readiness-track"/><button className="panel-link" onClick={() => go('Scopes / Programs')}>{tr('Review registered programs')} <Icon name="arrow" size={15}/></button></Panel></div>
          <Panel title={tr('Finding review queue')} subtitle={tr(demo ? 'Synthetic candidates from the local lab' : 'Findings from the selected scan')} action={<button className="text-button" onClick={() => go('Findings')}>{tr('View all')} <Icon name="arrow" size={14}/></button>}>{findingTable(findings.slice(0,3))}</Panel>
          <div className="overview-summary">
            <Panel title={language === 'ko' ? '최근 활동' : 'Recent activity'} subtitle={language === 'ko' ? '선택한 스캔의 최근 이벤트' : 'Latest events from the selected scan'}>
              <div className="overview-recent-activity">{(snapshot?.logs || []).slice(-3).reverse().map(log => <article className={`log-entry ${log.level}`} key={log.id}><div><time dateTime={log.time}>{new Date(log.time).toLocaleTimeString(language === 'ko' ? 'ko-KR' : 'en-GB', { hour12: false })}</time><span>{log.stage}</span><span className="sr-only">{tr(log.level)}</span></div><p>{log.message}</p></article>)}{!snapshot?.logs.length && <p className="table-empty">{language === 'ko' ? '아직 활동 기록이 없습니다.' : 'No activity yet.'}</p>}</div>
            </Panel>
          <Panel title={tr('Finding distribution')} subtitle={tr('Severity across this scan')}><div className="distribution"><div className="donut" style={{ background: findings.length ? `conic-gradient(${['CRITICAL','HIGH','MEDIUM','LOW','INFO'].flatMap((s,i,a) => { const start = a.slice(0,i).reduce((n,x) => n + findings.filter(f => f.severity === x).length,0)/findings.length*100; const end = start+findings.filter(f => f.severity === s).length/findings.length*100; return `${['#e98791','#e4a173','#dfc079','#89a9ce','#929bb3'][i]} ${start}% ${end}%`; }).join(',')})` : undefined }}><div><strong>{findings.length}</strong><span>{tr('findings')}</span></div></div><div className="legend">{['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s => <div key={s}><i className={s.toLowerCase()}/><span>{s[0] + s.slice(1).toLowerCase()}</span><strong>{findings.filter(f => f.severity === s).length}</strong></div>)}</div></div></Panel>
          </div>
          <Panel title={tr('Scope readiness')} subtitle={tr('Verified executable Scope artifacts')} action={<Icon name="scope"/>}><div className="readiness-number"><strong>{approvedScopeCount}</strong><Badge tone={approvedScopeCount ? 'success' : 'warning'}>{tr(approvedScopeCount ? 'Integrity verified' : 'Approval required')}</Badge></div><p className="panel-copy">{approvedScopeCount ? (language === 'ko' ? `${approvedScopeCount}개의 Scope 산출물이 매니페스트 및 승인 무결성 검증을 통과했습니다.` : `${approvedScopeCount} Scope artifact${approvedScopeCount === 1 ? '' : 's'} passed manifest and approval integrity verification.`) : tr('Register a program, collect its policy, and explicitly approve the draft before execution.')}</p><div className="readiness-track"/><button className="panel-link" onClick={() => go('Scopes / Programs')}>{tr('Review registered programs')} <Icon name="arrow" size={15}/></button></Panel>
          <div className="workspace-footer"><Icon name="lock" size={13}/><span>{tr('Python enforces scope, request budget, and authorization gates.')}</span><span>AI DAST · v0.1</span></div>
        </>}
        {page === 'Scopes / Programs' && <><div className="notice"><Icon name="lock"/><div><strong>{`사용자가 등록한 프로그램 ${totalProgramCount}개. ${approvedScopeCount ? `검증된 스코프 산출물 ${approvedScopeCount}개를 불러왔습니다.` : tr('No executable assets.')}`}</strong><p>{tr('No programs are preloaded. Registration does not establish authorization; only an explicitly approved, integrity-verified Scope becomes executable.')}</p></div></div>{verifiedScopesPanel}{registeredPrograms.length > 0 ? <><div className="toolbar"><label className="search-field"><Icon name="search" size={16}/><input aria-label={tr('Search programs')} value={search} onChange={e => setSearch(e.target.value)} placeholder={tr('Filter registered programs or platforms…')}/></label><button className="secondary-button" onClick={() => setPrivateVisible(v => !v)}>{tr(privateVisible ? 'Hide private name' : 'Reveal private name')}</button></div><Panel title={tr('Scope intake queue')} subtitle={`로컬 등록 프로그램 ${registeredPrograms.length}개 · 명시적인 승인 또는 거절 결정이 필요합니다`}><div className="intake-list">{visiblePrograms.map(item => <div key={item.id}><span className="artifact-icon"><Icon name={item.visibility === 'private' ? 'lock' : 'scope'}/></span><div><strong>{item.visibility === 'private' && !privateVisible ? tr('Private program') : item.program}</strong><p>{item.platform} · 등록 {new Date(item.created_at).toLocaleString('ko-KR')}{item.scope_error ? ` · ${item.scope_error}` : ''}</p></div><div className="intake-actions"><Badge tone={scopeStatusTone(item.scope_status)}>{tr(scopeStatusLabel[item.scope_status])}</Badge><button className="secondary-button" onClick={() => openScopeWorkflow(item)}>{tr(item.scope_status === 'review_required' ? 'Review Yes / No' : item.scope_status === 'collecting' || item.scope_status === 'awaiting_browser' || item.scope_status === 'paused' || item.scope_status === 'cancelling' ? 'View progress' : item.scope_status === 'approved' ? 'View result' : 'Collect Scope')}</button></div></div>)}{visiblePrograms.length === 0 && <p className="table-empty">{tr('No registered programs match this filter.')}</p>}</div></Panel></> : <Panel title={tr('No programs registered')} subtitle={tr('Start with a program policy URL')}><Empty title={tr('Your Scope queue is empty')}>{tr('Choose Add program, enter the bug bounty program URL, and select Public or Private. Nothing is added automatically.')}</Empty></Panel>}</>}
        {page === 'Scans' && <>{!demo && <div className="toolbar"><label>{tr('Persisted scan')} <select aria-label={tr('Select persisted scan')} value={scanId} onChange={event => setScanId(event.target.value)}>{!scanOptions.some(item => item.scan_id === scanId) && scanId && <option value={scanId}>{scanId}</option>}{scanOptions.map(item => <option key={item.scan_id} value={item.scan_id}>{item.targets?.length ? `${item.targets[0]}${item.targets.length > 1 ? ` 외 ${item.targets.length - 1}개` : ''} · ${item.scan_id.slice(0, 13)}` : item.scan_id} · {tr(item.status)}</option>)}</select></label><button className="secondary-button" onClick={refresh}>{tr('Reload snapshot')}</button></div>}{scanPanel}{!demo && attackTasksContent}<Panel title={tr('Run artifacts & provenance')} subtitle={tr('Mapped to the existing aidast pipeline')}><div className="artifact-list">{[['Scope.json + Approval.json','Scope',tr('Policy, approved assets, and integrity hashes')],['Recon.db + Surface.json','Recon',tr('Observed assets, origins, endpoints, and sessions')],['Handoff.json','Handoff',tr('Hashes and roles of immutable source artifacts')],['Pipeline.db','Attack → Validation','stage_runs · attack_tasks · findings · chain_candidates'],['Report.md + Report.json','Report',tr('Validated local draft; no automatic submission')]].map(([name,s,description]) => <div key={name}><span className="artifact-icon"><Icon name="report"/></span><div><strong className="mono">{name}</strong><p>{description}</p></div><Badge>{tr(s)}</Badge></div>)}</div></Panel></>}
        {page === 'Findings' && <><div className="toolbar"><label className="search-field"><Icon name="search" size={16}/><input aria-label={tr('Search findings')} value={search} onChange={e => setSearch(e.target.value)} placeholder={tr('Search finding, ID, or endpoint…')}/></label><select aria-label={tr('Filter severity')} value={severity} onChange={e => setSeverity(e.target.value)}>{['All severities','CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s => <option key={s} value={s}>{tr(s)}</option>)}</select></div><Panel title={tr('Scan findings')} subtitle={language === 'ko' ? `${shownFindings.length}개 결과 · ${demo ? '합성 데이터' : scanId}` : `${shownFindings.length} results · ${demo ? 'synthetic data' : scanId}`}>{findingTable(shownFindings)}</Panel><p className="muted footnote">{tr('Review statuses follow Pipeline.db: unreviewed, confirmed, rejected, resolved.')}</p></>}
        {page === 'Validation' && <><div className="notice"><Icon name="check"/><div><strong>{language === 'ko' ? `${reviewCount}개 후보가 증거 검토를 기다리고 있습니다` : `${reviewCount} candidates await evidence review`}</strong><p>{tr('Validation requires reproduction, a meaningful control, and redacted evidence. UI actions cannot confirm a vulnerability.')}</p></div></div><Panel title={tr('Validation queue')} subtitle={tr('Finding candidates awaiting a final verdict')}>{findingTable(findings.filter(f => f.status === 'unreviewed'))}</Panel><Panel title={tr('Evidence requirements')} subtitle={tr('Before promotion to a confirmed case')}><div className="checklist">{['Reproduce within the approved scope and identity boundary','Compare positive and negative controls','Link request / response evidence with secrets removed','Record the final verdict and reproducibility limits'].map((text,i) => <div key={text}><span>{String(i+1).padStart(2,'0')}</span><p>{tr(text)}</p><Badge>{tr('Required')}</Badge></div>)}</div></Panel><p className="muted footnote">{tr('The live validation-case API is not connected in this MVP. This queue reflects finding review status only.')}</p></>}
        {page === 'Reports' && <>{reportError && <div className="error-banner" role="alert"><span>{reportError}</span><button onClick={() => setReportError('')}>{tr('Dismiss')}</button></div>}<Panel title={tr('Local report drafts')} subtitle={tr('Integrity-checked local artifacts · never submitted automatically')}>{demo ? <div className="report-card"><div className="report-illustration"><Icon name="report" size={42}/></div><div><Badge tone="warning">{tr('DEMO DRAFT')}</Badge><h3>{tr('Server version disclosure')}</h3><p>{tr('A synthetic report showing finding, evidence, impact, and remediation sections.')}</p><small className="mono">F-0040 · {tr('LOW')} · Markdown</small><div className="button-row"><button className="secondary-button" onClick={() => { setSelectedReport(null); setReportPreview(sampleReport); setModal('report'); }}>{tr('Preview draft')}</button><button className="primary-button" onClick={() => download('DEMO-Report.md', sampleReport)}>{tr('Download demo .md')} <Icon name="arrow" size={14}/></button></div></div></div> : reports.length ? <div className="report-list">{reports.map(item => <div className="report-card" key={item.report_id}><div className="report-illustration"><Icon name="report" size={42}/></div><div><Badge tone="success">{tr('LOCAL DRAFT')}</Badge><h3>{item.title}</h3><p>{item.platform} · 케이스 {item.case_id}</p><small className="mono">{item.report_id} · {new Date(item.created_at).toLocaleString('ko-KR')}</small><div className="button-row"><button className="secondary-button" onClick={() => void openReport(item)}>{tr('Preview draft')}</button></div></div></div>)}</div> : <Empty title={tr('No report draft for this scan')}>{tr('Validated report artifacts will appear here after the existing CLI report workflow creates an integrity-bound draft.')}</Empty>}</Panel></>}
        {page === 'Audit log' && <><div className="notice"><Icon name="logs"/><div><strong>{tr(demo ? 'Synthetic audit trail' : 'Authoritative audit metadata')}</strong><p>{tr('Pipeline.db audit_events are append-only. Details, request bodies, headers, tokens, and cookies are never returned by this endpoint.')}</p></div></div>{auditError && <div className="error-banner" role="alert"><span>{auditError}</span><button onClick={() => { setAuditError(''); go('Scans'); }}>{tr('Open scans')}</button></div>}<Panel title={tr('Decision history')} subtitle={`${demo ? 4 : auditEntries.length}개 기록 · 최신순`}><div className="audit-list">{(demo ? [{id:'demo-4',created_at:'2026-09-20T05:28:24Z',event_type:'finding.created',stage:'Attack'},{id:'demo-3',created_at:'2026-09-20T05:28:12Z',event_type:'request.authorized',stage:'Attack'},{id:'demo-2',created_at:'2026-09-20T05:28:09Z',event_type:'pipeline.materialized',stage:'Recon'},{id:'demo-1',created_at:'2026-09-20T05:28:00Z',event_type:'scope.verified',stage:'Scope'}] : auditEntries).map(item => <div key={item.id}><time dateTime={item.created_at}>{new Date(item.created_at).toLocaleTimeString('ko-KR',{hour12:false})}</time><span className="audit-point"/><div><strong>{localizeAuditEventType(language, item.event_type)}</strong><p>{demo ? tr('Synthetic fixture decision') : `${tr('Redacted pipeline event')} · ${item.id}`}</p></div><Badge>{tr(item.stage)}</Badge></div>)}</div>{!demo && !auditEntries.length && !auditError && <p className="table-empty">{tr('No audit records are available for this scan.')}</p>}</Panel></>}
        {page === 'Settings' && <><Panel title={tr('Connection')} subtitle={tr('Configured at build time; no secrets in browser settings')}><dl className="detail-grid"><div><dt>{tr('Transport')}</dt><dd><Badge tone={demo ? 'warning' : 'success'}>{tr(demo ? 'Demo / local fixture' : 'Live / read-only')}</Badge></dd></div><div><dt>{tr('Connection state')}</dt><dd>{tr(state)}</dd></div><div><dt>{tr('Result storage')}</dt><dd className="mono">{tr(resultRoot || 'Unavailable')}</dd></div><div><dt>{tr('Snapshot endpoint')}</dt><dd className="mono">GET /api/v1/scans/:id</dd></div><div><dt>{tr('Delta stream')}</dt><dd className="mono">/ws/scans/:id?after=:event_id</dd></div><div><dt>{tr('Protocol')}</dt><dd>{tr('Version 1 · contiguous event IDs')}</dd></div><div><dt>{tr('Activity retention')}</dt><dd>{tr('Latest 500 events in memory')}</dd></div></dl><div className="panel-bottom"><p>{tr('Set VITE_TRANSPORT=live and VITE_SCAN_ID to connect an implemented backend. Live mode never falls back to demo data.')}</p><button className="secondary-button" onClick={refresh}>{tr(demo ? 'Restart demo' : 'Reload snapshot')}</button></div></Panel><Panel title={tr('Workspace preferences')} subtitle={tr('Theme is saved locally; operational data is never uploaded')}><div className="setting-row"><div><h3>{tr('Appearance')}</h3><p>{tr('Follow the system theme or keep this workspace light or dark.')}</p></div><select aria-label={tr('Color theme')} value={theme} onChange={event => setTheme(event.target.value as ThemeChoice)}><option value="system">{tr('System')}</option><option value="dark">{tr('Dark')}</option><option value="light">{tr('Light')}</option></select></div><div className="setting-row"><div><h3>{tr('Language')}</h3><p>{tr('Choose the dashboard display language.')}</p></div><select aria-label={tr('Language')} value={language} onChange={event => setLanguage(event.target.value as Language)}><option value="ko">한국어</option><option value="en">English</option></select></div><div className="setting-row"><div><h3>{tr('Compact density')}</h3><p>{tr('Reduce spacing in data tables and activity.')}</p></div><input aria-label={tr('Compact density')} type="checkbox" checked={compact} onChange={e => setCompact(e.target.checked)}/></div><div className="setting-row"><div><h3>{tr('Reveal private program name')}</h3><p>{tr('Hidden by default. Resets when the page reloads.')}</p></div><input aria-label={tr('Reveal private program name')} type="checkbox" checked={privateVisible} onChange={e => setPrivateVisible(e.target.checked)}/></div></Panel><Panel title={tr('Backend integration remaining')} subtitle={tr('Implemented boundaries stay separate from future operator workflows')}><ul className="integration-list"><li>{tr('Authentication and authorization for any deployment beyond the loopback-only local operator.')}</li><li>{tr('Evidence-backed Validation case decisions and review actions.')}</li><li>{tr('Report generation and platform submission remain explicit CLI/operator actions.')}</li></ul></Panel></>}
      </main>
      <aside className={`activity-panel ${collapsed ? 'collapsed' : ''}`} aria-label={tr('Persistent live activity')}>
        <div className="activity-heading"><div><Icon name="terminal" size={17}/><h2>{tr('Live activity')}</h2></div><button className="icon-button" onClick={() => setCollapsed(v => !v)} aria-label={tr(collapsed ? 'Expand activity' : 'Collapse activity')} aria-expanded={!collapsed}>{collapsed ? '+' : '−'}</button></div>
        {!collapsed && <>
          {(scopeActive || scanId || demo) && <div className="activity-source">
            {scopeActive && <Badge tone="warning"><span className="dot"/>스코프 수집 · {scopeWorkLabel} {scopeElapsedLabel}</Badge>}
            {(demo || scanId) && <Badge tone={demo ? 'warning' : 'success'}><span className="dot"/>{demo ? tr('SIMULATED STREAM') : tr(state)}</Badge>}
            <span className="mono">{snapshot?.scan_id || scanId || workflowProgram?.scope_job_id}</span>
          </div>}
          <div className="activity-stage">
            {scopeActive && <div className="scope-working-summary"><span>스코프 수집</span><strong role="timer">{scopeWorkLabel} · {scopeElapsedLabel}</strong></div>}
            <div><span>{tr('Current stage')}</span><strong>{tr(snapshot?.stage || 'Waiting')} <small>{snapshot?.progress || 0}%</small></strong></div>
            <progress aria-label={tr('Current stage progress')} max="100" value={snapshot?.progress || 0}/>
          </div>
          {hasActivity && <div className="activity-filters"><label className="search-field"><Icon name="search" size={14}/><input aria-label={tr('Search activity')} value={logSearch} onChange={e => setLogSearch(e.target.value)} placeholder={tr('Search activity…')}/></label><div><select aria-label={tr('Filter log level')} value={level} onChange={e => setLevel(e.target.value)}>{['All levels','info','success','warning','error'].map(l => <option key={l} value={l}>{tr(l)}</option>)}</select><select aria-label={tr('Filter log stage')} value={stageFilter} onChange={e => setStageFilter(e.target.value)}>{['All stages',...stages].map(s => <option key={s} value={s}>{tr(s)}</option>)}</select></div></div>}
          {hasActivity && <div className="log-toolbar"><span>{visibleLogs.length} {tr('events')}{scopeActive && <b> · {scopeWorkLabel} {scopeElapsedLabel}</b>}</span><button onClick={() => setPaused(v => !v)} aria-pressed={paused}>{tr(paused ? '▶ Resume following' : 'Ⅱ Pause scrolling')}</button></div>}
          <div className="log-stream" ref={stream} tabIndex={0} aria-label={tr('Activity events')}>
            {hasActivity && <div className="stream-start">{demo ? tr('SYNTHETIC SESSION STARTED') : '통합 활동 스트림 시작'}</div>}
            {visibleLogs.map(log => <article key={log.key} className={`log-entry ${log.level}`}><div><time dateTime={log.time}>{new Date(log.time).toLocaleTimeString('ko-KR',{hour12:false})}</time><span>{log.source === 'scope' ? '스코프 수집' : `스캔 · ${tr(log.stage)}`}</span><i title={tr(log.level)}/><span className="sr-only">{tr(log.level)}</span></div><p>{localizeActivityMessage(language, log)}</p></article>)}
            {showScopeWorking && <article className="log-entry scope-working"><div><time>{scopeElapsedLabel}</time><span>스코프 수집</span><i title={scopeWorkLabel}/><span className="sr-only">{scopeWorkLabel}</span></div><p role="timer">{scopeWorkLabel} · {scopeElapsedLabel}</p></article>}
            {!hasActivity && <div className="activity-empty"><strong>아직 활동이 없습니다</strong><p>스코프 수집 또는 스캔을 시작하면 활동이 여기에 표시됩니다.</p></div>}
            {hasActivity && visibleLogs.length === 0 && !showScopeWorking && <p className="table-empty">{tr('No matching events.')}</p>}
            {hasActivity && <div className="stream-end"><span className="dot"/>{scopeActive ? `스코프 수집 진행 중 · ${scopeElapsedLabel}` : tr(paused ? 'Following paused · events still arrive' : snapshot?.status === 'running' ? 'Waiting for the next event' : 'End of available activity')}</div>}
          </div>
          <footer className="activity-footer"><Icon name="lock" size={13}/><p>{tr(demo ? 'Fixtures contain no credentials. Live events must be redacted by the server.' : 'Server-side redaction required. Never stream tokens, cookies, or sensitive bodies.')}</p></footer>
        </>}
      </aside>
      </div>
    </div>
    <dialog ref={dialog} onCancel={closeDialog} onClose={closeDialog} aria-labelledby="dialog-title">
      <div className="dialog-heading"><h2 id="dialog-title">{modal === 'new' ? tr('Start a new scan') : modal === 'scan-progress' ? '스캔 진행 상황' : modal === 'scope' ? tr('Add bug bounty program') : modal === 'scope-workflow' ? tr(workflowProgram?.scope_status === 'approved' ? 'View approved Scope' : 'Collect and review Scope') : modal === 'verified-scope' ? '검증된 Scope 내용' : modal === 'report' ? tr(demo ? 'Demo report preview' : 'Local report preview') : selectedFinding?.id}</h2><button className="icon-button" aria-label={tr('Close dialog')} onClick={closeDialog}>×</button></div>
      {modal === 'new' ? newScanContent : modal === 'scan-progress' ? scanProgressContent : modal === 'scope' ? scopeIntakeContent : modal === 'scope-workflow' ? scopeWorkflowContent : modal === 'verified-scope' ? (catalogScopeSummaryOnly ? catalogScopeSummaryContent : catalogScopeError ? <p className="form-error" role="alert">{catalogScopeError}</p> : catalogScopeDraft && catalogScopeApproval ? <VerifiedScopeDetails draft={catalogScopeDraft} approval={catalogScopeApproval} language={language} onScan={() => scanFromScope(catalogScopeDraft.scope_id)}/> : <p className="form-empty">검증된 Scope 내용을 불러오는 중입니다…</p>) : modal === 'report' ? <><pre className="report-preview">{reportPreview}</pre><div className="button-row"><button className="primary-button" onClick={() => download(`${selectedReport?.report_id || 'DEMO-Report'}.md`, reportPreview)}>{tr('Download .md')} <Icon name="arrow" size={14}/></button></div></> : selectedFinding && <><Badge tone={selectedFinding.severity.toLowerCase()}>{tr(selectedFinding.severity)}</Badge><h3 className="finding-detail-title">{selectedFinding.title}</h3><dl className="detail-grid"><div><dt>{tr('Endpoint')}</dt><dd className="mono">{selectedFinding.endpoint}</dd></div><div><dt>{tr('Classification')}</dt><dd>{selectedFinding.cwe}</dd></div><div><dt>{tr('Review status')}</dt><dd>{tr(selectedFinding.status)}</dd></div><div><dt>{tr('Source')}</dt><dd>{tr(demo ? 'Synthetic fixture' : 'Pipeline finding')}</dd></div></dl><div className="notice"><Icon name="shield"/><p>{tr(demo ? 'This is synthetic evidence for UI demonstration. No listed program was tested.' : 'Evidence details require a redacted evidence endpoint. The summary alone is not proof of a vulnerability.')}</p></div><button className="secondary-button" onClick={() => { setModal(null); go('Validation'); }}>{tr('Open validation queue')} <Icon name="arrow" size={14}/></button></>}
    </dialog>
  </div>;
}
