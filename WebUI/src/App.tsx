import { useEffect, useRef, useState, type ReactNode } from 'react';
import { DEMO_SCAN } from './data/demo';
import { transportMode, useScanSocket } from './hooks/useScanSocket';
import { stages, type Finding, type Snapshot } from './lib/events';
import { initialLanguage, translate, type Language } from './lib/i18n';
import {
  resolveExecutionLimits,
  type ExecutionProfileId,
  type ScopeExecutionRequirements,
} from './lib/scan';
import { scopeCollectionRequest } from './lib/scope';

const pages = ['Overview', 'Scopes / Programs', 'Scans', 'Findings', 'Validation', 'Reports', 'Audit log', 'Settings'] as const;
type Page = typeof pages[number];
type ScanSummary = { scan_id: string; status: Snapshot['status']; started_at: string; finished_at: string | null };
type ScopeTarget = { asset_type: string; asset: string; description: string; maximum_severity: string };
type ApprovedScope = { scope_id: string; program_id: string; program_name: string; platform: string; targets: ScopeTarget[]; identity_header: 'hackerone' | 'intigriti' | null; approved_by: string; execution_requirements: ScopeExecutionRequirements };
type ScopeStatus = 'scope_required' | 'collecting' | 'awaiting_browser' | 'review_required' | 'approved' | 'rejected' | 'failed';
type RegisteredProgram = { id: string; platform: string; program: string; visibility: 'public' | 'private'; scope_status: ScopeStatus; scope_job_id?: string; scope_error?: string | null; scope_updated_at?: string; created_at: string };
type ScopeJobEvent = { job_id: string; event_id: number; occurred_at: string; level: string; message: string };
type ScopeDraftAsset = ScopeTarget & { eligibility: string };
type ScopeDraft = { scope_id: string; created_at: string; source_url: string; program_name: string; program_description: string; in_scope_assets: ScopeDraftAsset[]; out_of_scope_assets: ScopeDraftAsset[]; allowed_activities: string[]; prohibited_activities: string[]; submission_requirements: string[]; operational_constraints: string[]; safe_harbor: string; ambiguities: string[]; source_evidence: { section: string; quote: string }[] };
type ScopeApproval = { approved_by: string; approved_at: string };
type AuditEntry = { id: string; event_type: string; stage: string; created_at: string };
type ReportSummary = { report_id: string; scan_id: string; case_id: string; platform: string; title: string; created_at: string };
type ThemeChoice = 'system' | 'dark' | 'light';
const scopeStatusLabel: Record<ScopeStatus, string> = { scope_required: 'Scope required', collecting: 'Collecting', awaiting_browser: 'Login required', review_required: 'Review Yes / No', approved: 'Approved', rejected: 'Rejected', failed: 'Failed' };
const scopeStatusTone = (status: ScopeStatus) => status === 'approved' ? 'success' : status === 'failed' || status === 'rejected' ? 'critical' : 'warning';
const THEME_KEY = 'aidast-theme';
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
function Empty({ title, children }: { title: string; children: ReactNode }) { return <div className="empty"><Icon name="lock" size={26}/><h3>{title}</h3><p>{children}</p></div>; }
function Pipeline({ snapshot, language }: { snapshot: Snapshot; language: Language }) {
  const index = stages.indexOf(snapshot.stage);
  return <ol className="pipeline" aria-label={translate(language, 'Scan workflow')}>{stages.map((s, i) => <li key={s} className={i < index || snapshot.status === 'completed' ? 'done' : i === index ? 'current' : ''}><span className="stage-number">{i < index || snapshot.status === 'completed' ? <Icon name="check" size={13}/> : String(i + 1).padStart(2,'0')}</span><strong>{s}</strong><small>{i < index || snapshot.status === 'completed' ? translate(language, 'Completed') : i === index ? `${snapshot.progress}% · ${translate(language, snapshot.status)}` : translate(language, 'Pending')}</small></li>)}</ol>;
}
function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'text/markdown;charset=utf-8' }));
  const a = document.createElement('a'); a.href = url; a.download = name; a.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const sampleReport = '# DEMO — Local report draft\n\nSynthetic fixture only. No real program or target was tested.\n\n## Finding F-0040\nServer version in response headers (CWE-200).\nSeverity: Low. Fixture review status: confirmed.\n\n## Reproduction\nThe synthetic GET /health fixture includes a server version header.\nA repeat fixture and a control fixture were compared.\n\n## Impact\nLimited information exposure in an isolated demonstration.\nNo production impact is claimed.\n\n## Remediation\nRemove unnecessary server version headers.\n\nThis local draft has not been submitted to any platform.\n';

export default function App() {
  const getPage = () => pages[Math.max(0, slugs.indexOf(location.hash.slice(1)))];
  const [page, setPage] = useState<Page>(getPage);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('All severities');
  const [privateVisible, setPrivateVisible] = useState(false);
  const [modal, setModal] = useState<'new' | 'scope' | 'scope-workflow' | 'finding' | 'report' | null>(null);
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
  const stream = useRef<HTMLDivElement>(null);
  const demo = transportMode === 'demo';
  const configuredScanId = demo ? DEMO_SCAN : import.meta.env.VITE_SCAN_ID || '';
  const [scanId, setScanId] = useState<string>(configuredScanId);
  const [scanOptions, setScanOptions] = useState<ScanSummary[]>([]);
  const [scopes, setScopes] = useState<ApprovedScope[]>([]);
  const [registeredPrograms, setRegisteredPrograms] = useState<RegisteredProgram[]>([]);
  const [scopeProgramUrl, setScopeProgramUrl] = useState('');
  const [scopeVisibility, setScopeVisibility] = useState<'public' | 'private'>('public');
  const [scopeSubmitting, setScopeSubmitting] = useState(false);
  const [scopeError, setScopeError] = useState('');
  const [workflowProgram, setWorkflowProgram] = useState<RegisteredProgram | null>(null);
  const [scopeEvents, setScopeEvents] = useState<ScopeJobEvent[]>([]);
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
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditError, setAuditError] = useState('');
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [reportError, setReportError] = useState('');
  const [reportPreview, setReportPreview] = useState(sampleReport);
  const [selectedReport, setSelectedReport] = useState<ReportSummary | null>(null);
  const [resultRoot, setResultRoot] = useState(demo ? 'Synthetic demo data (memory)' : '');
  const { snapshot, state, error, refresh } = useScanSocket(scanId);
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
          return typeof row.scan_id === 'string' && row.scan_id.length > 0 && row.scan_id.length <= 128 && typeof row.status === 'string' && typeof row.started_at === 'string' && (row.finished_at === null || typeof row.finished_at === 'string');
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
    if (demo || modal !== 'scope-workflow' || !workflowProgram?.scope_job_id) return;
    const abort = new AbortController();
    const load = async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/scope-job?after=0`, base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        const body = await response.json() as { job?: Partial<RegisteredProgram>; events?: ScopeJobEvent[]; detail?: string };
        if (!response.ok || !body.job) throw new Error(body.detail || `Scope status returned ${response.status}`);
        setWorkflowProgram(current => current ? { ...current, ...body.job } : current);
        if (Array.isArray(body.events)) setScopeEvents(body.events);
        if (body.job.scope_status === 'review_required') {
          const draftResponse = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/scope-draft`, base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
          const draftBody = await draftResponse.json() as { draft?: ScopeDraft; detail?: string };
          if (!draftResponse.ok || !draftBody.draft) throw new Error(draftBody.detail || `Scope draft returned ${draftResponse.status}`);
          setScopeDraft(draftBody.draft);
          setScopeApproval(null);
        } else if (body.job.scope_status === 'approved') {
          const scopeResponse = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/approved-scope`, base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
          const scopeBody = await scopeResponse.json() as { scope?: ScopeDraft; approval?: ScopeApproval; detail?: string };
          if (!scopeResponse.ok || !scopeBody.scope || !scopeBody.approval) throw new Error(scopeBody.detail || `Approved Scope returned ${scopeResponse.status}`);
          setScopeDraft(scopeBody.scope);
          setScopeApproval(scopeBody.approval);
          setScopeWorkflowError('');
        }
      } catch (e) {
        if (!abort.signal.aborted) setScopeWorkflowError(e instanceof Error ? e.message : 'Scope status could not be loaded.');
      }
    };
    void load();
    const timer = workflowProgram.scope_status === 'approved' ? undefined : window.setInterval(() => void load(), 1000);
    return () => { abort.abort(); window.clearInterval(timer); };
  }, [demo, modal, workflowProgram?.id, workflowProgram?.scope_job_id, workflowProgram?.scope_status]);
  useEffect(() => { if (modal) dialog.current?.showModal(); else dialog.current?.close(); }, [modal]);
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
    if (demo || page !== 'Reports') return;
    const abort = new AbortController();
    setReportError('');
    void (async () => {
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const url = new URL('/api/v1/reports', base);
        if (scanId) url.searchParams.set('scan_id', scanId);
        const response = await fetch(url, { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        const body = await response.json() as { reports?: ReportSummary[]; detail?: string };
        if (!response.ok || !Array.isArray(body.reports)) throw new Error(body.detail || `Report request returned ${response.status}`);
        setReports(body.reports);
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
        setScopeId(current => loaded.some(item => item.scope_id === current) ? current : loaded[0]?.scope_id || '');
      } catch (e) { if (!abort.signal.aborted) setLaunchError(e instanceof Error ? e.message : 'Approved scopes could not be loaded.'); }
    })();
    return () => abort.abort();
  }, [modal, demo]);
  const selectedScope = scopes.find(item => item.scope_id === scopeId);
  const selectedLimits = selectedScope
    ? resolveExecutionLimits(selectedScope.execution_requirements, scanProfile)
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
    setWorkflowProgram(item); setScopeEvents([]); setScopeDraft(null); setScopeApproval(null); setScopeReviewer(''); setScopeConfirmed(false); setScopeWorkflowError(''); setModal('scope-workflow');
  };
  const startScopeCollection = async () => {
    if (!workflowProgram) return;
    setScopeActionBusy(true); setScopeWorkflowError(''); setScopeEvents([]); setScopeDraft(null); setScopeApproval(null);
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/programs/${encodeURIComponent(workflowProgram.id)}/scope-collection`, base), {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scopeCollectionRequest),
      });
      const body = await response.json() as { job?: Partial<RegisteredProgram>; detail?: string };
      if (!response.ok || !body.job) throw new Error(body.detail || `Scope collection returned ${response.status}`);
      setWorkflowProgram(current => current ? { ...current, ...body.job } : current);
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
    } catch (e) { setScopeWorkflowError(e instanceof Error ? e.message : 'Browser confirmation failed.'); }
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
      setScopeDraft(null); setScopeConfirmed(false);
      await refreshRegisteredPrograms();
    } catch (e) { setScopeWorkflowError(e instanceof Error ? e.message : 'Scope decision failed.'); }
    finally { setScopeActionBusy(false); }
  };
  const startScan = async () => {
    if (!selectedScope || !selectedTargets.length || !authorizationConfirmed) return;
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
      const created: ScanSummary = { scan_id: body.scan_id, status: body.status || 'running', started_at: body.started_at || new Date().toISOString(), finished_at: null };
      setScanOptions(current => [created, ...current.filter(item => item.scan_id !== created.scan_id)]);
      setScanId(created.scan_id); setModal(null); go('Scans');
    } catch (e) { setLaunchError(e instanceof Error ? e.message : 'The scan could not be started.'); }
    finally { setLaunching(false); }
  };
  const visibleLogs = (snapshot?.logs || []).filter(l => (level === 'All levels' || l.level === level) && (stageFilter === 'All stages' || l.stage === stageFilter) && `${l.message} ${l.stage}`.toLowerCase().includes(logSearch.toLowerCase()));
  useEffect(() => { if (!paused && stream.current) stream.current.scrollTop = stream.current.scrollHeight; }, [snapshot?.last_event_id, paused, logSearch, level, stageFilter, collapsed]);
  const findings = snapshot?.findings || [];
  const shownFindings = findings.filter(f => `${f.id} ${f.title} ${f.endpoint}`.toLowerCase().includes(search.toLowerCase()) && (severity === 'All severities' || f.severity === severity));
  const reviewCount = findings.filter(f => f.status === 'unreviewed').length;
  const approvedScopeCount = demo ? 0 : scopes.length;
  const totalProgramCount = registeredPrograms.length;
  const visiblePrograms = registeredPrograms.filter(item => `${item.visibility === 'private' && !privateVisible ? 'Private program' : item.program} ${item.platform}`.toLowerCase().includes(search.toLowerCase()));
  const inspect = (f: Finding) => { setSelectedFinding(f); setModal('finding'); };
  const openReport = async (item: ReportSummary) => {
    setReportError('');
    try {
      const base = import.meta.env.VITE_API_BASE_URL || location.origin;
      const response = await fetch(new URL(`/api/v1/reports/${encodeURIComponent(item.report_id)}`, base), { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error(`Report preview returned ${response.status}`);
      setSelectedReport(item); setReportPreview(await response.text()); setModal('report');
    } catch (e) { setReportError(e instanceof Error ? e.message : 'The report preview could not be loaded.'); }
  };
  const findingTable = (rows: Finding[]) => <div className="table-wrap"><table><thead><tr><th>{tr('Severity')}</th><th>{tr('Finding')}</th><th>{tr('Review status')}</th><th><span className="sr-only">{tr('Details')}</span></th></tr></thead><tbody>{rows.map(f => <tr key={f.id}><td><Badge tone={f.severity.toLowerCase()}>{f.severity}</Badge></td><td><button className="text-button finding-title" onClick={() => inspect(f)}>{f.title}</button><small className="mono">{f.id} <span>·</span> {f.endpoint}</small></td><td><Badge tone={f.status === 'confirmed' ? 'success' : ''}>{tr(f.status)}</Badge></td><td><button className="icon-button" aria-label={`${tr('Details')} ${f.id}`} onClick={() => inspect(f)}><Icon name="arrow" size={16}/></button></td></tr>)}</tbody></table>{rows.length === 0 && <p className="table-empty">{tr('No findings match this view.')}</p>}</div>;
  const scanPanel = <Panel title={demo ? tr('Local lab · API assessment') : snapshot?.program_name || scanId} subtitle={demo ? tr('Synthetic fixture · isolated from program inventory') : `${tr('Read-only scan snapshot')} · ${scanId}`} action={<Badge tone="success"><span className="dot"/>{tr(snapshot?.status || state)}</Badge>}>
    {snapshot ? <><Pipeline snapshot={snapshot} language={language}/><div className="scan-stats"><div><span>{tr('Scan ID')}</span><strong className="mono">{snapshot.scan_id}</strong></div><div><span>{tr('Endpoints')}</span><strong>{snapshot.endpoints}</strong></div><div><span>{tr('Request budget')}</span><strong>{snapshot.requests} <small>/ {snapshot.budget.toLocaleString()}</small></strong></div><div className="progress-stat"><span>{snapshot.stage} {tr('progress')} <b>{snapshot.progress}%</b></span><progress max="100" value={snapshot.progress} aria-label={`${snapshot.stage} ${tr('progress')}`}/></div></div></> : <Empty title={tr(state === 'offline' ? 'Backend unavailable' : 'Loading scan snapshot')}>{tr('Connect the REST snapshot endpoint to display scan state. Demo data is never substituted in live mode.')}</Empty>}
  </Panel>;
  const requiredHeader = selectedScope?.execution_requirements.required_header;
  const handleRequired = !!requiredHeader;
  const limitsValid = !!selectedLimits
    && maxRequests >= 1 && maxRequests <= selectedLimits.max_requests
    && maxRps > 0 && maxRps <= selectedLimits.requests_per_second
    && maxConcurrency >= 1 && maxConcurrency <= selectedLimits.concurrency
    && timeoutSeconds >= 1 && timeoutSeconds <= selectedLimits.timeout_seconds
    && maxDepth >= 0 && maxDepth <= selectedLimits.max_depth;
  const canLaunch = !demo && !!selectedScope && selectedTargets.length > 0
    && authorizationConfirmed && limitsValid
    && (!handleRequired || !!platformHandle.trim()) && !launching;
  const newScanContent = <div className="scan-form">
    <div className="notice"><Icon name="lock"/><div><strong>{tr('Approved Scope only')}</strong><p>{tr('The backend re-verifies approval integrity and the Python orchestrator enforces TargetPolicy and request budgets.')}</p></div></div>
    {demo ? <p className="form-error">{tr('Switch to the live local dashboard to start a scan.')}</p> : <>
      <label className="form-field"><span>{tr('Verified Scope')}</span><select aria-label={tr('Approved program')} value={scopeId} onChange={event => { setScopeId(event.target.value); setSelectedTargets([]); setPlatformHandle(''); }}><option value="">{tr('Select a recent approved scope')}</option>{scopes.map(scope => <option key={scope.scope_id} value={scope.scope_id}>{scope.program_name} · {scope.platform}</option>)}</select></label>
      {selectedScope && <>
        <fieldset className="target-fieldset"><legend>{tr('Targets')} <small>{selectedTargets.length}{tr('selected')}</small></legend><div className="target-actions"><button type="button" className="text-button" onClick={() => setSelectedTargets(selectedScope.targets.map(item => item.asset))}>{tr('Select all')}</button><button type="button" className="text-button" onClick={() => setSelectedTargets([])}>{tr('Clear')}</button></div><div className="target-list">{selectedScope.targets.map(target => <label key={`${target.asset_type}:${target.asset}`}><input type="checkbox" checked={selectedTargets.includes(target.asset)} onChange={() => setSelectedTargets(current => current.includes(target.asset) ? current.filter(item => item !== target.asset) : [...current, target.asset])}/><span><strong>{target.asset}</strong><small>{target.asset_type} · max {target.maximum_severity || tr('program policy')}</small></span></label>)}</div></fieldset>
        {selectedTargets.length > 0 && selectedLimits && <section className="execution-requirements"><div className="execution-requirements-heading"><div><h3>{tr('Execution requirements')}</h3><p>{tr("Derived from this Scope's policy and the selected safe profile.")}</p></div><div className="stage-badges"><Badge>{tr('Recon')}</Badge><Badge>{tr('Attack')}</Badge><Badge>{tr('Validation')}</Badge></div></div><div className="requirements-summary"><div><span>{tr('Scope request-rate limit')}</span><strong>{selectedScope.execution_requirements.scope_max_requests_per_second ? `${selectedScope.execution_requirements.scope_max_requests_per_second}/s` : tr('Not specified by policy')}</strong></div><div><span>{tr('Required request header')}</span><strong className="mono">{selectedScope.execution_requirements.required_header?.name || tr('None')}</strong></div></div>{selectedScope.execution_requirements.operational_constraints.length > 0 && <div className="operational-constraints"><h3>{tr('Operational constraints')}</h3><ul>{selectedScope.execution_requirements.operational_constraints.map(item => <li key={item}>{item}</li>)}</ul></div>}<p className="requirements-note">{tr('TargetPolicy is regenerated at launch and may lower these limits further.')}</p></section>}
        <div className="form-grid"><label className="form-field"><span>{tr('Execution profile')}</span><select value={scanProfile} onChange={event => setScanProfile(event.target.value as ExecutionProfileId)}><option value="safe-recon">{tr('Safe recon')}</option><option value="focused-discovery">{tr('Focused discovery')}</option></select></label><label className="form-field"><span>{tr('Request budget')} <small>≤ {selectedLimits?.max_requests.toLocaleString()}</small></span><input type="number" min="1" max={selectedLimits?.max_requests} value={maxRequests} onChange={event => setMaxRequests(Number(event.target.value))}/></label></div>
        <div className="form-grid"><label className="form-field"><span>{tr('Requests per second')} <small>≤ {selectedLimits?.requests_per_second}</small></span><input type="number" min="0.1" step="0.1" max={selectedLimits?.requests_per_second} value={maxRps} onChange={event => setMaxRps(Number(event.target.value))}/></label><label className="form-field"><span>{tr('Concurrency')} <small>≤ {selectedLimits?.concurrency}</small></span><input type="number" min="1" max={selectedLimits?.concurrency} value={maxConcurrency} onChange={event => setMaxConcurrency(Number(event.target.value))}/></label></div>
        <div className="form-grid"><label className="form-field"><span>{tr('Timeout seconds')} <small>≤ {selectedLimits?.timeout_seconds}</small></span><input type="number" min="1" max={selectedLimits?.timeout_seconds} value={timeoutSeconds} onChange={event => setTimeoutSeconds(Number(event.target.value))}/></label><label className="form-field"><span>{tr('Maximum depth')} <small>≤ {selectedLimits?.max_depth}</small></span><input type="number" min="0" max={selectedLimits?.max_depth} value={maxDepth} onChange={event => setMaxDepth(Number(event.target.value))}/></label></div>
        <div className="form-grid"><label className="form-field"><span>{tr('Login behavior')}</span><select value={loginMode} onChange={event => setLoginMode(event.target.value as 'none' | 'runtime-browser')}><option value="none">{tr('No login prompt')}</option><option value="runtime-browser">{tr('Open runtime browser')}</option></select></label>{requiredHeader && <label className="form-field"><span className="mono">{requiredHeader.name} <small>{tr('required for every request')}</small></span><input value={platformHandle} onChange={event => setPlatformHandle(event.target.value)} autoComplete="off" maxLength={64} placeholder={tr('Enter the platform username sent in this header')}/></label>}</div>
        <label className="confirm-field"><input type="checkbox" checked={authorizationConfirmed} onChange={event => setAuthorizationConfirmed(event.target.checked)}/><span>{tr('I confirm these selected targets are currently authorized and accept the policy-derived execution requirements shown above.')}</span></label>
      </>}
      {launchError && <p className="form-error" role="alert">{launchError}</p>}
      {!scopes.length && !launchError && <p className="form-empty">{tr('Loading verified scopes…')}</p>}
      <div className="button-row"><button className="secondary-button" onClick={() => { setModal(null); go('Scopes / Programs'); }}>{tr('Review programs')}</button><button className="primary-button" disabled={!canLaunch} onClick={() => void startScan()}>{tr(launching ? 'Starting…' : 'Start scan')} <Icon name="arrow" size={14}/></button></div>
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
    {(workflowProgram.scope_status === 'scope_required' || workflowProgram.scope_status === 'rejected' || workflowProgram.scope_status === 'failed') && <>
      <div className="notice"><Icon name="scope"/><div><strong>{tr('Collect a policy snapshot')}</strong><p>{tr('AI DAST opens its own browser. Log in to the bug bounty platform, open the exact Scope page, and continue here. The result remains an unapproved draft until you review it.')}</p></div></div>
      {workflowProgram.scope_error && <p className="form-error">{tr('Previous attempt:')} {workflowProgram.scope_error}</p>}
      <div className="button-row"><button className="secondary-button" onClick={() => setModal(null)}>{tr('Cancel')}</button><button className="primary-button" disabled={scopeActionBusy} onClick={() => void startScopeCollection()}>{tr(scopeActionBusy ? 'Starting…' : workflowProgram.scope_status === 'scope_required' ? 'Collect Scope' : 'Collect again')} <Icon name="arrow" size={14}/></button></div>
    </>}
    {(workflowProgram.scope_status === 'collecting' || workflowProgram.scope_status === 'awaiting_browser') && <>
      <div className="notice"><Icon name="terminal"/><div><strong>{tr(workflowProgram.scope_status === 'awaiting_browser' ? 'Browser input required' : 'Scope collection is running')}</strong><p>{tr(workflowProgram.scope_status === 'awaiting_browser' ? 'Finish login or MFA in the opened local browser, return to the exact policy page, then continue here.' : 'The dashboard is collecting and interpreting the program policy. Keep this dialog open to follow progress.')}</p></div></div>
      {workflowProgram.scope_status === 'awaiting_browser' && <button className="primary-button workflow-wide-button" disabled={scopeActionBusy} onClick={() => void confirmScopeBrowser()}>{tr(scopeActionBusy ? 'Continuing…' : 'I finished login · Continue')}</button>}
    </>}
    {scopeEvents.length > 0 && <details className="scope-event-list">
      <summary><strong className="scope-event-title">{tr('Collection activity')} <small>{scopeEvents.length}</small></strong></summary>
      <div className="scope-event-history">{scopeEvents.map(event => <div key={`${event.job_id}:${event.event_id}`} className={event.level}><time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleTimeString('en-GB', { hour12: false })}</time><span>{event.message}</span></div>)}</div>
    </details>}
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
      <div className="workspace-label"><span className="workspace-avatar">W</span><div>{tr('Local workspace')}<small>WHS4 / DAST Project</small></div><Badge>01</Badge></div>
      <nav aria-label={tr('Main navigation')}><p className="nav-label">{tr('OPERATIONS')}</p>{pages.map((p,i) => <button key={p} aria-label={pageLabel(p)} title={pageLabel(p)} className={`nav-item ${p === 'Settings' ? 'mobile-settings-nav' : ''} ${page === p ? 'active' : ''}`} onClick={() => go(p)} aria-current={page === p ? 'page' : undefined}><Icon name={symbols[i]}/><span>{pageLabel(p)}</span>{i === 1 && <em>{totalProgramCount}</em>}{i === 3 && snapshot && <em>{findings.length}</em>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="boundary-note"><Icon name="lock" size={16}/><strong>{tr('Scope comes first.')}</strong><p>{tr('Every request stays inside verified approval and policy boundaries.')}</p></div><button aria-label={tr('Settings')} title={tr('Settings')} className={`nav-item ${page === 'Settings' ? 'active' : ''}`} aria-current={page === 'Settings' ? 'page' : undefined} onClick={() => go('Settings')}><Icon name="settings"/><span>{tr('Settings')}</span></button><div className="operator"><div className="avatar">LO</div><div><strong>{tr('Local operator')}</strong><small>{tr(demo ? 'Demo workspace' : 'Backend session')}</small></div><span className="dot"/></div></div>
    </aside>
    <div className="main-shell"><header className="topbar"><div className="breadcrumb">{tr('Workspace')} <span>/</span> <strong>{pageLabel(page)}</strong></div><div className="top-actions"><span className={`connection ${demo ? 'demo' : ''}`}><span className="dot"/>{tr(demo ? 'Demo environment' : state)}</span><label className="language-select"><span className="sr-only">{tr('Language')}</span><select aria-label={tr('Language')} value={language} onChange={event => setLanguage(event.target.value as Language)}><option value="ko">한국어</option><option value="en">English</option></select></label><button className="icon-button theme-toggle" title={tr(`Switch to ${resolvedTheme === 'dark' ? 'light' : 'dark'} mode`)} aria-label={tr(`Switch to ${resolvedTheme === 'dark' ? 'light' : 'dark'} mode`)} onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}><Icon name={resolvedTheme === 'dark' ? 'sun' : 'moon'} size={16}/></button></div></header>
      <div className="demo-strip"><Icon name={demo ? 'terminal' : 'lock'} size={14}/><span>{tr(demo ? 'DEMO DATA' : 'LOCAL OPERATOR')}<b>·</b>{tr(demo ? 'A synthetic workflow. No network scans or program activity.' : 'Approved-scope scan controls + live REST and WebSocket status.')}</span><button onClick={() => go('Settings')}>{tr('Connection details')} <Icon name="arrow" size={13}/></button></div>
      <div className={`workspace-grid ${collapsed ? 'activity-collapsed' : ''}`}><main id="main-content" tabIndex={-1} className="content-column">
        <div className="page-heading"><div><p className="eyebrow">{tr(page === 'Overview' ? 'YOUR OPERATIONS, AT A GLANCE' : 'AI DAST / WORKSPACE')}</p><h1>{tr(page === 'Overview' ? 'Security overview' : page)}</h1><p>{tr(page === 'Overview' ? 'From approved scope to evidence you can stand behind.' : page === 'Scopes / Programs' ? 'Program inventory is a starting point. Approved scope defines execution.' : page === 'Scans' ? 'One deterministic pipeline. Traceable decisions at every stage.' : page === 'Findings' ? 'Signals become findings. Validation establishes the verdict.' : page === 'Validation' ? 'Reproduction, controls, and evidence before confirmation.' : page === 'Reports' ? 'Reviewable local drafts. Nothing is submitted automatically.' : page === 'Audit log' ? 'Trace the decisions and provenance behind each run.' : 'Connection, privacy, and display preferences.')}</p></div><span className="heading-tag">{demo ? 'FIXTURE / 042' : 'LIVE / V1'}</span></div>
        {page === 'Scopes / Programs' && <div className="scope-page-actions"><div><strong>{tr('Scope intake')}</strong><p>{tr('Register a bug bounty program before collecting and approving its executable Scope.')}</p></div><button className="primary-button" onClick={() => { setScopeError(''); setModal('scope'); }}><Icon name="plus" size={15}/>{tr('Add program')}</button></div>}
        {page === 'Scans' && <div className="scope-page-actions"><div><strong>{tr('Start scan')}</strong><p>{tr('Choose a verified approved Scope and configure a new scan.')}</p></div><button className="primary-button" onClick={() => { setSelectedTargets([]); setPlatformHandle(''); setAuthorizationConfirmed(false); setLaunchError(''); setModal('new'); }}><Icon name="plus" size={15}/>{tr('New scan')}</button></div>}
        {error && (page === 'Overview' || page === 'Scans' || page === 'Findings' || page === 'Validation') && <div className="error-banner" role="status"><span>{tr(error)}</span><button onClick={refresh}>{tr('Reload snapshot')}</button></div>}
        {page === 'Overview' && <>
          <section className="metrics" aria-label={tr('Workspace metrics')}>{[{ label: tr('Active scans'), value: snapshot?.status === 'running' ? '01' : '00', note: demo ? tr('1 synthetic workflow') : tr('Selected scan'), icon: 'pulse', color: 'green' },{ label: tr('Programs'), value: String(totalProgramCount).padStart(2,'0'), note: language === 'ko' ? `승인된 Scope ${approvedScopeCount}개` : `${approvedScopeCount} approved scope${approvedScopeCount === 1 ? '' : 's'}`, icon: 'scope', color: 'blue' },{ label: tr('Awaiting review'), value: String(reviewCount).padStart(2,'0'), note: tr('Candidates, not verdicts'), icon: 'shield', color: 'amber' },{ label: tr('Confirmed findings'), value: String(findings.filter(f => f.status === 'confirmed').length).padStart(2,'0'), note: tr(demo ? 'Synthetic evidence only' : 'From backend snapshot'), icon: 'check', color: 'purple' }].map(m => <article className={`metric ${m.color}`} key={m.label}><div><span>{m.label}</span><Icon name={m.icon}/></div><strong>{m.value}</strong><small><span className="mini-line"/>{m.note}</small></article>)}</section>
          <div className="section-caption"><span><span className="dot"/>{tr('IN PROGRESS')}</span><button className="text-button" onClick={() => go('Scans')}>{tr('Open scan workspace')} <Icon name="arrow" size={14}/></button></div>{scanPanel}
          <div className="insight-grid"><Panel title={tr('Finding distribution')} subtitle={tr('Severity across this scan')}><div className="distribution"><div className="donut" style={{ background: findings.length ? `conic-gradient(${['CRITICAL','HIGH','MEDIUM','LOW','INFO'].flatMap((s,i,a) => { const start = a.slice(0,i).reduce((n,x) => n + findings.filter(f => f.severity === x).length,0)/findings.length*100; const end = start+findings.filter(f => f.severity === s).length/findings.length*100; return `${['#e98791','#e4a173','#dfc079','#89a9ce','#929bb3'][i]} ${start}% ${end}%`; }).join(',')})` : undefined }}><div><strong>{findings.length}</strong><span>{tr('findings')}</span></div></div><div className="legend">{['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s => <div key={s}><i className={s.toLowerCase()}/><span>{s[0] + s.slice(1).toLowerCase()}</span><strong>{findings.filter(f => f.severity === s).length}</strong></div>)}</div></div></Panel>
          <Panel title={tr('Scope readiness')} subtitle={tr('Verified executable Scope artifacts')} action={<Icon name="scope"/>}><div className="readiness-number"><strong>{approvedScopeCount}</strong><Badge tone={approvedScopeCount ? 'success' : 'warning'}>{tr(approvedScopeCount ? 'Integrity verified' : 'Approval required')}</Badge></div><p className="panel-copy">{approvedScopeCount ? (language === 'ko' ? `${approvedScopeCount}개의 Scope 산출물이 매니페스트 및 승인 무결성 검증을 통과했습니다.` : `${approvedScopeCount} Scope artifact${approvedScopeCount === 1 ? '' : 's'} passed manifest and approval integrity verification.`) : tr('Register a program, collect its policy, and explicitly approve the draft before execution.')}</p><div className="readiness-track"/><button className="panel-link" onClick={() => go('Scopes / Programs')}>{tr('Review registered programs')} <Icon name="arrow" size={15}/></button></Panel></div>
          <Panel title={tr('Finding review queue')} subtitle={tr(demo ? 'Synthetic candidates from the local lab' : 'Findings from the selected scan')} action={<button className="text-button" onClick={() => go('Findings')}>{tr('View all')} <Icon name="arrow" size={14}/></button>}>{findingTable(findings.slice(0,3))}</Panel>
          <div className="workspace-footer"><Icon name="lock" size={13}/><span>{tr('Python enforces scope, request budget, and authorization gates.')}</span><span>AI DAST · v0.1</span></div>
        </>}
        {page === 'Scopes / Programs' && <><div className="notice"><Icon name="lock"/><div><strong>{language === 'ko' ? `사용자가 등록한 프로그램 ${totalProgramCount}개. ${approvedScopeCount ? `검증된 Scope 산출물 ${approvedScopeCount}개를 불러왔습니다.` : tr('No executable assets.')}` : `${totalProgramCount} user-registered program${totalProgramCount === 1 ? '' : 's'}. ${approvedScopeCount ? `${approvedScopeCount} verified scope artifact${approvedScopeCount === 1 ? '' : 's'} loaded.` : 'No executable assets.'}`}</strong><p>{tr('No programs are preloaded. Registration does not establish authorization; only an explicitly approved, integrity-verified Scope becomes executable.')}</p></div></div>{registeredPrograms.length > 0 ? <><div className="toolbar"><label className="search-field"><Icon name="search" size={16}/><input aria-label={tr('Search programs')} value={search} onChange={e => setSearch(e.target.value)} placeholder={tr('Filter registered programs or platforms…')}/></label><button className="secondary-button" onClick={() => setPrivateVisible(v => !v)}>{tr(privateVisible ? 'Hide private name' : 'Reveal private name')}</button></div><Panel title={tr('Scope intake queue')} subtitle={language === 'ko' ? `로컬 등록 프로그램 ${registeredPrograms.length}개 · 명시적인 Yes / No 결정이 필요합니다` : `${registeredPrograms.length} locally registered program${registeredPrograms.length === 1 ? '' : 's'} · collection requires an explicit Yes / No decision`}><div className="intake-list">{visiblePrograms.map(item => <div key={item.id}><span className="artifact-icon"><Icon name={item.visibility === 'private' ? 'lock' : 'scope'}/></span><div><strong>{item.visibility === 'private' && !privateVisible ? tr('Private program') : item.program}</strong><p>{item.platform} · {language === 'ko' ? '등록' : 'registered'} {new Date(item.created_at).toLocaleString(language === 'ko' ? 'ko-KR' : undefined)}{item.scope_error ? ` · ${item.scope_error}` : ''}</p></div><div className="intake-actions"><Badge tone={scopeStatusTone(item.scope_status)}>{tr(scopeStatusLabel[item.scope_status])}</Badge><button className="secondary-button" onClick={() => openScopeWorkflow(item)}>{tr(item.scope_status === 'review_required' ? 'Review Yes / No' : item.scope_status === 'collecting' || item.scope_status === 'awaiting_browser' ? 'View progress' : item.scope_status === 'approved' ? 'View Scope' : 'Collect Scope')}</button></div></div>)}{visiblePrograms.length === 0 && <p className="table-empty">{tr('No registered programs match this filter.')}</p>}</div></Panel></> : <Panel title={tr('No programs registered')} subtitle={tr('Start with a program policy URL')}><Empty title={tr('Your Scope queue is empty')}>{tr('Choose Add program, enter the bug bounty program URL, and select Public or Private. Nothing is added automatically.')}</Empty></Panel>}</>}
        {page === 'Scans' && <>{!demo && <div className="toolbar"><label>{tr('Persisted scan')} <select aria-label={tr('Select persisted scan')} value={scanId} onChange={event => setScanId(event.target.value)}>{!scanOptions.some(item => item.scan_id === scanId) && scanId && <option value={scanId}>{scanId}</option>}{scanOptions.map(item => <option key={item.scan_id} value={item.scan_id}>{item.scan_id} · {tr(item.status)}</option>)}</select></label><button className="secondary-button" onClick={refresh}>{tr('Reload snapshot')}</button></div>}{scanPanel}<Panel title={tr('Run artifacts & provenance')} subtitle={tr('Mapped to the existing aidast pipeline')}><div className="artifact-list">{[['Scope.json + Approval.json','Scope',tr('Policy, approved assets, and integrity hashes')],['Recon.db + Surface.json','Recon',tr('Observed assets, origins, endpoints, and sessions')],['Handoff.json','Handoff',tr('Hashes and roles of immutable source artifacts')],['Pipeline.db','Attack → Validation','stage_runs · attack_tasks · findings · chain_candidates'],['Report.md + Report.json','Report',tr('Validated local draft; no automatic submission')]].map(([name,s,description]) => <div key={name}><span className="artifact-icon"><Icon name="report"/></span><div><strong className="mono">{name}</strong><p>{description}</p></div><Badge>{s}</Badge></div>)}</div></Panel><Panel title={tr('Execution boundaries')} subtitle={tr('Enforced by the Python orchestrator')}><div className="boundary-grid">{[['01',tr('Approved scope'),tr('Scope and approval integrity must match.')],['02','TargetPolicy',tr('Each request must pass policy and budget checks.')],['03',tr('Authorization'),tr('Sensitive mutations require a valid envelope.')],['04',tr('Validation'),tr('Matcher hits alone never establish confirmation.')]].map(([n,t,d]) => <div key={n}><small>{n}</small><h3>{t}</h3><p>{d}</p></div>)}</div></Panel></>}
        {page === 'Findings' && <><div className="toolbar"><label className="search-field"><Icon name="search" size={16}/><input aria-label={tr('Search findings')} value={search} onChange={e => setSearch(e.target.value)} placeholder={tr('Search finding, ID, or endpoint…')}/></label><select aria-label={tr('Filter severity')} value={severity} onChange={e => setSeverity(e.target.value)}>{['All severities','CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s => <option key={s} value={s}>{tr(s)}</option>)}</select></div><Panel title={tr('Scan findings')} subtitle={language === 'ko' ? `${shownFindings.length}개 결과 · ${demo ? '합성 데이터' : scanId}` : `${shownFindings.length} results · ${demo ? 'synthetic data' : scanId}`}>{findingTable(shownFindings)}</Panel><p className="muted footnote">{tr('Review statuses follow Pipeline.db: unreviewed, confirmed, rejected, resolved.')}</p></>}
        {page === 'Validation' && <><div className="notice"><Icon name="check"/><div><strong>{language === 'ko' ? `${reviewCount}개 후보가 증거 검토를 기다리고 있습니다` : `${reviewCount} candidates await evidence review`}</strong><p>{tr('Validation requires reproduction, a meaningful control, and redacted evidence. UI actions cannot confirm a vulnerability.')}</p></div></div><Panel title={tr('Validation queue')} subtitle={tr('Finding candidates awaiting a final verdict')}>{findingTable(findings.filter(f => f.status === 'unreviewed'))}</Panel><Panel title={tr('Evidence requirements')} subtitle={tr('Before promotion to a confirmed case')}><div className="checklist">{['Reproduce within the approved scope and identity boundary','Compare positive and negative controls','Link request / response evidence with secrets removed','Record the final verdict and reproducibility limits'].map((text,i) => <div key={text}><span>{String(i+1).padStart(2,'0')}</span><p>{tr(text)}</p><Badge>{tr('Required')}</Badge></div>)}</div></Panel><p className="muted footnote">{tr('The live validation-case API is not connected in this MVP. This queue reflects finding review status only.')}</p></>}
        {page === 'Reports' && <>{reportError && <div className="error-banner" role="alert"><span>{reportError}</span><button onClick={() => setReportError('')}>{tr('Dismiss')}</button></div>}<Panel title={tr('Local report drafts')} subtitle={tr('Integrity-checked local artifacts · never submitted automatically')}>{demo ? <div className="report-card"><div className="report-illustration"><Icon name="report" size={42}/></div><div><Badge tone="warning">{tr('DEMO DRAFT')}</Badge><h3>{tr('Server version disclosure')}</h3><p>{tr('A synthetic report showing finding, evidence, impact, and remediation sections.')}</p><small className="mono">F-0040 · LOW · Markdown</small><div className="button-row"><button className="secondary-button" onClick={() => { setSelectedReport(null); setReportPreview(sampleReport); setModal('report'); }}>{tr('Preview draft')}</button><button className="primary-button" onClick={() => download('DEMO-Report.md', sampleReport)}>{tr('Download demo .md')} <Icon name="arrow" size={14}/></button></div></div></div> : reports.length ? <div className="report-list">{reports.map(item => <div className="report-card" key={item.report_id}><div className="report-illustration"><Icon name="report" size={42}/></div><div><Badge tone="success">{tr('LOCAL DRAFT')}</Badge><h3>{item.title}</h3><p>{item.platform} · case {item.case_id}</p><small className="mono">{item.report_id} · {new Date(item.created_at).toLocaleString(language === 'ko' ? 'ko-KR' : undefined)}</small><div className="button-row"><button className="secondary-button" onClick={() => void openReport(item)}>{tr('Preview draft')}</button></div></div></div>)}</div> : <Empty title={tr('No report draft for this scan')}>{tr('Validated report artifacts will appear here after the existing CLI report workflow creates an integrity-bound draft.')}</Empty>}</Panel></>}
        {page === 'Audit log' && <><div className="notice"><Icon name="logs"/><div><strong>{tr(demo ? 'Synthetic audit trail' : 'Authoritative audit metadata')}</strong><p>{tr('Pipeline.db audit_events are append-only. Details, request bodies, headers, tokens, and cookies are never returned by this endpoint.')}</p></div></div>{auditError && <div className="error-banner" role="alert"><span>{auditError}</span><button onClick={() => { setAuditError(''); go('Scans'); }}>{tr('Open scans')}</button></div>}<Panel title={tr('Decision history')} subtitle={language === 'ko' ? `${demo ? 4 : auditEntries.length}개 기록 · 최신순` : `${demo ? 4 : auditEntries.length} records · newest first`}><div className="audit-list">{(demo ? [{id:'demo-4',created_at:'2026-09-20T05:28:24Z',event_type:'finding.created',stage:'Attack'},{id:'demo-3',created_at:'2026-09-20T05:28:12Z',event_type:'request.authorized',stage:'Attack'},{id:'demo-2',created_at:'2026-09-20T05:28:09Z',event_type:'pipeline.materialized',stage:'Recon'},{id:'demo-1',created_at:'2026-09-20T05:28:00Z',event_type:'scope.verified',stage:'Scope'}] : auditEntries).map(item => <div key={item.id}><time dateTime={item.created_at}>{new Date(item.created_at).toLocaleTimeString(language === 'ko' ? 'ko-KR' : 'en-GB',{hour12:false})}</time><span className="audit-point"/><div><strong className="mono">{item.event_type}</strong><p>{demo ? tr('Synthetic fixture decision') : `${tr('Redacted pipeline event')} · ${item.id}`}</p></div><Badge>{item.stage}</Badge></div>)}</div>{!demo && !auditEntries.length && !auditError && <p className="table-empty">{tr('No audit records are available for this scan.')}</p>}</Panel></>}
        {page === 'Settings' && <><Panel title={tr('Connection')} subtitle={tr('Configured at build time; no secrets in browser settings')}><dl className="detail-grid"><div><dt>{tr('Transport')}</dt><dd><Badge tone={demo ? 'warning' : 'success'}>{tr(demo ? 'Demo / local fixture' : 'Live / read-only')}</Badge></dd></div><div><dt>{tr('Connection state')}</dt><dd>{tr(state)}</dd></div><div><dt>{tr('Result storage')}</dt><dd className="mono">{tr(resultRoot || 'Unavailable')}</dd></div><div><dt>{tr('Snapshot endpoint')}</dt><dd className="mono">GET /api/v1/scans/:id</dd></div><div><dt>{tr('Delta stream')}</dt><dd className="mono">/ws/scans/:id?after=:event_id</dd></div><div><dt>{tr('Protocol')}</dt><dd>{tr('Version 1 · contiguous event IDs')}</dd></div><div><dt>{tr('Activity retention')}</dt><dd>{tr('Latest 500 events in memory')}</dd></div></dl><div className="panel-bottom"><p>{tr('Set VITE_TRANSPORT=live and VITE_SCAN_ID to connect an implemented backend. Live mode never falls back to demo data.')}</p><button className="secondary-button" onClick={refresh}>{tr(demo ? 'Restart demo' : 'Reload snapshot')}</button></div></Panel><Panel title={tr('Workspace preferences')} subtitle={tr('Theme is saved locally; operational data is never uploaded')}><div className="setting-row"><div><h3>{tr('Language')}</h3><p>{tr('Choose the dashboard display language.')}</p></div><select aria-label={tr('Language')} value={language} onChange={event => setLanguage(event.target.value as Language)}><option value="ko">한국어</option><option value="en">English</option></select></div><div className="setting-row"><div><h3>{tr('Appearance')}</h3><p>{tr('Follow the system theme or keep this workspace light or dark.')}</p></div><select aria-label={tr('Color theme')} value={theme} onChange={event => setTheme(event.target.value as ThemeChoice)}><option value="system">{tr('System')}</option><option value="dark">{tr('Dark')}</option><option value="light">{tr('Light')}</option></select></div><div className="setting-row"><div><h3>{tr('Compact density')}</h3><p>{tr('Reduce spacing in data tables and activity.')}</p></div><input aria-label={tr('Compact density')} type="checkbox" checked={compact} onChange={e => setCompact(e.target.checked)}/></div><div className="setting-row"><div><h3>{tr('Reveal private program name')}</h3><p>{tr('Hidden by default. Resets when the page reloads.')}</p></div><input aria-label={tr('Reveal private program name')} type="checkbox" checked={privateVisible} onChange={e => setPrivateVisible(e.target.checked)}/></div></Panel><Panel title={tr('Backend integration remaining')} subtitle={tr('Implemented boundaries stay separate from future operator workflows')}><ul className="integration-list"><li>{tr('Authentication and authorization for any deployment beyond the loopback-only local operator.')}</li><li>{tr('Evidence-backed Validation case decisions and review actions.')}</li><li>{tr('Report generation and platform submission remain explicit CLI/operator actions.')}</li></ul></Panel></>}
      </main>
      <aside className={`activity-panel ${collapsed ? 'collapsed' : ''}`} aria-label={tr('Persistent live activity')}><div className="activity-heading"><div><Icon name="terminal" size={17}/><h2>{tr('Live activity')}</h2></div><button className="icon-button" onClick={() => setCollapsed(v => !v)} aria-label={tr(collapsed ? 'Expand activity' : 'Collapse activity')} aria-expanded={!collapsed}>{collapsed ? '+' : '−'}</button></div>{!collapsed && <><div className="activity-source"><Badge tone={demo ? 'warning' : 'success'}><span className="dot"/>{demo ? tr('SIMULATED STREAM') : language === 'ko' ? tr(state) : state.toUpperCase()}</Badge><span className="mono">{snapshot?.scan_id || scanId}</span></div><div className="activity-stage"><div><span>{tr('Current stage')}</span><strong>{snapshot?.stage || tr('Waiting')} <small>{snapshot?.progress || 0}%</small></strong></div><progress aria-label={tr('Current stage progress')} max="100" value={snapshot?.progress || 0}/></div><div className="activity-filters"><label className="search-field"><Icon name="search" size={14}/><input aria-label={tr('Search activity')} value={logSearch} onChange={e => setLogSearch(e.target.value)} placeholder={tr('Search activity…')}/></label><div><select aria-label={tr('Filter log level')} value={level} onChange={e => setLevel(e.target.value)}>{['All levels','info','success','warning','error'].map(l => <option key={l} value={l}>{tr(l)}</option>)}</select><select aria-label={tr('Filter log stage')} value={stageFilter} onChange={e => setStageFilter(e.target.value)}>{['All stages',...stages].map(s => <option key={s} value={s}>{tr(s)}</option>)}</select></div></div><div className="log-toolbar"><span>{visibleLogs.length} {tr('events')}</span><button onClick={() => setPaused(v => !v)} aria-pressed={paused}>{tr(paused ? '▶ Resume following' : 'Ⅱ Pause scrolling')}</button></div><div className="log-stream" ref={stream} tabIndex={0} aria-label={tr('Activity events')}><div className="stream-start">{tr(demo ? 'SYNTHETIC SESSION STARTED' : 'SCAN EVENT STREAM')}</div>{visibleLogs.map(l => <article key={l.id} className={`log-entry ${l.level}`}><div><time dateTime={l.time}>{new Date(l.time).toLocaleTimeString(language === 'ko' ? 'ko-KR' : 'en-GB',{hour12:false})}</time><span>{l.stage.toUpperCase()}</span><i title={tr(l.level)}/><span className="sr-only">{tr(l.level)}</span></div><p>{l.message}</p></article>)}{visibleLogs.length === 0 && <p className="table-empty">{tr('No matching events.')}</p>}<div className="stream-end"><span className="dot"/>{tr(paused ? 'Following paused · events still arrive' : snapshot?.status === 'running' ? 'Waiting for the next event' : 'End of available activity')}</div></div><footer className="activity-footer"><Icon name="lock" size={13}/><p>{tr(demo ? 'Fixtures contain no credentials. Live events must be redacted by the server.' : 'Server-side redaction required. Never stream tokens, cookies, or sensitive bodies.')}</p></footer></>}</aside>
      </div>
    </div>
    <dialog ref={dialog} onCancel={() => setModal(null)} onClose={() => setModal(null)} aria-labelledby="dialog-title">
      <div className="dialog-heading"><h2 id="dialog-title">{modal === 'new' ? tr('Start a new scan') : modal === 'scope' ? tr('Add bug bounty program') : modal === 'scope-workflow' ? tr(workflowProgram?.scope_status === 'approved' ? 'View approved Scope' : 'Collect and review Scope') : modal === 'report' ? tr(demo ? 'Demo report preview' : 'Local report preview') : selectedFinding?.id}</h2><button className="icon-button" aria-label={tr('Close dialog')} onClick={() => setModal(null)}>×</button></div>
      {modal === 'new' ? newScanContent : modal === 'scope' ? scopeIntakeContent : modal === 'scope-workflow' ? scopeWorkflowContent : modal === 'report' ? <><pre className="report-preview">{reportPreview}</pre><div className="button-row"><button className="primary-button" onClick={() => download(`${selectedReport?.report_id || 'DEMO-Report'}.md`, reportPreview)}>{tr('Download .md')} <Icon name="arrow" size={14}/></button></div></> : selectedFinding && <><Badge tone={selectedFinding.severity.toLowerCase()}>{selectedFinding.severity}</Badge><h3 className="finding-detail-title">{selectedFinding.title}</h3><dl className="detail-grid"><div><dt>{tr('Endpoint')}</dt><dd className="mono">{selectedFinding.endpoint}</dd></div><div><dt>{tr('Classification')}</dt><dd>{selectedFinding.cwe}</dd></div><div><dt>{tr('Review status')}</dt><dd>{tr(selectedFinding.status)}</dd></div><div><dt>{tr('Source')}</dt><dd>{tr(demo ? 'Synthetic fixture' : 'Pipeline finding')}</dd></div></dl><div className="notice"><Icon name="shield"/><p>{tr(demo ? 'This is synthetic evidence for UI demonstration. No listed program was tested.' : 'Evidence details require a redacted evidence endpoint. The summary alone is not proof of a vulnerability.')}</p></div><button className="secondary-button" onClick={() => { setModal(null); go('Validation'); }}>{tr('Open validation queue')} <Icon name="arrow" size={14}/></button></>}
    </dialog>
  </div>;
}
