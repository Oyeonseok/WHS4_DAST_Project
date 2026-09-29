import { useEffect, useRef, useState } from 'react';
import type { Language } from '../lib/i18n';
import { canExportSubmission, canPreviewPoc, parsePocInfo, parseReportSubmission, parseRequirementsForm, type PocInfo, type ProgramRequirements, type ReportSubmissionView, type RequirementsForm } from '../lib/reportSubmission';
import './ReportSubmission.css';

const formFromRules = (rules: ProgramRequirements): RequirementsForm => ({ source: rules.source, verified: rules.verified,
  severityRequired: rules.severity_required, requiredFields: JSON.stringify(rules.required_fields, null, 2),
  additionalFields: JSON.stringify(rules.additional_fields, null, 2), reportTemplate: rules.report_template || '', impactTemplate: rules.impact_template || '' });

const fieldLabels: Record<string, [string, string]> = {
  title: ['제목', 'Title'], asset: ['자산', 'Asset'], target: ['대상', 'Target'], weakness: ['취약점 분류', 'Weakness'],
  vulnerability_type: ['취약점 유형', 'Vulnerability type'], endpoint: ['엔드포인트', 'Endpoint'], severity: ['심각도', 'Severity'],
  technical_severity: ['기술적 심각도', 'Technical severity'], cvss_vector: ['CVSS 벡터', 'CVSS vector'], vrt_category: ['VRT 분류', 'VRT category'],
  summary: ['요약', 'Summary'], description: ['상세 설명', 'Description'], prerequisites: ['재현 조건', 'Prerequisites'],
  steps_to_reproduce: ['재현 단계', 'Steps to reproduce'], expected_behavior: ['기대 결과', 'Expected behavior'],
  actual_behavior: ['실제 결과', 'Actual behavior'], impact: ['영향', 'Impact'], demonstrated_impact: ['확인된 영향', 'Demonstrated impact'], remediation: ['해결 방법', 'Remediation'],
};
const checkLabels: Record<string, string> = {
  program_requirements: '프로그램 제출 요구사항과 출처를 확인하고 저장하세요.',
  source_integrity: '현재 검증 판정, 스코프 또는 증거 출처가 보고서와 일치하지 않거나 확인되지 않습니다.',
  draft_integrity: '초안 또는 증거 인용의 무결성을 확인할 수 없습니다.', draft_required: '유효한 보고서 초안이 필요합니다.',
  evidence_metadata: '증거가 너무 크거나 지원하지 않는 원문·첨부 자료를 포함합니다.', required_field: '필수 제출 필드가 비어 있습니다.',
  program_template: '템플릿에 잘못되거나 비어 있는 필드 참조가 있거나 문서 크기 제한을 초과합니다.',
  submission_size: '제출 패키지 크기 제한을 초과합니다.',
  metadata_only: '증거는 텍스트 메타데이터이며 설명 영상을 선택해 포함할 수 있습니다. 원문, 원본 이미지와 화면 녹화는 제공하지 않으며 패턴 마스킹으로 모든 비밀값을 찾을 수는 없습니다.',
  claim_quality: '필드와 증거 인용이 있다는 사실만으로 보고서의 모든 주장이 입증되지는 않습니다.',
};
const redactionLabels: Record<string, string> = { credential: '인증 정보', email: '이메일', identity: '식별 정보', path: '로컬 경로', local_path: '로컬 경로', secret: '민감값', token: '토큰' };

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function ReportSubmission({ reportId, language }: { reportId: string; language: Language }) {
  const tk = (ko: string, en: string) => language === 'ko' ? ko : en;
  const [view, setView] = useState<ReportSubmissionView | null>(null);
  const [form, setForm] = useState<RequirementsForm | null>(null);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState('inspect');
  const [error, setError] = useState('');
  const [pocInfo, setPocInfo] = useState<PocInfo | null>(null);
  const [pocError, setPocError] = useState('');
  const [includePoc, setIncludePoc] = useState(true);
  const request = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  const endpoint = (suffix: string) => new URL(`/api/v1/reports/${encodeURIComponent(reportId)}${suffix}`, import.meta.env.VITE_API_BASE_URL || location.origin);
  const fieldLabel = (key: string) => fieldLabels[key]?.[language === 'ko' ? 0 : 1] || key;

  async function acceptResponse(response: Response, signal: AbortSignal) {
    if (!response.ok) throw new Error(tk(`보고서를 불러오지 못했습니다 (${response.status}).`, `Could not load the report (${response.status}).`));
    const parsed = parseReportSubmission(await response.json(), reportId);
    if (!parsed) throw new Error(tk('보고서 검사 응답을 확인할 수 없습니다. 초안은 별도로 내려받을 수 있습니다.', 'The report check response could not be verified. The draft is available separately.'));
    if (signal.aborted || !mounted.current) return null;
    setView(parsed); setForm(formFromRules(parsed.requirements)); setDirty(false);
    return parsed;
  }
  async function loadPoc(signal: AbortSignal, current: ReportSubmissionView) {
    try {
      const response = await fetch(endpoint('/poc'), { signal, credentials: 'same-origin', cache: 'no-store' });
      if (signal.aborted || !mounted.current) return;
      if (!response.ok) throw new Error();
      const info = parsePocInfo(await response.json());
      if (signal.aborted || !mounted.current) return;
      if (!info) throw new Error();
      setPocInfo(info.status === 'ready' && info.source_revision !== current.revision_sha256 ? null : info);
    } catch {
      if (signal.aborted || !mounted.current) return;
      setPocInfo(null);
      setPocError(tk('PoC 영상 상태를 확인하지 못했습니다. 자동 생성을 다시 시도하세요.', 'Could not verify the PoC video status. Try automatic generation again.'));
    }
  }
  async function inspect(signal: AbortSignal) {
    const current = await acceptResponse(await fetch(endpoint('/submission'), { signal, credentials: 'same-origin', cache: 'no-store' }), signal);
    if (current) await loadPoc(signal, current);
  }
  async function run(action: string, task: (signal: AbortSignal) => Promise<void>) {
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, action === 'poc' || action === 'export' ? 120000 : 20000);
    setBusy(action); setError('');
    if (action === 'inspect' || action === 'save') setView(null);
    if (action === 'inspect' || action === 'save' || action === 'poc') { setPocInfo(null); setPocError(''); }
    try { await task(controller.signal); }
    catch (cause) {
      if (!mounted.current || request.current !== controller || (controller.signal.aborted && !timedOut)) return;
      setPocInfo(null);
      if (action !== 'draft' && action !== 'poc') setView(null);
      setError(timedOut ? tk('요청 시간이 초과됐습니다. 다시 시도하세요.', 'The request timed out. Try again.') : cause instanceof Error && cause.name !== 'TypeError' && cause.name !== 'SyntaxError'
        ? cause.message : tk('서버에 연결하지 못했거나 응답이 올바르지 않습니다. 다시 시도하세요.', 'Could not connect to the server or verify its response. Try again.'));
    } finally {
      clearTimeout(timer);
      if (mounted.current && request.current === controller) setBusy('');
    }
  }
  useEffect(() => {
    mounted.current = true;
    setForm(null); setDirty(false); setPocInfo(null); setPocError(''); setIncludePoc(true);
    void run('inspect', inspect);
    return () => { mounted.current = false; request.current?.abort(); };
    // The parent mounts each report under its own key; language changes preserve the form.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportId]);

  const edit = (changes: Partial<RequirementsForm>) => { if (form) { setForm({ ...form, ...changes }); setDirty(true); setPocInfo(null); setPocError(''); } };
  const parsedRules = form ? parseRequirementsForm(form) : null;
  const ready = canExportSubmission(view, reportId, dirty, !!busy);
  const previewReady = canPreviewPoc(pocInfo, view, reportId, dirty, !!busy);
  const displayedFields = view ? { ...view.fields } : {};
  for (const check of view?.checks || []) {
    if (check.field && !Object.hasOwn(displayedFields, check.field)) displayedFields[check.field] = '';
  }
  const save = () => {
    if (!parsedRules || busy) return;
    void run('save', async signal => {
      const response = await fetch(endpoint('/requirements'), { method: 'POST', signal, credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(parsedRules) });
      const current = await acceptResponse(response, signal);
      if (current) await loadPoc(signal, current);
    });
  };
  const generatePoc = () => {
    if (!ready || !view) return;
    const revision = view.revision_sha256;
    void run('poc', async signal => {
      const response = await fetch(endpoint(`/poc?revision=${encodeURIComponent(revision)}`), {
        method: 'POST', signal, credentials: 'same-origin', cache: 'no-store',
      });
      if (signal.aborted || !mounted.current) return;
      if (response.status === 409) {
        setError(tk('보고서 또는 영상 검사 상태를 다시 확인했습니다. 차단 항목을 확인하거나 생성을 다시 시도하세요.', 'The report or video check status has been refreshed. Review blockers or try generation again.'));
        await inspect(signal);
        if (!signal.aborted && mounted.current) setPocInfo(null);
        return;
      }
      if (!response.ok) throw new Error(tk('PoC 영상을 생성하지 못했습니다. 다시 시도하세요.', 'Could not generate the PoC video. Try again.'));
      const info = parsePocInfo(await response.json());
      if (signal.aborted || !mounted.current) return;
      if (!canPreviewPoc(info, view, reportId)) throw new Error(tk('현재 보고서의 PoC 영상 응답을 확인할 수 없습니다.', 'The PoC video response for the current report could not be verified.'));
      setPocInfo(info);
    });
  };
  const exportZip = () => {
    if (!ready || !view) return;
    const revision = view.revision_sha256;
    void run('export', async signal => {
      const response = await fetch(endpoint(`/export?revision=${encodeURIComponent(revision)}${includePoc ? '&include_poc=true' : ''}`), { signal, credentials: 'same-origin', cache: 'no-store' });
      if (signal.aborted || !mounted.current) return;
      if (response.status === 409) {
        setView(null);
        setError(tk('보고서 내용이나 검사 상태가 바뀌었습니다. 현재 상태를 다시 확인했습니다.', 'The report or check status changed. Its current state has been checked again.'));
        await inspect(signal); return;
      }
      if (!response.ok || !response.headers.get('Content-Type')?.includes('application/zip')) throw new Error(tk(`ZIP을 내보내지 못했습니다 (${response.status}). 검사를 다시 실행하세요.`, `Could not export ZIP (${response.status}). Run checks again.`));
      const blob = await response.blob();
      if (!signal.aborted && mounted.current) downloadBlob(blob, `${reportId}.zip`);
    });
  };
  const downloadDraft = () => void run('draft', async signal => {
    const response = await fetch(endpoint(''), { signal, credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) throw new Error(tk(`초안을 내려받지 못했습니다 (${response.status}).`, `Could not download the draft (${response.status}).`));
    const blob = await response.blob();
    if (!signal.aborted && mounted.current) downloadBlob(blob, `${reportId}-draft.md`);
  });

  return <div className="report-submission" aria-busy={!!busy}>
    <div className="report-submission-status" role="status">
      <strong>{busy ? tk('보고서 처리 중…', 'Processing report…') : dirty ? tk('요구사항 변경사항을 저장하세요', 'Save the changed requirements') : view?.ready ? tk('자동 검사 통과 · ZIP 내보내기 가능', 'Automatic checks passed · ZIP export available') : tk('최종 내보내기 대기', 'Final export pending')}</strong>
      <p>{tk('자동 검사 통과 후 제출 필드, 마스킹된 보고서와 증거를 ZIP으로 내려받습니다.', 'After automatic checks pass, download submission fields, the masked report and evidence as a ZIP.')}</p>
      {view && <small>{view.platform === 'hackerone' ? 'HackerOne' : view.platform === 'intigriti' ? 'Intigriti' : 'Bugcrowd'} · {reportId}</small>}
    </div>
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="button-row report-submission-actions">
      <button className="primary-button" disabled={!ready} onClick={exportZip}>{tk('최종 ZIP 내보내기', 'Export final ZIP')}</button>
      <button className="secondary-button" disabled={!!busy || dirty} onClick={() => void run('inspect', inspect)}>{tk('자동 검사 다시 실행', 'Run automatic checks')}</button>
      <button className="secondary-button" disabled={!!busy} onClick={downloadDraft}>{tk('로컬 초안 .md 내려받기', 'Download local draft .md')}</button>
    </div>
    <section className="report-submission-section" aria-labelledby="report-poc-title">
      <h3 id="report-poc-title">{tk('PoC 설명 영상', 'PoC explanation video')}</h3>
      <label className="report-rule-check"><input type="checkbox" checked={includePoc} disabled={!!busy || dirty || !view?.ready}
        onChange={event => setIncludePoc(event.target.checked)}/><span>{tk('PoC 설명 영상 포함', 'Include PoC explanation video')}</span></label>
      <p className="muted">{tk('저장된 마스킹 증거를 설명하는 영상입니다. 실시간 재현이나 원본 화면 녹화가 아닙니다. 영상 포함 ZIP을 내보내면 자동으로 생성하고 검사합니다.', 'This video explains stored masked evidence. It is not live reproduction footage or an original screen recording. Exporting a ZIP with video automatically generates and checks it.')}</p>
      <div className="button-row report-submission-actions"><button className="secondary-button" disabled={!ready} onClick={generatePoc}>{tk('PoC 영상 자동 생성', 'Automatically generate PoC video')}</button></div>
      {pocError && <p className="form-error" role="alert">{pocError}</p>}
      {pocInfo?.status === 'blocked' && <p className="muted">{tk('PoC 영상 자동 검사가 차단되었습니다. 보고서 검사 결과를 확인하세요.', 'PoC video automatic checks are blocked. Review the report checks.')}</p>}
      {previewReady && pocInfo && <video key={`${reportId}-${pocInfo.source_revision}`} className="report-poc-video" controls preload="metadata"
        aria-label={tk('저장된 마스킹 증거 설명 영상 미리보기', 'Stored masked evidence explanation video preview')}
        src={endpoint(`/poc/video?revision=${encodeURIComponent(pocInfo.source_revision!)}`).href}
        onError={() => { setPocInfo(null); setPocError(tk('PoC 영상 미리보기를 불러오지 못했습니다. 자동 생성을 다시 시도하세요.', 'Could not load the PoC video preview. Try automatic generation again.')); }}/ >}
    </section>
    {form && <section className="report-submission-section" aria-labelledby="report-rules-title">
      <h3 id="report-rules-title">{tk('프로그램 제출 요구사항', 'Program submission requirements')}</h3>
      <p className="muted">{tk('프로그램의 제출 안내나 양식을 기준으로 규칙을 설정하세요. 저장하면 자동 검사를 실행합니다.', 'Identify the rules from the program submission instructions or form. Saving runs the automatic checks.')}</p>
      <fieldset disabled={!!busy} className="report-rules-form">
        <label>{tk('요구사항 출처 (URL 또는 자료 설명)', 'Requirements source (URL or document description)')}<input value={form.source} maxLength={8192} onChange={event => edit({ source: event.target.value })}/></label>
        <label className="report-rule-check"><input type="checkbox" checked={form.verified} onChange={event => edit({ verified: event.target.checked })}/><span>{tk('위 출처에서 프로그램의 제출 규칙을 확인했습니다', 'I identified the program submission rules from the source above')}</span></label>
        <label className="report-rule-check"><input type="checkbox" checked={form.severityRequired} onChange={event => edit({ severityRequired: event.target.checked })}/><span>{tk('프로그램에서 심각도 입력을 요구합니다', 'The program requires severity')}</span></label>
        <label>{tk('필수 필드 이름 · JSON 배열', 'Required field names · JSON array')}<textarea rows={3} value={form.requiredFields} onChange={event => edit({ requiredFields: event.target.value })}/><small>{tk('예: ["title", "researcher_ip"] · 소문자와 밑줄을 사용하세요.', 'Example: ["title", "researcher_ip"] · Use lowercase names with underscores.')}</small></label>
        <label>{tk('추가 제출 필드 · JSON 객체', 'Additional submission fields · JSON object')}<textarea rows={3} value={form.additionalFields} onChange={event => edit({ additionalFields: event.target.value })}/><small>{tk('예: {"researcher_ip":"192.0.2.1"} · 기존 보고서 필드는 덮어쓸 수 없습니다.', 'Example: {"researcher_ip":"192.0.2.1"} · Existing report fields cannot be overwritten.')}</small></label>
        <label>{tk('보고서 템플릿 (선택)', 'Report template (optional)')}<textarea rows={3} maxLength={8192} value={form.reportTemplate} onChange={event => edit({ reportTemplate: event.target.value })}/></label>
        <label>{tk('영향 템플릿 (선택)', 'Impact template (optional)')}<textarea rows={3} maxLength={8192} value={form.impactTemplate} onChange={event => edit({ impactTemplate: event.target.value })}/><small>{tk('필드 참조 예: {summary}, {steps_to_reproduce}, {impact}', 'Field references: {summary}, {steps_to_reproduce}, {impact}')}</small></label>
        {dirty && !parsedRules && <p className="form-error" role="alert">{tk('출처와 JSON 형식을 확인하세요. 필드 이름은 중복 없이 소문자·숫자·밑줄로 적고, 추가 필드 값은 문자열로 입력하세요.', 'Check the source and JSON. Use unique lowercase field names with digits or underscores, and string values for additional fields.')}</p>}
        <button className="secondary-button" disabled={!parsedRules || !dirty} onClick={save}>{tk('요구사항 저장 및 검사', 'Save requirements and check')}</button>
      </fieldset>
    </section>}
    {view && <>
      <section className="report-submission-section" aria-labelledby="report-checks-title"><h3 id="report-checks-title">{tk('자동 검사 결과', 'Automatic check results')}</h3>
        {!view.checks.some(check => check.level === 'blocker') && <p className="report-check-pass">{tk('차단 항목이 없습니다.', 'No blocking issues.')}</p>}
        <ul className="report-checks">{view.checks.map((check, index) => <li key={`${check.code}-${index}`} className={`report-check-${check.level}`}>
          <strong>{check.level === 'blocker' ? tk('차단', 'Blocker') : check.level === 'warning' ? tk('참고', 'Warning') : tk('통과', 'Pass')}</strong>
          <span>{language === 'ko' ? checkLabels[check.code] || '검사 결과를 확인하세요.' : check.code === 'metadata_only'
            ? 'Evidence is text metadata, with an optional explanation video. Raw bodies, original images and screen recordings are unavailable, and pattern masking cannot find every secret.' : check.message}</span>
          {check.field && <a href={`#report-field-${check.field}`} onClick={event => {
            event.preventDefault()
            const target = document.getElementById(`report-field-${check.field}`)
            target?.scrollIntoView({ block: 'nearest' })
            target?.focus()
          }}>{fieldLabel(check.field)}</a>}
        </li>)}</ul>
      </section>
      <section className="report-submission-section" aria-labelledby="report-fields-title"><h3 id="report-fields-title">{tk('플랫폼 제출 필드', 'Platform submission fields')}</h3>
        <dl className="report-submission-fields">{Object.entries(displayedFields).map(([key, value]) => <div key={key} id={`report-field-${key}`} tabIndex={-1}><dt>{fieldLabel(key)}</dt><dd>{value || tk('비어 있음', 'Empty')}</dd></div>)}</dl>
      </section>
      <section className="report-submission-section" aria-labelledby="report-evidence-title"><h3 id="report-evidence-title">{tk('마스킹된 증거 메타데이터', 'Masked evidence metadata')}</h3>
        <p className="muted">{tk('증거는 텍스트 메타데이터이며 선택한 경우 설명 영상을 포함합니다. 원문, 원본 이미지와 화면 녹화는 제공하지 않습니다.', 'Evidence is text metadata, with an explanation video when selected. Raw bodies, original images and screen recordings are unavailable.')}</p>
        <ul className="report-redactions">{view.redactions.map(item => <li key={item.kind}>{language === 'ko' ? redactionLabels[item.kind] || '민감정보' : item.kind} <strong>{item.count}</strong></li>)}</ul>
        {!view.redactions.length && <p className="muted">{tk('마스킹된 항목 0개', '0 masked items')}</p>}
        {view.evidence.map(item => <details className="report-evidence" key={item.evidence_id}><summary>{item.evidence_id} · {item.kind}</summary><pre>{JSON.stringify(item.details, null, 2)}</pre><dl><dt>{tk('원본 해시', 'Source digest')}</dt><dd>{item.content_sha256}</dd><dt>{tk('마스킹된 메타데이터 해시', 'Masked metadata digest')}</dt><dd>{item.sanitized_sha256}</dd></dl></details>)}
        {!view.evidence.length && <p className="muted">{tk('표시할 증거가 없습니다.', 'No evidence to display.')}</p>}
      </section>
      <section className="report-submission-section" aria-labelledby="report-text-title"><h3 id="report-text-title">{tk('제출용 보고서 본문', 'Submission report text')}</h3><pre className="report-preview">{view.markdown || tk('본문을 생성하려면 차단 항목을 해결하세요.', 'Resolve the blocking issues to generate the report text.')}</pre></section>
    </>}
  </div>;
}
