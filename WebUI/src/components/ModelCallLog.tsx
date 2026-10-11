import { useEffect, useRef, useState } from 'react';
import { formatActivityElapsed } from '../lib/activity';
import { groupModelCalls, mergeModelCallEvents, parseModelCallPage, tokenStages, type ModelCallEvent, type ModelCallPage } from '../lib/modelCalls';
import { translate, type Language } from '../lib/i18n';

const callStateLabels: Record<ModelCallEvent['state'], string> = {
  started: 'LLM call started',
  success: 'LLM call succeeded',
  error: 'LLM call failed',
};
const operationLabels: Record<string, string> = {
  scope_collection: 'Collect program scope',
  scope_navigation: 'Find scope policy page',
  recon_plan: 'Plan reconnaissance',
  target_policy: 'Generate target policy',
  recon_review: 'Review reconnaissance evidence',
  scope_interpretation: 'Interpret captured scope',
  scope_grounding: 'Correct scope interpretation',
  scope_execution_interpretation: 'Interpret approved Scope requirements',
  scope_header_interpretation: 'Interpret approved Scope headers',
  scope_references: 'Select Scope policy references',
  finding_validation: 'Validate a finding',
  report_draft: 'Draft a report',
  legacy_report_draft: 'Draft a legacy report',
  attack_hypotheses: 'Plan attack hypotheses',
  attack_assessment: 'Assess attack evidence',
  validation_assessment: 'Assess validation case',
  validation_comparison: 'Compare validation claims',
  validation_eligibility: 'Check validation eligibility',
  impact_planning: 'Plan impact analysis',
  ffuf_root_selection: 'Choose discovery roots',
  endpoint_annotation: 'Annotate endpoint',
  attack_orchestrator: 'Run attack agents',
  chaining_orchestrator: 'Run chaining agents',
  structured_other: 'Other Codex operation',
};
const summaryLabels: Record<string, string> = {
  prompt_characters: 'Prompt characters', task_count: 'Task count', field_count: 'Result fields',
  captured_characters: 'Captured characters', in_scope_count: 'In-Scope items',
  out_of_scope_count: 'Out-of-Scope items', header_count: 'Required headers',
  rule_count: 'Policy requirements', endpoint_count: 'Endpoint count',
  observation_count: 'Observation count', finding_count: 'Finding count', evidence_count: 'Evidence count',
  capture_selected: 'Current page capture', navigation_selected: 'Navigate to another page',
};
const primaryResultKeys = [
  'in_scope_count', 'out_of_scope_count', 'header_count', 'finding_count',
  'endpoint_count', 'observation_count', 'capture_selected', 'navigation_selected',
] as const;
const supportingResultKeys = [
  'rule_count', 'evidence_count', 'field_count', 'captured_characters', 'prompt_characters', 'task_count',
] as const;
const primaryResultLabels: Record<string, string> = {
  in_scope_count: 'Allowed items', out_of_scope_count: 'Excluded items', header_count: 'Header requirements',
};
const errorLabels: Record<string, string> = {
  timeout: 'LLM response timed out', tool_unavailable: 'Codex executable unavailable',
  io_error: 'LLM execution input/output error', agent_error: 'Agent execution failed',
};

async function fetchModelCalls(before: number | null, signal: AbortSignal): Promise<ModelCallPage> {
  const base = import.meta.env.VITE_API_BASE_URL || location.origin;
  const url = new URL('/api/v1/model-calls', base);
  if (before !== null) url.searchParams.set('before', String(before));
  const response = await fetch(url, { signal, credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) throw new Error('Model call request failed');
  const page = parseModelCallPage(await response.json());
  if (!page) throw new Error('Invalid model call page');
  return page;
}

export function ModelCallLog({ language, demo }: { language: Language; demo: boolean }) {
  const tr = (key: string) => translate(language, key);
  const [events, setEvents] = useState<ModelCallEvent[]>([]);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [loading, setLoading] = useState(!demo);
  const [error, setError] = useState(false);
  const [revision, setRevision] = useState(0);
  const [search, setSearch] = useState('');
  const [stateFilter, setStateFilter] = useState('all');
  const [stageFilter, setStageFilter] = useState('all');
  const pageAbort = useRef<AbortController | null>(null);
  const olderLoaded = useRef(false);

  useEffect(() => {
    if (demo) return;
    const timer = window.setInterval(() => setRevision(value => value + 1), 5000);
    return () => window.clearInterval(timer);
  }, [demo]);

  useEffect(() => {
    if (demo) return;
    const controller = new AbortController();
    pageAbort.current?.abort();
    setLoading(true);
    setError(false);
    void fetchModelCalls(null, controller.signal).then(page => {
      if (!controller.signal.aborted) {
        setEvents(current => mergeModelCallEvents(current, page.events));
        if (!olderLoaded.current) setNextBefore(page.next_before);
      }
    }).catch(() => {
      if (!controller.signal.aborted) setError(true);
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => { controller.abort(); pageAbort.current?.abort(); };
  }, [demo, revision]);

  const loadOlder = async () => {
    if (nextBefore === null || loading) return;
    const controller = new AbortController();
    pageAbort.current = controller;
    setLoading(true);
    setError(false);
    try {
      const page = await fetchModelCalls(nextBefore, controller.signal);
      if (controller.signal.aborted) return;
      olderLoaded.current = true;
      setEvents(current => mergeModelCallEvents(current, page.events));
      setNextBefore(page.next_before);
    } catch {
      if (!controller.signal.aborted) setError(true);
    } finally {
      if (!controller.signal.aborted) setLoading(false);
      if (pageAbort.current === controller) pageAbort.current = null;
    }
  };

  const term = search.trim().toLowerCase();
  const calls = groupModelCalls(events).map(event => ({
    ...event, stage: event.stage || (event.operation_code.startsWith('scope_') ? 'Scope' : null),
  }));
  const shown = calls.filter(event =>
    (stateFilter === 'all' || event.state === stateFilter)
    && (stageFilter === 'all' || event.stage === stageFilter)
    && (!term || [event.operation_code, tr(operationLabels[event.operation_code] || 'Other Codex operation'),
      event.requested_model, event.scan_id, event.stage, event.task_id, event.case_id, event.scope_job_id]
      .some(value => value?.toLowerCase().includes(term))));
  return <section className="panel model-call-panel" aria-labelledby="model-call-title">
    <div className="panel-heading"><div><h2 id="model-call-title">{tr('Codex calls')}</h2>
      <p>{tr('Review each call’s purpose, input size and final result summary. Raw contents remain hidden.')}</p></div>
      {!demo && <button className="secondary-button" onClick={() => setRevision(value => value + 1)}>{tr('Refresh LLM log')}</button>}
    </div>
    {demo ? <p className="table-empty">{tr('No LLM calls in synthetic preview.')}</p> : <>
      <div className="toolbar model-call-toolbar">
        <label className="search-field"><span className="sr-only">{tr('Search LLM calls')}</span>
          <input aria-label={tr('Search LLM calls')} value={search} onChange={event => setSearch(event.target.value)}
            placeholder={tr('Search model, work, or ID')}/></label>
        <select aria-label={tr('Filter LLM call state')} value={stateFilter} onChange={event => setStateFilter(event.target.value)}>
          <option value="all">{tr('All call states')}</option>
          <option value="started">{tr('LLM call started')}</option>
          <option value="success">{tr('LLM call succeeded')}</option>
          <option value="error">{tr('LLM call failed')}</option>
        </select>
        <select aria-label={tr('Filter LLM stage')} value={stageFilter} onChange={event => setStageFilter(event.target.value)}>
          <option value="all">{tr('All LLM stages')}</option>
          {['Scope', ...tokenStages].map(stage => <option key={stage} value={stage}>{tr(stage)}</option>)}
        </select>
      </div>
      {error && <div className="error-banner" role="alert"><span>{tr('LLM log unavailable.')}</span>
        <button onClick={() => setRevision(value => value + 1)}>{tr('Retry LLM log')}</button></div>}
      <p className="model-call-count" role="status">{shown.length} {tr('LLM calls shown')}</p>
      <div className="model-call-list">
        {shown.map(event => {
          const resultEntries = Object.entries(event.result_summary);
          const primaryResults = resultEntries.filter(([key]) => primaryResultKeys.some(item => item === key))
            .sort(([a], [b]) => primaryResultKeys.findIndex(key => key === a) - primaryResultKeys.findIndex(key => key === b));
          const supportingResults = resultEntries.filter(([key]) => !primaryResultKeys.some(item => item === key))
            .sort(([a], [b]) => supportingResultKeys.findIndex(key => key === a) - supportingResultKeys.findIndex(key => key === b));
          return <article key={event.event_id} className={`model-call-entry ${event.state}`}>
          <div className="model-call-head"><span className={`badge ${event.state === 'success' ? 'success' : event.state === 'error' ? 'critical' : 'warning'}`}>{tr(callStateLabels[event.state])}</span>
            <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString(language === 'ko' ? 'ko-KR' : 'en-GB', { hour12: false })}</time>
          </div>
          <h3>{tr(operationLabels[event.operation_code] || 'Other Codex operation')}</h3>
          <code className="model-call-code">{event.operation_code}</code>
          <dl className="model-call-facts">
            <div><dt>{tr('Requested LLM model')}</dt><dd>{event.requested_model || tr('Model was not recorded for this call')}</dd></div>
            {event.stage && <div><dt>{tr('LLM stage')}</dt><dd>{tr(event.stage)}</dd></div>}
            {event.elapsed_ms !== null && <div><dt>{tr('LLM duration')}</dt><dd>{formatActivityElapsed(event.elapsed_ms / 1000, language)}</dd></div>}
            {event.error_code && <div><dt>{tr('LLM error cause')}</dt><dd>{tr(errorLabels[event.error_code] || 'Agent execution failed')} · <code>{event.error_code}</code></dd></div>}
          </dl>
          <dl className="model-call-input">
            <dt>{tr('Input summary')}</dt>
            <dd>{Object.keys(event.input_summary).length ? Object.entries(event.input_summary).map(([key, value]) =>
              <span className="model-call-input-stat" key={key}>
                {key !== 'prompt_characters' && <span>{tr(summaryLabels[key])}</span>}
                <strong>{key === 'capture_selected' || key === 'navigation_selected' ? tr('Selected')
                  : <>{value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-GB')}
                    {(key === 'prompt_characters' || key === 'captured_characters') && tr('characters')}</>}</strong>
              </span>) : <span className="model-call-summary-empty">{tr('No summary recorded')}</span>}</dd>
          </dl>
          <details className="scope-rule-item model-call-result" open>
            <summary>{tr('Result summary')}</summary>
            <div className="model-call-result-body">
              {primaryResults.length > 0 && <dl className="model-call-result-primary">{primaryResults.map(([key, value]) =>
                <div key={key}><dt>{tr(primaryResultLabels[key] || summaryLabels[key])}</dt>
                  <dd>{key === 'capture_selected' || key === 'navigation_selected' ? tr('Selected')
                    : <>{value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-GB')}<span>{tr('items')}</span></>}</dd>
                </div>)}</dl>}
              {supportingResults.length > 0 && <dl className="model-call-facts model-call-result-supporting">{supportingResults.map(([key, value]) =>
                <div key={key}><dt>{tr(summaryLabels[key])}</dt><dd>{value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-GB')}</dd></div>)}</dl>}
              {resultEntries.length === 0 && <p className="model-call-summary-empty">{event.state === 'started' ? tr('Awaiting final response') : tr('No summary recorded')}</p>}
            </div>
          </details>
          <p className="model-call-usage">{event.input_tokens !== null || event.output_tokens !== null || event.cached_input_tokens !== null
            ? `${tr('Input tokens')} ${event.input_tokens ?? tr('Unavailable')} · ${tr('Output tokens')} ${event.output_tokens ?? tr('Unavailable')} · ${tr('Cached input tokens')} ${event.cached_input_tokens ?? tr('Unavailable')}`
            : tr('Token usage unavailable')}</p>
          <dl className="model-call-facts model-call-technical">
            {event.stage !== 'Scope' && <div><dt>{tr('Scan ID')}</dt><dd>{event.scan_id || tr('Not linked to a scan')}</dd></div>}
            {event.scope_job_id && <div><dt>{tr('Scope job ID')}</dt><dd>{event.scope_job_id}</dd></div>}
            {event.task_id && <div><dt>{tr('Task ID')}</dt><dd>{event.task_id}</dd></div>}
            {event.case_id && <div><dt>{tr('LLM case ID')}</dt><dd>{event.case_id}</dd></div>}
            {event.started_at && <div><dt>{tr('LLM started at')}</dt><dd>{new Date(event.started_at).toLocaleString(language === 'ko' ? 'ko-KR' : 'en-GB', { hour12: false })}</dd></div>}
          </dl>
          <small className="model-call-id">{tr('LLM call ID')} · <code>{event.call_id}</code></small>
        </article>;
        })}
      </div>
      {!loading && !error && shown.length === 0 && <p className="table-empty">{events.length ? tr('No matching LLM calls.') : tr('No LLM calls recorded yet.')}</p>}
      {loading && <p className="table-empty" role="status">{tr('Loading LLM calls')}</p>}
      {nextBefore !== null && <div className="model-call-pagination"><button className="secondary-button" disabled={loading} onClick={() => void loadOlder()}>{tr('Older LLM calls')}</button></div>}
    </>}
  </section>;
}
