import type { ReportSubmissionView } from '../lib/reportSubmission';
import type { Language } from '../lib/i18n';

export function ReportDocument({ view, language }: { view: ReportSubmissionView; language: Language }) {
  const documentLanguage = view.language || language;
  const tk = (ko: string, en: string) => documentLanguage === 'ko' ? ko : en;
  const fields = view.fields;
  const section = (name: string, key: string) => fields[key] && <section id={`report-field-${key}`} tabIndex={-1}>
    <h3>{name}</h3><p>{fields[key]}</p>
  </section>;
  // Continuation lines stay attached to their action rather than becoming extra steps.
  const steps = fields.steps_to_reproduce?.split(/\n(?=\d+\. )/).map(step => step.replace(/^\d+\.\s*/, '')) || [];
  return <article className="report-document" lang={documentLanguage} aria-label={tk('보안 보고서', 'Security report')}>
    <header><span className="report-document-kicker">{tk('보안 검증 보고서', 'Security validation report')}</span>
      <h2 id="report-field-title">{fields.title}</h2>
    </header>
    {section(tk('핵심 요약', 'Summary'), 'summary')}
    {section(tk('영향과 범위', 'Impact and scope'), 'impact')}
    <div className="report-document-facts">
      {section(tk('영향받는 대상', 'Affected asset'), 'asset')}
      {section(tk('엔드포인트', 'Endpoint'), 'endpoint')}
      {section(tk('취약점 분류', 'Weakness'), 'weakness')}
      {section(tk('심각도', 'Severity'), 'severity')}
      {section('CVSS', 'cvss_vector')}
    </div>
    {section(tk('재현 조건', 'Prerequisites'), 'prerequisites')}
    {!!steps.length && <section id="report-field-steps_to_reproduce" tabIndex={-1}><h3>{tk('재현 절차', 'Reproduction steps')}</h3>
      <ol>{steps.map((step, index) => <li key={index}>{step}</li>)}</ol>
    </section>}
    <div className="report-document-comparison">
      {section(tk('기대 결과', 'Expected behavior'), 'expected_behavior')}
      {section(tk('실제 관측 결과', 'Observed behavior'), 'actual_behavior')}
    </div>
    {!!view.evidence.length && <section><h3>{tk('검증 근거', 'Validation evidence')}</h3>
      <div className="report-document-table"><table><thead><tr><th>{tk('확인 항목', 'Check')}</th><th>{tk('응답', 'Response')}</th><th>{tk('관측 결과', 'Observation')}</th></tr></thead>
        <tbody>{view.evidence.map((item, index) => <tr key={item.evidence_id}>
          <td>{item.display?.label || tk(`검증 기록 ${index + 1}`, `Validation record ${index + 1}`)}</td>
          <td>{item.display?.response || '—'}</td><td>{item.display?.result || tk('상세 기록에 포함', 'Included in detailed records')}</td>
        </tr>)}</tbody>
      </table></div>
    </section>}
    {section(tk('개선 권고', 'Recommended remediation'), 'remediation')}
    {!!view.rendered_impact && <section><h3>{tk('추가 영향 설명', 'Additional impact statement')}</h3><p>{view.rendered_impact}</p></section>}
    <p className="muted report-document-note">{tk('상세 검증 기록은 ZIP의 별도 자료에서 확인할 수 있습니다.', 'Detailed validation records are available separately in the ZIP.')}</p>
  </article>;
}
