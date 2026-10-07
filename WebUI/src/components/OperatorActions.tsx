import type { OperatorAction } from '../hooks/useOperatorActions';

type Props = {
  actions: OperatorAction[];
  busy: string;
  error: string;
  language: 'ko' | 'en';
  acknowledge: (actionId: string) => Promise<void>;
};

export function OperatorActions({ actions, busy, error, language, acknowledge }: Props) {
  const active = actions.filter(action => action.status === 'pending' || action.status === 'acknowledged');
  if (!active.length && !error) return null;
  const text = (ko: string, en: string) => language === 'ko' ? ko : en;
  return <section className="operator-actions" aria-live="polite">
    <div>
      <strong>{text('공격 선행조건 · 사용자 조치', 'Attack prerequisites · operator action')}</strong>
      <p>{text('아래 조치를 대상에서 수행하세요. 완료 확인은 새 자격증명이나 상태 증거가 실제로 저장됐을 때만 공격 항목을 다시 엽니다.', 'Perform the action on the target. Confirmation reopens attack coverage only after new credential or state evidence is stored.')}</p>
    </div>
    {active.map(action => <article key={action.action_id}>
      <div><strong>{action.title}</strong><code>{action.method} {action.normalized_path} · {action.vuln_class}</code></div>
      <p>{action.instruction}</p>
      <button className="primary-button" disabled={!!busy} onClick={() => void acknowledge(action.action_id)}>
        {busy === action.action_id ? text('증거 확인 중…', 'Checking evidence…') : action.status === 'acknowledged' ? text('다시 증거 확인', 'Check evidence again') : text('조치 완료 · 증거 확인', 'Action complete · Check evidence')}
      </button>
    </article>)}
    {error && <p className="form-error" role="alert">{error}</p>}
  </section>;
}
