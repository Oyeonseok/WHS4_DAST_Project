import type { ManualLoginRequest } from '../lib/manualLogin';
import type { Language } from '../lib/i18n';
import './ManualLoginNotice.css';

const problems: Record<string, [string, string]> = {
  browser_unavailable: ['로그인 창을 확인할 수 없습니다. 창이 열려 있는지 확인해주세요.', 'The login window is unavailable. Check that it is open.'],
  target_page_missing: ['로그인 후 스캔 대상 사이트로 돌아와주세요.', 'Return to the scan target after logging in.'],
  login_form_visible: ['로그인 입력 화면이 남아 있습니다. 로그인을 마친 뒤 다시 확인해주세요.', 'A login form is still visible. Finish logging in, then confirm again.'],
  invite_required: ['초대 코드 입력이 필요합니다. 입력을 마친 뒤 다시 확인해주세요.', 'An invitation code is required. Enter it, then confirm again.'],
  access_required: ['접근 권한 안내가 표시됩니다. 사이트 접근 절차를 마친 뒤 다시 확인해주세요.', 'An access restriction is displayed. Complete the access requirements, then confirm again.'],
};

export function ManualLoginNotice({ request, busy, error, canConfirm, confirm, language }: {
  request: ManualLoginRequest | null; busy: boolean; error: string; canConfirm: boolean;
  confirm: () => Promise<void>; language: Language;
}) {
  const text = (ko: string, en: string) => language === 'ko' ? ko : en;
  if (!request || !['waiting', 'confirmed', 'expired', 'failed'].includes(request.status)) return null;
  const pending = request.status === 'waiting' || request.status === 'confirmed';
  return <section className="manual-login-notice" aria-label={text('스캔 로그인 확인', 'Scan login confirmation')}>
    <strong>{pending ? text('브라우저 로그인 대기', 'Waiting for browser login') : text('로그인 확인 종료', 'Login confirmation ended')}</strong>
    <p className="mono">{request.target_origin}</p>
    <p>{pending ? text('열린 Chromium 창에서 로그인과 필요한 가입 절차를 마친 뒤 로그인 완료를 눌러주세요.', 'Finish login and any required signup steps in Chromium, then select Login complete.')
      : request.status === 'expired' ? text('로그인 완료 확인 시간이 지났습니다. 스캔을 다시 시작해주세요.', 'The login confirmation period expired. Start the scan again.')
      : text('브라우저 로그인 확인을 마치지 못했습니다. 스캔 오류를 확인해주세요.', 'Browser login confirmation did not finish. Check the scan error.')}</p>
    {request.problem && <p role="status">{(problems[request.problem] || problems.browser_unavailable)[language === 'ko' ? 0 : 1]}</p>}
    {pending && <button className="primary-button" disabled={busy || !canConfirm} onClick={() => void confirm()}>
      {busy || request.status === 'confirmed' ? text('브라우저 확인 중…', 'Checking browser…') : text('로그인 완료', 'Login complete')}
    </button>}
    {error && <p className="form-error" role="alert">{text('로그인 확인 요청을 전달하지 못했습니다. 다시 시도해주세요.', 'Could not send the login confirmation. Please try again.')}</p>}
  </section>;
}
