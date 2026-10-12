import { manualActionLabel, type ManualLoginRequest } from '../lib/manualLogin';
import type { Language } from '../lib/i18n';
import './ManualLoginNotice.css';

const problems: Record<string, [string, string]> = {
  browser_unavailable: ['로그인 창을 확인할 수 없습니다. 창이 열려 있는지 확인해주세요.', 'The login window is unavailable. Check that it is open.'],
  target_page_missing: ['로그인 후 스캔 대상 사이트로 돌아와주세요.', 'Return to the scan target after logging in.'],
  login_form_visible: ['로그인 입력 화면이 남아 있습니다. 로그인을 마친 뒤 다시 확인해주세요.', 'A login form is still visible. Finish logging in, then confirm again.'],
  invite_required: ['초대 코드 입력이 필요합니다. 입력을 마친 뒤 다시 확인해주세요.', 'An invitation code is required. Enter it, then confirm again.'],
  access_required: ['접근 권한 안내가 표시됩니다. 사이트 접근 절차를 마친 뒤 다시 확인해주세요.', 'An access restriction is displayed. Complete the access requirements, then confirm again.'],
  mfa_required: ['열린 브라우저에서 MFA 인증 코드를 직접 입력한 뒤 완료를 눌러주세요.', 'Enter the MFA code yourself in the open browser, then confirm completion.'],
  captcha_required: ['열린 브라우저에서 CAPTCHA 또는 사용자 확인을 직접 마친 뒤 완료를 눌러주세요.', 'Complete the CAPTCHA or human verification yourself in the open browser, then confirm completion.'],
  runtime_browser_required: ['이 실행의 브라우저는 화면이 없는 모드입니다. 사용자 조치 대기는 이미 열린 로그인 브라우저에서만 지원합니다. 수동 로그인 모드로 다시 시작해주세요.', 'This run has a headless browser. Operator actions require the existing visible login browser. Start another run with manual login.'],
};

export function ManualLoginNotice({ request, busy, error, canConfirm, confirm, language }: {
  request: ManualLoginRequest | null; busy: boolean; error: string; canConfirm: boolean;
  confirm: () => Promise<void>; language: Language;
}) {
  const text = (ko: string, en: string) => language === 'ko' ? ko : en;
  if (!request || !['waiting', 'confirmed', 'expired', 'failed'].includes(request.status)) return null;
  const pending = request.status === 'waiting' || request.status === 'confirmed';
  const runtimeAction = !!request.action_kind && request.action_kind !== 'login';
  return <section className="manual-login-notice" aria-label={text('스캔 사용자 조치 확인', 'Scan operator action confirmation')}>
    <strong>{pending ? `${manualActionLabel(request, language)} · ${text('사용자 조치 대기', 'Waiting for operator')}` : text('사용자 조치 확인 종료', 'Operator confirmation ended')}</strong>
    <p className="mono">{request.target_origin}</p>
    <p>{pending ? runtimeAction ? text('정찰의 자동 UI 조작이 대기 중입니다. 이미 열린 Chromium에서 필요한 조치를 마친 뒤 완료를 누르면 같은 브라우저 세션으로 계속합니다.', 'Automatic Recon UI actions are waiting. Complete the required step in the existing Chromium window, then confirm to continue with the same browser session.') : text('열린 Chromium 창에서 로그인과 필요한 가입 절차를 마친 뒤 로그인 완료를 눌러주세요.', 'Finish login and any required signup steps in Chromium, then select Login complete.')
      : request.status === 'expired' ? text('사용자 조치 확인 시간이 지났습니다. 해당 화면의 자동 조작은 중단됐습니다.', 'The operator confirmation period expired. Automatic actions on this screen stopped.')
      : text('사용자 조치를 확인하지 못했습니다. 아래 안내를 확인해주세요.', 'The required operator action could not be confirmed. Check the guidance below.')}</p>
    {request.problem && <p role="status">{(problems[request.problem] || problems.browser_unavailable)[language === 'ko' ? 0 : 1]}</p>}
    {pending && <button className="primary-button" disabled={busy || !canConfirm} onClick={() => void confirm()}>
      {busy || request.status === 'confirmed' ? text('브라우저 확인 중…', 'Checking browser…') : runtimeAction ? text('조치 완료 · 같은 세션으로 계속', 'Action complete · Continue session') : text('로그인 완료', 'Login complete')}
    </button>}
    {error && <p className="form-error" role="alert">{text('로그인 확인 요청을 전달하지 못했습니다. 다시 시도해주세요.', 'Could not send the login confirmation. Please try again.')}</p>}
  </section>;
}
