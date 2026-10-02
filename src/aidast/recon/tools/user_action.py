"""Read-only detection of visible UI that requires the operator's input."""

_MFA_INPUTS = (
    'input[autocomplete="one-time-code"]:visible, input[name="otp"]:visible, '
    'input[name="totp"]:visible, input[name="verification_code"]:visible'
)
_CAPTCHA_UI = (
    'iframe[src*="recaptcha"][title*="challenge"]:visible, '
    'iframe[src*="hcaptcha"]:visible, iframe[src*="challenges.cloudflare.com"]:visible'
)


def visible_user_action(page, *, include_login: bool = False) -> str | None:
    """Use explicit rendered evidence; a navbar sign-in link is not a blocker.

    This does not solve challenges or claim an AI decision. Callers retain
    responsibility for origin/policy checks and for providing a visible browser.
    """
    if page.locator(_MFA_INPUTS).count() > 0:
        return 'mfa_required'
    if page.locator(_CAPTCHA_UI).count() > 0:
        return 'captcha_required'
    text = page.locator('body').inner_text(timeout=1500).casefold()[:12000]
    if any(marker in text for marker in (
        'verify you are human', 'confirm you are human', 'complete the captcha',
        '사람인지 확인', '로봇이 아닙니다',
    )):
        return 'captcha_required'
    if include_login and page.locator('input[type="password"]:visible').count() > 0:
        return 'login_form_visible'
    if any(marker in text for marker in (
        'sign in to continue', 'log in to continue', 'login required to access',
        '로그인이 필요합니다', '로그인 후 이용',
    )):
        return 'login_form_visible'
    return None
