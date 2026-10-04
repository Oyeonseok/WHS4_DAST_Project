"""Read-only detection of visible UI that requires the operator's input."""

from urllib.parse import urlparse

_MFA_INPUTS = (
    'input[autocomplete="one-time-code"]:visible, input[name="otp"]:visible, '
    'input[name="totp"]:visible, input[name="verification_code"]:visible'
)
_CAPTCHA_UI = (
    'iframe[src*="recaptcha"][title*="challenge"]:visible, '
    'iframe[src*="hcaptcha"]:visible, iframe[src*="challenges.cloudflare.com"]:visible'
)

_LOGIN_PATHS = frozenset({"login", "log-in", "signin", "sign-in", "authenticate"})
_LOGIN_LABELS = frozenset({"login", "log in", "sign in", "signin", "로그인", "로그 인"})


def _visible_login_form(page) -> bool:
    """Distinguish login from registration and password-management forms."""
    if page.locator('input[type="password"]:visible').count() <= 0:
        return False
    try:
        segments = {part.casefold() for part in urlparse(str(page.url)).path.split('/') if part}
        if segments & _LOGIN_PATHS:
            return True
    except (TypeError, ValueError):
        pass
    try:
        labels = page.locator(
            'form:has(input[type="password"]:visible) '
            ':is(button[type="submit"], input[type="submit"]):visible'
        ).evaluate_all(
            "elements => elements.map(element => "
            "(element.innerText || element.value || element.getAttribute('aria-label') || '').trim())"
        )
        return any(str(label).casefold() in _LOGIN_LABELS for label in labels)
    except Exception:
        return False


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
    if include_login and _visible_login_form(page):
        return 'login_form_visible'
    if any(marker in text for marker in (
        'sign in to continue', 'log in to continue', 'login required to access',
        '로그인이 필요합니다', '로그인 후 이용',
    )):
        return 'login_form_visible'
    return None
