export const scopeCollectionRequest = {
  login_mode: 'runtime-browser',
  identity: 'primary',
} as const;

export function programRegistrationUrlError(programUrl: string): string | null {
  return /^http:\/\//i.test(programUrl.trim())
    ? 'HTTP URLs cannot be registered. Enter a URL starting with https://.'
    : null;
}
