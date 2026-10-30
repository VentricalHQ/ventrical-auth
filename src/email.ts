/** Trim, then lowercase. The one rule for every stored or compared email. Returns undefined when nothing is left. */
export function normalizeEmail(email: string): string | undefined {
  const e = email.trim().toLowerCase();
  return e === '' ? undefined : e;
}
