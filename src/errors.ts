/** The 403 body message for a signed-in credential whose account is suspended (code `account_suspended`). */
export const SUSPENDED_MESSAGE = "This account has been suspended, so you can't sign in right now. If you think this is a mistake, please contact support.";

export class AuthHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AuthHttpError';
  }
}

/** Thrown by stores when createUserWithIdentity hits an existing (provider, subject). */
export class DuplicateIdentityError extends Error {
  constructor() {
    super('Identity already exists');
    this.name = 'DuplicateIdentityError';
  }
}
