import type { AuthProvider } from './providers.js';

export type ProviderName = 'google' | 'microsoft' | 'github';

export interface ProviderProfile {
  subject: string;
  email?: string;
  emailVerified: boolean;
  name?: string;
}

export interface AuthUser {
  id: string;
  email: string | null;
  name: string | null;
}

export interface NewIdentity {
  provider: ProviderName;
  subject: string;
  email?: string;
  emailVerified: boolean;
}

export interface AuthStore<Tx = unknown> {
  transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T>;
  findUserByIdentity(provider: ProviderName, subject: string, tx?: Tx): Promise<AuthUser | undefined>;
  createUserWithIdentity(p: NewIdentity & { name?: string }, tx?: Tx): Promise<AuthUser>;
  linkIdentity(userId: string, identity: NewIdentity, tx?: Tx): Promise<void>;
  /** Verified identity emails only, case-insensitive. */
  emailBelongsToSuspendedUser(email: string, tx?: Tx): Promise<boolean>;
  /** Holds the user row FOR SHARE; returns false when the user is suspended. */
  createSessionUnlessSuspended(
    userId: string,
    idHash: string,
    expiresAt: Date,
    identity: { provider: string; subject: string },
    tx: Tx,
  ): Promise<boolean>;
  /** Excludes suspended users. */
  getSessionWithExpiry(
    idHash: string,
    now: Date,
  ): Promise<{ user: AuthUser; expiresAt: Date; identity?: { provider: string; subject: string } } | undefined>;
  touchSession(idHash: string, expiresAt: Date): Promise<void>;
  deleteSession(idHash: string): Promise<void>;
  deleteSessionsForUser(userId: string, tx?: Tx): Promise<number>;
  isSuspendedCredential?(idHash: string, now: Date): Promise<boolean>;
}

export type CanCreateResult = { allow: true } | { allow: false; reason: string };

export interface AuthHooks<Tx = unknown> {
  canCreateAccount?(profile: ProviderProfile & { provider: ProviderName }): Promise<CanCreateResult>;
  afterSignIn?(ctx: {
    user: AuthUser;
    profile: ProviderProfile;
    provider: ProviderName;
    isNew: boolean;
    tx: Tx;
  }): Promise<void>;
  resolveRedirect?(path: string): { target: 'backend' | 'frontend'; path: string };
  onLogoutEverywhere?(userId: string, tx: Tx): Promise<void>;
}

export interface AuthConfig<Tx = unknown> {
  providers: {
    google?: { clientId: string; clientSecret: string };
    microsoft?: { clientId: string; clientSecret: string; tenant: string };
    github?: { clientId: string; clientSecret: string };
  };
  publicUrl: string;
  frontendUrl: string;
  encryptionKey: Buffer;
  store: AuthStore<Tx>;
  hooks?: AuthHooks<Tx>;
  cookieNames?: { session?: string; oauth?: string };
  cookieDomain?: string;
  sessionTtlMs?: number;
  clock?: () => Date;
  fetch?: typeof fetch;
  userAgent?: string;
  /**
   * TEST-ONLY seam: replaces (or adds) providers by name so tests can run without network.
   * Not part of the supported public API; never set it in production.
   */
  providerOverrides?: Partial<Record<ProviderName, AuthProvider>>;
}
