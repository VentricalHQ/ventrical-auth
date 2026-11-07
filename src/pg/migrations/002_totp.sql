-- TOTP second factor. Safe to apply whether or not you turn `twoFactor` on.

create table user_totp (
  user_id text primary key references users(id) on delete cascade,
  -- Both secrets are AES-256-GCM blobs with the user id as AAD, never the secret itself.
  secret_enc text,
  pending_secret_enc text,
  confirmed_at timestamptz,
  last_step bigint,
  failed_count int not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now()
);

create table recovery_codes (
  user_id text not null references users(id) on delete cascade,
  code_hash text not null,
  used_at timestamptz,
  primary key (user_id, code_hash)
);

alter table sessions
  add column mfa_pending boolean not null default false,
  add column mfa_attempts int not null default 0,
  add column mfa_verified_at timestamptz,
  add column mfa_redirect text;
