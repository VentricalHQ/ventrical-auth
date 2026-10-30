create table users (
  id text primary key,
  email text,
  name text,
  suspended_at timestamptz,
  created_at timestamptz not null default now()
);

create table identities (
  provider text not null,
  subject text not null,
  user_id text not null references users(id) on delete cascade,
  email text,
  email_verified boolean not null default false,
  primary key (provider, subject)
);
create index identities_user_id_idx on identities (user_id);
create index identities_verified_email_idx on identities (lower(email)) where email_verified;

create table sessions (
  id_hash text primary key,
  user_id text not null references users(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  identity_provider text,
  identity_subject text
);
create index sessions_user_id_idx on sessions (user_id);
