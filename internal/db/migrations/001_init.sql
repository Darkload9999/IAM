-- ZEIT26 Identity Hub: the central place where people are created, given
-- access to the company's applications, and granted permissions in them.
-- Asgardeo holds the accounts and passwords; this database holds what the
-- Hub needs around them.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Every Asgardeo user, kept in step by the sync (internal/sync). Accounts
-- created through the Hub arrive here at once; everything else (created in
-- the Asgardeo console, the organization owner, ...) on the next sync.
CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asgardeo_id     text NOT NULL UNIQUE,
    username        text NOT NULL,
    email           text NOT NULL,
    given_name      text NOT NULL DEFAULT '',
    family_name     text NOT NULL DEFAULT '',
    -- Owner, Administrator or Customer (Asgardeo's own words).
    account_type    text NOT NULL DEFAULT 'Customer',
    -- As Asgardeo reports it: UNLOCKED, LOCKED, PENDING_AP (waiting for the
    -- person to set a password from the invite), ...
    account_state   text NOT NULL DEFAULT '',
    locked          boolean NOT NULL DEFAULT false,
    department      text NOT NULL DEFAULT '',
    created_via_hub boolean NOT NULL DEFAULT false,
    asgardeo_created_at timestamptz,
    -- Set when the account disappeared from Asgardeo.
    removed_at      timestamptz,
    synced_at       timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX users_email_idx ON users (lower(email));

-- Admins of the Hub besides the organization owner, who is always one.
CREATE TABLE hub_admins (
    email      text PRIMARY KEY,
    added_by   text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The company's internal applications.
CREATE TABLE applications (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key         text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9-]{1,39}$'),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    url         text NOT NULL DEFAULT '',
    -- Where the Hub pushes accounts (SCIM 2.0), and the bearer token it
    -- sends, encrypted with HUB_ENCRYPTION_KEY. Empty: nothing is pushed.
    scim_url              text NOT NULL DEFAULT '',
    scim_token_encrypted  text NOT NULL DEFAULT '',
    -- The Asgardeo group whose members may sign in to the application.
    asgardeo_group_id     text NOT NULL DEFAULT '',
    asgardeo_group_name   text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- What an application lets somebody do, defined by the Hub's admins.
CREATE TABLE permissions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id      uuid NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    key         text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.:-]{1,79}$'),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, key)
);

-- Named bundles of an application's permissions.
CREATE TABLE roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id      uuid NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    key         text NOT NULL CHECK (key ~ '^[A-Za-z][A-Za-z0-9_.:-]{1,79}$'),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, key)
);

CREATE TABLE role_permissions (
    role_id       uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- A person's access to an application, and its provisioning state there.
CREATE TABLE access_grants (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    app_id         uuid NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    -- The id the application gave the account (SCIM "id").
    remote_id      text NOT NULL DEFAULT '',
    -- pending, provisioned, failed, revoking
    sync_status    text NOT NULL DEFAULT 'pending',
    last_error     text NOT NULL DEFAULT '',
    last_synced_at timestamptz,
    granted_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, app_id)
);

CREATE TABLE grant_roles (
    grant_id uuid NOT NULL REFERENCES access_grants (id) ON DELETE CASCADE,
    role_id  uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (grant_id, role_id)
);

-- Permissions given directly, on top of those the roles carry.
CREATE TABLE grant_permissions (
    grant_id      uuid NOT NULL REFERENCES access_grants (id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (grant_id, permission_id)
);

-- Work for the provisioning worker: push (create or update) an account to
-- an application, or remove it there. Written in the same transaction as
-- the change that needs it, so none is ever lost.
CREATE TABLE provisioning_jobs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    app_id      uuid NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    operation   text NOT NULL CHECK (operation IN ('upsert', 'deprovision')),
    status      text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'done', 'failed')),
    attempts    integer NOT NULL DEFAULT 0,
    next_run_at timestamptz NOT NULL DEFAULT now(),
    last_error  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX provisioning_jobs_due_idx
    ON provisioning_jobs (next_run_at) WHERE status IN ('pending', 'running');

-- Who did what, to whom. Never updated, never deleted.
CREATE TABLE audit_events (
    id          bigserial PRIMARY KEY,
    actor       text NOT NULL,
    action      text NOT NULL,
    target_type text NOT NULL,
    target_id   text NOT NULL DEFAULT '',
    summary     text NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_created_idx ON audit_events (created_at DESC);

-- Signed-in dashboard sessions. Only a hash of the cookie value is kept.
CREATE TABLE sessions (
    id_hash     text PRIMARY KEY,
    subject     text NOT NULL,
    email       text NOT NULL,
    name        text NOT NULL DEFAULT '',
    csrf_token  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
