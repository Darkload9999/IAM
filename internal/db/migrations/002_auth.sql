-- The ID token a session was signed in with (encrypted), sent back to
-- Asgardeo as id_token_hint when the admin signs out.
ALTER TABLE sessions ADD COLUMN id_token_encrypted text NOT NULL DEFAULT '';

-- A Hub admin is a particular Asgardeo account, not whoever holds an email
-- address: an address can be changed, or be shared by two accounts. An
-- account deleted in Asgardeo takes its appointment with it.
DELETE FROM hub_admins;
ALTER TABLE hub_admins ADD COLUMN user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE;
CREATE UNIQUE INDEX hub_admins_user_idx ON hub_admins (user_id);
