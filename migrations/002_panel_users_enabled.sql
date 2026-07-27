-- Libera usuários já existentes; novos cadastros nascem com enabled = false.
ALTER TABLE panel_users
    ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE panel_users
    ALTER COLUMN enabled SET DEFAULT false;
