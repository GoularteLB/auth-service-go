ALTER TABLE clients ADD COLUMN audiences text[] NOT NULL DEFAULT '{}';
