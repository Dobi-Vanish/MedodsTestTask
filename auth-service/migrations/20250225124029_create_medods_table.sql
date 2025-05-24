-- +goose Up
CREATE TABLE IF NOT EXISTS medods(
    id serial PRIMARY KEY,
    guid VARCHAR(36) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    password VARCHAR(255) NOT NULL,
    active INT NOT NULL DEFAULT 1,
    refresh_token TEXT,
    refresh_token_expires TIMESTAMP,
    token_pair_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

CREATE UNIQUE INDEX idx_medods_email ON medods(email);
CREATE INDEX idx_medods_created_at ON medods(created_at);
CREATE INDEX idx_medods_inactive ON medods(email) WHERE active = 0;
CREATE INDEX idx_medods_name ON medods(first_name, last_name);
CREATE INDEX idx_medods_refresh_token ON medods(refresh_token);
CREATE INDEX idx_medods_refresh_token_expires ON medods(refresh_token_expires);
CREATE INDEX idx_medods_token_pair_id ON medods(token_pair_id);
CREATE INDEX idx_medods_refresh_token_composite ON medods(refresh_token, refresh_token_expires);
CREATE INDEX idx_medods_active_guids ON medods(guid) WHERE active = 1;

-- +goose StatementBegin
SELECT 'up SQL query';
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS medods;
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd