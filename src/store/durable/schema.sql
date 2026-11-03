CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(64) PRIMARY KEY,
    platform VARCHAR(16) NOT NULL,
    public_key_pem TEXT NOT NULL,
    key_id VARCHAR(128),
    sign_count BIGINT,
    last_sequence VARCHAR(32) NOT NULL DEFAULT '0',
    registered_at BIGINT NOT NULL,
    tier VARCHAR(16) NOT NULL DEFAULT 'hardware',
    expires_at BIGINT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    receipt TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_devices_platform ON devices(platform);
CREATE INDEX IF NOT EXISTS idx_devices_registered_at ON devices(registered_at);
