CREATE TABLE usage_notifications (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    feature VARCHAR(100) NOT NULL,

    day DATE NOT NULL DEFAULT CURRENT_DATE,

    warning_sent BOOLEAN NOT NULL DEFAULT FALSE,
    limit_sent BOOLEAN NOT NULL DEFAULT FALSE,

    warning_sent_at TIMESTAMPTZ,
    limit_sent_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT usage_notifications_unique
        UNIQUE (user_id, feature, day)
);

-- Optional indexes for reporting/admin dashboards
CREATE INDEX idx_usage_notifications_day
    ON usage_notifications(day);

CREATE INDEX idx_usage_notifications_feature
    ON usage_notifications(feature);

-- Automatically keep updated_at current
CREATE OR REPLACE FUNCTION update_usage_notifications_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_usage_notifications_updated_at
BEFORE UPDATE ON usage_notifications
FOR EACH ROW
EXECUTE FUNCTION update_usage_notifications_updated_at();