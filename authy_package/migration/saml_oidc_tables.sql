-- SAML 2.0 Tables
CREATE TABLE IF NOT EXISTS saml_providers (
    id SERIAL PRIMARY KEY,
    entity_id VARCHAR(512) UNIQUE NOT NULL,
    metadata_xml TEXT,
    sso_url VARCHAR(512),
    slo_url VARCHAR(512),
    certificate TEXT,
    private_key_ref VARCHAR(256),
    name_id_format VARCHAR(256) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    allow_create BOOLEAN DEFAULT true,
    force_authn BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS saml_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(256) UNIQUE NOT NULL,
    request_id VARCHAR(256) UNIQUE NOT NULL,
    name_id VARCHAR(512),
    session_index VARCHAR(256),
    user_id INTEGER,
    idp_entity_id VARCHAR(512),
    authenticated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    relay_state TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_saml_sessions_request_id ON saml_sessions(request_id);
CREATE INDEX idx_saml_sessions_session_id ON saml_sessions(session_id);
CREATE INDEX idx_saml_providers_entity_id ON saml_providers(entity_id);

-- OIDC Tables
CREATE TABLE IF NOT EXISTS oidc_providers (
    id SERIAL PRIMARY KEY,
    provider_id VARCHAR(256) UNIQUE NOT NULL,
    issuer VARCHAR(512) NOT NULL,
    client_id VARCHAR(256) NOT NULL,
    client_secret_encrypted TEXT,
    config_json JSONB,
    authorization_endpoint VARCHAR(512),
    token_endpoint VARCHAR(512),
    userinfo_endpoint VARCHAR(512),
    jwks_uri VARCHAR(512),
    end_session_endpoint VARCHAR(512),
    scopes TEXT[],
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_oidc_providers_provider_id ON oidc_providers(provider_id);
CREATE INDEX idx_oidc_providers_issuer ON oidc_providers(issuer);

-- Add columns to users table for SAML/OIDC
ALTER TABLE users ADD COLUMN IF NOT EXISTS saml_subject VARCHAR(512);
ALTER TABLE users ADD COLUMN IF NOT EXISTS idp_entity_id VARCHAR(512);
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject VARCHAR(512);
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_method VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS issuer VARCHAR(512);

CREATE INDEX idx_users_saml_subject ON users(saml_subject);
CREATE INDEX idx_users_oidc_subject ON users(oidc_subject);
CREATE INDEX idx_users_auth_method ON users(auth_method);
