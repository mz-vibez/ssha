-- Spring Security's WebAuthn schema (spring-security-web user-entities/user-credentials-schema.sql),
-- made idempotent so it can run on every start.
create table if not exists user_entities
(
    id           varchar(1000) not null,
    name         varchar(100)  not null,
    display_name varchar(200),
    primary key (id)
);

create table if not exists user_credentials
(
    credential_id                varchar(1000) not null,
    user_entity_user_id          varchar(1000) not null,
    public_key                   blob          not null,
    signature_count              bigint,
    uv_initialized               boolean,
    backup_eligible              boolean       not null,
    authenticator_transports     varchar(1000),
    public_key_credential_type   varchar(100),
    backup_state                 boolean       not null,
    attestation_object           blob,
    attestation_client_data_json blob,
    created                      timestamp,
    last_used                    timestamp,
    label                        varchar(1000) not null,
    primary key (credential_id)
);

-- Public halves of the phone's SSH keys (the private keys stay in the phone's browser).
create table if not exists ssh_keys
(
    id         varchar(64)  not null,
    label      varchar(100) not null,
    public_key varbinary(2048) not null,
    created    timestamp    not null,
    primary key (id)
);
-- Widened for RSA keys (an 8192-bit public key is about 1 KB); a no-op once applied.
alter table ssh_keys alter column public_key set data type varbinary(2048);

-- Accounts: the id is a random secret-ish handle; it is also the phone's sign-in name.
create table if not exists accounts
(
    id      varchar(64) not null,
    created timestamp   not null,
    primary key (id)
);

-- Computers allowed to use an account's agent. Only a hash of each bearer token is stored.
create table if not exists clients
(
    id         varchar(64)    not null,
    account_id varchar(64)    not null,
    name       varchar(100)   not null,
    token_hash varbinary(32)  not null,
    created    timestamp      not null,
    last_used  timestamp,
    primary key (id),
    unique (token_hash)
);

alter table ssh_keys add column if not exists account_id varchar(64);

-- Web Push subscriptions of the account's browsers and home-screen apps.
create table if not exists push_subscriptions
(
    endpoint   varchar(2000) not null,
    account_id varchar(64)   not null,
    p256dh     varbinary(65) not null,
    auth       varbinary(16) not null,
    created    timestamp     not null,
    primary key (endpoint)
);

-- Host keys of SSH logins the account approved, by verified fingerprint, so the phone can tell a host
-- it has logged in to before from a new one.
create table if not exists known_hosts
(
    account_id  varchar(64)  not null,
    fingerprint varchar(100) not null,
    first_seen  timestamp    not null,
    last_seen   timestamp    not null,
    logins      int          not null,
    primary key (account_id, fingerprint)
);
