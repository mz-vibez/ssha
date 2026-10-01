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
