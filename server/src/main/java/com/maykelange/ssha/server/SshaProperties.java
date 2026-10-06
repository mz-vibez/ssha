package com.maykelange.ssha.server;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * @param rpId             WebAuthn relying party id — the domain passkeys are bound to
 * @param allowedOrigins   origins the browser may run passkey ceremonies from
 * @param openRegistration whether anyone may create an account through {@code POST /api/accounts}
 * @param legacyTokenFile  the single-user version's CLI token, migrated once (see {@link Accounts})
 * @param signTimeout      how long an SSH sign request waits for approval on the phone
 * @param joinTimeout      how long a computer asking to join an account waits for approval on the phone
 */
@ConfigurationProperties("ssha")
public record SshaProperties(String rpId, Set<String> allowedOrigins,
                             @DefaultValue("true") boolean openRegistration, Path legacyTokenFile,
                             @DefaultValue("60s") Duration signTimeout,
                             @DefaultValue("120s") Duration joinTimeout) {
}
