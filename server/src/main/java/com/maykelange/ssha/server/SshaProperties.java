package com.maykelange.ssha.server;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * @param username       the single account; passkeys are registered against it
 * @param rpId           WebAuthn relying party id — the domain passkeys are bound to
 * @param allowedOrigins origins the browser may run passkey ceremonies from
 * @param apiToken       CLI bearer token; when blank it is read from (or generated into) {@code apiTokenFile}
 * @param signTimeout    how long an SSH sign request waits for approval on the phone
 */
@ConfigurationProperties("ssha")
public record SshaProperties(String username, String rpId, Set<String> allowedOrigins,
                             String apiToken, Path apiTokenFile,
                             @DefaultValue("60s") Duration signTimeout) {
}
