package com.maykelange.ssha.server;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * The shared secret the CLI authenticates with. Taken from {@code ssha.api-token} if set, otherwise
 * read from {@code ssha.api-token-file}, which is generated on first start. A CLI on the same
 * machine reads that same file, so it works without any setup.
 */
@Component
public class ApiToken {

    private static final Logger log = LoggerFactory.getLogger(ApiToken.class);

    private final byte[] token;

    public ApiToken(SshaProperties properties) {
        String value = StringUtils.hasText(properties.apiToken())
                ? properties.apiToken().strip()
                : readOrCreate(properties.apiTokenFile());
        this.token = value.getBytes(StandardCharsets.UTF_8);
    }

    public boolean matches(String candidate) {
        return candidate != null && MessageDigest.isEqual(token, candidate.getBytes(StandardCharsets.UTF_8));
    }

    private static String readOrCreate(Path file) {
        try {
            if (Files.exists(file)) {
                return Files.readString(file).strip();
            }
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            String value = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
            Files.createDirectories(file.getParent());
            Files.writeString(file, value + "\n");
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            log.info("Generated CLI API token in {}", file);
            return value;
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read or create API token file " + file, e);
        }
    }
}
