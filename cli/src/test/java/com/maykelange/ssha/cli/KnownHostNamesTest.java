package com.maykelange.ssha.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

class KnownHostNamesTest {

    private static final byte[] KEY = {1, 2, 3};
    private static final String B64 = Base64.getEncoder().encodeToString(KEY);

    @Test
    void findsThePlainNameOfTheKey() {
        List<String> lines = List.of("# comment", "other ssh-ed25519 AAAA", "|1|salt|hash ssh-ed25519 " + B64,
                "[git.example.com]:2222,192.0.2.1 ssh-ed25519 " + B64);
        assertThat(KnownHostNames.find(lines, KEY)).isEqualTo("git.example.com:2222");
    }

    @Test
    void dropsTheDefaultPortAndIgnoresHashedOrUnknown() {
        assertThat(KnownHostNames.find(List.of("[h.example]:22 ssh-ed25519 " + B64), KEY)).isEqualTo("h.example");
        assertThat(KnownHostNames.find(List.of("|1|salt|hash ssh-ed25519 " + B64), KEY)).isNull();
        assertThat(KnownHostNames.find(List.of("*.example ssh-ed25519 " + B64), KEY)).isNull();
        assertThat(KnownHostNames.find(List.of(), KEY)).isNull();
    }
}
