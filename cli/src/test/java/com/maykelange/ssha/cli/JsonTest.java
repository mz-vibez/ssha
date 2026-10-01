package com.maykelange.ssha.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void readsEnrollLinkAndIgnoresUnknownFields() throws IOException {
        SshaCli.EnrollLink link = Json.enrollLink("""
                {"url":"https://ssha.example/login/ott?token=abc","expiresAt":"2026-10-02T10:15:30.123456Z",
                 "extra":{"nested":[1,2,{"x":null}]},"more":true}""");
        assertThat(link.url()).isEqualTo("https://ssha.example/login/ott?token=abc");
        assertThat(link.expiresAt()).isEqualTo(Instant.parse("2026-10-02T10:15:30.123456Z"));
    }

    @Test
    void readsAgentKeys() throws IOException {
        List<SshaCli.AgentKey> keys = Json.agentKeys("""
                [{"id":"k1","label":"phone","publicKey":"AAAAC3NzaC1lZDI1NTE5","authorizedKey":"ssh-ed25519 AAAA ssha:phone"},
                 {"id":"k2","label":"old \\"rsa\\" key","publicKey":"AQID","authorizedKey":"ssh-rsa AAAA x","type":"RSA"}]""");
        assertThat(keys).hasSize(2);
        assertThat(keys.get(0).label()).isEqualTo("phone");
        assertThat(keys.get(0).publicKey()).startsWith(0, 0, 0, 11);
        assertThat(keys.get(1).label()).isEqualTo("old \"rsa\" key");
        assertThat(keys.get(1).publicKey()).containsExactly(1, 2, 3);
        assertThat(Json.agentKeys("[]")).isEmpty();
    }

    @Test
    void readsSignResponse() throws IOException {
        assertThat(Json.signResponse("{\"signature\":\"AQID\"}").signature()).containsExactly(1, 2, 3);
    }

    @Test
    void writesSignRequest() {
        String withoutBinding = Json.signRequest(
                new SshaCli.SignRequest(new byte[] {1, 2, 3}, new byte[] {(byte) 0xfb, (byte) 0xff}, 4, "laptop", null));
        assertThat(withoutBinding).isEqualTo(
                "{\"publicKey\":\"AQID\",\"data\":\"+/8=\",\"flags\":4,\"client\":\"laptop\",\"binding\":null}");

        String withBinding = Json.signRequest(new SshaCli.SignRequest(new byte[] {1}, new byte[] {2}, 0, "a\"b",
                new SshAgent.Binding(new byte[] {3}, new byte[] {4}, new byte[] {5}, true)));
        assertThat(withBinding).isEqualTo("{\"publicKey\":\"AQ==\",\"data\":\"Ag==\",\"flags\":0,\"client\":\"a\\\"b\","
                + "\"binding\":{\"hostKey\":\"Aw==\",\"sessionId\":\"BA==\",\"signature\":\"BQ==\",\"forwarded\":true}}");
    }

    @Test
    void badResponsesBecomeIoExceptions() {
        assertThatThrownBy(() -> Json.agentKeys("<html>502 Bad Gateway</html>")).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> Json.agentKeys("{\"error\":\"x\"}")).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> Json.signResponse("{}")).isInstanceOf(IOException.class)
                .hasMessageContaining("signature");
        assertThatThrownBy(() -> Json.signResponse("{\"signature\":\"not base64!\"}")).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> Json.enrollLink("{\"url\":\"u\",\"expiresAt\":\"tomorrow\"}"))
                .isInstanceOf(IOException.class);
    }
}
