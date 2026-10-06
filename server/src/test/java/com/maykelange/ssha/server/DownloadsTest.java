package com.maykelange.ssha.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
        "ssha.rp-id=localhost",
        "ssha.vapid-key-file=",
        "ssha.allowed-origins=http://localhost",
        "spring.datasource.url=jdbc:h2:mem:ssha-downloads-test;DB_CLOSE_DELAY=-1",
})
@AutoConfigureMockMvc
class DownloadsTest {

    static final byte[] JAR = {'P', 'K', 3, 4, 1, 2, 3};
    /** The start of an x86-64 ELF header: magic, then e_machine at offset 18. */
    static final byte[] ELF = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x3e, 0, 1, 0, 0, 0};

    static Path dir;

    @DynamicPropertySource
    static void downloads(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("ssha-downloads");
        Files.write(dir.resolve("ssha-cli.jar"), JAR);
        Files.write(dir.resolve("ssha-cli"), ELF);
        Files.writeString(dir.resolve("secret.txt"), "not for download");
        registry.add("ssha.downloads-dir", dir::toString);
    }

    @Autowired
    MockMvc mvc;
    @Autowired
    Accounts accounts;

    @Test
    void nativeCliIsDownloadableWithoutSignIn() throws Exception {
        mvc.perform(get("/download/ssha-cli"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/octet-stream"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"ssha-cli\""))
                .andExpect(content().bytes(ELF));
    }

    @Test
    void onlyTheCliIsServed() throws Exception {
        mvc.perform(get("/download/ssha-cli.jar")).andExpect(status().isNotFound());
        mvc.perform(get("/download/secret.txt")).andExpect(status().isNotFound());
        // Spring Security's firewall already refuses an encoded slash.
        mvc.perform(get("/download/..%2Fsecret.txt")).andExpect(status().is4xxClientError());
    }

    @Test
    void computersPageOffersTheCliWithReadyCommands() throws Exception {
        String account = accounts.create("laptop").accountId();
        mvc.perform(get("/clients").with(user(account)))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("href=\"/download/ssha-cli\"")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Linux x86-64, no Java needed")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString(
                        "curl -fLO http://localhost/download/ssha-cli &amp;&amp; chmod +x ssha-cli")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("./ssha-cli --account " + account)))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString(".jar"))));
    }

    @Test
    void nativeExecutablePlatformComesFromItsHeader() throws Exception {
        Path arm = dir.resolve("arm");
        byte[] header = ELF.clone();
        header[18] = (byte) 0xb7;
        Files.write(arm, header);
        assertThat(DownloadsController.platform(arm)).isEqualTo("Linux ARM64, no Java needed");
        assertThat(DownloadsController.platform(dir.resolve("ssha-cli.jar"))).isEqualTo("native executable");
    }
}
