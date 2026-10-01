package com.maykelange.ssha.server;

import java.nio.file.Files;
import java.nio.file.Path;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan
public class SshaServerApplication {

    public static void main(String[] args) {
        // Runtime data (passkey database, CLI token) lives in <project>/data; see application.properties.
        if (System.getProperty("ssha.project-dir") == null) {
            System.setProperty("ssha.project-dir", projectDir().toString());
        }
        SpringApplication.run(SshaServerApplication.class, args);
    }

    /**
     * The project folder (the one holding {@code server/} and {@code cli/}), found by walking up from
     * the running jar or classes directory; falls back to the working directory.
     */
    static Path projectDir() {
        String classPath = System.getProperty("java.class.path", "").split(java.io.File.pathSeparator)[0];
        for (Path dir = Path.of(classPath).toAbsolutePath(); dir != null; dir = dir.getParent()) {
            if (Files.isRegularFile(dir.resolve("server/pom.xml")) && Files.isRegularFile(dir.resolve("cli/pom.xml"))) {
                return dir;
            }
        }
        return Path.of("").toAbsolutePath();
    }
}
