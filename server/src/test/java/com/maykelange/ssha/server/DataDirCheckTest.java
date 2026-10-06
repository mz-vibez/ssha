package com.maykelange.ssha.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DataDirCheckTest {

    @Test
    void writableFolderIsFine(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("ssha.mv.db"), "x");
        assertThat(DataDirCheck.problem(dir)).isEmpty();
        assertThat(DataDirCheck.problem(dir.resolve("new/data"))).isEmpty();
        assertThat(dir.resolve("new/data")).isDirectory();
    }

    @Test
    void readOnlyDatabaseFileIsReported(@TempDir Path dir) throws Exception {
        Path db = Files.writeString(dir.resolve("ssha.mv.db"), "x");
        Files.setPosixFilePermissions(db, PosixFilePermissions.fromString("r--r--r--"));
        assertThat(DataDirCheck.problem(dir)).get().asString()
                .contains("The database file " + db + " is not writable by this process (uid ")
                .contains("chown -R");
    }

    @Test
    void readOnlyFolderIsReported(@TempDir Path dir) throws Exception {
        Path data = Files.createDirectory(dir.resolve("data"));
        Files.setPosixFilePermissions(data, PosixFilePermissions.fromString("r-xr-xr-x"));
        try {
            assertThat(DataDirCheck.problem(data)).get().asString().contains("The data folder " + data + " is not writable");
        } finally {
            Files.setPosixFilePermissions(data, PosixFilePermissions.fromString("rwxr-xr-x"));
        }
    }
}
