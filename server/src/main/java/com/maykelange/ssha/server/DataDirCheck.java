package com.maykelange.ssha.server;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;

/**
 * Fails the start with a clear message when the data folder can't be written. H2 would otherwise
 * open the database read-only and fail later with "The database is read only" (typically a
 * container running as a user that doesn't own the mounted folder).
 */
class DataDirCheck implements ApplicationListener<ApplicationEnvironmentPreparedEvent> {

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        String dir = event.getEnvironment().getProperty("ssha.data-dir");
        if (dir != null) {
            problem(Path.of(dir).toAbsolutePath()).ifPresent(message -> {
                throw new IllegalStateException(message);
            });
        }
    }

    /** What is wrong with the data folder, if anything. */
    static Optional<String> problem(Path dir) {
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            return Optional.of("Cannot create the data folder " + dir + " (" + e + "). " + advice(dir));
        }
        if (!Files.isWritable(dir)) {
            return Optional.of("The data folder " + dir + " is not writable" + ownership(dir) + ". " + advice(dir));
        }
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(f -> f.getFileName().toString().startsWith("ssha.") && Files.isRegularFile(f))
                    .filter(f -> !Files.isWritable(f))
                    .findFirst()
                    .map(f -> "The database file " + f + " is not writable" + ownership(f) + ". " + advice(dir));
        } catch (IOException e) {
            return Optional.of("Cannot read the data folder " + dir + " (" + e + "). " + advice(dir));
        }
    }

    private static String ownership(Path path) {
        try {
            return " by this process (uid " + Files.getAttribute(Path.of("/proc/self"), "unix:uid")
                    + "); it belongs to uid " + Files.getAttribute(path, "unix:uid");
        } catch (IOException | UnsupportedOperationException | IllegalArgumentException e) {
            return "";
        }
    }

    private static String advice(Path dir) {
        return "Make " + dir + " and everything in it writable for the user the server runs as: with Docker, "
                + "chown -R <uid>:<gid> the mounted folder to the compose file's user:, or set user: to its owner.";
    }
}
