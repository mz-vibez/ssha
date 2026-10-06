package com.maykelange.ssha.server;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * Serves the CLI (the agent) as a native executable from {@code ssha.downloads-dir}, if one was built.
 * Public, so a computer without a browser can fetch it with curl.
 */
@Controller
public class DownloadsController {

    /** A file offered for download. */
    public record Download(String name, String description, long size) {

        public String sizeText() {
            return size >= 1 << 20 ? "%.0f MB".formatted(size / (double) (1 << 20)) : "%d KB".formatted(size >> 10);
        }
    }

    static final String NATIVE = "ssha-cli";

    private final Path dir;

    public DownloadsController(SshaProperties props) {
        this.dir = props.downloadsDir();
    }

    /** The native CLI, if the server has one. */
    public Optional<Download> download() {
        return file(NATIVE).map(f -> new Download(NATIVE, platform(f), size(f)));
    }

    @GetMapping("/download/{name}")
    public ResponseEntity<Resource> download(@PathVariable String name) {
        if (!name.equals(NATIVE)) {
            return ResponseEntity.notFound().build();
        }
        return file(name)
                .<ResponseEntity<Resource>>map(f -> ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(name).build().toString())
                        .body(new FileSystemResource(f)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private Optional<Path> file(String name) {
        if (dir == null) {
            return Optional.empty();
        }
        Path f = dir.resolve(name);
        return Files.isRegularFile(f) ? Optional.of(f) : Optional.empty();
    }

    private static long size(Path f) {
        try {
            return Files.size(f);
        } catch (IOException e) {
            return 0;
        }
    }

    /** The native executable's platform, from its ELF or Mach-O header. */
    static String platform(Path f) {
        byte[] h = new byte[20];
        try (InputStream in = Files.newInputStream(f)) {
            if (in.readNBytes(h, 0, h.length) < h.length) {
                return "native executable";
            }
        } catch (IOException e) {
            return "native executable";
        }
        if (h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
            int machine = (h[18] & 0xff) | (h[19] & 0xff) << 8;
            return switch (machine) {
                case 0x3e -> "Linux x86-64, no Java needed";
                case 0xb7 -> "Linux ARM64, no Java needed";
                default -> "Linux, no Java needed";
            };
        }
        if ((h[0] & 0xff) == 0xcf && (h[1] & 0xff) == 0xfa && (h[2] & 0xff) == 0xed && (h[3] & 0xff) == 0xfe) {
            int cpu = (h[4] & 0xff) | (h[5] & 0xff) << 8 | (h[6] & 0xff) << 16 | (h[7] & 0xff) << 24;
            return cpu == 0x0100000c ? "macOS Apple silicon, no Java needed" : "macOS, no Java needed";
        }
        return "native executable";
    }
}
