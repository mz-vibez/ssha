package com.maykelange.ssha.cli;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

/**
 * The host name ssh was asked to connect to, which the agent protocol doesn't carry: only the host's
 * key is bound to the connection, so the name is looked up by that key in the user's known_hosts.
 */
final class KnownHostNames {

    private KnownHostNames() {
    }

    /** @return the first plain host name listed for the key in {@code ~/.ssh/known_hosts}; null if none */
    static String find(byte[] hostKey) {
        String home = System.getenv("HOME");
        Path file = Path.of(home != null && !home.isBlank() ? home : System.getProperty("user.home"),
                ".ssh", "known_hosts");
        try {
            return find(Files.readAllLines(file), hostKey);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    static String find(List<String> lines, byte[] hostKey) {
        String wanted = Base64.getEncoder().encodeToString(hostKey);
        for (String line : lines) {
            String[] f = line.strip().split("\\s+");
            int at = f.length > 0 && f[0].startsWith("@") ? 1 : 0; // @cert-authority / @revoked marker
            if (at == 1 || f.length < at + 3 || !f[at + 2].equals(wanted) || f[at].startsWith("|")) {
                continue; // hashed entries can't be turned back into a name
            }
            for (String name : f[at].split(",")) {
                if (!name.isEmpty() && !name.startsWith("!") && !name.contains("*") && !name.contains("?")) {
                    return name.replaceFirst("^\\[(.*)]:22$", "$1").replaceFirst("^\\[(.*)]:(\\d+)$", "$1:$2");
                }
            }
        }
        return null;
    }
}
