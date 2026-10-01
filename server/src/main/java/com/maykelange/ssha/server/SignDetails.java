package com.maykelange.ssha.server;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.util.Arrays;

/**
 * What a sign request is for, decoded on the server so the phone can show it before you approve.
 *
 * @param kind         "SSH login", "Signature" (SSHSIG, e.g. git commit signing) or "Unknown data"
 * @param user         remote user name of an SSH login
 * @param hostKey      fingerprint of the server's host key, if known
 * @param hostVerified whether the host key is proven by OpenSSH's session binding
 * @param forwarded    whether the request came through a forwarded agent
 * @param namespace    SSHSIG namespace, e.g. "git" or "file"
 * @param warning      shown prominently when something doesn't add up
 */
public record SignDetails(String kind, String user, String hostKey, boolean hostVerified, boolean forwarded,
                          String namespace, String warning) {

    private static final byte[] SSHSIG = "SSHSIG".getBytes(US_ASCII);
    private static final int SSH_MSG_USERAUTH_REQUEST = 50;

    static SignDetails describe(byte[] keyBlob, byte[] data, SignService.Binding binding) {
        boolean forwarded = binding != null && binding.forwarded();
        if (data.length > SSHSIG.length && Arrays.equals(data, 0, SSHSIG.length, SSHSIG, 0, SSHSIG.length)) {
            try {
                SshWire.Reader r = new SshWire.Reader(Arrays.copyOfRange(data, SSHSIG.length, data.length));
                String namespace = r.utf8();
                r.string(); // reserved
                r.utf8(); // hash algorithm
                r.string(); // message hash
                if (r.done()) {
                    return new SignDetails("Signature", null, null, false, forwarded, namespace, null);
                }
            } catch (IllegalArgumentException ignored) {
                // fall through to "unknown"
            }
        }
        try {
            SshWire.Reader r = new SshWire.Reader(data);
            byte[] sessionId = r.string();
            if (r.byte8() == SSH_MSG_USERAUTH_REQUEST) {
                String user = r.utf8();
                r.utf8(); // service
                String method = r.utf8();
                boolean hostbound = method.equals("publickey-hostbound-v00@openssh.com");
                if ((hostbound || method.equals("publickey")) && r.bool()) {
                    r.utf8(); // algorithm
                    byte[] userKey = r.string();
                    byte[] hostKey = hostbound ? r.string() : null;
                    if (r.done()) {
                        return login(keyBlob, userKey, user, sessionId, hostKey, binding);
                    }
                }
            }
        } catch (IllegalArgumentException ignored) {
            // fall through to "unknown"
        }
        return new SignDetails("Unknown data", null, null, false, forwarded, null,
                "This is neither an SSH login nor a signature. Only approve it if you know what asked for it.");
    }

    private static SignDetails login(byte[] keyBlob, byte[] userKey, String user, byte[] sessionId, byte[] hostKey,
                                     SignService.Binding binding) {
        String warning = Arrays.equals(keyBlob, userKey) ? null : "The login names a different key than the one asked to sign.";
        if (binding == null) {
            return new SignDetails("SSH login", user, hostKey == null ? null : SshWire.fingerprint(hostKey), false, false,
                    null, warning != null ? warning : "ssh didn't tell the agent which host this is for, so the host is unverified.");
        }
        boolean verified = Arrays.equals(binding.sessionId(), sessionId)
                && (hostKey == null || Arrays.equals(hostKey, binding.hostKey()))
                && SshWire.verify(binding.hostKey(), binding.sessionId(), binding.signature());
        if (!verified) {
            return new SignDetails("SSH login", user, hostKey == null ? null : SshWire.fingerprint(hostKey), false,
                    binding.forwarded(), null, "The host does not match this login — something may be relaying it. Deny unless you are sure.");
        }
        return new SignDetails("SSH login", user, SshWire.fingerprint(binding.hostKey()), true, binding.forwarded(), null,
                warning);
    }
}
