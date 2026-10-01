package com.maykelange.ssha.server;

import java.time.Instant;

/**
 * The public half of an SSH key whose private half lives, encrypted, in the phone's browser.
 *
 * @param publicKey SSH wire-format public key blob (Ed25519 or RSA)
 */
public record SshKey(String id, String label, byte[] publicKey, Instant created) {

    /** "ED25519" or e.g. "RSA 4096". */
    public String type() {
        return SshWire.keyType(publicKey);
    }

    public String fingerprint() {
        return SshWire.fingerprint(publicKey);
    }

    public String authorizedKey() {
        return SshWire.authorizedKey(publicKey, "ssha:" + label.replace(' ', '-'));
    }
}
