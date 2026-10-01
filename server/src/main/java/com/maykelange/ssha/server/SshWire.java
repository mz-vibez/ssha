package com.maykelange.ssha.server;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * SSH wire encoding (RFC 4251 strings, uint32s, mpints) and the key and signature formats ssha needs.
 * User keys are Ed25519 or RSA; host keys (for verifying OpenSSH's session binding) can also be ECDSA.
 */
final class SshWire {

    static final String ED25519 = "ssh-ed25519";
    static final String RSA = "ssh-rsa";
    static final int MIN_RSA_BITS = 2048;

    /** ssh-agent sign request flags selecting the RSA signature hash. */
    private static final int SSH_AGENT_RSA_SHA2_256 = 2;
    private static final int SSH_AGENT_RSA_SHA2_512 = 4;

    /** DER prefix of an X.509 SubjectPublicKeyInfo for Ed25519; the 32 raw key bytes follow it. */
    private static final byte[] ED25519_X509_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private SshWire() {
    }

    static final class Reader {
        private final ByteBuffer buf;

        Reader(byte[] data) {
            this.buf = ByteBuffer.wrap(data);
        }

        int byte8() {
            need(1);
            return buf.get() & 0xff;
        }

        boolean bool() {
            return byte8() != 0;
        }

        int uint32() {
            need(4);
            return buf.getInt();
        }

        byte[] bytes(int n) {
            need(n);
            byte[] b = new byte[n];
            buf.get(b);
            return b;
        }

        byte[] string() {
            return bytes(uint32());
        }

        String utf8() {
            return new String(string(), UTF_8);
        }

        BigInteger mpint() {
            byte[] b = string();
            return b.length == 0 ? BigInteger.ZERO : new BigInteger(b);
        }

        boolean done() {
            return !buf.hasRemaining();
        }

        private void need(int n) {
            if (n < 0 || buf.remaining() < n) {
                throw new IllegalArgumentException("truncated SSH data");
            }
        }
    }

    static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Writer uint32(int v) {
            out.write(v >>> 24);
            out.write(v >>> 16);
            out.write(v >>> 8);
            out.write(v);
            return this;
        }

        Writer string(byte[] b) {
            uint32(b.length);
            out.writeBytes(b);
            return this;
        }

        Writer string(String s) {
            return string(s.getBytes(UTF_8));
        }

        byte[] toByteArray() {
            return out.toByteArray();
        }
    }

    static byte[] ed25519Blob(byte[] raw) {
        if (raw.length != 32) {
            throw new IllegalArgumentException("an Ed25519 public key is 32 bytes");
        }
        return new Writer().string(ED25519).string(raw).toByteArray();
    }

    /** Checks that {@code blob} is a public key the phone can hold: Ed25519, or RSA of at least 2048 bits. */
    static void checkUserKey(byte[] blob) {
        Reader r = new Reader(blob);
        switch (r.utf8()) {
            case ED25519 -> {
                if (r.string().length != 32) {
                    throw new IllegalArgumentException("an Ed25519 public key is 32 bytes");
                }
            }
            case RSA -> {
                BigInteger e = r.mpint();
                BigInteger n = r.mpint();
                if (e.signum() <= 0 || !e.testBit(0) || n.signum() <= 0) {
                    throw new IllegalArgumentException("invalid RSA public key");
                }
                if (n.bitLength() < MIN_RSA_BITS) {
                    throw new IllegalArgumentException("RSA keys need at least " + MIN_RSA_BITS + " bits");
                }
            }
            default -> throw new IllegalArgumentException("only Ed25519 and RSA keys are supported");
        }
        if (!r.done()) {
            throw new IllegalArgumentException("trailing data after the public key");
        }
    }

    /** "ED25519" or e.g. "RSA 4096", as ssh-keygen -l shows it. */
    static String keyType(byte[] blob) {
        Reader r = new Reader(blob);
        if (r.utf8().equals(RSA)) {
            r.mpint();
            return "RSA " + r.mpint().bitLength();
        }
        return "ED25519";
    }

    /**
     * The signature algorithm for a sign request: the key's own for Ed25519, and for RSA the SHA-2
     * variant the flags ask for. Legacy SHA-1 RSA signatures are refused.
     */
    static String signatureAlgorithm(byte[] keyBlob, int flags) {
        String algorithm = algorithm(keyBlob);
        if (!algorithm.equals(RSA)) {
            return algorithm;
        }
        if ((flags & SSH_AGENT_RSA_SHA2_512) != 0) {
            return "rsa-sha2-512";
        }
        if ((flags & SSH_AGENT_RSA_SHA2_256) != 0) {
            return "rsa-sha2-256";
        }
        throw new IllegalArgumentException("SHA-1 RSA signatures (ssh-rsa) are not supported; use rsa-sha2-256/512");
    }

    static byte[] signatureBlob(String algorithm, byte[] raw) {
        return new Writer().string(algorithm).string(raw).toByteArray();
    }

    static String algorithm(byte[] keyBlob) {
        return new Reader(keyBlob).utf8();
    }

    /** {@code SHA256:…}, as printed by {@code ssh-keygen -l} and {@code ssh-add -l}. */
    static String fingerprint(byte[] keyBlob) {
        return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(sha256(keyBlob));
    }

    /** URL-safe id for a key, derived from the same hash as its fingerprint. */
    static String keyId(byte[] keyBlob) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(keyBlob));
    }

    /** A line for {@code ~/.ssh/authorized_keys}. */
    static String authorizedKey(byte[] keyBlob, String comment) {
        return algorithm(keyBlob) + " " + Base64.getEncoder().encodeToString(keyBlob) + " " + comment;
    }

    /** Verifies an SSH signature blob ({@code string algorithm, string signature}) over {@code data}. */
    static boolean verify(byte[] keyBlob, byte[] data, byte[] signatureBlob) {
        try {
            Reader sr = new Reader(signatureBlob);
            String sigAlg = sr.utf8();
            byte[] sig = sr.string();
            Reader kr = new Reader(keyBlob);
            String keyAlg = kr.utf8();

            PublicKey key;
            Signature verifier;
            switch (keyAlg) {
                case ED25519 -> {
                    if (!sigAlg.equals(keyAlg)) {
                        return false;
                    }
                    key = ed25519Key(kr.string());
                    verifier = Signature.getInstance("Ed25519");
                }
                case "ssh-rsa" -> {
                    BigInteger e = kr.mpint();
                    BigInteger n = kr.mpint();
                    key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
                    verifier = Signature.getInstance(switch (sigAlg) {
                        case "rsa-sha2-256" -> "SHA256withRSA";
                        case "rsa-sha2-512" -> "SHA512withRSA";
                        default -> throw new IllegalArgumentException("unsupported RSA signature " + sigAlg);
                    });
                }
                case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" -> {
                    if (!sigAlg.equals(keyAlg)) {
                        return false;
                    }
                    String curve = kr.utf8();
                    ECParameterSpec spec = curve(curve);
                    int size = (spec.getCurve().getField().getFieldSize() + 7) / 8;
                    byte[] q = kr.string();
                    if (q.length != 1 + 2 * size || q[0] != 4) {
                        throw new IllegalArgumentException("bad EC point");
                    }
                    ECPoint w = new ECPoint(new BigInteger(1, Arrays.copyOfRange(q, 1, 1 + size)),
                            new BigInteger(1, Arrays.copyOfRange(q, 1 + size, q.length)));
                    key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, spec));
                    Reader rs = new Reader(sig);
                    byte[] r = unsigned(rs.mpint(), size);
                    byte[] s = unsigned(rs.mpint(), size);
                    sig = new byte[2 * size];
                    System.arraycopy(r, 0, sig, 0, size);
                    System.arraycopy(s, 0, sig, size, size);
                    String hash = switch (curve) {
                        case "nistp256" -> "SHA256";
                        case "nistp384" -> "SHA384";
                        default -> "SHA512";
                    };
                    verifier = Signature.getInstance(hash + "withECDSAinP1363Format");
                }
                default -> {
                    return false;
                }
            }
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(sig);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    private static PublicKey ed25519Key(byte[] raw) throws GeneralSecurityException {
        if (raw.length != 32) {
            throw new IllegalArgumentException("an Ed25519 public key is 32 bytes");
        }
        byte[] der = Arrays.copyOf(ED25519_X509_PREFIX, ED25519_X509_PREFIX.length + 32);
        System.arraycopy(raw, 0, der, ED25519_X509_PREFIX.length, 32);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }

    private static ECParameterSpec curve(String name) throws GeneralSecurityException {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(switch (name) {
            case "nistp256" -> "secp256r1";
            case "nistp384" -> "secp384r1";
            case "nistp521" -> "secp521r1";
            default -> throw new IllegalArgumentException("unknown curve " + name);
        }));
        return params.getParameterSpec(ECParameterSpec.class);
    }

    /** Big-endian, unsigned, left-padded to {@code size} bytes. */
    private static byte[] unsigned(BigInteger v, int size) {
        byte[] b = v.toByteArray();
        int start = b.length > 1 && b[0] == 0 ? 1 : 0;
        int length = b.length - start;
        if (v.signum() < 0 || length > size) {
            throw new IllegalArgumentException("integer out of range");
        }
        byte[] out = new byte[size];
        System.arraycopy(b, start, out, size - length, length);
        return out;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
