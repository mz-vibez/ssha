package com.maykelange.ssha.server;

import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The cryptography of Web Push, with the JDK only: message encryption (RFC 8291, {@code aes128gcm}
 * from RFC 8188) and the VAPID authorization header (RFC 8292). All keys are P-256.
 */
final class WebPush {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    /** Record size advertised in the header; a message is always a single record. */
    private static final int RECORD_SIZE = 4096;

    private WebPush() {
    }

    static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A public key as an uncompressed point (0x04 || X || Y), the form browsers and VAPID use. */
    static byte[] rawPublicKey(ECPublicKey key) {
        byte[] raw = new byte[65];
        raw[0] = 4;
        copyUnsigned(key.getW().getAffineX(), raw, 1);
        copyUnsigned(key.getW().getAffineY(), raw, 33);
        return raw;
    }

    static ECPublicKey publicKey(byte[] raw) {
        if (raw.length != 65 || raw[0] != 4) {
            throw new IllegalArgumentException("not an uncompressed P-256 point");
        }
        ECPoint point = new ECPoint(new BigInteger(1, Arrays.copyOfRange(raw, 1, 33)),
                new BigInteger(1, Arrays.copyOfRange(raw, 33, 65)));
        try {
            ECParameterSpec params = ((ECPublicKey) generateKeyPair().getPublic()).getParams();
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, params));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("not a P-256 public key", e);
        }
    }

    /**
     * Encrypts a push message for one subscription.
     *
     * @param uaPublic the subscription's {@code p256dh} key, uncompressed
     * @param auth     the subscription's 16-byte {@code auth} secret
     * @return the request body, to send with {@code Content-Encoding: aes128gcm}
     */
    static byte[] encrypt(byte[] payload, byte[] uaPublic, byte[] auth) {
        KeyPair ephemeral = generateKeyPair();
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return encrypt(payload, uaPublic, auth, ephemeral, salt);
    }

    static byte[] encrypt(byte[] payload, byte[] uaPublic, byte[] auth, KeyPair ephemeral, byte[] salt) {
        try {
            byte[] asPublic = rawPublicKey((ECPublicKey) ephemeral.getPublic());
            KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
            ecdh.init(ephemeral.getPrivate());
            ecdh.doPhase(publicKey(uaPublic), true);
            byte[] ikm = keyMaterial(ecdh.generateSecret(), auth, uaPublic, asPublic);
            byte[][] keys = contentKeys(ikm, salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keys[0], "AES"), new GCMParameterSpec(128, keys[1]));
            // 0x02 marks the last (here: only) record; no padding.
            byte[] plaintext = Arrays.copyOf(payload, payload.length + 1);
            plaintext[payload.length] = 2;
            byte[] ciphertext = cipher.doFinal(plaintext);

            return ByteBuffer.allocate(16 + 4 + 1 + asPublic.length + ciphertext.length)
                    .put(salt).putInt(RECORD_SIZE).put((byte) asPublic.length).put(asPublic).put(ciphertext)
                    .array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RFC 8291 section 3.3: mixes the ECDH secret with the subscription's auth secret. */
    static byte[] keyMaterial(byte[] ecdhSecret, byte[] auth, byte[] uaPublic, byte[] asPublic) {
        byte[] info = concat("WebPush: info\0".getBytes(StandardCharsets.US_ASCII), uaPublic, asPublic, new byte[] {1});
        return hmac(hmac(auth, ecdhSecret), info);
    }

    /** RFC 8188 section 2.2/2.3: the content encryption key and nonce. */
    static byte[][] contentKeys(byte[] ikm, byte[] salt) {
        byte[] prk = hmac(salt, ikm);
        byte[] cek = hmac(prk, "Content-Encoding: aes128gcm\0\1".getBytes(StandardCharsets.US_ASCII));
        byte[] nonce = hmac(prk, "Content-Encoding: nonce\0\1".getBytes(StandardCharsets.US_ASCII));
        return new byte[][] {Arrays.copyOf(cek, 16), Arrays.copyOf(nonce, 12)};
    }

    /**
     * The {@code Authorization} header for a push to {@code endpoint}: a JWT for the push service's
     * origin, signed with the server's VAPID key.
     *
     * @param subject a {@code mailto:} or {@code https:} contact for the push service
     */
    static String vapidAuthorization(URI endpoint, KeyPair vapid, String subject, Instant expires) {
        String audience = endpoint.getScheme() + "://" + endpoint.getRawAuthority();
        String header = B64URL.encodeToString("{\"typ\":\"JWT\",\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8));
        String claims = B64URL.encodeToString("{\"aud\":%s,\"exp\":%d,\"sub\":%s}"
                .formatted(jsonString(audience), expires.getEpochSecond(), jsonString(subject))
                .getBytes(StandardCharsets.UTF_8));
        String signingInput = header + "." + claims;
        String jwt = signingInput + "." + B64URL.encodeToString(sign(vapid.getPrivate(), signingInput));
        return "vapid t=" + jwt + ", k=" + B64URL.encodeToString(rawPublicKey((ECPublicKey) vapid.getPublic()));
    }

    private static byte[] sign(PrivateKey key, String data) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
            signature.initSign(key);
            signature.update(data.getBytes(StandardCharsets.US_ASCII));
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Only for values we control (an origin, a configured subject): escapes quotes and backslashes. */
    private static String jsonString(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(byte[]... parts) {
        ByteBuffer out = ByteBuffer.allocate(Arrays.stream(parts).mapToInt(p -> p.length).sum());
        for (byte[] p : parts) {
            out.put(p);
        }
        return out.array();
    }

    private static void copyUnsigned(BigInteger value, byte[] target, int offset) {
        byte[] bytes = value.toByteArray();
        int start = Math.max(0, bytes.length - 32);
        int length = bytes.length - start;
        System.arraycopy(bytes, start, target, offset + 32 - length, length);
    }
}
