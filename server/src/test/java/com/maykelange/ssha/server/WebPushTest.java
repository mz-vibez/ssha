package com.maykelange.ssha.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import com.jayway.jsonpath.JsonPath;

class WebPushTest {

    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

    /** RFC 8291 appendix A. */
    @Test
    void encryptsLikeTheRfcExample() throws Exception {
        byte[] asPublic = b64("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8");
        KeyPair as = new KeyPair(WebPush.publicKey(asPublic), privateKey(b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")));
        byte[] uaPublic = b64("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        byte[] auth = b64("BTBZMqHH6r4Tts7J_aSIgg");
        byte[] salt = b64("DGv6ra1nlYgDCS1FRnbzlw");

        byte[] body = WebPush.encrypt("When I grow up, I want to be a watermelon".getBytes(StandardCharsets.UTF_8),
                uaPublic, auth, as, salt);

        assertThat(Base64.getUrlEncoder().withoutPadding().encodeToString(body)).isEqualTo(
                "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN");
        assertThat(new String(decrypt(body, privateKey(b64("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")), uaPublic, auth),
                StandardCharsets.UTF_8)).isEqualTo("When I grow up, I want to be a watermelon");
    }

    @Test
    void vapidHeaderIsASignedJwtForThePushServiceOrigin() throws Exception {
        KeyPair vapid = WebPush.generateKeyPair();
        String header = WebPush.vapidAuthorization(java.net.URI.create("https://fcm.googleapis.com/fcm/send/abc"),
                vapid, "https://ssha.example", Instant.ofEpochSecond(1_800_000_000L));

        assertThat(header).startsWith("vapid t=");
        String jwt = header.substring("vapid t=".length(), header.indexOf(", k="));
        String k = header.substring(header.indexOf(", k=") + 4);
        assertThat(b64(k)).isEqualTo(WebPush.rawPublicKey((ECPublicKey) vapid.getPublic()));

        String[] parts = jwt.split("\\.");
        String claims = new String(b64(parts[1]), StandardCharsets.UTF_8);
        assertThat((String) JsonPath.read(claims, "$.aud")).isEqualTo("https://fcm.googleapis.com");
        assertThat((Integer) JsonPath.read(claims, "$.exp")).isEqualTo(1_800_000_000);
        assertThat((String) JsonPath.read(claims, "$.sub")).isEqualTo("https://ssha.example");
        Signature verify = Signature.getInstance("SHA256withECDSAinP1363Format");
        verify.initVerify(WebPush.publicKey(b64(k)));
        verify.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertThat(verify.verify(b64(parts[2]))).isTrue();
    }

    /** What the browser does with a push message (RFC 8291/8188), to check what the server sends. */
    static byte[] decrypt(byte[] body, PrivateKey uaPrivate, byte[] uaPublic, byte[] auth) throws Exception {
        ByteBuffer in = ByteBuffer.wrap(body);
        byte[] salt = new byte[16];
        in.get(salt);
        in.getInt();
        byte[] asPublic = new byte[in.get()];
        in.get(asPublic);
        byte[] ciphertext = new byte[in.remaining()];
        in.get(ciphertext);

        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
        ecdh.init(uaPrivate);
        ecdh.doPhase(WebPush.publicKey(asPublic), true);
        byte[][] keys = WebPush.contentKeys(WebPush.keyMaterial(ecdh.generateSecret(), auth, uaPublic, asPublic), salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keys[0], "AES"), new GCMParameterSpec(128, keys[1]));
        byte[] plaintext = cipher.doFinal(ciphertext);
        assertThat(plaintext[plaintext.length - 1]).isEqualTo((byte) 2);
        return Arrays.copyOf(plaintext, plaintext.length - 1);
    }

    static PrivateKey privateKey(byte[] scalar) throws Exception {
        var params = ((ECPublicKey) WebPush.generateKeyPair().getPublic()).getParams();
        return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, scalar), params));
    }

    private static byte[] b64(String value) {
        return B64URL.decode(value);
    }
}
