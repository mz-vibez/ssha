package com.maykelange.ssha.cli;

import java.io.IOException;
import java.io.StringWriter;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.json.JsonFactory;

/**
 * The CLI's JSON, read and written with Jackson's streaming API only. Without data binding there is
 * no reflection, so the GraalVM native image needs no reflection configuration. Unknown fields are
 * skipped, so a newer server stays compatible. Binary values are standard base64, as the server's
 * Jackson writes {@code byte[]}.
 */
final class Json {

    private static final JsonFactory FACTORY = new JsonFactory();

    private Json() {
    }

    static SshaCli.EnrollLink enrollLink(String json) throws IOException {
        return read(json, p -> {
            Map<String, String> f = object(p);
            return new SshaCli.EnrollLink(required(f, "url"), Instant.parse(required(f, "expiresAt")));
        });
    }

    static SshaCli.Enrolled enrolled(String json) throws IOException {
        return read(json, p -> {
            Map<String, String> f = object(p);
            return new SshaCli.Enrolled(required(f, "account"), required(f, "token"));
        });
    }

    static String account(String json) throws IOException {
        return read(json, p -> required(object(p), "account"));
    }

    /** A flat object of string fields, e.g. {@code {"client": "laptop"}}. */
    static String strings(Map<String, String> fields) {
        StringWriter out = new StringWriter();
        try (JsonGenerator g = FACTORY.createGenerator(ObjectWriteContext.empty(), out)) {
            g.writeStartObject();
            for (Map.Entry<String, String> field : fields.entrySet()) {
                g.writeName(field.getKey()).writeString(field.getValue());
            }
            g.writeEndObject();
        }
        return out.toString();
    }

    static List<SshaCli.AgentKey> agentKeys(String json) throws IOException {
        return read(json, p -> {
            expect(p, JsonToken.START_ARRAY);
            List<SshaCli.AgentKey> keys = new ArrayList<>();
            while (p.nextToken() != JsonToken.END_ARRAY) {
                Map<String, String> f = object(p);
                keys.add(new SshaCli.AgentKey(required(f, "id"), required(f, "label"),
                        binary(f, "publicKey"), required(f, "authorizedKey")));
            }
            return keys;
        });
    }

    static SshaCli.SignResponse signResponse(String json) throws IOException {
        return read(json, p -> new SshaCli.SignResponse(binary(object(p), "signature")));
    }

    static String signRequest(SshaCli.SignRequest request) {
        StringWriter out = new StringWriter();
        try (JsonGenerator g = FACTORY.createGenerator(ObjectWriteContext.empty(), out)) {
            g.writeStartObject();
            g.writeName("publicKey").writeBinary(request.publicKey());
            g.writeName("data").writeBinary(request.data());
            g.writeName("flags").writeNumber(request.flags());
            g.writeName("client").writeString(request.client());
            g.writeName("binding");
            SshAgent.Binding b = request.binding();
            if (b == null) {
                g.writeNull();
            } else {
                g.writeStartObject();
                g.writeName("hostKey").writeBinary(b.hostKey());
                g.writeName("sessionId").writeBinary(b.sessionId());
                g.writeName("signature").writeBinary(b.signature());
                g.writeName("forwarded").writeBoolean(b.forwarded());
                g.writeEndObject();
            }
            g.writeEndObject();
        }
        return out.toString();
    }

    // --- reading -------------------------------------------------------------------------------

    private interface Reader<T> {
        T read(JsonParser parser) throws IOException;
    }

    /** Parses one JSON document; malformed or unexpected input becomes an IOException. */
    private static <T> T read(String json, Reader<T> reader) throws IOException {
        try (JsonParser p = FACTORY.createParser(ObjectReadContext.empty(), json)) {
            p.nextToken();
            return reader.read(p);
        } catch (JacksonException | DateTimeParseException | IllegalArgumentException e) {
            throw new IOException("unexpected response from the server: " + e.getMessage(), e);
        }
    }

    /** Reads the object at the current token: scalar fields as text, nested values skipped. */
    private static Map<String, String> object(JsonParser p) throws IOException {
        expect(p, JsonToken.START_OBJECT);
        Map<String, String> fields = new HashMap<>();
        while (p.nextToken() == JsonToken.PROPERTY_NAME) {
            String name = p.currentName();
            JsonToken value = p.nextToken();
            if (value.isScalarValue()) {
                if (value != JsonToken.VALUE_NULL) {
                    fields.put(name, p.getString());
                }
            } else {
                p.skipChildren();
            }
        }
        return fields;
    }

    private static void expect(JsonParser p, JsonToken token) throws IOException {
        if (p.currentToken() != token) {
            throw new IOException("unexpected response from the server: expected " + token + ", got " + p.currentToken());
        }
    }

    private static String required(Map<String, String> fields, String name) throws IOException {
        String value = fields.get(name);
        if (value == null) {
            throw new IOException("unexpected response from the server: no \"" + name + "\"");
        }
        return value;
    }

    private static byte[] binary(Map<String, String> fields, String name) throws IOException {
        return Base64.getDecoder().decode(required(fields, name));
    }
}
