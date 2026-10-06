package com.maykelange.ssha.cli;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

/**
 * A minimal ssh-agent (draft-ietf-sshm-ssh-agent) whose private keys live on the phone. It lists the
 * phone's public keys and forwards every sign request to the phone for approval. Adding, removing
 * and locking keys are refused: keys are managed on the phone.
 */
public final class SshAgent {

    private static final int SSH_AGENT_FAILURE = 5;
    private static final int SSH_AGENT_SUCCESS = 6;
    private static final int SSH_AGENTC_REQUEST_IDENTITIES = 11;
    private static final int SSH_AGENT_IDENTITIES_ANSWER = 12;
    private static final int SSH_AGENTC_SIGN_REQUEST = 13;
    private static final int SSH_AGENT_SIGN_RESPONSE = 14;
    private static final int SSH_AGENTC_EXTENSION = 27;
    private static final int MAX_MESSAGE = 256 * 1024;
    /** Most session bindings one connection may record (OpenSSH's ssh-agent allows 16 too). */
    private static final int MAX_BINDINGS = 16;

    public record Identity(byte[] publicKey, String comment) {
    }

    /**
     * OpenSSH's session-bind@openssh.com: which host (key) the connection's logins are for. As sent to
     * the phone, {@code forwarded} means the connection came through a forwarded agent on any hop.
     */
    public record Binding(byte[] hostKey, byte[] sessionId, byte[] signature, boolean forwarded) {
    }

    public interface Phone {
        List<Identity> identities() throws IOException, InterruptedException;

        /** @return an SSH signature blob, or null when the phone refused or didn't answer */
        byte[] sign(byte[] publicKey, byte[] data, int flags, Binding binding) throws IOException, InterruptedException;
    }

    private final Phone phone;

    public SshAgent(Phone phone) {
        this.phone = phone;
    }

    /** Listens on {@code socket} until the process is stopped; {@code ready} runs once it accepts connections. */
    public void serve(Path socket, Runnable ready) throws IOException {
        if (isListening(socket)) {
            throw new IOException("another agent is already listening on " + socket);
        }
        Files.createDirectories(socket.getParent());
        Files.deleteIfExists(socket);
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(socket));
            Files.setPosixFilePermissions(socket, PosixFilePermissions.fromString("rw-------"));
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    Files.deleteIfExists(socket);
                } catch (IOException ignored) {
                    // best effort
                }
            }));
            ready.run();
            while (true) {
                SocketChannel client = server.accept();
                Thread.ofVirtual().name("agent-connection").start(() -> handle(client));
            }
        }
    }

    private static boolean isListening(Path socket) {
        try (SocketChannel ignored = SocketChannel.open(UnixDomainSocketAddress.of(socket))) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** One ssh process per connection; requests are answered in order. */
    private void handle(SocketChannel channel) {
        try (channel;
             DataInputStream in = new DataInputStream(new BufferedInputStream(Channels.newInputStream(channel)));
             DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Channels.newOutputStream(channel)))) {
            // Every ssh on the way binds the connection: through a forwarded agent, first the hop that
            // forwards it (forwarded = true), then the ssh that logs in from there (forwarded = false).
            List<Binding> bindings = new ArrayList<>();
            while (true) {
                int length;
                try {
                    length = in.readInt();
                } catch (EOFException e) {
                    return;
                }
                if (length <= 0 || length > MAX_MESSAGE) {
                    return;
                }
                Reader r = new Reader(in.readNBytes(length));
                byte[] reply;
                switch (r.byte8()) {
                    case SSH_AGENTC_REQUEST_IDENTITIES -> reply = identities();
                    case SSH_AGENTC_SIGN_REQUEST -> reply = sign(r.string(), r.string(), r.uint32(), summary(bindings));
                    case SSH_AGENTC_EXTENSION -> {
                        if (r.utf8().equals("session-bind@openssh.com")) {
                            reply = bind(bindings, new Binding(r.string(), r.string(), r.string(), r.byte8() != 0));
                        } else {
                            reply = new byte[] {SSH_AGENT_FAILURE};
                        }
                    }
                    default -> reply = new byte[] {SSH_AGENT_FAILURE};
                }
                out.writeInt(reply.length);
                out.write(reply);
                out.flush();
            }
        } catch (IOException | RuntimeException e) {
            SshaCli.log("agent connection error: " + e.getMessage());
        }
    }

    /**
     * Records a binding. Like OpenSSH's ssh-agent, a connection bound for authentication (not for
     * forwarding) can't be bound again, so the far end can't re-label it as another host.
     */
    static byte[] bind(List<Binding> bindings, Binding binding) {
        if (bindings.size() >= MAX_BINDINGS || (!bindings.isEmpty() && !bindings.getLast().forwarded())) {
            SshaCli.log("refused a session binding: this connection is already bound");
            return new byte[] {SSH_AGENT_FAILURE};
        }
        bindings.add(binding);
        return new byte[] {SSH_AGENT_SUCCESS};
    }

    /** The binding the phone sees: the last hop's host, flagged as forwarded if any hop forwarded the agent. */
    static Binding summary(List<Binding> bindings) {
        if (bindings.isEmpty()) {
            return null;
        }
        Binding last = bindings.getLast();
        boolean forwarded = bindings.stream().anyMatch(Binding::forwarded);
        return new Binding(last.hostKey(), last.sessionId(), last.signature(), forwarded);
    }

    private byte[] identities() {
        try {
            List<Identity> ids = phone.identities();
            Writer w = new Writer().byte8(SSH_AGENT_IDENTITIES_ANSWER).uint32(ids.size());
            ids.forEach(id -> w.string(id.publicKey()).string(id.comment().getBytes(UTF_8)));
            return w.toByteArray();
        } catch (IOException e) {
            SshaCli.log("couldn't list keys: " + e.getMessage());
            return new byte[] {SSH_AGENT_FAILURE};
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new byte[] {SSH_AGENT_FAILURE};
        }
    }

    private byte[] sign(byte[] publicKey, byte[] data, int flags, Binding binding) {
        try {
            byte[] signature = phone.sign(publicKey, data, flags, binding);
            return signature == null
                    ? new byte[] {SSH_AGENT_FAILURE}
                    : new Writer().byte8(SSH_AGENT_SIGN_RESPONSE).string(signature).toByteArray();
        } catch (IOException e) {
            SshaCli.log("sign request failed: " + e.getMessage());
            return new byte[] {SSH_AGENT_FAILURE};
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new byte[] {SSH_AGENT_FAILURE};
        }
    }

    private static final class Reader {
        private final ByteBuffer buf;

        Reader(byte[] data) {
            this.buf = ByteBuffer.wrap(data);
        }

        int byte8() {
            return buf.get() & 0xff;
        }

        int uint32() {
            return buf.getInt();
        }

        byte[] string() {
            int n = uint32();
            if (n < 0 || n > buf.remaining()) {
                throw new IllegalArgumentException("malformed agent message");
            }
            byte[] b = new byte[n];
            buf.get(b);
            return b;
        }

        String utf8() {
            return new String(string(), UTF_8);
        }
    }

    private static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Writer byte8(int v) {
            out.write(v);
            return this;
        }

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

        byte[] toByteArray() {
            return out.toByteArray();
        }
    }
}
