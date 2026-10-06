package com.maykelange.ssha.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

class SshAgentTest {

    private static final byte SUCCESS = 6;
    private static final byte FAILURE = 5;

    private static SshAgent.Binding binding(int host, boolean forwarded) {
        return new SshAgent.Binding(new byte[] {(byte) host}, new byte[] {(byte) host}, new byte[] {0}, forwarded);
    }

    @Test
    void directLoginIsNotForwarded() {
        List<SshAgent.Binding> bindings = new ArrayList<>();
        assertThat(SshAgent.summary(bindings)).isNull();
        assertThat(SshAgent.bind(bindings, binding(1, false))).containsExactly(SUCCESS);
        assertThat(SshAgent.summary(bindings).forwarded()).isFalse();
        assertThat(SshAgent.summary(bindings).hostKey()).containsExactly(1);
    }

    @Test
    void loginThroughAForwardedAgentStaysMarkedForwarded() {
        // ssh -A to host 1 forwards the agent; ssh on host 1 then logs in to host 2 through it.
        List<SshAgent.Binding> bindings = new ArrayList<>();
        assertThat(SshAgent.bind(bindings, binding(1, true))).containsExactly(SUCCESS);
        assertThat(SshAgent.bind(bindings, binding(2, false))).containsExactly(SUCCESS);
        SshAgent.Binding summary = SshAgent.summary(bindings);
        assertThat(summary.hostKey()).containsExactly(2);
        assertThat(summary.forwarded()).isTrue();
    }

    @Test
    void connectionBoundForAuthenticationCannotBeReboundToAnotherHost() {
        List<SshAgent.Binding> bindings = new ArrayList<>();
        SshAgent.bind(bindings, binding(1, false));
        assertThat(SshAgent.bind(bindings, binding(2, false))).containsExactly(FAILURE);
        assertThat(SshAgent.summary(bindings).hostKey()).containsExactly(1);
    }
}
