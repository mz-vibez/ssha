package com.maykelange.ssha.server.security;

import java.security.Principal;

import com.maykelange.ssha.server.account.Accounts;

/**
 * The computer a CLI request was authenticated as. Its name is the account id, like a signed-in
 * phone's, so both sides see the same account; {@link #client()} says which computer it is, as stored
 * when it joined (never what the request claims).
 */
public record ClientPrincipal(Accounts.Client client) implements Principal {

    @Override
    public String getName() {
        return client.accountId();
    }
}
