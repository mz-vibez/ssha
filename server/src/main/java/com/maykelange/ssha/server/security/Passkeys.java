package com.maykelange.ssha.server.security;

import java.util.Comparator;
import java.util.List;

import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Component;

/** The passkeys registered to each account. */
@Component
public class Passkeys {

    private final PublicKeyCredentialUserEntityRepository userEntities;
    private final UserCredentialRepository credentials;

    public Passkeys(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository credentials) {
        this.userEntities = userEntities;
        this.credentials = credentials;
    }

    /** Oldest first. */
    public List<CredentialRecord> of(String accountId) {
        PublicKeyCredentialUserEntity user = userEntities.findByUsername(accountId);
        if (user == null) {
            return List.of();
        }
        return credentials.findByUserId(user.getId()).stream()
                .sorted(Comparator.comparing(CredentialRecord::getCreated))
                .toList();
    }

    public boolean owns(String accountId, Bytes credentialId) {
        return of(accountId).stream().anyMatch(c -> c.getCredentialId().equals(credentialId));
    }

    public void delete(Bytes credentialId) {
        credentials.delete(credentialId);
    }
}
