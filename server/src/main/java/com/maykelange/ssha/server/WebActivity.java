package com.maykelange.ssha.server;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

/** Writes the phone's browser sign-ins to the account's connection log. */
@Component
public class WebActivity {

    private final ActivityLog activity;

    public WebActivity(ActivityLog activity) {
        this.activity = activity;
    }

    @EventListener
    void signedIn(AuthenticationSuccessEvent event) {
        Object source = event.getAuthentication();
        String how = source instanceof WebAuthnAuthentication ? "signed in with a passkey"
                : source instanceof OneTimeTokenAuthentication ? "signed in with a link"
                : null;
        if (how != null) {
            activity.web(event.getAuthentication().getName(), how, null, currentRequest());
        }
    }

    static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes a ? a.getRequest() : null;
    }
}
