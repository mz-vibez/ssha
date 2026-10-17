package com.maykelange.ssha.server.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import com.jayway.jsonpath.JsonPath;

import com.maykelange.ssha.server.account.Accounts;
import com.maykelange.ssha.server.activity.ActivityLog;

@SpringBootTest(properties = {
        "ssha.rp-id=localhost",
        "ssha.vapid-key-file=",
        "ssha.allowed-origins=http://localhost",
        "spring.datasource.url=jdbc:h2:mem:ssha-test;DB_CLOSE_DELAY=-1",
})
@AutoConfigureMockMvc
class SecurityTest {


    @Autowired
    MockMvc mvc;
    @Autowired
    Accounts accounts;
    @Autowired
    RateLimits limits;
    @Autowired
    ActivityLog activity;

    String account;
    String bearer;

    @BeforeEach
    void createAccount() {
        limits.clear();
        Accounts.Enrolled enrolled = accounts.create("laptop");
        account = enrolled.accountId();
        bearer = "Bearer " + enrolled.token();
    }

    @Test
    void signupAndSignOutAreInTheConnectionLog() throws Exception {
        MvcResult signup = mvc.perform(post("/signup").with(csrf()).header("User-Agent", "TestPhone/1.0"))
                .andExpect(status().isFound()).andReturn();
        MockHttpSession session = (MockHttpSession) signup.getRequest().getSession();
        String id = jdbcAccountOf(session);
        mvc.perform(post("/logout").session(session).with(csrf())).andExpect(status().isFound());
        assertThat(activity.recent(id, ActivityLog.WEB, 10)).extracting(ActivityLog.Entry::event)
                .containsExactly("signed out", "created the account");
        assertThat(activity.recent(id, ActivityLog.WEB, 10).get(1).source()).contains("TestPhone/1.0");
        mvc.perform(get("/activity").with(user(id))).andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("signed out")));
    }

    @Autowired
    org.springframework.security.authentication.ott.OneTimeTokenService oneTimeTokens;

    @Test
    void linkSignInIsInTheConnectionLog() throws Exception {
        var token = oneTimeTokens.generate(new org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest(account));
        mvc.perform(post("/login/ott").with(csrf()).param("token", token.getTokenValue()))
                .andExpect(status().isFound());
        assertThat(activity.recent(account, ActivityLog.WEB, 10)).extracting(ActivityLog.Entry::event)
                .containsExactly("signed in with a link");
    }

    @Autowired
    BrowserSessions browsers;

    @Test
    void signedInBrowsersAreListedAndCanBeSignedOutOneByOne() throws Exception {
        MockHttpSession phone = new MockHttpSession(null, "phone-session-cookie-value");
        MockHttpSession desktop = new MockHttpSession();
        mvc.perform(get("/activity").session(phone).with(user(account)).header("User-Agent", "Phone/1"))
                .andExpect(status().isOk());
        mvc.perform(get("/activity").session(desktop).with(user(account)).header("User-Agent", "Desktop/2"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Phone/1")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("(this browser)")))
                // the session id is the cookie: it must never be on the page
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString(phone.getId()))));
        var list = browsers.of(account, desktop.getId());
        assertThat(list).hasSize(2);
        String phoneHandle = list.stream().filter(b -> b.label().contains("Phone/1")).findFirst().orElseThrow().handle();

        // another account can't sign it out
        Accounts.Enrolled other = accounts.create("other");
        mvc.perform(post("/browsers/signout").session(desktop).with(user(other.accountId())).with(csrf())
                .param("handle", phoneHandle)).andExpect(status().isNotFound());
        assertThat(phone.isInvalid()).isFalse();

        mvc.perform(post("/browsers/signout").session(desktop).with(user(account)).with(csrf())
                .param("handle", phoneHandle)).andExpect(status().isFound());
        assertThat(phone.isInvalid()).isTrue();
        assertThat(desktop.isInvalid()).isFalse();
        assertThat(browsers.of(account, desktop.getId())).hasSize(1);
        assertThat(activity.recent(account, ActivityLog.WEB, 5).get(0).event()).isEqualTo("signed a browser out");
    }

    private String jdbcAccountOf(MockHttpSession session) {
        var context = (org.springframework.security.core.context.SecurityContext) session
                .getAttribute("SPRING_SECURITY_CONTEXT");
        return context.getAuthentication().getName();
    }

    // --- web: anonymous access ---------------------------------------------------------------

    @Test
    void pageRedirectsToLoginWhenAnonymous() throws Exception {
        mvc.perform(get("/")).andExpect(status().isFound()).andExpect(redirectedUrl("/login"));
    }

    @Test
    void backgroundRequestsGet401InsteadOfRedirect() throws Exception {
        mvc.perform(get("/").header("HX-Request", "true")).andExpect(status().isUnauthorized());
        mvc.perform(get("/stream")).andExpect(status().isUnauthorized());
        mvc.perform(post("/sign/x/deny").with(csrf()).header("HX-Request", "true"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginPageIsPublic() throws Exception {
        mvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Sign in with passkey")));
    }

    @Test
    void passkeySignInOptionsArePublic() throws Exception {
        mvc.perform(post("/webauthn/authenticate/options").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challenge").isString())
                .andExpect(jsonPath("$.rpId").value("localhost"));
    }

    @Test
    void passkeyRegistrationNeedsSignIn() throws Exception {
        // Spring's options filter refuses anonymous callers itself.
        mvc.perform(post("/webauthn/register/options").with(csrf())).andExpect(status().isBadRequest());
        mvc.perform(post("/webauthn/register/options").with(csrf()).with(user(account)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rp.id").value("localhost"))
                .andExpect(jsonPath("$.authenticatorSelection.residentKey").value("required"));
    }

    // --- web: signed in ----------------------------------------------------------------------

    @Test
    void signedInUserSeesApprovalsPage() throws Exception {
        mvc.perform(get("/").with(user(account)))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("No sign requests waiting")));
        mvc.perform(get("/stream").with(user(account))).andExpect(request().asyncStarted());
    }

    @Test
    void pageFilesAreLinkedByContentHashAndCachedForAYear() throws Exception {
        // Public files of the login page: found by their hashed name without a session.
        String login = mvc.perform(get("/login")).andReturn().getResponse().getContentAsString();
        var m = java.util.regex.Pattern.compile("href=\"(/app-[0-9a-f]{32}\\.css)\"").matcher(login);
        assertThat(m.find()).isTrue();
        mvc.perform(get(m.group(1))).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("max-age=31536000")));
        // The unhashed name still works (service worker, bookmarks).
        mvc.perform(get("/app.css")).andExpect(status().isOk());
    }

    @Test
    void refusedFilesAreNotRememberedAsTheSignInTarget() throws Exception {
        var session = mvc.perform(get("/app.js")).andExpect(status().is3xxRedirection())
                .andReturn().getRequest().getSession(false);
        assertThat(session == null || session.getAttribute("SPRING_SECURITY_SAVED_REQUEST") == null).isTrue();
    }

    @Test
    void pagesOnlyRunTheServersOwnScripts() throws Exception {
        mvc.perform(get("/").with(user(account)))
                .andExpect(header().string("Content-Security-Policy", SecurityConfig.CONTENT_SECURITY_POLICY))
                .andExpect(content().string(org.hamcrest.Matchers.matchesPattern("(?s).*src=\"/app-[0-9a-f]{32}\\.js\".*")))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("unpkg"))));
        mvc.perform(get("/login")).andExpect(header().string("Content-Security-Policy",
                org.hamcrest.Matchers.containsString("script-src 'self';")));
        mvc.perform(get("/confirm.js")).andExpect(status().isOk());
    }

    @Test
    void postingRequiresCsrfToken() throws Exception {
        mvc.perform(post("/sign/x/deny").with(user(account)).header("HX-Request", "true"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/sign/x/deny").with(user(account)).with(csrf()).header("HX-Request", "true"))
                .andExpect(status().isNotFound());
    }

    @Test
    void chatIsGone() throws Exception {
        mvc.perform(post("/messages").with(user(account)).with(csrf()).param("text", "hi"))
                .andExpect(status().isNotFound());
        mvc.perform(post("/api/messages").header("Authorization", bearer).contentType(MediaType.TEXT_PLAIN)
                        .content("hi"))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/stream").header("Authorization", bearer)).andExpect(status().isNotFound());
    }

    @Test
    void passkeysPageListsNothingInitially() throws Exception {
        mvc.perform(get("/passkeys").with(user(account)))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("no passkeys yet")));
    }

    @Test
    void cannotDeleteUnknownPasskey() throws Exception {
        mvc.perform(post("/passkeys/AAAA/delete").with(user(account)).with(csrf()))
                .andExpect(status().isNotFound());
    }

    // --- API ---------------------------------------------------------------------------------

    @Test
    void apiRejectsMissingOrWrongToken() throws Exception {
        mvc.perform(get("/api/keys")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/keys").header("Authorization", "Bearer nope")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/sign").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/enroll")).andExpect(status().isUnauthorized());
    }

    @Test
    void apiAcceptsToken() throws Exception {
        mvc.perform(get("/api/keys").header("Authorization", bearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    // --- enrolment via one-time link ---------------------------------------------------------

    @Test
    void enrollLinkSignsInOnceAndLandsOnPasskeys() throws Exception {
        MvcResult enroll = mvc.perform(post("/api/enroll").header("Authorization", bearer))
                .andExpect(request().asyncStarted())
                .andReturn();
        String body = mvc.perform(asyncDispatch(enroll))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String url = JsonPath.read(body, "$.url");
        assertThat(url).startsWith("http://localhost/login/ott?token=");
        String token = UriComponentsBuilder.fromUriString(url).build().getQueryParams().getFirst("token");

        // Opening the link only shows a confirmation page; it doesn't consume the token.
        mvc.perform(get("/login/ott").param("token", token))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString(token)));

        MockHttpSession session = (MockHttpSession) mvc.perform(post("/login/ott").with(csrf()).param("token", token))
                .andExpect(redirectedUrl("/passkeys"))
                .andReturn().getRequest().getSession();
        mvc.perform(get("/").session(session)).andExpect(status().isOk());
        // A browser session is no substitute for the API token.
        mvc.perform(get("/api/keys").session(session)).andExpect(status().isUnauthorized());

        // Single use.
        mvc.perform(post("/login/ott").with(csrf()).param("token", token))
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void publicTokenGenerationEndpointDeliversNothing() throws Exception {
        mvc.perform(post("/ott/generate").with(csrf()).param("username", account))
                .andExpect(status().isNotFound());
    }

    // --- sessions survive a restart (server.servlet.session.persistent) -------------------------

    @Test
    void signupSessionSurvivesRestart() throws Exception {
        MockHttpSession session = (MockHttpSession) mvc.perform(post("/signup").with(csrf()))
                .andExpect(status().isFound()).andReturn().getRequest().getSession();
        mvc.perform(get("/").session(restarted(session))).andExpect(status().isOk());
    }

    @Test
    void linkSessionSurvivesRestart() throws Exception {
        var token = oneTimeTokens.generate(new org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest(account));
        MockHttpSession session = (MockHttpSession) mvc.perform(post("/login/ott").with(csrf()).param("token", token.getTokenValue()))
                .andExpect(status().isFound()).andReturn().getRequest().getSession();
        mvc.perform(get("/").session(restarted(session))).andExpect(status().isOk());
    }

    @Test
    void passkeySessionSurvivesRestart() throws Exception {
        var user = ImmutablePublicKeyCredentialUserEntity.builder()
                .name(account).id(Bytes.random()).displayName(account).build();
        var auth = new WebAuthnAuthentication(user, AuthorityUtils.createAuthorityList("ROLE_USER"));
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, new SecurityContextImpl(auth));
        mvc.perform(get("/").session(restarted(session))).andExpect(status().isOk());
    }

    /**
     * The session as Tomcat brings it back after a restart: every attribute written with Java
     * serialization and read back. Fails if any of them, or anything they hold, isn't serializable.
     */
    private static MockHttpSession restarted(MockHttpSession session) throws Exception {
        MockHttpSession copy = new MockHttpSession(null, session.getId());
        List<String> names = Collections.list(session.getAttributeNames());
        assertThat(names).isNotEmpty();
        for (String name : names) {
            var bytes = new ByteArrayOutputStream();
            try (var out = new ObjectOutputStream(bytes)) {
                out.writeObject(session.getAttribute(name));
            }
            try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
                copy.setAttribute(name, in.readObject());
            }
        }
        return copy;
    }
}
