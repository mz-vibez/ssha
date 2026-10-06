package com.maykelange.ssha.server;

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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import com.jayway.jsonpath.JsonPath;

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

    String account;
    String bearer;

    @BeforeEach
    void createAccount() {
        limits.clear();
        Accounts.Enrolled enrolled = accounts.create("laptop");
        account = enrolled.accountId();
        bearer = "Bearer " + enrolled.token();
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
    void pagesOnlyRunTheServersOwnScripts() throws Exception {
        mvc.perform(get("/").with(user(account)))
                .andExpect(header().string("Content-Security-Policy", SecurityConfig.CONTENT_SECURITY_POLICY))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("/webjars/htmx.org/2.0.4/dist/htmx.min.js")))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("unpkg"))));
        mvc.perform(get("/login")).andExpect(header().string("Content-Security-Policy",
                org.hamcrest.Matchers.containsString("script-src 'self';")));
        mvc.perform(get("/webjars/htmx.org/2.0.4/dist/htmx.min.js")).andExpect(status().isOk());
        mvc.perform(get("/webjars/htmx-ext-sse/2.2.2/sse.js")).andExpect(status().isOk());
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
}
