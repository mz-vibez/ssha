package com.maykelange.ssha.server;

import java.security.Principal;
import java.util.Base64;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import jakarta.servlet.http.HttpServletResponse;

/** The phone's home page: SSH sign requests waiting for approval. */
@Controller
public class WebController {

    private final StreamHub streams;
    private final PushService push;

    public WebController(StreamHub streams, PushService push) {
        this.streams = streams;
        this.push = push;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("vapidKey", push.publicKey());
        return "index";
    }

    /** A browser's push subscription, as {@code PushSubscription.toJSON()} gives it. */
    public record Subscription(String endpoint, Keys keys) {
        /** @param p256dh the browser's P-256 key, base64url; @param auth its auth secret, base64url */
        public record Keys(String p256dh, String auth) {
        }
    }

    @PostMapping(value = "/push/subscribe", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void subscribe(@RequestBody Subscription subscription, Principal principal) {
        try {
            Base64.Decoder b64 = Base64.getUrlDecoder();
            if (subscription.keys() == null) {
                throw new IllegalArgumentException("no keys");
            }
            push.subscribe(principal.getName(), subscription.endpoint(),
                    b64.decode(subscription.keys().p256dh()), b64.decode(subscription.keys().auth()));
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid subscription");
        } catch (IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, e.getMessage());
        }
    }

    @PostMapping(value = "/push/unsubscribe", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void unsubscribe(@RequestBody Subscription subscription, Principal principal) {
        if (subscription.endpoint() != null) {
            push.unsubscribe(principal.getName(), subscription.endpoint());
        }
    }

    /** Streams rendered sign request cards; every pending one is sent on (re)connect. */
    @GetMapping("/stream")
    public SseEmitter stream(Principal principal, HttpServletResponse response) {
        response.setHeader("X-Accel-Buffering", "no");
        response.setHeader("Cache-Control", "no-cache");
        return streams.open(principal.getName());
    }
}
