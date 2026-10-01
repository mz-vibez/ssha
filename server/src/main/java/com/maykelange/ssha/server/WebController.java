package com.maykelange.ssha.server;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import jakarta.servlet.http.HttpServletResponse;

/** The phone's home page: SSH sign requests waiting for approval. */
@Controller
public class WebController {

    private final StreamHub streams;

    public WebController(StreamHub streams) {
        this.streams = streams;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    /** Streams rendered sign request cards; every pending one is sent on (re)connect. */
    @GetMapping("/stream")
    public SseEmitter stream(HttpServletResponse response) {
        response.setHeader("X-Accel-Buffering", "no");
        response.setHeader("Cache-Control", "no-cache");
        return streams.open();
    }
}
