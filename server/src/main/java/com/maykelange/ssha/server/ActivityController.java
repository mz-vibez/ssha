package com.maykelange.ssha.server;

import java.security.Principal;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/** The account's history: how sign requests ended, and when its browsers signed in. */
@Controller
public class ActivityController {

    private static final int SHOWN = 200;

    private final ActivityLog activity;
    private final BrowserSessions browsers;

    public ActivityController(ActivityLog activity, BrowserSessions browsers) {
        this.activity = activity;
        this.browsers = browsers;
    }

    @GetMapping("/activity")
    public String activity(Principal principal, Model model, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        model.addAttribute("browsers", browsers.of(principal.getName(), session == null ? null : session.getId()));
        model.addAttribute("signs", activity.recent(principal.getName(), ActivityLog.SIGN, SHOWN));
        model.addAttribute("webs", activity.recent(principal.getName(), ActivityLog.WEB, SHOWN));
        return "activity";
    }

    /** Signs another (or this) browser out of the account. */
    @PostMapping("/browsers/signout")
    public String signOut(@RequestParam String handle, Principal principal, HttpServletRequest request) {
        String label = browsers.revoke(principal.getName(), handle);
        if (label == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        activity.web(principal.getName(), "signed a browser out", label, request);
        return "redirect:/activity";
    }
}
