package com.maykelange.ssha.server;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/** The account's history: how sign requests ended, and when its browsers signed in. */
@Controller
public class ActivityController {

    private static final int SHOWN = 200;

    private final ActivityLog activity;

    public ActivityController(ActivityLog activity) {
        this.activity = activity;
    }

    @GetMapping("/activity")
    public String activity(Principal principal, Model model) {
        model.addAttribute("signs", activity.recent(principal.getName(), ActivityLog.SIGN, SHOWN));
        model.addAttribute("webs", activity.recent(principal.getName(), ActivityLog.WEB, SHOWN));
        return "activity";
    }
}
