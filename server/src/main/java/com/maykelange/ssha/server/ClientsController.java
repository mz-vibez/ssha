package com.maykelange.ssha.server;

import java.security.Principal;
import java.util.NoSuchElementException;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/** The computers allowed to use this account: answering join requests, listing and revoking them. */
@Controller
public class ClientsController {

    private final Accounts accounts;
    private final JoinService joins;
    private final DownloadsController downloads;

    public ClientsController(Accounts accounts, JoinService joins, DownloadsController downloads) {
        this.accounts = accounts;
        this.joins = joins;
        this.downloads = downloads;
    }

    @GetMapping("/clients")
    public String clients(Principal principal, Model model) {
        model.addAttribute("account", principal.getName());
        model.addAttribute("download", downloads.download().orElse(null));
        model.addAttribute("server", ServletUriComponentsBuilder.fromCurrentContextPath().toUriString());
        model.addAttribute("clients", accounts.clients(principal.getName()));
        return "clients";
    }

    @PostMapping("/clients/{id}/delete")
    public String delete(@PathVariable String id, Principal principal) {
        if (!accounts.deleteClient(principal.getName(), id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return "redirect:/clients";
    }

    @PostMapping("/join/{id}/accept")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void accept(@PathVariable String id, Principal principal) {
        try {
            joins.accept(principal.getName(), id);
        } catch (NoSuchElementException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
    }

    @PostMapping("/join/{id}/deny")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deny(@PathVariable String id, Principal principal) {
        try {
            joins.deny(principal.getName(), id);
        } catch (NoSuchElementException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
    }
}
