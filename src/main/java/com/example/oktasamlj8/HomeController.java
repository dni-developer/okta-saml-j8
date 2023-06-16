package com.example.oktasamlj8;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

    @RequestMapping("/")
    public String home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("email", principal.getFirstAttribute("email"));
        model.addAttribute("registrationId", principal.getRelyingPartyRegistrationId());
        model.addAttribute("attributes", principal.getAttributes());
        return "home";
    }

}
