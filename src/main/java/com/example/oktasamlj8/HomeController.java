package com.example.oktasamlj8;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

    @RequestMapping("/")
    public String home(@AuthenticationPrincipal CustomSaml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("email", principal.getFirstAttribute("email"));
        model.addAttribute("registrationId", principal.getRegistrationId());
        model.addAttribute("attributes", principal.getAttributes());
        model.addAttribute("customField", principal.getCustomField());
        return "home";
    }

}
