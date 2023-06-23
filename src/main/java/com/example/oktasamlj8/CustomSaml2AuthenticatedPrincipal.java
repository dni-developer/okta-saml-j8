package com.example.oktasamlj8;

import lombok.Data;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * A custom SAML Principle that can have custom user attributes.
 */
@Data
public class CustomSaml2AuthenticatedPrincipal implements Saml2AuthenticatedPrincipal, Serializable {

    private final String name;

    private final Map<String, List<Object>> attributes;

    private final List<String> sessionIndexes;

    private String registrationId;

    /* A custom field that is not available in DefaultSaml2AuthenticatedPrincipal */
    private double customField;

    public CustomSaml2AuthenticatedPrincipal(String name, Map<String, List<Object>> attributes, List<String> sessionIndexes) {
        this.name = name;
        this.attributes = attributes;
        this.sessionIndexes = sessionIndexes;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Map<String, List<Object>> getAttributes() {
        return attributes;
    }

    @Override
    public List<String> getSessionIndexes() {
        return sessionIndexes;
    }


    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }



}
