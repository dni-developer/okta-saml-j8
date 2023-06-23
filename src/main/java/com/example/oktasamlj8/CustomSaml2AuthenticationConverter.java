package com.example.oktasamlj8;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.*;
import org.opensaml.saml.saml2.core.*;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class CustomSaml2AuthenticationConverter {

    /**
     * See OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter
     */
    public Converter<OpenSamlAuthenticationProvider.ResponseToken, Saml2Authentication> createDefaultResponseAuthenticationConverter() {
        return (responseToken) -> {
            Response response = responseToken.getResponse();
            Saml2AuthenticationToken token = responseToken.getToken();
            Assertion assertion = CollectionUtils.firstElement(response.getAssertions());
            String username = assertion.getSubject().getNameID().getValue();
            Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
            List<String> sessionIndexes = getSessionIndexes(assertion);
            CustomSaml2AuthenticatedPrincipal principal = new CustomSaml2AuthenticatedPrincipal(username, attributes, sessionIndexes);
            String registrationId = responseToken.getToken().getRelyingPartyRegistration().getRegistrationId();
            principal.setRegistrationId(registrationId);

            /* populate a custom field which is not available in default OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter */
            principal.setCustomField(Math.random());
            return new Saml2Authentication(principal, token.getSaml2Response(),
                    AuthorityUtils.createAuthorityList("ROLE_USER"));
        };
    }

    private static List<String> getSessionIndexes(Assertion assertion) {
        List<String> sessionIndexes = new ArrayList<>();
        for (AuthnStatement statement : assertion.getAuthnStatements()) {
            sessionIndexes.add(statement.getSessionIndex());
        }
        return sessionIndexes;
    }

    private static Map<String, List<Object>> getAssertionAttributes(Assertion assertion) {
        MultiValueMap<String, Object> attributeMap = new LinkedMultiValueMap<>();
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                List<Object> attributeValues = new ArrayList<>();
                for (XMLObject xmlObject : attribute.getAttributeValues()) {
                    Object attributeValue = getXmlObjectValue(xmlObject);
                    if (attributeValue != null) {
                        attributeValues.add(attributeValue);
                    }
                }
                attributeMap.addAll(attribute.getName(), attributeValues);
            }
        }
        return new LinkedHashMap<>(attributeMap); // gh-11785
    }

    private static Object getXmlObjectValue(XMLObject xmlObject) {
        if (xmlObject instanceof XSAny) {
            return ((XSAny) xmlObject).getTextContent();
        }
        if (xmlObject instanceof XSString) {
            return ((XSString) xmlObject).getValue();
        }
        if (xmlObject instanceof XSInteger) {
            return ((XSInteger) xmlObject).getValue();
        }
//        if (xmlObject instanceof XSURI) {
//            return ((XSURI) xmlObject).getURI();
//        }
        if (xmlObject instanceof XSBoolean) {
            XSBooleanValue xsBooleanValue = ((XSBoolean) xmlObject).getValue();
            return (xsBooleanValue != null) ? xsBooleanValue.getValue() : null;
        }
        if (xmlObject instanceof XSDateTime) {
            return ((XSDateTime) xmlObject).getValue();
        }
        return xmlObject;
    }

}
