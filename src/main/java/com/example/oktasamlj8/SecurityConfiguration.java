package com.example.oktasamlj8;


import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;

import java.io.File;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   OpenSamlAuthenticationProvider provider) throws Exception {
        http.authorizeRequests(authorize -> authorize.anyRequest().authenticated());
        http.saml2Login(saml2 -> saml2.authenticationManager(new ProviderManager(provider)));
        http.saml2Logout(withDefaults());
        return http.build();
    }

    @Bean
    public OpenSamlAuthenticationProvider openSamlAuthenticationProvider(CustomSaml2AuthenticationConverter converter) {
        OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
        Converter<OpenSamlAuthenticationProvider.ResponseToken, Saml2Authentication> authenticationConverter = converter.createDefaultResponseAuthenticationConverter();
        provider.setResponseAuthenticationConverter(authenticationConverter);
        return provider;
    }


    //load key and certificate from keystore
    @Bean
    RelyingPartyRegistration oktaRegistrations(@Value("${okta.keystore.location}") File keystoreLocation,
                                               @Value("${okta.keystore.password}") String keystorePassword,
                                               @Value("${app.key.alias}") String keyAlias,
                                               @Value("${app.key.password}") String keyPassword,
                                               @Value("${app.certificate.alias}") String certificateAlias,
                                               @Value("${spring.security.saml2.relyingparty.registration.okta.identityprovider.metadata-uri}") String metadataUri,
                                               @Value("${spring.security.saml2.relyingparty.registration.okta.identityprovider.registrationId}") String registrationId,
                                               @Value("${spring.security.saml2.relyingparty.registration.okta.identityprovider.singlelogout.url}") String singleLogoutUrl,
                                               @Value("${spring.security.saml2.relyingparty.registration.okta.identityprovider.singlelogout.response-url}") String singleLogoutResponseUrl) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(Files.newInputStream(keystoreLocation.toPath()), keystorePassword.toCharArray());
        Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());
        Certificate certificate = keyStore.getCertificate(certificateAlias);

        Saml2X509Credential credential = Saml2X509Credential.signing((PrivateKey) key, (X509Certificate) certificate);
        return RelyingPartyRegistrations
                .fromMetadataLocation(metadataUri)
                .registrationId(registrationId)
                .singleLogoutServiceResponseLocation(singleLogoutResponseUrl)
                .singleLogoutServiceLocation(singleLogoutUrl)
                .signingX509Credentials((signing) -> signing.add(credential))
                .build();
    }


    //load key and certificate from file
    @Bean
    RelyingPartyRegistration oktaAdminRegistrations(@Value("${app.key.location}") RSAPrivateKey key,
                                                    @Value("${app.certificate.location}") File certificateFile,
                                                    @Value("${spring.security.saml2.relyingparty.registration.okta-admin.identityprovider.metadata-uri}") String metadataUri,
                                                    @Value("${spring.security.saml2.relyingparty.registration.okta-admin.identityprovider.registrationId}") String registrationId,
                                                    @Value("${spring.security.saml2.relyingparty.registration.okta-admin.identityprovider.singlelogout.url}") String singleLogoutUrl,
                                                    @Value("${spring.security.saml2.relyingparty.registration.okta-admin.identityprovider.singlelogout.response-url}") String singleLogoutResponseUrl) throws Exception {
        X509Certificate certificate = X509Support.decodeCertificate(certificateFile);
        Saml2X509Credential credential = Saml2X509Credential.signing(key, certificate);
        return RelyingPartyRegistrations
                .fromMetadataLocation(metadataUri)
                .registrationId(registrationId)
                .singleLogoutServiceResponseLocation(singleLogoutResponseUrl)
                .singleLogoutServiceLocation(singleLogoutUrl)
                .signingX509Credentials((signing) -> signing.add(credential))
                .build();
    }

    @Bean
    RelyingPartyRegistrationRepository registrationRepository(RelyingPartyRegistration oktaRegistrations, RelyingPartyRegistration oktaAdminRegistrations) {
        return new InMemoryRelyingPartyRegistrationRepository(oktaAdminRegistrations, oktaRegistrations);
    }

}
