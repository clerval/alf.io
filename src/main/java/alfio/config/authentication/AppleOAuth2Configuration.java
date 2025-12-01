/**
 * This file is part of alf.io.
 *
 * alf.io is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * alf.io is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with alf.io.  If not, see <http://www.gnu.org/licenses/>.
 */
package alfio.config.authentication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Configuration
@ConditionalOnProperty(value = "spring.security.oauth2.client.registration.apple.client-id")
@EnableConfigurationProperties(OAuth2ClientProperties.class)
public class AppleOAuth2Configuration {

    private static final String APPLE_PROVIDER_ID = "apple";

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties oAuth2ClientProperties,
                                                                     @Value("${spring.security.oauth2.client.registration.apple.team-id}") String teamId,
                                                                     @Value("${spring.security.oauth2.client.registration.apple.key-id}") String keyId,
                                                                     @Value("${spring.security.oauth2.client.registration.apple.private-key}") String privateKey) {

        List<ClientRegistration> registrations = oAuth2ClientProperties.getRegistration().entrySet().stream().map(entry -> {
            String registrationId = entry.getKey();
            OAuth2ClientProperties.Registration registration = entry.getValue();
            OAuth2ClientProperties.Provider provider = oAuth2ClientProperties.getProvider().get(registrationId);

            if (provider == null || provider.getIssuerUri() == null) {
                // Not an OIDC provider, or misconfigured. Could be the Apple provider which we handle separately.
                if (APPLE_PROVIDER_ID.equals(registrationId)) {
                    return buildAppleClientRegistration(registration, oAuth2ClientProperties.getProvider().get(APPLE_PROVIDER_ID), teamId, keyId, privateKey);
                }
                return null;
            }

                // For other providers like Google, use Spring's default mechanism
            return ClientRegistrations.fromOidcIssuerLocation(provider.getIssuerUri())                    .registrationId(registrationId)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .scope(registration.getScope())
                    .build();
        }).filter(Objects::nonNull).collect(Collectors.toList());


        return new InMemoryClientRegistrationRepository(registrations);
    }

    private ClientRegistration buildAppleClientRegistration(OAuth2ClientProperties.Registration registration,
                                                            OAuth2ClientProperties.Provider provider,
                                                            String teamId, String keyId, String privateKey) {

        String clientSecret = createClientSecret(registration.getClientId(), teamId, keyId, privateKey);

        return ClientRegistrations.fromIssuerLocation(provider.getIssuerUri())
                .registrationId(APPLE_PROVIDER_ID)
                .clientId(registration.getClientId())
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(registration.getRedirectUri())
                .scope(registration.getScope())
                .authorizationUri(provider.getAuthorizationUri())
                .tokenUri(provider.getTokenUri())
                .userInfoUri(provider.getUserInfoUri())
                .jwkSetUri(provider.getJwkSetUri())
                .userNameAttributeName(provider.getUserNameAttribute())
                .clientName("Apple")
                .build();
    }

    private String createClientSecret(String clientId, String teamId, String keyId, String privateKeyPem) {
        try {
            String pkcs8Pem = privateKeyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] encoded = Base64.getDecoder().decode(pkcs8Pem);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey privateKey = kf.generatePrivate(keySpec);

            Instant now = Instant.now();
            return Jwts.builder()
                    .setAudience("https://appleid.apple.com")
                    .setIssuer(teamId)
                    .setSubject(clientId)
                    .setExpiration(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                    .setIssuedAt(Date.from(now))
                    .setHeaderParam("kid", keyId)
                    .signWith(privateKey, SignatureAlgorithm.ES256)
                    .compact();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create client secret for Apple OAuth2", e);
        }
    }
}