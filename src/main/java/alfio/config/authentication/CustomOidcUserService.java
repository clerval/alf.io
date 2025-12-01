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

import alfio.model.user.User;
import alfio.repository.user.UserRepository;
import alfio.security.AlfioUser;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@Service
public class CustomOidcUserService extends OidcUserService {

    private static final Logger log = LoggerFactory.getLogger(CustomOidcUserService.class);

    private final UserRepository userRepository;

    public CustomOidcUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        Map<String, Object> attributes = oidcUser.getAttributes();
        String email = (String) attributes.get("email");

        if (StringUtils.isBlank(email)) {
            log.error("Email not found from OAuth2 provider. Full attributes: {}", attributes);
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token", "Email not found from OAuth2 provider", null));
        }

        User user = userRepository.findByUsername(email)
                .map(existingUser -> {
                    log.debug("Updating existing user {}", email);
                    return updateExistingUser(existingUser, oidcUser);
                })
                .orElseGet(() -> {
                    log.debug("Creating new user {}", email);
                    return createNewUser(oidcUser);
                });

        return new AlfioUser(user, oidcUser.getAuthorities(), attributes, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    private User createNewUser(OidcUser oidcUser) {
        Map<String, Object> attributes = oidcUser.getAttributes();
        String email = (String) attributes.get("email");
        int id = userRepository.createPublicUserIfNotExists(email,"", extractFirstName(attributes), extractLastName(attributes), email, true);
        return userRepository.findById(id);
    }

    private User updateExistingUser(User existingPerson, OidcUser oidcUser) {
        // Apple only provides name on first login, so only update if it's currently null
        if (StringUtils.isBlank(existingPerson.getFirstName()) && StringUtils.isBlank(existingPerson.getLastName())) {
            userRepository.updateContactInfo(existingPerson.getId(), extractFirstName(oidcUser.getAttributes()), extractLastName(oidcUser.getAttributes()), existingPerson.getEmailAddress());
        }
        return existingPerson;
    }

    private String extractFirstName(Map<String, Object> attributes) {
        return Optional.ofNullable((String) attributes.get("given_name")) // Standard OIDC claim
                .orElseGet(() -> {
                    String name = (String) attributes.get("name"); // Fallback for some providers
                    return StringUtils.isNotBlank(name) ? name.split(" ")[0] : "User";
                });
    }

    private String extractLastName(Map<String, Object> attributes) {
        return Optional.ofNullable((String) attributes.get("family_name")) // Standard OIDC claim
                .orElseGet(() -> {
                    String name = (String) attributes.get("name"); // Fallback for some providers
                    return StringUtils.isNotBlank(name) && name.contains(" ") ? name.substring(name.indexOf(' ') + 1) : "";
                });
    }
}