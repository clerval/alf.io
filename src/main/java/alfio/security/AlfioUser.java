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
package alfio.security;

import alfio.model.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class AlfioUser implements OidcUser, UserDetails {

    private final User user;
    private final OidcUser oidcUser;

    /**
     * Constructor for OIDC-based authentication.
     * @param user the application's internal user object
     * @param authorities the authorities granted to the user
     * @param attributes the attributes from the OIDC provider
     * @param idToken the ID token from the OIDC provider
     * @param userInfo the user info from the OIDC provider
     */
    public AlfioUser(User user, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo) {
        this.user = user;
        // The "sub" (subject) claim is a standard and reliable choice for the name attribute
        this.oidcUser = new DefaultOidcUser(authorities, idToken, userInfo, "sub");
    }

    /**
     * Constructor for standard username/password authentication.
     * @param user the application's internal user object
     */
    public AlfioUser(User user) {
        this.user = user;
        this.oidcUser = null;
    }

    public User getUser() {
        return user;
    }

    public int getId() {
        return user.getId();
    }

    // --- OidcUser implementation (delegated) ---

    @Override
    public Map<String, Object> getClaims() {
        return oidcUser != null ? oidcUser.getClaims() : Map.of();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return oidcUser != null ? oidcUser.getUserInfo() : null;
    }

    @Override
    public OidcIdToken getIdToken() {
        return oidcUser != null ? oidcUser.getIdToken() : null;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oidcUser != null ? oidcUser.getAttributes() : Map.of();
    }

    @Override
    public String getName() {
        return user.getUsername();
    }

    // --- UserDetails implementation ---

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
        //return user.getAuthorities();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.isEnabled();
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.isEnabled();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.isEnabled();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }
}