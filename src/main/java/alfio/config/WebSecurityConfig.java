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
package alfio.config;

import alfio.config.authentication.CustomOidcUserService;
import alfio.config.authentication.OpenIdUserSynchronizer;
import alfio.manager.ExtensionManager;
import alfio.manager.user.UserManager;
import alfio.repository.user.AuthorityRepository;
import alfio.repository.user.OrganizationRepository;
import alfio.repository.user.UserRepository;
import alfio.repository.user.join.UserOrganizationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class WebSecurityConfig {

    public static final String CSRF_PARAM_NAME = "_csrf";
    private static final String CSRF_SESSION_ATTRIBUTE = "CSRF_SESSION_ATTRIBUTE";
    
    @Autowired
    private CustomOidcUserService customOidcUserService;

    @Autowired
    private RememberMeServices rememberMeServices;
    
    @Bean
    public CsrfTokenRepository getCsrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setSessionAttributeName(CSRF_SESSION_ATTRIBUTE);
        repository.setParameterName(CSRF_PARAM_NAME);
        return repository;
    }

    @Bean
    public OpenIdUserSynchronizer openIdUserSynchronizer(PlatformTransactionManager transactionManager,
                                                         PasswordEncoder passwordEncoder,
                                                         UserManager userManager,
                                                         UserRepository userRepository,
                                                         UserOrganizationRepository userOrganizationRepository,
                                                         NamedParameterJdbcTemplate jdbcTemplate,
                                                         AuthorityRepository authorityRepository,
                                                         OrganizationRepository organizationRepository,
                                                         ExtensionManager extensionManager) {
        return new OpenIdUserSynchronizer(transactionManager,
            passwordEncoder,
            userManager,
            userRepository,
            userOrganizationRepository,
            jdbcTemplate,
            authorityRepository,
            organizationRepository,
            extensionManager);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers(
                    "/",
                    "/login",
                    "/assets/**",
                    "/error/**",
                    "/favicon.ico",
                    "/public/**",
                    "/event/**",
                    "/v2/api-docs",
                    "/swagger-ui.html",
                    "/swagger-resources/**",
                    "/webjars/**"
                ).permitAll()
                .requestMatchers(HttpMethod.POST, "/public/events/*/subscribe").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll()
            )
            .rememberMe(rememberMe -> rememberMe.rememberMeServices(rememberMeServices))
            .oauth2Login(oauth -> oauth.loginPage("/login").userInfoEndpoint(userInfo -> userInfo.oidcUserService(customOidcUserService)));
        return http.build();
    }
}
