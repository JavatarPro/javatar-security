package pro.javatar.security.oidc.filters;

import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.utils.SecurityContextUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * For dev purposes to hard-code security authorities
 * to develop without any identity provider dependency
 */
@Component
public class AuthorizationStubFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationStubFilter.class);

    private boolean enableFilter = false;

    private String userLogin;

    private List<String> authorities;
    OidcConfiguration oidcConfiguration;
    OidcAuthenticationHelper oidcHelper;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info(AuthorizationStubFilter.class.getName() + " initialized");
        logger.debug(this.toString());
    }

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
        if (!enableFilter) {
            logger.debug("{} is disabled", getClass().getCanonicalName());
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }
        authenticate();
        filterChain.doFilter(servletRequest, servletResponse);
        oidcHelper.safeCleanupSecurityContext(AuthorizationStubFilter.class);
    }

    @Override
    public void destroy() {
        logger.info("AuthorizationStubFilter destroyed");
    }

    private void authenticate() {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String role : authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(role));
        }
        String token = UUID.randomUUID().toString();
        TokenDetails tokenDetails = new TokenDetails(token, token, LocalDateTime.now().plusMinutes(15L));
        tokenDetails.setRealm(oidcConfiguration.getDefaultRealm());
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userLogin, tokenDetails, grantedAuthorities);

        SecurityContextUtils.setAuthentication(authenticationToken);
    }

    public boolean isFilterEnable() {
        return enableFilter;
    }

    @Value("${security.oidc.AuthorizationStubFilter.enable:false}")
    public void setEnableFilter(boolean enableFilter) {
        this.enableFilter = enableFilter;
    }

    @Value("#{'${security.oidc.AuthorizationStubFilter.authorities:ADMIN,USER}'.split(',')}")
    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    @Value("${security.oidc.AuthorizationStubFilter.userLogin:stubAdmin}")
    public void setUserLogin(String userLogin) {
        this.userLogin = userLogin;
    }

    @Autowired
    public void setOidcHelper(OidcAuthenticationHelper oidcHelper) {
        this.oidcHelper = oidcHelper;
    }

    @Autowired
    public void setOidcConfiguration(OidcConfiguration oidcConfiguration) {
        this.oidcConfiguration = oidcConfiguration;
    }

    @Override
    public String toString() {
        return "AuthorizationStubFilter{" +
                "enableFilter=" + enableFilter +
                ", userLogin='" + userLogin + '\'' +
                ", authorities=" + authorities +
                ", oidcHelper=" + oidcHelper +
                '}';
    }
}
