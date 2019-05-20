package pro.javatar.security.oidc.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;

import javax.servlet.*;
import java.io.IOException;

/**
 * For dev purposes to hard-code security authorities
 * to develop without any identity provider dependency
 */
public class AuthorizationStubFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationStubFilter.class);

    private boolean enableFilter;

    private String accessToken;

    private OidcAuthenticationHelper oidcHelper;

    public AuthorizationStubFilter(OidcAuthenticationHelper oidcHelper, SecurityConfig securityConfig) {
        this.oidcHelper = oidcHelper;
        this.enableFilter = securityConfig.stub().enabled();
        this.accessToken = securityConfig.stub().accessToken();
    }

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
        oidcHelper.authenticateCurrentThread(accessToken, accessToken);
        filterChain.doFilter(servletRequest, servletResponse);
        oidcHelper.safeCleanupSecurityContext(AuthorizationStubFilter.class);
    }

    @Override
    public void destroy() {
        logger.info("AuthorizationStubFilter destroyed");
    }

    public boolean isFilterEnable() {
        return enableFilter;
    }

    public void setEnableFilter(boolean enableFilter) {
        this.enableFilter = enableFilter;
    }

    @Override
    public String toString() {
        return "AuthorizationStubFilter{" +
                "enableFilter=" + enableFilter +
                ", oidcHelper=" + oidcHelper +
                '}';
    }
}
