package pro.javatar.security.oidc.filters;

import pro.javatar.security.oidc.exceptions.BearerJwtTokenNotFoundAuthenticationException;
import pro.javatar.security.oidc.exceptions.ExchangeTokenByCodeAuthenticationException;
import pro.javatar.security.oidc.exceptions.RefreshTokenObsoleteAuthenticationException;
import pro.javatar.security.oidc.services.FilterOptionConverter;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.utils.UrlResolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Component;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

/**
 * This filter should be used only by stateful services with UI inside like MVC.
 * Do not enable this filter inside µServices.
 * For µServices we recommend use 401 response status with WWW-Authenticate header with identity provider location.
 */
@Component
public class AuthenticationOAuth2RedirectAwareFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationOAuth2RedirectAwareFilter.class);

    private final AuthorizationStubFilter authorizationStubFilter;
    private final OidcConfiguration oidcConfiguration;
    private final OidcAuthenticationHelper oidcHelper;
    private final FilterOptionConverter filterOptionConverter = new FilterOptionConverter();
    private final UrlResolver urlResolver = new UrlResolver();

    @Autowired
    public AuthenticationOAuth2RedirectAwareFilter(AuthorizationStubFilter authorizationStubFilter,
                                                   OidcAuthenticationHelper oidcHelper,
                                                   OidcConfiguration oidcConfiguration) {
        this.authorizationStubFilter = authorizationStubFilter;
        this.oidcHelper = oidcHelper;
        this.oidcConfiguration = oidcConfiguration;
    }

    private boolean enableFilter = false;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info("AuthenticationOAuth2RedirectAwareFilter initialized");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        // TODO remove stub
        boolean stubFilterEnable = authorizationStubFilter.isFilterEnable();
        if (!enableFilter || stubFilterEnable) {
            logger.info("{} is disabled. Dev mode is {}.", getClass().getCanonicalName(), stubFilterEnable ? "on" : "off");
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (shouldSkip(servletRequest)) {
            logger.debug("Filter was skipped by filter condition.");
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        try {
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (BearerJwtTokenNotFoundAuthenticationException e) {
            logger.warn("request without bearer was captured and will be redirected to identity provider", e);
            redirectToAuthorizationEndpoint(servletRequest, servletResponse);
        } catch (RefreshTokenObsoleteAuthenticationException e) {
            logger.error("Even refresh token was expired! Possible cases: delay was bigger that refresh token lifetime " +
                    "or UI does not receive token updates. Request will be redirected to identity provider", e);
            redirectToAuthorizationEndpoint(servletRequest, servletResponse);
        } catch (ExchangeTokenByCodeAuthenticationException e) {
            logger.error("Danger! Can not exchange token. Token might be stolen and already exchanged " +
                    "or just identity provider unavailable at that moment", e);
            // TODO (bzo) redirect without ?code=...
            redirectToAuthorizationEndpoint(servletRequest, servletResponse);
        }
    }

    @Override
    public void destroy() {
        logger.info("AuthenticationOAuth2RedirectAwareFilter destroyed");
    }

    void redirectToAuthorizationEndpoint(ServletRequest servletRequest, ServletResponse servletResponse)
            throws IOException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String redirectUrl = oidcConfiguration.buildRedirectUrl(
                oidcHelper.getRealmForCurrentRequest(), oidcHelper.removeCodeFromUrl(request));
        ((HttpServletResponse) servletResponse).sendRedirect(redirectUrl);
    }

    boolean shouldSkip(ServletRequest request) {
        return shouldSkip(new ServletServerHttpRequest((HttpServletRequest) request));
    }

    /**
     * If necessary, the method can be redefined
     *
     * @return <code>true</code> filter is ignored
     * @param request
     */
    boolean shouldSkip(HttpRequest request) {
        if (!urlResolver.isEmpty()) {
            return urlResolver.skip(request);
        }
        return oidcHelper.shouldSkip(request);
    }

    @Value("${security.oidc.AuthenticationOAuth2RedirectAwareFilter.enable:false}")
    public void setEnableFilter(boolean enableFilter) {
        this.enableFilter = enableFilter;
    }

    @Value("${security.oidc.AuthenticationOAuth2RedirectAwareFilter.filterApplyUrlRegex:}")
    public void setFilterApplyUrlRegex(String filterApplyUrlRegex) {
        urlResolver.setFilterApplyUrlRegex(filterApplyUrlRegex);
    }

    @Value("#{'${security.oidc.AuthenticationOAuth2RedirectAwareFilter.filterApplyUrlList:}'.split(',')}")
    public void setFilterApplyUrlList(List<String> filterApplyUrlList) {
        urlResolver.setFilterApplyUrls(filterOptionConverter.convertList(filterApplyUrlList));
    }

    @Value("#{'${security.oidc.AuthenticationOAuth2RedirectAwareFilter.filterIgnoreUrlList:}'.split(',')}")
    public void setFilterIgnoreUrls(List<String> filterIgnoreUrlList) {
        urlResolver.setFilterIgnoreUrls(filterOptionConverter.convertList(filterIgnoreUrlList));
    }

}
