package pro.javatar.security.oidc.filters;

import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.exceptions.RealmNotFoundAuthenticationException;
import pro.javatar.security.oidc.services.FilterOptionConverter;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.utils.StringUtils;
import pro.javatar.security.oidc.utils.UrlResolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.core.context.SecurityContextHolder;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This filter aims to retrieve realm from request and setup it for current thread.
 * There are three places where realm is expected: header, url or query parameter.
 * If realm is mandatory and not provided RealmNotFoundAuthenticationException will be thrown.
 * You can check realmMandatory variable (security.oidc.AuthenticationRealmAwareFilter.isRealmMandatory),
 * default value is true.
 * This filter could be enable by setting enableFilter (security.oidc.AuthenticationRealmAwareFilter.enable) to true.
 * By default filter is enabled.
 * Please provide filterApplyUrlRegex (security.oidc.AuthenticationRealmAwareFilter.filterApplyUrlRegex)
 * or default (security.oidc.filterApplyUrlRegex) will be used otherwise.
 */
@Component
public class AuthenticationRealmAwareFilter implements Filter {

    public static final String BASE_REALM_REGEX = "(.*)";
    private static final Logger logger =
            LoggerFactory.getLogger(AuthenticationRealmAwareFilter.class);
    private static final String REALM_PLACEHOLDER = "{realm}";

    private boolean enableFilter = false;

    private String realmUrlPattern;

    private String realmParamName;

    private boolean realmMandatory;

    private Pattern urlPattern;

    private final OidcAuthenticationHelper oidcAuthenticationHelper;
    private final FilterOptionConverter filterOptionConverter = new FilterOptionConverter();
    private final UrlResolver urlResolver = new UrlResolver();

    @Override
    public void init(FilterConfig filterConfig) {
        logger.info("init filter: {}", AuthenticationRealmAwareFilter.class);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        if (!enableFilter) {
            logger.debug("{} is disabled", getClass().getCanonicalName());
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        oidcAuthenticationHelper.removeRealmFromCurrentRequest();
        HttpServletRequest request = (HttpServletRequest) servletRequest;

        if (shouldSkip(new ServletServerHttpRequest(request))) {
            logger.debug("{} {} is skipped", request.getMethod(), request.getRequestURI());
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        logger.debug("setup realm for current request");
        setupRealmForCurrentRequestThread(request);
        validateRealmSetup();
        setupRealmInResponse(servletResponse);

        try {
            filterChain.doFilter(servletRequest, servletResponse);
        } finally {
            logger.debug("clean up realm from current request");
            oidcAuthenticationHelper.removeRealmFromCurrentRequest();
            cleanupSecurityContextForCurrentThread();
        }
    }

    @Override
    public void destroy() {
    }

    void setupRealmInResponse(ServletResponse servletResponse) {
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String realm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        response.setHeader(SecurityConstants.REALM_HEADER, realm);
    }

    void setupRealmForCurrentRequestThread(HttpServletRequest request) {
        if (containsRealmHeader(request)) {
            setupRealmFromHeader(request);
            return;
        }

        if (isUrlRetrieverEnabled()) {
            if (isSuccessfulSetupRealmFromUri(request))
                return;
        }

        setupRealmFromParams(request);
    }

    void validateRealmSetup() {
        if (!realmMandatory) {
            return;
        }

        String realm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        if (StringUtils.isBlank(realm)) {
            logger.warn("validate realm fails, it is mandatory");
            throw new RealmNotFoundAuthenticationException();
        }
    }

    boolean containsRealmHeader(HttpServletRequest request) {
        String realm = request.getHeader(SecurityConstants.REALM_HEADER);
        return StringUtils.isNotBlank(realm);
    }

    void setupRealmFromHeader(HttpServletRequest request) {
        String realm = request.getHeader(SecurityConstants.REALM_HEADER);
        oidcAuthenticationHelper.setRealmForCurrentRequest(realm);
    }

    boolean isUrlRetrieverEnabled() {
        return urlPattern != null;
    }

    boolean isSuccessfulSetupRealmFromUri(HttpServletRequest request) {
        String url = request.getRequestURI();
        String realm = retrieveRealmFromUrl(url);
        if (StringUtils.isBlank(realm))
            return false;
        logger.debug("realm: {} was retrieved from url: {}", realm, url);
        oidcAuthenticationHelper.setRealmForCurrentRequest(realm);
        return true;
    }

    void setupRealmFromParams(HttpServletRequest request) {
        String realm = request.getParameter(realmParamName);
        oidcAuthenticationHelper.setRealmForCurrentRequest(realm);
    }

    String prepareRealmRegex(String realmUrlPattern) {
        String realmRegex = BASE_REALM_REGEX;
        int lastIndex = realmUrlPattern.lastIndexOf('}');
        if (lastIndex != (realmUrlPattern.length() - 1)) {
            char lastChar = realmUrlPattern.charAt(lastIndex + 1);
            realmRegex = "([^" + lastChar + "]{2,})";
        }
        return realmRegex;
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
        return oidcAuthenticationHelper.shouldSkip(request);
    }

    private String retrieveRealmFromUrl(String url) {
        Matcher matcher = urlPattern.matcher(url);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private void cleanupSecurityContextForCurrentThread() {
        SecurityContextHolder.clearContext();
    }

    @Value("${security.oidc.AuthenticationRealmAwareFilter.enable:true}")
    public void setEnableFilter(boolean enableFilter) {
        this.enableFilter = enableFilter;
    }

    @Value("${security.oidc.AuthenticationRealmAwareFilter.realmUrlPattern:}")
    public void setRealmUrlPattern(String realmUrlPattern) {
        this.realmUrlPattern = realmUrlPattern;
        if (StringUtils.isNotBlank(realmUrlPattern)
                && realmUrlPattern.contains(REALM_PLACEHOLDER)) {
            urlPattern = Pattern.compile(realmUrlPattern.replace(REALM_PLACEHOLDER,
                    prepareRealmRegex(realmUrlPattern)), Pattern.CASE_INSENSITIVE);
        }
    }

    @Value("${security.oidc.AuthenticationRealmAwareFilter.filterApplyUrlRegex:}")
    public void setFilterApplyUrlRegex(String filterApplyUrlRegex) {
        urlResolver.setFilterApplyUrlRegex(filterApplyUrlRegex);
    }

    @Value("${security.oidc.AuthenticationRealmAwareFilter.realmParamName:realm}")
    public void setRealmParamName(String realmParamName) {
        this.realmParamName = realmParamName;
    }

    @Value("${security.oidc.AuthenticationRealmAwareFilter.isRealmMandatory:true}")
    public void setRealmMandatory(boolean realmMandatory) {
        this.realmMandatory = realmMandatory;
    }

    @Value("#{'${security.oidc.AuthenticationRealmAwareFilter.filterApplyUrlList:}'.split(',')}")
    public void setFilterApplyUrlList(List<String> filterApplyUrlList) {
        urlResolver.setFilterApplyUrls(filterOptionConverter.convertList(filterApplyUrlList));
    }

    @Value("#{'${security.oidc.AuthenticationRealmAwareFilter.filterIgnoreUrlList:}'.split(',')}")
    public void setFilterIgnoreUrls(List<String> filterIgnoreUrlList) {
        urlResolver.setFilterIgnoreUrls(filterOptionConverter.convertList(filterIgnoreUrlList));
    }

    @Autowired
    public AuthenticationRealmAwareFilter(OidcAuthenticationHelper oidcAuthenticationHelper) {
        this.oidcAuthenticationHelper = oidcAuthenticationHelper;
    }

    @Override
    public String toString() {
        return "AuthenticationRealmAwareFilter{" +
                "enableFilter=" + enableFilter +
                ", realmUrlPattern='" + realmUrlPattern + '\'' +
                ", urlResolver='" + urlResolver.toString() + '\'' +
                ", realmParamName='" + realmParamName + '\'' +
                ", realmMandatory=" + realmMandatory +
                ", urlPattern=" + urlPattern +
                ", oidcAuthenticationHelper=" + oidcAuthenticationHelper +
                '}';
    }
}
