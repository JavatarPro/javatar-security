package pro.javatar.security.oidc.filters;

import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.exceptions.AuthenticationException;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.utils.JsonMessageBuilder;
import pro.javatar.security.oidc.utils.StringUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
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
import java.io.UnsupportedEncodingException;

@Component
public class AuthenticationControllerAdviceFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationControllerAdviceFilter.class);

    private RealmService realmService;

    private OidcConfiguration oidcConfiguration;

    private JsonMessageBuilder messageBuilder;

    @Autowired
    public AuthenticationControllerAdviceFilter(RealmService realmService,
                                                OidcConfiguration oidcConfiguration,
                                                JsonMessageBuilder messageBuilder) {
        this.realmService = realmService;
        this.oidcConfiguration = oidcConfiguration;
        this.messageBuilder = messageBuilder;
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest servletRequest = (HttpServletRequest) request;
        String url = servletRequest.getRequestURL().toString();
        logger.debug("advice filter for url: {}", url);
        try {
            populateResponseHeaders(response);
            if (!HttpMethod.OPTIONS.name().equals(servletRequest.getMethod())) {
                chain.doFilter(request, response);
            }
        } catch (AuthenticationException e) {
            logger.warn("while handling url: {}, was caught exception: {}", url, e.getClass().getCanonicalName());
            String referer = servletRequest.getHeader(SecurityConstants.REFERER_HEADER);
            String redirectUrl = StringUtils.isNotBlank(referer) ? referer : url;

            prepareErrorResponse(response, e, redirectUrl);
        }
    }

    @Override
    public void destroy() {}

    void prepareErrorResponse(ServletResponse servletResponse, AuthenticationException e, String url)
            throws IOException {
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        setupStatusCode(response, e);
        setupResponseHeaders(response, e, url);
        setupBody(response, e);
    }

    void setupStatusCode(HttpServletResponse response, AuthenticationException e) {
        if (e.getStatus() != null) {
            response.setStatus(e.getStatus().value());
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    void setupBody(HttpServletResponse response, AuthenticationException e) throws IOException {
        response.getWriter().print(messageBuilder.authenticationExceptionBodyJson(e));
    }

    // according to https://tools.ietf.org/html/rfc2617#section-1.2
    void setupResponseHeaders(HttpServletResponse response, AuthenticationException e, String url)
            throws UnsupportedEncodingException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        String realm = realmService.getRealmForCurrentRequest(response);
        String location = oidcConfiguration.getIdentityProviderHost();
        String wwwAuthenticateHeader = getWwwAuthenticateHeader(
                realm,
                location,
                oidcConfiguration.buildRedirectUrl(realm, url),
                oidcConfiguration.getTokenEndpoint());
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticateHeader);
        populateResponseHeaders(response);
    }

    // http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    String getWwwAuthenticateHeader(String realm, String location, String authorizationEndpoint, String tokenEndpoint) {
        return String.format("Bearer realm=%s, location=%s, authorization_endpoint=%s, token_endpoint=%s",
                realm, location, authorizationEndpoint, tokenEndpoint);
    }

    private void populateResponseHeaders(ServletResponse response) {
        if (oidcConfiguration.isCorsFilterEnable()) {
            HttpServletResponse servletResponse = (HttpServletResponse) response;
            servletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, "GET,HEAD,OPTIONS,POST,PUT,PATCH,DELETE");
            servletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, "Authorization,X-Refresh-Token, "
                    + "Access-Control-Allow-Origin, "
                    + "Access-Control-Allow-Headers, "
                    + "Origin,Accept, "
                    + "X-Requested-With, "
                    + "Content-Type, "
                    + "Access-Control-Request-Method, "
                    + "Access-Control-Request-Headers, "
                    + "X-Correlation-ID, "
                    + "X-REALM");
            servletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
            servletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                    SecurityConstants.REALM_HEADER + "," +
                            HttpHeaders.WWW_AUTHENTICATE + "," +
                            HttpHeaders.AUTHORIZATION + "," +
                            SecurityConstants.REFRESH_TOKEN_HEADER + "," +
                            SecurityConstants.LOGOUT_URL_HEADER + "," +
                            SecurityConstants.X_CORRELATION_ID);
        }
    }
}
