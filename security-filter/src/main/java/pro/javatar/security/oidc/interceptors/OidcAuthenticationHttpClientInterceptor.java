package pro.javatar.security.oidc.interceptors;

import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.filters.AuthorizationStubFilter;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.services.TokenService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * interceptor logic: if we have user token use it, if no token provided get µService client token
 */
@Service
public class OidcAuthenticationHttpClientInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger logger =
            LoggerFactory.getLogger(OidcAuthenticationHttpClientInterceptor.class);

    private OidcAuthenticationHelper oidcAuthenticationHelper;

    private OidcConfiguration oidcConfiguration;

    private TokenService tokenService;
    // TODO (bzo) ask configuration about is filter enable/disable
    private AuthorizationStubFilter authorizationStubFilter;

    @Autowired
    public OidcAuthenticationHttpClientInterceptor(TokenService tokenService,
                                                   OidcConfiguration oidcConfiguration,
                                                   OidcAuthenticationHelper oidcAuthenticationHelper,
                                                   AuthorizationStubFilter authorizationStubFilter) {
        this.tokenService = tokenService;
        this.oidcConfiguration = oidcConfiguration;
        this.oidcAuthenticationHelper = oidcAuthenticationHelper;
        this.authorizationStubFilter = authorizationStubFilter;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        boolean stubFilterEnable = authorizationStubFilter.isFilterEnable();
        logger.debug("{} is disabled. Dev mode is {}.", getClass().getCanonicalName(),
                stubFilterEnable ? "on" : "off");
        if (stubFilterEnable) {
            return execution.execute(request, body);
        }
        logger.debug("request was intercepted by oidc authentication http client interceptor");

        String securityInterceptorStatus = oidcConfiguration.isSecurityInterceptorEnable() ? "enabled" : "disabled";
        logger.debug("OidcAuthenticationHttpClientInterceptor is " + securityInterceptorStatus);

        boolean shouldSkip = oidcConfiguration.getInterceptorUrlResolver().skip(request);
        logger.debug("OidcAuthenticationHttpClientInterceptor is {} to {}", shouldSkip ? "skipped" : "applied", request.getURI().getPath());

        if (oidcConfiguration.isSecurityInterceptorEnable() && !shouldSkip) {
            addAuthorizationHeader(request);
        }

        return execution.execute(request, body);
    }

    void addAuthorizationHeader(HttpRequest request) {
        TokenDetails tokenDetails = tokenService.getTokenDetails();
        if (!tokenDetails.isEmpty()) {
            logger.debug("token added to Authorization header, token: {}", tokenDetails.getMaskedAccessToken());
            request.getHeaders().add(HttpHeaders.AUTHORIZATION,
                    OidcAuthenticationHelper.AUTH_HEADER_VALUE_PREFIX + tokenDetails.getAccessToken());
            request.getHeaders().add(SecurityConstants.REFRESH_TOKEN_HEADER, tokenDetails.getRefreshToken());
        } else {
            logger.warn("security enabled but request will be sent without any security headers");
        }
    }

}
