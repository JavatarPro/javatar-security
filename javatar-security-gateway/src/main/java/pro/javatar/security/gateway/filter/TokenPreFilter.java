/*
 * Copyright (c) 2018 Javatar LLC
 * All rights reserved.
 */
package pro.javatar.security.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.security.gateway.config.GatewayConfig;
import pro.javatar.security.gateway.model.HeaderMapRequestWrapper;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;

import javax.servlet.*;
import java.io.IOException;

/**
 * This filter should extract access & refresh tokens from secret storage and populate http request with them.
 *
 * @author Serhii Petrychenko / Javatar LLC
 * @author Borys Zora
 * @version 05-07-2018
 */
@Service
public class TokenPreFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(TokenPreFilter.class);

    private GatewaySecurityService gatewaySecurityService;

    private GatewayConfig config;

    @Autowired
    public TokenPreFilter(GatewaySecurityService gatewaySecurityService, GatewayConfig config) {
        this.gatewaySecurityService = gatewaySecurityService;
        this.config = config;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.debug("Init TokenPreFilter");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HeaderMapRequestWrapper wrapper = new HeaderMapRequestWrapper(request);
        gatewaySecurityService.appendSecurityHeaders(wrapper);
        chain.doFilter(wrapper, response);
    }

    @Override
    public void destroy() {
        logger.debug("Destroy TokenPreFilter");
    }

}
