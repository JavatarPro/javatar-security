/*
 * Copyright (c) 2018 Javatar LLC
 * All rights reserved.
 */

package pro.javatar.security.gateway.filter;

import com.netflix.util.Pair;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.security.gateway.model.FilterType;
import pro.javatar.security.gateway.config.GatewayConfig;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;

import java.util.*;

/**
 * This filter will make sure no secure headers send to the browser/user
 * Also tokens could be more fresher than before in secret storage (some service could update token)
 * so this filter will update info in secret storage and update browser's cookies
 *
 * @author Borys Zora
 * @author Serhii Petrychenko
 * @version 2018-07-05 # initial class received token and exchange one more time on out
 * @version 2019-07-11 # rewritten to just exclude sensitive headers,
 *                     # token exchanges is simplified and skipped on this stage
 */
@Service
public class ExcludeHeadersZuulPostFilter extends ZuulFilter {

    private static final Logger logger = LoggerFactory.getLogger(ExcludeHeadersZuulPostFilter.class);

    private GatewaySecurityService gatewaySecurityService;

    private GatewayConfig config;

    @Autowired
    public ExcludeHeadersZuulPostFilter(GatewaySecurityService gatewaySecurityService,
                                        GatewayConfig config) {
        this.gatewaySecurityService = gatewaySecurityService;
        this.config = config;
    }

    @Override
    public String filterType() {
        return FilterType.POST.asText();
    }

    @Override
    public int filterOrder() {
        // after security filters
        return 10;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
        RequestContext context = RequestContext.getCurrentContext();
        excludeHeaders(context);
        return null;
    }

    private void excludeHeaders(RequestContext context) {
        logger.debug("Start excludeHeaders");

        Set<String> excludedHeaders = gatewaySecurityService.excludedHeaders();
        List<Pair<String, String>> filteredResponseHeaders = new ArrayList<>();

        List<Pair<String, String>> zuulResponseHeaders = context.getZuulResponseHeaders();
        if (zuulResponseHeaders != null) {
            for (Pair<String, String> header : zuulResponseHeaders) {
                if (!excludedHeaders.contains(header.first())) {
                    Pair<String, String> pair = new Pair<>(header.first(), header.second());
                    filteredResponseHeaders.add(pair);
                }
            }
        }
        context.put("zuulResponseHeaders", filteredResponseHeaders);

        logger.debug("Finish excludeHeaders");
    }

}
