package pro.javatar.security.gateway.config;

import java.time.Duration;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
public interface GatewayConfig {

    Boolean loginEnabled();

    Boolean logoutEnabled();

    String uiPathPrefix();

    Duration tokenRefreshInterval();

    DevMode devMode();

    RealmDetection realmDetection();

    interface DevMode {

        Boolean enabled();

        Boolean disableTokenIdSecuredCookies();

    }

    interface RealmDetection {

        String defaultRealm();

        boolean isAlias(String subdomain);

        String getRealmBySubdomainAlias(String alias);
    }
}
