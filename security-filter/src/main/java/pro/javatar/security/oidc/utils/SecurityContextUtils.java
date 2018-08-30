package pro.javatar.security.oidc.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityContextUtils {

    private SecurityContextUtils() {
    }

    public static void setAuthentication(Authentication authentication) {
        setAuthentication(authentication, SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    public static void setAuthentication(Authentication authentication, String strategyName) {
        SecurityContextHolder.setStrategyName(strategyName);
        SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
