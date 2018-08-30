package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.model.TokenDetails;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class OidcSecurityDetailsServiceImpl implements OidcSecurityDetailsService {

    @Override
    public String getTokenRealm() {
        Authentication authentication = getAuthentication();
        if (authentication == null)
            return null;
        TokenDetails tokenDetails = (TokenDetails) authentication.getCredentials();
        return tokenDetails.getRealm();
    }

    @Override
    public String getTokenUser() {
        Authentication authentication = getAuthentication();
        if (authentication == null)
            return null;
        return authentication.getName();
    }

    private Authentication getAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getCredentials() instanceof TokenDetails)) {
            return null;
        }
        return authentication;
    }
}
