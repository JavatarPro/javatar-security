package pro.javatar.security.oidc.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javatar.security.oidc.model.TokenDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNull;

class OidcSecurityDetailsServiceImplTest {
    static final String TEST3_REALM = "test3-realm";
    static final String LOGIN = "krs";
    private OidcSecurityDetailsService securityDetailsService;

    @BeforeEach
    void setUp() {
        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setRealm(TEST3_REALM);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(LOGIN, tokenDetails);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        securityDetailsService = new OidcSecurityDetailsServiceImpl();
    }

    @Test
    void getTokenRealm() {
        assertThat(securityDetailsService.getTokenRealm(), is(TEST3_REALM));

        SecurityContextHolder.getContext().setAuthentication(null);
        assertNull(securityDetailsService.getTokenRealm());
    }

    @Test
    void getTokenUser() {
        assertThat(securityDetailsService.getTokenUser(), is(LOGIN));

        SecurityContextHolder.getContext().setAuthentication(null);
        assertNull(securityDetailsService.getTokenUser());
    }
}