package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.model.TokenDetails;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class OidcSecurityDetailsServiceImplTest {
    public static final String TEST3_REALM = "test3-realm";
    public static final String LOGIN = "krs";
    private OidcSecurityDetailsService securityDetailsService;

    @Before
    public void setUp() throws Exception {
        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setRealm(TEST3_REALM);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(LOGIN, tokenDetails);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        securityDetailsService = new OidcSecurityDetailsServiceImpl();
    }

    @Test
    public void getTokenRealm() throws Exception {
        assertThat(securityDetailsService.getTokenRealm(), is(TEST3_REALM));

        SecurityContextHolder.getContext().setAuthentication(null);
        assertNull(securityDetailsService.getTokenRealm());
    }

    @Test
    public void getTokenUser() throws Exception {
        assertThat(securityDetailsService.getTokenUser(), is(LOGIN));

        SecurityContextHolder.getContext().setAuthentication(null);
        assertNull(securityDetailsService.getTokenUser());
    }
}