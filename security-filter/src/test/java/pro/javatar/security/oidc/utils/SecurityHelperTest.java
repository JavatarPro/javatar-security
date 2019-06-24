package pro.javatar.security.oidc.utils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.services.OidcConfiguration;

import java.util.ArrayList;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

/**
 * @author Andrii Murashkin / Javatar LLC
 * @version 10-03-2019
 */
@RunWith(MockitoJUnitRunner.class)
public class SecurityHelperTest {

    private static final String LOGIN = "user6767";
    private static final String REALM = "test-realm";
    private static final String DEFAULT_REALM = "default-realm";

    // decouple securityHelper from OidcConfiguration
    // since 2019-06-24
//    @Mock
//    private OidcConfiguration oidcConfiguration;

    @InjectMocks
    private SecurityHelper securityHelper;

    @Test
    public void getCurrentRealm() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(LOGIN, getTokenDetails(), new ArrayList<>()));
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());

        assertEquals(REALM, securityHelper.getCurrentRealm());
    }

    @Test
    public void getCurrentRealmTokenDetailsIsNull() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(LOGIN, null, new ArrayList<>()));
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());

        // when(oidcConfiguration.getDefaultRealm()).thenReturn(DEFAULT_REALM);

        // assertEquals(DEFAULT_REALM, securityHelper.getCurrentRealm());
        // change behaviour to return null, to not couple securityHelper to configuration
        // since 2019-06-24
        assertEquals(null, securityHelper.getCurrentRealm());
    }

    @Test
    public void getCurrentRealmDefaultRealm() {
        SecurityContextHolder.clearContext();
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // when(oidcConfiguration.getDefaultRealm()).thenReturn(DEFAULT_REALM);

        // assertEquals(DEFAULT_REALM, securityHelper.getCurrentRealm());
        // change behaviour to return null, to not couple securityHelper to configuration
        // since 2019-06-24
        assertEquals(null, securityHelper.getCurrentRealm());
    }

    @Test
    public void getCurrentLogin() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(LOGIN, null, new ArrayList<>()));
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());

        assertEquals(LOGIN, securityHelper.getCurrentLogin());
    }

    @Test(expected = AccessDeniedException.class)
    public void getCurrentLoginException() {
        SecurityContextHolder.clearContext();
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        securityHelper.getCurrentLogin();
    }

    private TokenDetails getTokenDetails() {
        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setRealm(REALM);
        return tokenDetails;
    }
}