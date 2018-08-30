package pro.javatar.security.jwt;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class TokenValidatorTest {

    @Test
    public void isRealmValid() throws Exception {
        TokenValidator tokenValidator = new TokenValidator();
        assertTrue(tokenValidator.isRealmValid("http://identity-provider/auth/realms/realm", "realm"));

        assertFalse(tokenValidator.isRealmValid("http://identity-provider/auth/realms/realm", ""));
        assertFalse(tokenValidator.isRealmValid("http://identity-provider/auth/realms/realm", null));

        assertFalse(tokenValidator.isRealmValid("http://identity-provider/auth/realms/realmrealm", "realm"));
        assertFalse(tokenValidator.isRealmValid("", "realm"));
        assertFalse(tokenValidator.isRealmValid(null, "realm"));
    }
}