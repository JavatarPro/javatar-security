package pro.javatar.security.jwt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenValidatorTest {

    @Test
    void isRealmValid() {
        TokenValidator tokenValidator = new TokenValidator();
        assertTrue(tokenValidator.isRealmValid("http://identity-provider/auth/realms/realm", "realm"));

        assertFalse(tokenValidator.isRealmValid("http://identity-provider/auth/realms/realm", ""));
        assertFalse(tokenValidator.isRealmValid("http://identity-provider/auth/realms/realm", null));

        assertFalse(tokenValidator.isRealmValid("http://identity-provider/auth/realms/realmrealm", "realm"));
        assertFalse(tokenValidator.isRealmValid("", "realm"));
        assertFalse(tokenValidator.isRealmValid(null, "realm"));
    }
}