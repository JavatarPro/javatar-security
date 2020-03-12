package pro.javatar.security.oidc.services;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javatar.security.oidc.model.UserKey;

import java.util.Map;

class OidcConfigurationTest {

    private OidcConfiguration oidcConfiguration;

    @BeforeEach
    void setUp() {
        oidcConfiguration = new OidcConfiguration();
    }

    @Test
    void setRunOnBehalfOfUsersAllSucceeded() {
        oidcConfiguration.setRunOnBehalfOfUsers("admin:wtqwerty@test-qa-rc, ecommerce:abcd1234@test-qa-rc");
        Map<UserKey, String> runOnBehalfOfUsers = oidcConfiguration.getRunOnBehalfOfUsers();
        String adminPassword = runOnBehalfOfUsers.get(new UserKey("admin", "test-qa-rc"));
        String ecommercePassword = runOnBehalfOfUsers.get(new UserKey("ecommerce", "test-qa-rc"));
        assertThat(runOnBehalfOfUsers.size(), is(2));
        assertThat(adminPassword, is("wtqwerty"));
        assertThat(ecommercePassword, is("abcd1234"));
    }

    @Test
    void setRunOnBehalfOfUsersOneSucceeded() {
        oidcConfiguration.setRunOnBehalfOfUsers("admin:wtqwerty@test-qa-rc, ecommerce:abcd1234:test-qa-rc");
        Map<UserKey, String> runOnBehalfOfUsers = oidcConfiguration.getRunOnBehalfOfUsers();
        String adminPassword = runOnBehalfOfUsers.get(new UserKey("admin", "test-qa-rc"));
        String ecommercePassword = runOnBehalfOfUsers.get(new UserKey("ecommerce", "test-qa-rc"));
        assertThat(runOnBehalfOfUsers.size(), is(1));
        assertThat(adminPassword, is("wtqwerty"));
        assertThat(ecommercePassword, is(nullValue()));
    }

    @Test
    void afterPropertiesSetUserAndPasswordAreConfigured() throws Exception {
        oidcConfiguration.setUsername("login3");
        oidcConfiguration.setUserPassword("login3-password");
        oidcConfiguration.setDefaultRealm("default-realm");

        oidcConfiguration.afterPropertiesSet();
        Map<UserKey, String> runOnBehalfOfUsers = oidcConfiguration.getRunOnBehalfOfUsers();

        assertThat(runOnBehalfOfUsers.size(), is(1));
        assertThat(oidcConfiguration.getRunOnBehalfOfUserPassword("login3", "default-realm"), is("login3-password"));
    }

    @Test
    void afterPropertiesSetPasswordAreNotConfigured() {
        oidcConfiguration.setUsername("login3");
        oidcConfiguration.setDefaultRealm("default-realm");

        assertThrows(IllegalStateException.class, () -> oidcConfiguration.afterPropertiesSet());
    }
}