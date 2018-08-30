package pro.javatar.security.oidc.services;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import pro.javatar.security.oidc.model.UserKey;

import org.junit.Before;
import org.junit.Test;

import java.util.Map;

public class OidcConfigurationTest {

    private OidcConfiguration oidcConfiguration;

    @Before
    public void setUp() throws Exception {
        oidcConfiguration = new OidcConfiguration();
    }

    @Test
    public void setRunOnBehalfOfUsersAllSucceeded() throws Exception {
        oidcConfiguration.setRunOnBehalfOfUsers("admin:wtqwerty@test-qa-rc, ecommerce:abcd1234@test-qa-rc");
        Map<UserKey, String> runOnBehalfOfUsers = oidcConfiguration.getRunOnBehalfOfUsers();
        String adminPassword = runOnBehalfOfUsers.get(new UserKey("admin", "test-qa-rc"));
        String ecommercePassword = runOnBehalfOfUsers.get(new UserKey("ecommerce", "test-qa-rc"));
        assertThat(runOnBehalfOfUsers.size(), is(2));
        assertThat(adminPassword, is("wtqwerty"));
        assertThat(ecommercePassword, is("abcd1234"));
    }

    @Test
    public void setRunOnBehalfOfUsersOneSucceeded() throws Exception {
        oidcConfiguration.setRunOnBehalfOfUsers("admin:wtqwerty@test-qa-rc, ecommerce:abcd1234:test-qa-rc");
        Map<UserKey, String> runOnBehalfOfUsers = oidcConfiguration.getRunOnBehalfOfUsers();
        String adminPassword = runOnBehalfOfUsers.get(new UserKey("admin", "test-qa-rc"));
        String ecommercePassword = runOnBehalfOfUsers.get(new UserKey("ecommerce", "test-qa-rc"));
        assertThat(runOnBehalfOfUsers.size(), is(1));
        assertThat(adminPassword, is("wtqwerty"));
        assertThat(ecommercePassword, is(nullValue()));
    }

    @Test
    public void afterPropertiesSetUserAndPasswordAreConfigured() throws Exception {
        oidcConfiguration.setUsername("login3");
        oidcConfiguration.setUserPassword("login3-password");
        oidcConfiguration.setDefaultRealm("default-realm");

        oidcConfiguration.afterPropertiesSet();
        Map<UserKey, String> runOnBehalfOfUsers = oidcConfiguration.getRunOnBehalfOfUsers();

        assertThat(runOnBehalfOfUsers.size(), is(1));
        assertThat(oidcConfiguration.getRunOnBehalfOfUserPassword("login3", "default-realm"), is("login3-password"));
    }

    @Test(expected = IllegalStateException.class)
    public void afterPropertiesSetPasswordAreNotConfigured() throws Exception {
        oidcConfiguration.setUsername("login3");
        oidcConfiguration.setDefaultRealm("default-realm");

        oidcConfiguration.afterPropertiesSet();
    }
}