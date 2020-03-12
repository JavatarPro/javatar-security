package pro.javatar.security.oidc.model;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

class TokenDetailsTest {

    @Test
    void getMaskedAccessToken() {
        TokenDetails tokenDetails = new TokenDetails();
        assertThat(tokenDetails.getMaskedAccessToken(), is(nullValue()));
        tokenDetails.setAccessToken("0123456789");
        assertThat(tokenDetails.getMaskedAccessToken(), is("*****3456789"));
    }

    @Test
    void getMaskedRefreshToken() {
        TokenDetails tokenDetails = new TokenDetails();
        assertThat(tokenDetails.getMaskedRefreshToken(), is(nullValue()));
        tokenDetails.setRefreshToken("0123456789");
        assertThat(tokenDetails.getMaskedRefreshToken(), is("*****3456789"));
    }
}