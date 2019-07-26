package pro.javatar.security.impl.coverter;

import org.junit.Before;
import org.junit.Test;
import pro.javatar.security.api.model.TokenExpirationInfoBO;
import pro.javatar.security.api.model.User;

import java.time.Duration;
import java.time.Instant;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

/**
 * @author Borys Zora
 * @version 2019-04-21
 */
public class AccessTokenConverterTest {

    AccessTokenConverter converter = new AccessTokenConverter();

    String token;

    @Before
    public void setUp() throws Exception {
        token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwWFljSnBMcFJBd0FHLTNjalpZZC1iLVZRRlFaSklMNHhZWmZ6ZHVuUy1ZIn0.eyJqdGkiOiJjMTQzYWQwMy02NzJiLTRlNjktODBkYi1hNjcxODM5NDEyMjEiLCJleHAiOjE1NTU3OTk0MTUsIm5iZiI6MCwiaWF0IjoxNTU1Nzk5MTE1LCJpc3MiOiJodHRwOi8vMTk1LjIwMS4xMTAuMTIzOjQ4NjY2L2F1dGgvcmVhbG1zL2RldiIsImF1ZCI6Indvcmstc2VydmljZSIsInN1YiI6IjM1NmYxZTk5LTJjNzQtNDk4Zi1hNTQ4LWJiNzE0ZjZkZDdiNiIsInR5cCI6IkJlYXJlciIsImF6cCI6Indvcmstc2VydmljZSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImZjN2E1MTBjLTdmZTgtNDA3Zi05ODUzLTM0NjcyZjk4ODVjYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IkJvcnlzIFpvcmEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJib3J5cyIsImdpdmVuX25hbWUiOiJCb3J5cyIsImZhbWlseV9uYW1lIjoiWm9yYSIsImVtYWlsIjoiYm9yeXMuem9yYUBqYXZhdGFyLnBybyJ9.YvT7lw_TbV2mCjArpxqC2W8VISQgEYLVeuPc_DJKS60b5FAIPrfofyc80MKqMflavm02Ds4MxngNRV7CeHy5es3R8qqnZA07uzOkGQLETEXzQOAE5veklMLKdxjN0UKqwPKzWQbSTNNyZ2Z8l8Q9e7pInwevQ4ehztMvVuJbvRcPP_q8EHRyS9yUCtwI5QF8PbS7DAD6XIGapy6zICsrrwU6IPsiZJsdD1NylvvHAFga1z1Yj-YEmwq5BGnj_FKklL-tR5desPMezco6VDeyC_L0lJ5T_B9q8We2l-ldtfg7oi7_ywnz0SDGEV-2XyuqFL0M1L6tPYiUecP47qp-mg";
    }

    @Test
    public void toUserFromAccessToken() {
        User user = converter.toUserFromAccessToken(token);
        assertThat(user.getId(), is("356f1e99-2c74-498f-a548-bb714f6dd7b6"));
        assertThat(user.getEmail(), is("borys.zora@javatar.pro"));
        assertThat(user.getName(), is("Borys Zora"));
        assertThat(user.getGivenName(), is("Borys"));
        assertThat(user.getFamilyName(), is("Zora"));
        assertThat(user.getPreferredUsername(), is("borys"));
        assertThat(user.getEmailVerified(), is(false));
        assertThat(user.getScope(), is("profile email"));
    }

    @Test
    public void toTokenExpirationInfoBO() throws Exception {
        TokenExpirationInfoBO tokenExpiration = converter.toTokenExpirationInfoBO(token);
        assertThat(tokenExpiration.getIssuedAt(), is(Instant.parse("2019-04-20T22:25:15Z")));
        assertThat(tokenExpiration.getExpiration(), is(Instant.parse("2019-04-20T22:30:15Z")));
        assertThat(tokenExpiration.getTokenExpirationDuration(), is(Duration.parse("PT5M")));
    }
}