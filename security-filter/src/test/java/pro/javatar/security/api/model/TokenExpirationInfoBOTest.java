package pro.javatar.security.api.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

/**
 * @author Borys Zora
 * @version 2019-07-22
 */
class TokenExpirationInfoBOTest {

    TokenExpirationInfoBO token;

    @BeforeEach
    void setUp() {
        token = new TokenExpirationInfoBO(1555799115, 1555799415);
    }

    @Test
    void getTokenExpirationDuration() {
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(1555799115, 1555799415);
        Duration actualDuration = token.getTokenExpirationDuration();
        assertThat(actualDuration, is(Duration.parse("PT5M")));
    }

    @Test
    void getTokenLifetimeDuration() {
        long issueToken = Instant.now().minusSeconds(150).toEpochMilli() / 1000;
        long expiration = Instant.now().plusSeconds(150).toEpochMilli() /1000;
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(issueToken, expiration);
        Duration tokenLifetimeDuration = token.getTokenLifetimeDuration();
        assertThat(tokenLifetimeDuration.minus(Duration.parse("PT2M30S")).getSeconds() < 5, is(true));
    }

    @Test
    void isDurationPassed() {
        long issueToken = Instant.now().minusSeconds(150).toEpochMilli() / 1000;
        long expiration = Instant.now().plusSeconds(150).toEpochMilli() /1000;
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(issueToken, expiration);
        assertThat(token.isDurationPassed(Duration.parse("PT2M20S")), is(true));
        assertThat(token.isDurationPassed(Duration.parse("PT2M40S")), is(false));
    }

    @Test
    void isDurationPassed2Params() {
        Instant now = Instant.now();
        long issueToken = now.minusSeconds(150).toEpochMilli() / 1000;
        long expiration = now.plusSeconds(150).toEpochMilli() /1000;
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(issueToken, expiration);
        assertThat(token.isDurationPassed(Duration.parse("PT2M20S"), now), is(true));
        assertThat(token.isDurationPassed(Duration.parse("PT2M40S"), now), is(false));
    }

    @Test
    void isExpired() {
        Instant now = Instant.now();
        long issueToken = now.minusSeconds(350).toEpochMilli() / 1000;
        long expiration = now.minusSeconds(50).toEpochMilli() /1000;
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(issueToken, expiration);
        assertThat(token.isExpired(), is(true));
    }

    @Test
    void isNotExpired() {
        Instant now = Instant.now();
        long issueToken = now.minusSeconds(150).toEpochMilli() / 1000;
        long expiration = now.plusSeconds(150).toEpochMilli() /1000;
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(issueToken, expiration);
        assertThat(token.isExpired(), is(false));
    }

    @Test
    void isPartLifetimePassed30Percent() {
        Instant now = Instant.now();
        long issueToken = now.minusSeconds(300).toEpochMilli() / 1000;
        long expiration = now.plusSeconds(700).toEpochMilli() /1000;
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(issueToken, expiration);
        assertThat(token.isPartLifetimePassed(0.25), is(true));
        assertThat(token.isPartLifetimePassed(0.5), is(false));
        assertThat(token.isPartLifetimePassed(0.75), is(false));
    }

    @Test
    void isPartLifetimePassed60Percent() {
        Instant now = Instant.now();
        long issueToken = now.minusSeconds(600).toEpochMilli() / 1000;
        long expiration = now.plusSeconds(400).toEpochMilli() /1000;
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(issueToken, expiration);
        assertThat(token.isPartLifetimePassed(0.25), is(true));
        assertThat(token.isPartLifetimePassed(0.5), is(true));
        assertThat(token.isPartLifetimePassed(0.75), is(false));
    }

    @Test
    void isPartLifetimePassed80Percent() {
        Instant now = Instant.now();
        long issueToken = now.minusSeconds(800).toEpochMilli() / 1000;
        long expiration = now.plusSeconds(200).toEpochMilli() /1000;
        TokenExpirationInfoBO token = new TokenExpirationInfoBO(issueToken, expiration);
        assertThat(token.isPartLifetimePassed(0.25), is(true));
        assertThat(token.isPartLifetimePassed(0.5), is(true));
        assertThat(token.isPartLifetimePassed(0.75), is(true));
    }
}