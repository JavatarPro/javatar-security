package pro.javatar.security.api.model;

import java.time.Duration;
import java.time.Instant;

/**
 * @author Borys Zora
 * @version 2019-07-20
 */
public class TokenExpirationInfoBO {

    private Instant issuedAt;

    private Instant expiration;

    public TokenExpirationInfoBO() {}

    public TokenExpirationInfoBO(long issuedAt, long expiration) {
        this.issuedAt = Instant.ofEpochSecond(issuedAt);
        this.expiration = Instant.ofEpochSecond(expiration);
    }

    // helper methods

    public Duration getTokenExpirationDuration() {
        return Duration.between(issuedAt, expiration);
    }

    public Duration getTokenLifetimeDuration() {
        return Duration.between(issuedAt, Instant.now());
    }

    public boolean isDurationPassed(Duration duration) {
        return isDurationPassed(duration, Instant.now());
    }

    public boolean isDurationPassed(Duration duration, Instant comparing) {
        return issuedAt.plus(duration).isBefore(comparing);
    }

    public boolean isExpired() {
        return expiration.isBefore(Instant.now());
    }

    /**
     * @param part - token percentage expiration e.g. 0.3 -> 30% or 0.75 -> 75% of token time already passed,
     *             closer to expiration
     * @return boolean does part already spent
     */
    public boolean isPartLifetimePassed(double part) {
        Duration tokenDurationAllowedByIdentityProvider = getTokenExpirationDuration();
        Duration actualTokenDuration = getTokenLifetimeDuration();
        return tokenDurationAllowedByIdentityProvider.toMillis() * 1.0 * part < actualTokenDuration.toMillis();
}

    // getters & setters

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Instant getExpiration() {
        return expiration;
    }

    public void setExpiration(Instant expiration) {
        this.expiration = expiration;
    }

    @Override
    public String toString() {
        return "TokenExpirationInfoBO{" +
                "issuedAt=" + issuedAt +
                ", expiration=" + expiration +
                '}';
    }
}


