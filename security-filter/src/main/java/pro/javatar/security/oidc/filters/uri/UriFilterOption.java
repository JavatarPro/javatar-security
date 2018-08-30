package pro.javatar.security.oidc.filters.uri;

import pro.javatar.security.oidc.utils.StringUtils;

import org.springframework.http.HttpMethod;

import java.text.MessageFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class UriFilterOption {

    private static final Pattern URI_PATTERN = Pattern.compile("^((GET|POST|PUT|DELETE|PATCH) )?((/|\\*).*)$");
    private static final UriFilterOption EMPTY = new UriFilterOption("");

    String uri;
    Optional<HttpMethod> httpMethod;

    public UriFilterOption(String uri) {
        this(uri, Optional.empty());
    }

    public UriFilterOption(String uri, Optional<HttpMethod> httpMethod) {
        Objects.requireNonNull(uri);
        Objects.requireNonNull(httpMethod);
        this.uri = uri;
        this.httpMethod = httpMethod;
    }

    public String getUri() {
        return uri;
    }

    public Optional<HttpMethod> getHttpMethod() {
        return httpMethod;
    }

    public boolean isEmpty() {
        return StringUtils.isBlank(getUri()) && !httpMethod.isPresent();
    }

    public boolean isNotEmpty() {
        return !isEmpty();
    }

    public static UriFilterOption fromString(String value) {
        if (StringUtils.isBlank(value)) {
            return UriFilterOption.EMPTY;
        }
        Matcher matcher = URI_PATTERN.matcher(value);
        if (matcher.matches()) {
            String method = matcher.group(2);
            String uri = matcher.group(3);
            return new UriFilterOption(uri, Optional.ofNullable(HttpMethod.resolve(method)));
        }
        throw new IllegalArgumentException(
                MessageFormat.format("Value \"{0}\" does not match pattern \"{1}\"", value, URI_PATTERN.toString()));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UriFilterOption that = (UriFilterOption) o;
        return Objects.equals(uri, that.uri) &&
                Objects.equals(httpMethod, that.httpMethod);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uri, httpMethod);
    }

    @Override
    public String toString() {
        return "UriFilterOption{" +
                "uri='" + uri + '\'' +
                ", httpMethod=" + httpMethod +
                '}';
    }
}
