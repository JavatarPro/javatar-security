package pro.javatar.security.oidc.filters.uri;

import org.springframework.http.HttpMethod;

import java.util.Objects;
import java.util.function.Predicate;

public class UriPredicate {

    public static Predicate<UriFilterOption> httpMethodEquals(String method, String path) {
        return p -> {
            if (p.getHttpMethod().isPresent() &&
                    !Objects.equals(HttpMethod.resolve(method), p.getHttpMethod().get())) {
                return false;
            }
            return true;
        };
    }

    public static Predicate<UriFilterOption> uriContains(String path) {
        return p -> path.contains(p.getUri());
    }

    public static Predicate<UriFilterOption> uriEquals(String path) {
        return p -> path.equals(p.getUri());
    }

    public static Predicate<UriFilterOption> uriStarts(String path) {
        return p -> path.startsWith(p.getUri());
    }
}
