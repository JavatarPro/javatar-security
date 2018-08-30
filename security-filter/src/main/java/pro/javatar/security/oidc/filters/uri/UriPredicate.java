package pro.javatar.security.oidc.filters.uri;

import org.springframework.http.HttpRequest;

import java.util.Objects;
import java.util.function.Predicate;

public class UriPredicate {

    public static Predicate<UriFilterOption> httpMethodEquals(HttpRequest request) {
        return p -> {
            if (p.getHttpMethod().isPresent() &&
                    !Objects.equals(request.getMethod(), p.getHttpMethod().get())) {
                return false;
            }
            return true;
        };
    }

    public static Predicate<UriFilterOption> uriContains(HttpRequest request) {
        return p -> request.getURI().getPath().contains(p.getUri());
    }

    public static Predicate<UriFilterOption> uriEquals(HttpRequest request) {
        return p -> request.getURI().getPath().equals(p.getUri());
    }

    public static Predicate<UriFilterOption> uriStarts(HttpRequest request) {
        return p -> request.getURI().getPath().startsWith(p.getUri());
    }
}
