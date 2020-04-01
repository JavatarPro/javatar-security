package pro.javatar.security.oidc.model;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import pro.javatar.security.oidc.filters.uri.UriFilterOption;

import org.springframework.http.HttpMethod;

import java.util.Optional;

class UriFilterOptionTest {

    @Test
    void fromString_anyUri() {
        UriFilterOption option = UriFilterOption.fromString("*");
        assertThat(option.getHttpMethod(), is(Optional.empty()));
        assertThat(option.getUri(), is("*"));

        option = UriFilterOption.fromString("/*");
        assertThat(option.getHttpMethod(), is(Optional.empty()));
        assertThat(option.getUri(), is("/*"));
    }

    @Test
    void fromString_methodAndUri() {
        UriFilterOption option = UriFilterOption.fromString("GET /resource");
        assertThat(option.getHttpMethod(), is(Optional.of(HttpMethod.GET)));
        assertThat(option.getUri(), is("/resource"));

        option = UriFilterOption.fromString("GET /resource/*");
        assertThat(option.getHttpMethod(), is(Optional.of(HttpMethod.GET)));
        assertThat(option.getUri(), is("/resource/*"));

        option = UriFilterOption.fromString("GET /*");
        assertThat(option.getHttpMethod(), is(Optional.of(HttpMethod.GET)));
        assertThat(option.getUri(), is("/*"));

        option = UriFilterOption.fromString("POST *");
        assertThat(option.getHttpMethod(), is(Optional.of(HttpMethod.POST)));
        assertThat(option.getUri(), is("*"));
    }

    @Test
    void fromString__invalidMethod() {
        assertThrows(IllegalArgumentException.class, () -> UriFilterOption.fromString("GETT /resource"));
    }

    @Test
    void fromString__empty() {
        UriFilterOption option = UriFilterOption.fromString("");
        assertTrue(option.isEmpty());
    }
}