package pro.javatar.security.oidc.model;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import pro.javatar.security.oidc.filters.uri.UriFilterOption;

import org.junit.Test;
import org.springframework.http.HttpMethod;

import java.util.Optional;

public class UriFilterOptionTest {

    @Test
    public void fromString_anyUri() throws Exception {
        UriFilterOption option = UriFilterOption.fromString("*");
        assertThat(option.getHttpMethod(), is(Optional.empty()));
        assertThat(option.getUri(), is("*"));

        option = UriFilterOption.fromString("/*");
        assertThat(option.getHttpMethod(), is(Optional.empty()));
        assertThat(option.getUri(), is("/*"));
    }

    @Test
    public void fromString_methodAndUri() throws Exception {
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

    @Test(expected = IllegalArgumentException.class)
    public void fromString__invalidMethod() {
        UriFilterOption.fromString("GETT /resource");
    }

    @Test
    public void fromString__empty() {
        UriFilterOption option = UriFilterOption.fromString("");
        assertTrue(option.isEmpty());
    }
}