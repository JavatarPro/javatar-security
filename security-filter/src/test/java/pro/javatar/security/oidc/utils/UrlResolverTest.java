package pro.javatar.security.oidc.utils;

import static org.hamcrest.MatcherAssert.assertThat;
import static pro.javatar.security.oidc.filters.uri.UriFilterOption.fromString;
import static pro.javatar.security.oidc.utils.MockHttpRequest.mockGetUri;
import static pro.javatar.security.oidc.utils.MockHttpRequest.mockMethodAndUri;
import static org.hamcrest.core.Is.is;

import org.junit.jupiter.api.Test;
import pro.javatar.security.oidc.filters.uri.UriFilterOption;

import org.springframework.http.HttpMethod;

import java.util.ArrayList;
import java.util.List;

class UrlResolverTest {

    @Test
    void apply() {
        List<UriFilterOption> applyFilters = new ArrayList<>();
        applyFilters.add(fromString("/test/get/11"));
        applyFilters.add(fromString("/test/list/*"));
        applyFilters.add(fromString("*test1*"));
        applyFilters.add(fromString("/test3/pupils"));

        List<UriFilterOption> ignoreFilters = new ArrayList<>();
        ignoreFilters.add(fromString("/test2/*"));
        ignoreFilters.add(fromString("*/test3/*"));

        UrlResolver resolver = new UrlResolver("^(\\/payments\\/.*\\/).*$", applyFilters, ignoreFilters);

        assertThat(resolver.apply(mockGetUri("/test/get/11")), is(true));
        assertThat(resolver.apply(mockGetUri("/test/list/students")), is(true));
        assertThat(resolver.apply(mockGetUri("/test/list/teachers")), is(true));
        assertThat(resolver.apply(mockGetUri("/test1/all")), is(true));
        assertThat(resolver.apply(mockGetUri("/test/test1/all")), is(true));

        assertThat(resolver.apply(mockGetUri("/test2/get/11")), is(false));
        assertThat(resolver.apply(mockGetUri("/test2")), is(false));
        assertThat(resolver.apply(mockGetUri("/test3/test")), is(false));
        assertThat(resolver.apply(mockGetUri("/test3/pupils")), is(false));
        assertThat(resolver.apply(mockGetUri("/another/url")), is(false));

        assertThat(resolver.apply(mockGetUri("/payments/get/*")), is(true));
        assertThat(resolver.apply(mockMethodAndUri(HttpMethod.POST,"/ota/post/*")), is(false));

        //empty filterApplyUrlRegex
        resolver = new UrlResolver("", applyFilters, ignoreFilters);
        assertThat(resolver.apply(mockGetUri("/payments/get/*")), is(false));
    }

    @Test
    void applyWithPriority() {
        List<UriFilterOption> applyFilters = new ArrayList<>();
        applyFilters.add(fromString("/test1/*"));

        List<UriFilterOption> ignoreFilters = new ArrayList<>();
        ignoreFilters.add(fromString("/test2/delete"));

        UrlResolver resolver = new UrlResolver("^\\/test2\\/.+$", applyFilters, ignoreFilters);

        assertThat(resolver.apply(mockMethodAndUri(HttpMethod.POST, "/test1/create")), is(true));
        assertThat(resolver.apply(mockMethodAndUri(HttpMethod.DELETE, "/test1/delete")), is(true));

        assertThat(resolver.apply(mockMethodAndUri(HttpMethod.POST,"/test2/create")), is(true));
        assertThat(resolver.apply(mockMethodAndUri(HttpMethod.PUT,"/test2/update")), is(true));
        assertThat(resolver.apply(mockMethodAndUri(HttpMethod.DELETE,"/test2/delete")), is(false));
    }

    @Test
    void applyWithHttpMethods() {
        List<UriFilterOption> applyFilters = new ArrayList<>();
        applyFilters.add(fromString("/test1/*"));

        List<UriFilterOption> ignoreFilters = new ArrayList<>();
        ignoreFilters.add(fromString("GET /test1/*"));
        ignoreFilters.add(fromString("GET /test2/id"));

        UrlResolver resolver = new UrlResolver("^\\/test2\\/.+$", applyFilters, ignoreFilters);

        assertThat(resolver.apply(mockMethodAndUri(HttpMethod.POST, "/test1/id")), is(true));
        assertThat(resolver.apply(mockMethodAndUri(HttpMethod.DELETE, "/test1/id")), is(true));
        assertThat("ignore starts", resolver.apply(mockMethodAndUri(HttpMethod.GET, "/test1/id")), is(false));
        assertThat("ignore equals", resolver.apply(mockMethodAndUri(HttpMethod.GET, "/test2/id?q=text")), is(false));
        assertThat("ignore equals", resolver.apply(mockMethodAndUri(HttpMethod.POST, "/test2/id")), is(true));
    }
}