package pro.javatar.security.oidc.utils;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.mock.http.client.MockAsyncClientHttpRequest;

import java.net.URI;

public final class MockHttpRequest {

    public static HttpRequest mockGetUri(String uri) {
        return mockMethodAndUri(HttpMethod.GET, uri);
    }

    public static HttpRequest mockMethodAndUri(HttpMethod httpMethod, String uri) {
        return new MockAsyncClientHttpRequest(httpMethod, URI.create(uri));
    }

}
