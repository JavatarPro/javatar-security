package pro.javatar.security.gateway.service.impl;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * @author Borys Zora
 * @version 2020-11-15
 */
public class GatewaySecurityServiceImplTest {

    GatewaySecurityServiceImpl service;

    @Before
    public void setUp() throws Exception {
        service = new GatewaySecurityServiceImpl(null, null, null,
                null, null, null, null, null);
    }

    @Test
    public void retrieveSubdomain() {
        assertThat(service.retrieveFirstSubdomain("javatar.com"), is(nullValue()));
        assertThat(service.retrieveFirstSubdomain("dev-work.javatar.com"), is("dev-work"));
        assertThat(service.retrieveFirstSubdomain("feature.dev-work.javatar.com"), is("dev-work"));
        assertThat(service.retrieveFirstSubdomain("dev-work.javatar.com:8080"), is("dev-work"));
    }

}