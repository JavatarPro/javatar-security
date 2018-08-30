package pro.javatar.security.oidc.utils;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class UrlFilterAnalyzerTest {

    private UrlFilterAnalyzer urlFilterAnalyzer;

    @Before
    public void setUp() throws Exception {
        urlFilterAnalyzer = new UrlFilterAnalyzer();
    }

    @Test
    public void getApplyAsContainingFilter() throws Exception {
        assertThat(urlFilterAnalyzer.getApplyAsContainingFilter("/test/get"), is(nullValue()));
        assertThat(urlFilterAnalyzer.getApplyAsContainingFilter("*/test/get"), is(nullValue()));

        assertThat(urlFilterAnalyzer.getApplyAsContainingFilter("*/test/get*"), is("/test/get"));
        assertThat(urlFilterAnalyzer.getApplyAsContainingFilter("*/test/*get"), is("/test/"));
    }

    @Test
    public void applyAsStartingPattern() throws Exception {
        assertThat(urlFilterAnalyzer.getApplyAsStartingFilter("/test/get"), is(nullValue()));
        assertThat(urlFilterAnalyzer.getApplyAsStartingFilter("/test/get*"), is("/test/get"));
    }
}