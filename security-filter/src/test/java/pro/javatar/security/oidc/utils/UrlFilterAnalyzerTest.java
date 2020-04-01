package pro.javatar.security.oidc.utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;

public class UrlFilterAnalyzerTest {

    private UrlFilterAnalyzer urlFilterAnalyzer;

    @BeforeEach
    public void setUp() {
        urlFilterAnalyzer = new UrlFilterAnalyzer();
    }

    @Test
    public void getApplyAsContainingFilter() {
        assertThat(urlFilterAnalyzer.getApplyAsContainingFilter("/test/get"), is(nullValue()));
        assertThat(urlFilterAnalyzer.getApplyAsContainingFilter("*/test/get"), is(nullValue()));

        assertThat(urlFilterAnalyzer.getApplyAsContainingFilter("*/test/get*"), is("/test/get"));
        assertThat(urlFilterAnalyzer.getApplyAsContainingFilter("*/test/*get"), is("/test/"));
    }

    @Test
    public void applyAsStartingPattern() {
        assertThat(urlFilterAnalyzer.getApplyAsStartingFilter("/test/get"), is(nullValue()));
        assertThat(urlFilterAnalyzer.getApplyAsStartingFilter("/test/get*"), is("/test/get"));
    }
}