package pro.javatar.security.oidc.utils;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class StringUtilsTest {

    @Test
    public void isBlank() throws Exception {
        assertThat(StringUtils.isBlank(null), is(true));
        assertThat(StringUtils.isBlank(""), is(true));
        assertThat(StringUtils.isBlank(" "), is(true));
        assertThat(StringUtils.isBlank("bob"), is(false));
        assertThat(StringUtils.isBlank(" bob   "), is(false));
    }

    @Test
    public void isNotBlank() throws Exception {
        assertThat(StringUtils.isNotBlank(null), is(false));
        assertThat(StringUtils.isNotBlank(""), is(false));
        assertThat(StringUtils.isNotBlank(" "), is(false));
        assertThat(StringUtils.isNotBlank("bob"), is(true));
        assertThat(StringUtils.isNotBlank(" bob   "), is(true));
    }

    @Test
    public void getMaskedString() throws Exception {
        assertThat(StringUtils.getMaskedString("1234567890"), is("*****4567890"));
        assertThat(StringUtils.getMaskedString("1234567890", 1), is("*****0"));
        assertThat(StringUtils.getMaskedString("1234567890", 2), is("*****90"));

        assertThat(StringUtils.getMaskedString("12345"), is("12345")); //less than default 7
        assertThat(StringUtils.getMaskedString("12", 1), is("*****2")); //less than default 7

        assertThat(StringUtils.getMaskedString(""), is(""));
        assertThat(StringUtils.getMaskedString(null), is(nullValue()));
    }
}