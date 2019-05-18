package pro.javatar.security.oidc.utils;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Borys Zora
 * @version 2019-05-18
 */
@Configuration
public class SpringTestConfig {

    @Bean
    public JsonMessageBuilder messageBuilder() {
        return new JsonMessageBuilder("http://jira.javatar.pro/confluence/x/TgZmAQ");
    }

}
