package pro.javatar.security.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import pro.javatar.security.gateway.filter.TokenPreFilter;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
@Configuration
@EnableConfigurationProperties(GatewayConfigImpl.class)
@ComponentScan("pro.javatar.security.gateway")
public class GatewaySpringConfig {

    @Autowired
    private TokenPreFilter tokenPreFilter;

    @Bean
    public FilterRegistrationBean tokenPreFilterBean() {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(tokenPreFilter);
        registrationBean.setOrder(0);
        return registrationBean;
    }

}
