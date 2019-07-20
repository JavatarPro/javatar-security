package pro.javatar.security.starter.filter.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import pro.javatar.security.oidc.filters.AuthenticationControllerAdviceFilter;
import pro.javatar.security.oidc.filters.AuthenticationJwtBearerTokenAwareFilter;
import pro.javatar.security.oidc.filters.AuthenticationOAuth2RedirectAwareFilter;
import pro.javatar.security.oidc.filters.AuthenticationRealmAwareFilter;

/**
 * Filter configuration: in which order should be used filters as we have some dependencies
 * to not force developers to know this details of implementation we setup right order by ourselves
 * e.g. AuthenticationJwtBearerTokenAwareFilter should know realm and AuthenticationRealmAwareFilter could retrieve it
 *
 * @author Borys Zora
 * @version 2019-06-15
 */
@Configuration
public class JavatarSecurityFilterOrderConfiguration {

    @Autowired
    private AuthenticationRealmAwareFilter realmAwareFilter;

    @Autowired
    private AuthenticationControllerAdviceFilter controllerAdviceFilter;

    @Autowired
    private AuthenticationJwtBearerTokenAwareFilter bearerTokenAwareFilter;

    @Autowired
    private AuthenticationOAuth2RedirectAwareFilter redirectAwareFilter;

    @Bean
    public FilterRegistrationBean controllerAdviceFilter() {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(controllerAdviceFilter);
        registrationBean.setOrder(1);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean realmFilter() {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(realmAwareFilter);
        registrationBean.setOrder(3);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean redirectFilter() {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(redirectAwareFilter);
        registrationBean.setOrder(4);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean jwtFilter() {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(bearerTokenAwareFilter);
        registrationBean.setOrder(5);
        return registrationBean;
    }

}
