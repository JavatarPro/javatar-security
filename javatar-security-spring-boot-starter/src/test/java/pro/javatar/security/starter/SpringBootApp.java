package pro.javatar.security.starter;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import pro.javatar.security.starter.config.SecurityConfigImpl;

/**
 * @author Borys Zora
 * @version 2019-05-11
 */
//@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
//@EnableConfigurationProperties({SecurityConfigImpl.class})
@SpringBootApplication// (scanBasePackages = "pro.javatar")
public class SpringBootApp {

}
