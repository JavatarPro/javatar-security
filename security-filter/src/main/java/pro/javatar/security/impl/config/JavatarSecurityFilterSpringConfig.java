package pro.javatar.security.impl.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author Borys Zora
 * @version 2019-06-09
 */
@Configuration
@ComponentScan(basePackages = {
        "pro.javatar.security.impl",
        "pro.javatar.security.oidc" // TODO move all to impl package
})
public class JavatarSecurityFilterSpringConfig {

}
