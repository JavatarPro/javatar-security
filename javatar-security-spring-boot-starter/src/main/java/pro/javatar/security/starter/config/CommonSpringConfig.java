package pro.javatar.security.starter.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import pro.javatar.security.impl.config.JavatarSecurityFilterSpringConfig;

/**
 * @author Borys Zora
 * @version 2019-05-19
 */
@Configuration
@Import(JavatarSecurityFilterSpringConfig.class)
public class CommonSpringConfig {

}
