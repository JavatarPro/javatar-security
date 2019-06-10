package pro.javatar.security.gateway.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
@Configuration
@EnableConfigurationProperties(GatewayConfigImpl.class)
@ComponentScan("pro.javatar.security.gateway")
public class GatewaySpringConfig {

}
