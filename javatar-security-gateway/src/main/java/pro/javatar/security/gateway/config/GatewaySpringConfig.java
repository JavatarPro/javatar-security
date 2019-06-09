package pro.javatar.security.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import pro.javatar.security.api.AuthService;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;
import pro.javatar.security.gateway.service.impl.GatewaySecurityServiceImpl;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
@Configuration
@EnableConfigurationProperties(GatewayConfigImpl.class)
@ComponentScan("pro.javatar.security.gateway")
public class GatewaySpringConfig {

}
