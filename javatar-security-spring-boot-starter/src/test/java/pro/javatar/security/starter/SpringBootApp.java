package pro.javatar.security.starter;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

/**
 * @author Borys Zora
 * @version 2019-05-11
 */
@SpringBootApplication(scanBasePackages = "pro.javatar.security.starter.config", exclude = SecurityAutoConfiguration.class)
public class SpringBootApp {

}
