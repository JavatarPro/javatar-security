package pro.javatar.security.starter.resources;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author Borys Zora
 * @version 2019-05-28
 */
@ConditionalOnProperty(value = "javatar.security.login-enabled", havingValue = "true", matchIfMissing = false)
@RequestMapping("/login")
public class LoginResource {


}
