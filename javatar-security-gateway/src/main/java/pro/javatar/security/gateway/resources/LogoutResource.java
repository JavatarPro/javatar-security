package pro.javatar.security.gateway.resources;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pro.javatar.secret.storage.api.SecretStorageService;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;
import pro.javatar.security.gateway.service.impl.util.CookieUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Borys Zora
 * @author Andrii Murashkin
 * @author Serhii Petrychenko
 *
 * @version 2019-05-08
 */
@ConditionalOnProperty(value = "javatar.security.logout.enabled", havingValue = "true", matchIfMissing = false)
@RestController
@RequestMapping(value = "/logout", produces = MediaType.APPLICATION_JSON_VALUE)
public class LogoutResource {

    private GatewaySecurityService gatewaySecurityService;

    private SecretStorageService secretService;

    @Autowired
    public LogoutResource(GatewaySecurityService gatewaySecurityService) {
        this.gatewaySecurityService = gatewaySecurityService;
    }

    @PostMapping
    public ResponseEntity logout(HttpServletRequest request,
                                 HttpServletResponse response) {
        gatewaySecurityService.logout(request, response);
        return ResponseEntity.ok().build();
    }

}