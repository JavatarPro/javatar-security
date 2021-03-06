package pro.javatar.security.gateway.resources;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The aim of this class is to prevent of exchanging all issued tokens for the logged in user
 * who trigger this endpoint
 *
 * @author Borys Zora
 * @author Andrii Murashkin
 * @author Serhii Petrychenko
 *
 * @version 2019-05-08
 */
@ConditionalOnProperty(value = "javatar.security.gateway.logout-enabled", havingValue = "true", matchIfMissing = false)
@RestController
@RequestMapping(value = "/logout", produces = MediaType.APPLICATION_JSON_VALUE)
public class LogoutResource {

    private GatewaySecurityService gatewaySecurityService;

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