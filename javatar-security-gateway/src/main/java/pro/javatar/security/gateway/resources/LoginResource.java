package pro.javatar.security.gateway.resources;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.gateway.converter.GatewayConverter;
import pro.javatar.security.gateway.model.AuthRequestTO;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Andrii Murashkin / Javatar LLC
 * @author Borys Zora / Javatar LLC
 * @version 2019-05-28
 */
@ConditionalOnProperty(value = "javatar.security.gateway.login.enabled", havingValue = "true", matchIfMissing = false)
@RestController
@RequestMapping(value = "/login",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
public class LoginResource {

    private static final Logger logger = LoggerFactory.getLogger(LoginResource.class);

    private GatewaySecurityService gatewaySecurityService;

    private GatewayConverter converter;

    @Autowired
    public LoginResource(GatewaySecurityService gatewaySecurityService,
                         GatewayConverter converter) {
        this.gatewaySecurityService = gatewaySecurityService;
        this.converter = converter;
        logger.info("LoginResource created");
    }

    @PostMapping
    public ResponseEntity login(@RequestBody AuthRequestTO loginRequest,
                                HttpServletRequest request,
                                HttpServletResponse response) {
        logger.info("received login request: {}", loginRequest);
        AuthRequestBO authRequestBO = converter.toAuthRequestBO(loginRequest);
        String rootToken = gatewaySecurityService.login(authRequestBO, request, response);
        logger.info("rootToken: {} was issued for loginRequest: {}", rootToken, loginRequest);
        Map<String, String> body = new HashMap<>();
        body.put("login", "success");
        return ResponseEntity.created(null)
                .body(body); // TODO add more info about session expiration
    }

}
