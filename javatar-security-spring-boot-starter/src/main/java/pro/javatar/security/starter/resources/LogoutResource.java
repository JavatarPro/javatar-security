package pro.javatar.security.starter.resources;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pro.javatar.secret.storage.api.SecretStorageService;
import pro.javatar.security.starter.util.CookieUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * TODO move to security-api-gateway module
 * @author Borys Zora
 * @author Andrii Murashkin
 * @author Serhii Petrychenko
 *
 * @version 2019-05-08
 */
@ConditionalOnProperty(value = "javatar.security.logout-url",  matchIfMissing = false)
@RestController
@RequestMapping(value = "/logout", produces = MediaType.APPLICATION_JSON_VALUE)
public class LogoutResource {

    private SecretStorageService secretService;

    @Autowired
    public LogoutResource(SecretStorageService secretService) {
        this.secretService = secretService;
    }

    @PostMapping
    public ResponseEntity logout(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String secretKey = CookieUtil.getCookie("tokenID", cookies);
        // TODO remove parent vault key, rotate keys more frequently
        secretService.delete(secretKey);
        return ResponseEntity.ok().build();
    }

}