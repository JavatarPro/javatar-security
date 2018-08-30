package pro.javatar.security.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/security/{tenant}")
public class SecurityTestResource {

    private static final Logger logger = LoggerFactory.getLogger(SecurityTestResource.class);


    @ExceptionHandler(value = AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ResponseBody
    public String exception(Exception exception, WebRequest request) {
        return "Access is denied";
    }

    @PreAuthorize("hasAnyRole('USER_READ','USER_WRITE')")
    @RequestMapping(method = RequestMethod.GET, path = "/users/{id}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> getUser(String tenant, String id) {
        logger.info("get user for tenant: {} by id: {}", tenant, id);
        Map<String, String> result = new HashMap<>();
        result.put("userId", id);
        result.put("tenant", tenant);
        result.put("status", "ok");
        result.put("name", "Chuck");
        result.put("lastName", "Norris");
        return result;
    }

    @PreAuthorize("hasAnyRole('USER_WRITE')")
    @RequestMapping(method = RequestMethod.POST, path = "/users",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity createUser(String tenant,
                                     @RequestBody User user) {
        logger.info("user successfully created");
        Map<String, String> result = new HashMap<>();
        result.put("userId", UUID.randomUUID().toString());
        result.put("tenant", tenant);
        result.put("status", "created");
        result.put("name", user.getName());
        result.put("lastName", user.getLastName());
        return new ResponseEntity<>(result, HttpStatus.CREATED);
    }

    @PreAuthorize("hasAuthority('READ_DEV_CONFIG')")
    @RequestMapping(method = RequestMethod.GET, path = "/configs/dev",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity getDevConfig(@PathVariable String tenant) {
        return getResponseEntity(tenant);
    }

    @PreAuthorize("hasAnyRole('READ_QA_CONFIG')")
    @RequestMapping(method = RequestMethod.GET, path = "/configs/qa",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity getMatchSeatsAdminUrl(@PathVariable String tenant) {
        return getResponseEntity(tenant);
    }

    private ResponseEntity getResponseEntity(String tenant) {
        logger.info("user successfully created");
        UsernamePasswordAuthenticationToken user =
                (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        Map<String, String> result = new HashMap<>();
        result.put("tenant", tenant);
        result.put("username", user.getName());
        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    List<String> convert(Collection<GrantedAuthority> authorities) {
        List<String> result = new LinkedList<>();
        for(GrantedAuthority authority: authorities) {
            result.add(authority.getAuthority());
        }
        return result;
    }

}
