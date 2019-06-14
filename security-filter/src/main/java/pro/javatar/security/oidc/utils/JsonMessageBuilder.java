package pro.javatar.security.oidc.utils;

import static java.time.format.DateTimeFormatter.ISO_DATE_TIME;
import static pro.javatar.security.oidc.utils.StringUtils.defaultIfBlank;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.exceptions.AuthenticationException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class JsonMessageBuilder {

    private static final String DEFAULT_ERROR_DESCRIPTION_LINK = "http://jira.javatar.pro/confluence/x/TgZmAQ";

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private String descriptionLink;

    @Autowired
    public JsonMessageBuilder(SecurityConfig config) {
        this.descriptionLink = defaultIfBlank(config.errorDescriptionLink(), DEFAULT_ERROR_DESCRIPTION_LINK);
    }

    public String authenticationExceptionBodyJson(AuthenticationException ex) throws JsonProcessingException {
        return objectMapper.writeValueAsString(authenticationExceptionBody(ex));
    }

    private Map<String, String> authenticationExceptionBody(AuthenticationException ex) {
        Map<String, String> errorBody = new HashMap<>();
        String status = ex.getStatus() != null ? ex.getStatus().toString() : "";

        errorBody.put("status",         status);
        errorBody.put("internalStatus", ex.getCode());
        errorBody.put("message",        ex.getMessage());
        errorBody.put("devMessage",     ex.getDevMessage());
        errorBody.put("dateTime",       LocalDateTime.now().format(ISO_DATE_TIME));
        errorBody.put("errorDescription", StringUtils.isNotBlank(ex.getLink()) ? ex.getLink() : descriptionLink);
        return errorBody;
    }
}
