package pro.javatar.security.oidc.utils;

import static java.time.format.DateTimeFormatter.ISO_DATE_TIME;

import pro.javatar.security.oidc.exceptions.AuthenticationException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Component
public class JsonMessageBuilder {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    @Value("${error.description.link: http://jira.javatar.pro/confluence/x/TgZmAQ}")
    private String descriptionLink;

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
