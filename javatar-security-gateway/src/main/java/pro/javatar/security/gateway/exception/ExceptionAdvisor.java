package pro.javatar.security.gateway.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import pro.javatar.security.gateway.model.GatewayErrorResponseTO;

import java.time.Instant;

/**
 * @author Borys Zora
 * @version 2019-07-24
 */
@ControllerAdvice
public class ExceptionAdvisor {

    private static final Logger logger = LoggerFactory.getLogger(ExceptionAdvisor.class);

    @ExceptionHandler(GatewayRestException.class)
    public ResponseEntity<GatewayErrorResponseTO> handleJavatarGatewayRestException(GatewayRestException e) {
        logger.error(e.getMessage(), e);
        GatewayErrorResponseTO errorResponseTO = toGatewayErrorResponseTO(e);
        return ResponseEntity.status(e.getStatus())
                .body(errorResponseTO);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<GatewayErrorResponseTO> handleSpringSecurityException(AccessDeniedException e) {
        logger.error(e.getMessage(), e);
        HttpStatus status = HttpStatus.FORBIDDEN;
        GatewayErrorResponseTO errorResp = new GatewayErrorResponseTO();
        errorResp.setCode("403.spring.access.denied.method.level");
        errorResp.setMessage(e.getMessage());
        errorResp.setDevMessage("Access denied on method level");
        errorResp.setDateTime(Instant.now());
        errorResp.setL18Code("403.spring.access.denied.method.level");
        errorResp.setStatus(status.value() + " " + status.getReasonPhrase());
        return ResponseEntity.status(status)
                .body(errorResp);
    }

    GatewayErrorResponseTO toGatewayErrorResponseTO(GatewayRestException ex) {
        GatewayErrorResponseTO errorResp = new GatewayErrorResponseTO();
        errorResp.setCode(ex.getCode());
        errorResp.setMessage(ex.getMessage());
        errorResp.setDevMessage(ex.getDevMessage());
        errorResp.setDateTime(Instant.now());
        errorResp.setL18Code(ex.getL18Code());
        errorResp.setStatus(ex.getStatus().value() + " " + ex.getStatus().getReasonPhrase());
        return errorResp;
    }
}
