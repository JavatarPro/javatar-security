package pro.javatar.security.gateway.converter;

import org.mapstruct.Mapper;
import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.gateway.model.AuthRequestTO;

/**
 * @author Borys Zora
 * @version 2019-06-01
 */
@Mapper(componentModel = "spring")
public interface GatewayConverter {

    AuthRequestBO toAuthRequestBO(AuthRequestTO loginRequest);

}
