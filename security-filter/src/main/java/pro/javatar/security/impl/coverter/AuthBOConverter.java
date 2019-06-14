/*
 * Copyright (c) 2019 Javatar LLC
 * All rights reserved.
 */
package pro.javatar.security.impl.coverter;

import org.mapstruct.Mapper;
import pro.javatar.security.api.model.TokenInfoBO;
import pro.javatar.security.oidc.model.TokenDetails;

/**
 * @author Andrii Murashkin / Javatar LLC
 * @version 06-03-2019
 */
@Mapper(componentModel = "spring")
public interface AuthBOConverter {

    TokenInfoBO toTokenInfoBO(TokenDetails tokenDetails);

}
