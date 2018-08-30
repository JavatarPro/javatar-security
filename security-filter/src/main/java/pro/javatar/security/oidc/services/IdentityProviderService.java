package pro.javatar.security.oidc.services;


import pro.javatar.security.oidc.model.TokenDetails;

public interface IdentityProviderService {

    TokenDetails getNotExpiredToken(String accessToken, String refreshToken);

}
