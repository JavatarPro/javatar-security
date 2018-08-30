/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pro.javatar.security.jwt.adapter;

import pro.javatar.security.jwt.RSATokenVerifier;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AdapterRSATokenVerifier {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(AdapterRSATokenVerifier.class);

    public static AccessToken verifyToken(PublicKey publicKey, String token, String realm)
            throws  TokenExpirationException, VerificationException {
        return verifyToken(publicKey, token, realm, true, true);
    }

    public static AccessToken verifyToken(String publicB62key, String token, String realm)
            throws  TokenExpirationException, VerificationException {
        return verifyToken(publicB62key, token, realm,  true, true);
    }


    @SuppressWarnings("WeakerAccess")
    public static AccessToken verifyToken(PublicKey publicKey, String token, String realm,
                                          boolean checkActive, boolean checkTokenType)
            throws TokenExpirationException, VerificationException {
        RSATokenVerifier verifier =
                RSATokenVerifier.create(token).realmUrl(realm).checkActive(checkActive).checkTokenType(checkTokenType);
        //        PublicKey publicKey = getPublicKey(verifier.getHeader().getKeyId(), deployment);
        return verifier.publicKey(publicKey).verify().getToken();
    }

    public static AccessToken verifyToken(String publicB62key, String token, String realm,
                                          boolean checkActive, boolean checkTokenType)
            throws TokenExpirationException, VerificationException {
        PublicKey publicKey;
        try {
            publicKey = getPublicKey(publicB62key);
        } catch (Exception e) {
            logger.error("Could not get public key", e);
            throw new VerificationException("", e);
        }
        return verifyToken(publicKey, token, realm, checkActive, checkTokenType);
    }

    @SuppressWarnings("WeakerAccess")
    public static PublicKey getPublicKey(String publicB62key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicBytes = Base64.decodeBase64(publicB62key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}
