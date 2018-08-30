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

package pro.javatar.security.jwt.bean.jws.crypto;


import pro.javatar.security.jwt.bean.jws.Algorithm;
import pro.javatar.security.jwt.bean.jws.JWSInput;
import pro.javatar.security.jwt.exception.JwtException;
import pro.javatar.security.jwt.utils.PemUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RSAProvider implements SignatureProvider {
    private static final Logger logger = LoggerFactory.getLogger(RSAProvider.class.getName());

    public static String getJavaAlgorithm(Algorithm alg) {
        switch (alg) {
            case RS256:
                return "SHA256withRSA";
            case RS384:
                return "SHA384withRSA";
            case RS512:
                return "SHA512withRSA";
            default:
                throw new IllegalArgumentException("Not an RSA Algorithm");
        }
    }

    public static Signature getSignature(Algorithm alg) {
        try {
            return Signature.getInstance(getJavaAlgorithm(alg));
        } catch (Exception e) {
            logger.error("Get signature exception: ", e.getMessage());
            throw new JwtException(e.getMessage(), e);
        }
    }

    public static byte[] sign(byte[] data, Algorithm algorithm, PrivateKey privateKey) {
        try {
            Signature signature = getSignature(algorithm);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            logger.error("Sign exception: ",  e.getMessage());
            throw new JwtException(e.getMessage(), e);
        }
    }

    public static boolean verifyViaCertificate(JWSInput input, String cert) {
        X509Certificate certificate = null;
        try {
            certificate = PemUtils.decodeCertificate(cert);
        } catch (Exception e) {
            logger.error("Verify via certificate exception: ",  e.getMessage());
            throw new JwtException(e.getMessage(), e);
        }
        return verify(input, certificate.getPublicKey());
    }

    public static boolean verify(JWSInput input, PublicKey publicKey) {
        try {
            Signature verifier = getSignature(input.getHeader().getAlgorithm());
            verifier.initVerify(publicKey);
            verifier.update(input.getEncodedSignatureInput().getBytes("UTF-8"));
            return verifier.verify(input.getSignature());
        } catch (Exception e) {
            logger.error("Verify exception: ",  e.getMessage());
            throw new JwtException(e.getMessage(), e);
        }

    }

    @Override
    public boolean verify(JWSInput input, String key) {
        return verifyViaCertificate(input, key);
    }
}
