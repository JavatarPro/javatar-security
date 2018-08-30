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
import pro.javatar.security.jwt.exception.JwtException;
import pro.javatar.security.jwt.utils.Base64Url;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class HashProvider {
    private static final Logger logger = LoggerFactory.getLogger(HashProvider.class.getName());

    // See "at_hash" and "c_hash" in OIDC specification
    public static String oidcHash(Algorithm jwtAlgorithm, String input) {
        byte[] digest = digest(jwtAlgorithm, input);

        int hashLength = digest.length / 2;
        byte[] hashInput = Arrays.copyOf(digest, hashLength);

        return Base64Url.encode(hashInput);
    }

    private static byte[] digest(Algorithm algorithm, String input) {
        String digestAlg = getJavaDigestAlgorithm(algorithm);

        try {
            MessageDigest md = MessageDigest.getInstance(digestAlg);
            md.update(input.getBytes("UTF-8"));
            return md.digest();
        } catch (Exception e) {
            logger.error("Digest exception",  e.getMessage());
            throw new JwtException(e.getMessage(), e);
        }
    }

    private static String getJavaDigestAlgorithm(Algorithm alg) {
        switch (alg) {
            case RS256:
                return "SHA-256";
            case RS384:
                return "SHA-384";
            case RS512:
                return "SHA-512";
            default:
                throw new IllegalArgumentException("Not an RSA Algorithm");
        }
    }

}
