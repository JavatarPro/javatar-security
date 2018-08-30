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

package pro.javatar.security.jwt.utils;


import pro.javatar.security.jwt.exception.Base64UtilException;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class Base64Url {
    public static String encode(byte[] bytes) {
        String s = Base64.encodeBytes(bytes);
        s = s.split("=")[0]; // Remove any trailing '='s
        s = s.replace('+', '-'); // 62nd char of encoding
        s = s.replace('/', '_'); // 63rd char of encoding
        return s;
    }

    public static byte[] decode(String s) {
        String decoded = s.replace('-', '+') // 62nd char of encoding
                .replace('_', '/'); // 63rd char of encoding
        switch (decoded.length() % 4) // Pad with trailing '='s
        {
            case 0:
                break; // No pad chars in this case
            case 2:
                decoded += "==";
                break; // Two pad chars
            case 3:
                decoded += "=";
                break; // One pad char
            default:
                throw new Base64UtilException("Illegal base64url string!");
        }
        try {
            // KEYCLOAK-2479 : Avoid to try gzip decoding as for some objects, it may display exception to STDERR. And we know that object wasn't encoded as GZIP
            return Base64.decode(decoded, Base64.DONT_GUNZIP);
        } catch (Exception e) {
            throw new Base64UtilException(e.getMessage(), e);
        }
    }
}
