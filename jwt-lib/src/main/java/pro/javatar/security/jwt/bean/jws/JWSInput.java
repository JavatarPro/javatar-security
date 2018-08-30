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

package pro.javatar.security.jwt.bean.jws;

import pro.javatar.security.jwt.exception.JwtException;
import pro.javatar.security.jwt.utils.Base64Url;
import pro.javatar.security.jwt.utils.JsonSerialization;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class JWSInput {
    private static final Logger logger = LoggerFactory.getLogger(JWSInput.class.getName());
    String wireString;
    String encodedHeader;
    String encodedContent;
    String encodedSignature;
    String encodedSignatureInput;
    JWSHeader header;
    byte[] content;
    byte[] signature;


    public JWSInput(String wire) throws JWSInputException {
        try {
            this.wireString = wire;
            String[] parts = wire.split("\\.");
            if (parts.length < 2 || parts.length > 3) throw new IllegalArgumentException("Parsing error");
            encodedHeader = parts[0];
            encodedContent = parts[1];
            encodedSignatureInput = encodedHeader + '.' + encodedContent;
            content = Base64Url.decode(encodedContent);
            if (parts.length > 2) {
                encodedSignature = parts[2];
                signature = Base64Url.decode(encodedSignature);

            }
            byte[] headerBytes = Base64Url.decode(encodedHeader);
            header = JsonSerialization.readValue(headerBytes, JWSHeader.class);
        } catch (Exception t) {
            logger.error("Initialization exception", t);
            throw new JWSInputException(t);
        }
    }

    public String getWireString() {
        return wireString;
    }

    public String getEncodedHeader() {
        return encodedHeader;
    }

    public String getEncodedContent() {
        return encodedContent;
    }

    public String getEncodedSignature() {
        return encodedSignature;
    }
    public String getEncodedSignatureInput() {
        return encodedSignatureInput;
    }

    public JWSHeader getHeader() {
        return header;
    }

    public byte[] getContent() {
        return content;
    }

    public byte[] getSignature() {
        return signature;
    }

    public boolean verify(String key) {
        if (header.getAlgorithm().getProvider() == null) {
            logger.error("signing algorithm not supported");
            throw new JwtException("signing algorithm not supported");
        }
        return header.getAlgorithm().getProvider().verify(this, key);
    }

    public <T> T readJsonContent(Class<T> type) throws JWSInputException {
        try {
            return JsonSerialization.readValue(content, type);
        } catch (IOException e) {
            logger.error("Read json content exception", e);
            throw new JWSInputException(e);
        }
    }

    public String readContentAsString() {
        try {
            return new String(content, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new JwtException(e.getMessage(), e);
        }
    }
}
