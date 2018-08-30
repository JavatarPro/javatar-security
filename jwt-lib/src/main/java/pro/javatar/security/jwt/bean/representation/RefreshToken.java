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

package pro.javatar.security.jwt.bean.representation;

import pro.javatar.security.jwt.utils.TokenUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RefreshToken extends AccessToken {

    private RefreshToken() {
        type(TokenUtil.TOKEN_TYPE_REFRESH);
    }

    /*
     * Deep copies issuer, subject, issuedFor, sessionState, realmAccess, and resourceAccess
     * from AccessToken.
     */
    public RefreshToken(AccessToken token) throws CloneNotSupportedException {
        this();
        this.setSessionState(token.getClientSession());
        this.issuer = token.issuer;
        this.subject = token.subject;
        this.issuedFor = token.issuedFor;
        this.setSessionState(token.getSessionState());
        this.setNonce(token.getNonce());
        this.audience = token.audience;
        if (token.getRealmAccess() != null) {
            setRealmAccess((Access) token.getRealmAccess().clone());
        }
        if (token.getResourceAccess() != null) {
            setResourceAccess(new HashMap<String, Access>());
            for (Map.Entry<String, Access> entry : token.getResourceAccess().entrySet()) {
                getResourceAccess().put(entry.getKey(), (Access) entry.getValue().clone());
            }
        }
    }
}
