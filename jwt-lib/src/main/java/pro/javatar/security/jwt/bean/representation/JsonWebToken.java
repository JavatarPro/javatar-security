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

import pro.javatar.security.jwt.json.StringOrArrayDeserializer;
import pro.javatar.security.jwt.json.StringOrArraySerializer;
import pro.javatar.security.jwt.utils.Time;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.io.Serializable;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class JsonWebToken implements Serializable {
    @JsonProperty("jti")
    protected String id;
    @JsonProperty("exp")
    protected int expiration;
    @JsonProperty("nbf")
    protected int notBefore;
    @JsonProperty("iat")
    protected int issuedAt;
    @JsonProperty("iss")
    protected String issuer;
    @JsonProperty("aud")
    @JsonSerialize(using = StringOrArraySerializer.class)
    @JsonDeserialize(using = StringOrArrayDeserializer.class)
    protected String[] audience;
    @JsonProperty("sub")
    protected String subject;
    @JsonProperty("typ")
    protected String type;
    @JsonProperty("azp")
    public String issuedFor;

    public String getId() {
        return id;
    }

    public JsonWebToken id(String id) {
        this.id = id;
        return this;
    }


    public int getExpiration() {
        return expiration;
    }

    public JsonWebToken expiration(int expiration) {
        this.expiration = expiration;
        return this;
    }

    @JsonIgnore
    public boolean isExpired() {
        return Time.currentTime() > expiration;
    }

    public int getNotBefore() {
        return notBefore;
    }

    public JsonWebToken notBefore(int notBefore) {
        this.notBefore = notBefore;
        return this;
    }


    @JsonIgnore
    public boolean isNotBefore() {
        return Time.currentTime() >= notBefore;
    }

    /*
     * Tests that the token is not expired and is not-before.
     */
    @JsonIgnore
    public boolean isActive() {
        return (!isExpired() || expiration == 0) && (isNotBefore() || notBefore == 0);
    }

    public int getIssuedAt() {
        return issuedAt;
    }

    /*
     * Set issuedAt to the current time
     */
    @JsonIgnore
    public JsonWebToken issuedNow() {
        issuedAt = Time.currentTime();
        return this;
    }

    public JsonWebToken issuedAt(int issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }


    public String getIssuer() {
        return issuer;
    }

    public JsonWebToken issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    @JsonIgnore
    public String[] getAudience() {
        return audience;
    }

    public boolean hasAudience(String audience) {
        for (String a : this.audience) {
            if (a.equals(audience)) {
                return true;
            }
        }
        return false;
    }

    public JsonWebToken audience(String... audience) {
        this.audience = audience;
        return this;
    }

    public String getSubject() {
        return subject;
    }

    public JsonWebToken subject(String subject) {
        this.subject = subject;
        return this;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getType() {
        return type;
    }

    public JsonWebToken type(String type) {
        this.type = type;
        return this;
    }

    /*
     * OAuth client the token was issued for.
     */
    public String getIssuedFor() {
        return issuedFor;
    }

    public JsonWebToken issuedFor(String issuedFor) {
        this.issuedFor = issuedFor;
        return this;
    }
}
