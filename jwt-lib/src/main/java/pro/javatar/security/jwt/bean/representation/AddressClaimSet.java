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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

/**
* @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
* @version $Revision: 1 $
*/
public class AddressClaimSet implements Serializable{
    private static final long serialVersionUID = 1805133041950251207L;

    public static final String FORMATTED = "formatted";
    public static final String STREET_ADDRESS = "street_address";
    public static final String LOCALITY = "locality";
    public static final String REGION = "region";
    public static final String POSTAL_CODE = "postal_code";
    public static final String COUNTRY = "country";

    @JsonProperty(FORMATTED)
    private String formattedAddress;

    @JsonProperty(STREET_ADDRESS)
    private String streetAddress;

    @JsonProperty(LOCALITY)
    private String locality;

    @JsonProperty(REGION)
    private String region;

    @JsonProperty(POSTAL_CODE)
    private String postalCode;

    @JsonProperty(COUNTRY)
    private String country;

    public String getFormattedAddress() {
        return this.formattedAddress;
    }

    public void setFormattedAddress(String formattedAddress) {
        this.formattedAddress = formattedAddress;
    }

    public String getStreetAddress() {
        return this.streetAddress;
    }

    public void setStreetAddress(String streetAddress) {
        this.streetAddress = streetAddress;
    }

    public String getLocality() {
        return this.locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getRegion() {
        return this.region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getPostalCode() {
        return this.postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    public String getCountry() {
        return this.country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

}
