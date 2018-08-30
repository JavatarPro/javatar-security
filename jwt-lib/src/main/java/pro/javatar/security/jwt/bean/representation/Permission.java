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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Permission implements Serializable{
    private static final long serialVersionUID = 1705122041945671207L;

    @JsonProperty("resource_set_id")
    private String resourceSetId;

    @JsonProperty("resource_set_name")
    private final String resourceSetName;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Set<String> scopes;

    public Permission() {
        this(null, null, null);
    }

    public Permission(final String resourceSetId, String resourceSetName, final Set<String> scopes) {
        this.resourceSetId = resourceSetId;
        this.resourceSetName = resourceSetName;
        this.scopes = scopes;
    }

    public String getResourceSetId() {
        return this.resourceSetId;
    }

    public String getResourceSetName() {
        return this.resourceSetName;
    }

    public Set<String> getScopes() {
        if (this.scopes == null) {
            this.scopes = new HashSet<>();
        }

        return this.scopes;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();

        builder.append("Permission {").append("id=").append(resourceSetId).append(", name=").append(resourceSetName)
                .append(", scopes=").append(scopes).append("}");

        return builder.toString();
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }
}
