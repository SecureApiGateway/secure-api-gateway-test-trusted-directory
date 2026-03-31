/*
 * Copyright © 2020-2026 Ping Identity Corporation (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.test.trusted.directory.dto;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SsaRequest {

    @JsonProperty("software_id")
    private String softwareId;

    @JsonProperty("software_client_name")
    private String softwareClientName;

    @JsonProperty("software_client_id")
    private String softwareClientId;

    @JsonProperty("software_tos_uri")
    private String softwareTosUri;

    @JsonProperty("software_client_description")
    private String softwareClientDescription;

    @JsonProperty("software_redirect_uris")
    private List<String> softwareRedirectUris;

    @JsonProperty("software_policy_uri")
    private String softwarePolicyUri;

    @JsonProperty("software_logo_uri")
    private String softwareLogoUri;

    @JsonProperty("software_roles")
    private List<String> softwareRoles;

    /** Optional: embed a JWKS directly instead of using the stored jwks_endpoint. */
    @JsonProperty("software_jwks")
    private Map<String, Object> softwareJwks;

    public String getSoftwareId() { return softwareId; }
    public void setSoftwareId(String softwareId) { this.softwareId = softwareId; }
    public String getSoftwareClientName() { return softwareClientName; }
    public void setSoftwareClientName(String softwareClientName) { this.softwareClientName = softwareClientName; }
    public String getSoftwareClientId() { return softwareClientId; }
    public void setSoftwareClientId(String softwareClientId) { this.softwareClientId = softwareClientId; }
    public String getSoftwareTosUri() { return softwareTosUri; }
    public void setSoftwareTosUri(String softwareTosUri) { this.softwareTosUri = softwareTosUri; }
    public String getSoftwareClientDescription() { return softwareClientDescription; }
    public void setSoftwareClientDescription(String softwareClientDescription) { this.softwareClientDescription = softwareClientDescription; }
    public List<String> getSoftwareRedirectUris() { return softwareRedirectUris; }
    public void setSoftwareRedirectUris(List<String> softwareRedirectUris) { this.softwareRedirectUris = softwareRedirectUris; }
    public String getSoftwarePolicyUri() { return softwarePolicyUri; }
    public void setSoftwarePolicyUri(String softwarePolicyUri) { this.softwarePolicyUri = softwarePolicyUri; }
    public String getSoftwareLogoUri() { return softwareLogoUri; }
    public void setSoftwareLogoUri(String softwareLogoUri) { this.softwareLogoUri = softwareLogoUri; }
    public List<String> getSoftwareRoles() { return softwareRoles; }
    public void setSoftwareRoles(List<String> softwareRoles) { this.softwareRoles = softwareRoles; }
    public Map<String, Object> getSoftwareJwks() { return softwareJwks; }
    public void setSoftwareJwks(Map<String, Object> softwareJwks) { this.softwareJwks = softwareJwks; }
}
