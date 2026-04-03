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

/**
 * Request body for the {@code POST /jwkms/apiclient/getssa} endpoint.
 *
 * @param softwareId              the unique identifier of the software
 * @param softwareClientName      the display name of the software client
 * @param softwareClientId        the OAuth 2.0 client ID of the software
 * @param softwareTosUri          URI to the software's Terms of Service
 * @param softwareClientDescription human-readable description of the software client
 * @param softwareRedirectUris    the list of allowed redirect URIs for the software
 * @param softwarePolicyUri       URI to the software's privacy policy
 * @param softwareLogoUri         URI to the software's logo
 * @param softwareRoles           the list of roles assigned to the software (e.g. {@code PISP}, {@code AISP})
 * @param softwareJwks            optional inline JWKS; if present, embedded in the SSA instead of a JWKS endpoint URL
 */
public record SsaRequest(
        @JsonProperty("software_id") String softwareId,
        @JsonProperty("software_client_name") String softwareClientName,
        @JsonProperty("software_client_id") String softwareClientId,
        @JsonProperty("software_tos_uri") String softwareTosUri,
        @JsonProperty("software_client_description") String softwareClientDescription,
        @JsonProperty("software_redirect_uris") List<String> softwareRedirectUris,
        @JsonProperty("software_policy_uri") String softwarePolicyUri,
        @JsonProperty("software_logo_uri") String softwareLogoUri,
        @JsonProperty("software_roles") List<String> softwareRoles,
        @JsonProperty("software_jwks") Map<String, Object> softwareJwks
) {
}
