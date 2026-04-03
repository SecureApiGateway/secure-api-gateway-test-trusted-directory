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

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request body for the {@code POST /jwkms/apiclient/jwks/revokecert} endpoint.
 *
 * @param orgId      the unique identifier of the owning organisation
 * @param softwareId the unique identifier of the software whose key should be revoked
 * @param keyId      the {@code kid} of the key to remove from the software's JWKS
 */
public record RevokeCertRequest(
        @JsonProperty("org_id") String orgId,
        @JsonProperty("software_id") String softwareId,
        @JsonProperty("key_id") String keyId
) {
}
