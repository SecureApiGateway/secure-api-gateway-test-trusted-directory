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
package com.forgerock.sapi.gateway.test.trusted.directory.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaSigningService;

/**
 * Exposes the Test Trusted Directory's own JWKS (route 77).
 * Used by Secure API Gateway to verify SSA signatures.
 */
@RestController
@RequestMapping("/jwkms/testdirectory")
public class JwkmsDirectoryController {

    private final SsaSigningService ssaSigningService;

    /**
     * Creates the controller with the signing service used to retrieve the directory's public JWKS.
     *
     * @param ssaSigningService provides the directory's public JWKS for SSA signature verification
     */
    public JwkmsDirectoryController(SsaSigningService ssaSigningService) {
        this.ssaSigningService = ssaSigningService;
    }

    /**
     * Returns the directory's public JWKS, used by the Secure API Gateway to verify SSA signatures.
     *
     * @return {@code 200 OK} with the public JWKS JSON
     */
    @GetMapping(value = "/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getDirectoryJwks() {
        return ResponseEntity.ok(ssaSigningService.getPublicJwks().toJsonValue().getObject());
    }
}
