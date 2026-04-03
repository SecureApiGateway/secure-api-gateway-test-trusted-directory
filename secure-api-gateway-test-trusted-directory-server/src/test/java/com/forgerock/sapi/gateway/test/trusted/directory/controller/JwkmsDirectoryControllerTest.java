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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaSigningService;

@WebMvcTest(JwkmsDirectoryController.class)
class JwkmsDirectoryControllerTest {

    private static final CaCertificateResource CA = CaCertificateResource.getInstance();

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SsaSigningService ssaSigningService;

    @Test
    void shouldReturnDirectoryPublicJwks() throws Exception {
        String keyId = CA.getCertificate().getSerialNumber().toString(16);
        JWK publicJwk = RsaJWK.builder((RSAPublicKey) CA.getPublicKey())
                .keyId(keyId)
                .keyUse("sig")
                .algorithm(JwsAlgorithm.PS256)
                .build();
        when(ssaSigningService.getPublicJwks()).thenReturn(new JWKSet(Collections.singletonList(publicJwk)));

        mockMvc.perform(get("/jwkms/testdirectory/jwks"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kid").value(keyId))
                .andExpect(jsonPath("$.keys[0].use").value("sig"));
    }

    @Test
    void getDirectoryJwks_shouldReturn500WhenServiceThrows() throws Exception {
        when(ssaSigningService.getPublicJwks()).thenThrow(new RuntimeException("signing key unavailable"));

        mockMvc.perform(get("/jwkms/testdirectory/jwks"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").exists());
    }
}
