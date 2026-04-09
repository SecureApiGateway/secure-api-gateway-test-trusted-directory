/*
 * Copyright © 2024-2026 Ping Identity Corporation (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.directory.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.directory.ca.CaCertificateResource;

class SsaSigningServiceTest {

    private static final CaCertificateResource CA = CaCertificateResource.getInstance();

    private SsaSigningService service;
    private String expectedKeyId;

    @BeforeEach
    void setUp() {
        expectedKeyId = CA.getCertificate().getSerialNumber().toString(16);
        JWK publicJwk = RsaJWK.builder((RSAPublicKey) CA.getPublicKey())
                .keyId(expectedKeyId)
                .keyUse("sig")
                .algorithm(JwsAlgorithm.PS256)
                .build();
        JWKSet publicJwks = new JWKSet(List.of(publicJwk));
        service = new SsaSigningService(CA.getPrivateKey(), expectedKeyId, publicJwks);
    }

    @Test
    void shouldSignJwtContainingProvidedClaims() throws Exception {
        Map<String, Object> claims = Map.of("iss", "test-issuer", "sub", "test-subject");
        String jwt = service.sign(claims);

        assertThat(jwt).isNotBlank();
        // JWT compact format: header.payload.signature
        String[] parts = jwt.split("\\.");
        assertThat(parts).hasSize(3);
    }

    @Test
    void shouldEmbedKeyIdInJwtHeader() throws Exception {
        String jwt = service.sign(Map.of("iss", "test"));

        // Decode header (base64url part 0)
        String headerJson = new String(java.util.Base64.getUrlDecoder().decode(jwt.split("\\.")[0]));
        assertThat(headerJson).contains("\"kid\":\"" + expectedKeyId + "\"");
        assertThat(headerJson).contains("\"alg\":\"PS256\"");
    }

    @Test
    void shouldExposePublicJwks() {
        JWKSet jwks = service.getPublicJwks();

        assertThat(jwks).isNotNull();
        assertThat(jwks.getJWKsAsList()).hasSize(1);
        JWK key = jwks.getJWKsAsList().get(0);
        assertThat(key.getKeyId()).isEqualTo(expectedKeyId);
        assertThat(key.getUse()).isEqualTo("sig");
        // Public JWKS should not expose private key material
        assertThat(key.toPublicJwk()).isPresent();
    }

    @Test
    void shouldRejectNullConstructorParams() {
        JWKSet jwks = service.getPublicJwks();
        assertThatNullPointerException()
                .isThrownBy(() -> new SsaSigningService(null, expectedKeyId, jwks))
                .withMessageContaining("signingPrivateKey");
        assertThatNullPointerException()
                .isThrownBy(() -> new SsaSigningService(CA.getPrivateKey(), null, jwks))
                .withMessageContaining("keyId");
        assertThatNullPointerException()
                .isThrownBy(() -> new SsaSigningService(CA.getPrivateKey(), expectedKeyId, null))
                .withMessageContaining("publicJwks");
    }
}
