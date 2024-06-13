/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.test.trusted.directory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerServiceTest;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;

class SoftwareJwksServiceTest {

    private static final String ORG_ID = "Test-Corp-1234";
    private static final String ORG_NAME = "Test Corporation";
    private static final String SOFTWARE_ID = "software-1234";

    private final CaCertificateResource caCertificateResource = CaCertificateResource.getInstance();

    private SoftwareJwksService softwareJwksService;

    @BeforeEach
    public void beforeEach() {
        softwareJwksService = new SoftwareJwksService(new CertificateIssuerService(caCertificateResource.getCertificate(),
                caCertificateResource.getPrivateKey(), CaCertificateResource.DEFAULT_CA_CERT_SIGNING_ALG));
    }

    @Test
    void shouldIssueCertificatesForSoftware() {
        final JwsAlgorithm keyAlg = JwsAlgorithm.PS256;

        JWKSet softwareJwks = softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(keyAlg, 3096));

        assertThat(softwareJwks.getJWKsAsList()).hasSize(2);

        final JWK signingKey = softwareJwks.findJwk(keyAlg, "sig");
        assertThat(signingKey).isNotNull();
        CertificateIssuerServiceTest.validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, signingKey);

        final JWK transportKey = softwareJwks.findJwk(keyAlg, "tls");
        assertThat(transportKey).isNotNull();
        CertificateIssuerServiceTest.validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, transportKey);
    }

    @Test
    void shouldGetJwksContainingOnlyPublicKeyDataForSoftware() {
        JWKSet issuedJwks = softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID,
                new CertificateOptions(JwsAlgorithm.PS256, 3096));

        JWKSet retrievedJwks = softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID);
        final List<JWK> retrievedJwksList = retrievedJwks.getJWKsAsList();
        final List<JWK> issuedJwksList = issuedJwks.getJWKsAsList();
        assertThat(retrievedJwksList.size()).isEqualTo(issuedJwksList.size());
        assertThat(retrievedJwksList).noneMatch(JWK::isPrivate);
        assertThat(issuedJwksList).map(jwk -> jwk.toPublicJwk().get().toJsonString())
                .isEqualTo(retrievedJwksList.stream().map(JWK::toJsonString).toList());
    }

    @Test
    void shouldAppendForSoftwareJwksIfAlreadyExists() {
        final JwsAlgorithm keyAlg = JwsAlgorithm.PS256;

        JWKSet softwareJwks = softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(keyAlg, 3096));

        assertThat(softwareJwks.getJWKsAsList()).hasSize(2);

        JWKSet appendedSoftwareJwks = softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(keyAlg, 3096));

        assertThat(appendedSoftwareJwks.getJWKsAsList()).hasSize(4);
    }

    @Test
    void shouldFailToIssueCertificateIfParamIsNull() {
        final CertificateOptions certificateOptions = new CertificateOptions(JwsAlgorithm.PS256, 2048);

        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(null, ORG_NAME, SOFTWARE_ID, certificateOptions));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, null, SOFTWARE_ID, certificateOptions));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, null, certificateOptions));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, null));
    }

    @Test
    void shouldRemoveCertificates() {
        final JWKSet softwareJwks = softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID,
                new CertificateOptions(JwsAlgorithm.PS256, 3096));

        final List<JWK> jwks = softwareJwks.getJWKsAsList();
        assertThat(jwks).hasSize(2);

        final JWK firstJwk = jwks.get(0);
        final JWK secondJwk = jwks.get(1);

        softwareJwksService.removeCertificate(ORG_ID, SOFTWARE_ID, firstJwk.getKeyId());
        assertThat(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID).getJWKsAsList()).hasSize(1);

        softwareJwksService.removeCertificate(ORG_ID, SOFTWARE_ID, secondJwk.getKeyId());
        // No JWKS returned when there are no keys mapped.
        assertThat(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).isNull();
    }

    @Test
    void shouldFailToRemoveCertificatesIfParamIsNull() {
        assertThrows(NullPointerException.class, () -> softwareJwksService.removeCertificate(null, SOFTWARE_ID, "key-123"));
        assertThrows(NullPointerException.class, () -> softwareJwksService.removeCertificate(ORG_ID, null, "key-123"));
        assertThrows(NullPointerException.class, () -> softwareJwksService.removeCertificate(ORG_ID, ORG_NAME, null));
    }
}