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

        final String orgId  = "Test-Corp-1234";
        final String orgName = "Test Corporation";
        final String softwareId = "software-1234";

        JWKSet softwareJwks = softwareJwksService.issueSoftwareCertificates(orgId, orgName, softwareId, new CertificateOptions(keyAlg, 3096));

        assertThat(softwareJwks.getJWKsAsList()).hasSize(2);

        final JWK signingKey = softwareJwks.findJwk(keyAlg, "sig");
        assertThat(signingKey).isNotNull();
        CertificateIssuerServiceTest.validateCertIssuedByCa(caCertificateResource.getPublicKey(), orgId, orgName, signingKey);

        final JWK transportKey = softwareJwks.findJwk(keyAlg, "tls");
        assertThat(transportKey).isNotNull();
        CertificateIssuerServiceTest.validateCertIssuedByCa(caCertificateResource.getPublicKey(), orgId, orgName, transportKey);
    }

    @Test
    void shouldGetJwksContainingOnlyPublicKeyDataForSoftware() {
        final String orgId  = "Test-Corp-1234";
        final String orgName = "Test Corporation";
        final String softwareId = "software-1234";

        JWKSet issuedJwks = softwareJwksService.issueSoftwareCertificates(orgId, orgName, softwareId,
                new CertificateOptions(JwsAlgorithm.PS256, 3096));

        JWKSet retrievedJwks = softwareJwksService.getPublicSoftwareJwks(orgId, softwareId);
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

        final String orgId  = "Test-Corp-1234";
        final String orgName = "Test Corporation";
        final String softwareId = "software-1234";

        JWKSet softwareJwks = softwareJwksService.issueSoftwareCertificates(orgId, orgName, softwareId, new CertificateOptions(keyAlg, 3096));

        assertThat(softwareJwks.getJWKsAsList()).hasSize(2);

        JWKSet appendedSoftwareJwks = softwareJwksService.issueSoftwareCertificates(orgId, orgName, softwareId, new CertificateOptions(keyAlg, 3096));

        assertThat(appendedSoftwareJwks.getJWKsAsList()).hasSize(4);
    }

    @Test
    void shouldFailToIssueCertificateIfParamIsNull() {
        final String orgId  = "Test-Corp-1234";
        final String orgName = "Test Corporation";
        final String softwareId = "software-1234";
        final CertificateOptions certificateOptions = new CertificateOptions(JwsAlgorithm.PS256, 2048);

        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(null, orgName, softwareId, certificateOptions));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(orgId, null, softwareId, certificateOptions));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(orgId, orgName, null, certificateOptions));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(orgId, orgName, softwareId, null));
    }
}