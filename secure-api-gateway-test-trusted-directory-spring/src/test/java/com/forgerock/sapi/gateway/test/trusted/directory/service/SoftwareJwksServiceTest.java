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
package com.forgerock.sapi.gateway.test.trusted.directory.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.List;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerServiceTest;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryProperties;

class SoftwareJwksServiceTest {

    private static final String ORG_ID = "Test-Corp-1234";
    private static final String ORG_NAME = "Test Corporation";
    private static final String SOFTWARE_ID = "software-1234";

    @TempDir
    Path tempDir;

    private final CaCertificateResource caCertificateResource = CaCertificateResource.getInstance();
    private SoftwareJwksService softwareJwksService;

    @BeforeEach
    void beforeEach() {
        softwareJwksService = createService(tempDir.resolve("jwks-store.json").toString());
    }

    private SoftwareJwksService createService(String storePath) {
        CertificateIssuerService certificateIssuerService = new CertificateIssuerService(
                caCertificateResource.getCertificate(),
                caCertificateResource.getPrivateKey(),
                CaCertificateResource.DEFAULT_CA_CERT_SIGNING_ALG);
        TrustedDirectoryProperties properties = new TrustedDirectoryProperties();
        properties.getStorage().setFilePath(storePath);
        return new SoftwareJwksService(certificateIssuerService, properties, new ObjectMapper());
    }

    @Test
    void shouldIssueCertificatesForSoftware() {
        JwsAlgorithm keyAlg = JwsAlgorithm.PS256;
        JWKSet softwareJwks = softwareJwksService.issueSoftwareCertificates(
                ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(keyAlg, 2048));

        assertThat(softwareJwks.getJWKsAsList()).hasSize(2);

        JWK signingKey = softwareJwks.findJwk(keyAlg, "sig");
        assertThat(signingKey).isNotNull();
        CertificateIssuerServiceTest.validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, signingKey);

        JWK transportKey = softwareJwks.findJwk(keyAlg, "tls");
        assertThat(transportKey).isNotNull();
        CertificateIssuerServiceTest.validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, transportKey);
    }

    @Test
    void shouldReturnPublicJwksOnly() {
        JWKSet issued = softwareJwksService.issueSoftwareCertificates(
                ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(JwsAlgorithm.PS256, 2048));

        JWKSet publicJwks = softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID);

        assertThat(publicJwks.getJWKsAsList()).hasSize(issued.getJWKsAsList().size());
        assertThat(publicJwks.getJWKsAsList()).noneMatch(JWK::isPrivate);
        assertThat(issued.getJWKsAsList()).map(jwk -> jwk.toPublicJwk().get().toJsonString())
                .isEqualTo(publicJwks.getJWKsAsList().stream().map(JWK::toJsonString).toList());
    }

    @Test
    void shouldReturnNullWhenNoJwksExists() {
        assertThat(softwareJwksService.getPublicSoftwareJwks(ORG_ID, "unknown-software")).isNull();
    }

    @Test
    void shouldOnlyReturnNewlyCreatedCertsOnReissue() {
        softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(JwsAlgorithm.PS256, 2048));
        JWKSet reissued = softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(JwsAlgorithm.PS256, 2048));
        assertThat(reissued.getJWKsAsList()).hasSize(2);
    }

    @Test
    void shouldRemoveCertificates() {
        JWKSet softwareJwks = softwareJwksService.issueSoftwareCertificates(
                ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(JwsAlgorithm.PS256, 2048));

        List<JWK> jwks = softwareJwks.getJWKsAsList();
        assertThat(jwks).hasSize(2);

        softwareJwksService.removeCertificate(ORG_ID, SOFTWARE_ID, jwks.get(0).getKeyId());
        assertThat(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID).getJWKsAsList()).hasSize(1);

        softwareJwksService.removeCertificate(ORG_ID, SOFTWARE_ID, jwks.get(1).getKeyId());
        assertThat(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).isNull();
    }

    @Test
    void shouldPersistAndReloadFromFile() {
        JWKSet issued = softwareJwksService.issueSoftwareCertificates(
                ORG_ID, ORG_NAME, SOFTWARE_ID, new CertificateOptions(JwsAlgorithm.PS256, 2048));

        String storePath = tempDir.resolve("jwks-store.json").toString();
        assertThat(Path.of(storePath)).exists();

        SoftwareJwksService reloadedService = createService(storePath);
        JWKSet reloaded = reloadedService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID);

        assertThat(reloaded).isNotNull();
        assertThat(reloaded.getJWKsAsList()).hasSize(issued.getJWKsAsList().size());
        List<String> issuedIds = issued.getJWKsAsList().stream().map(JWK::getKeyId).sorted().toList();
        List<String> reloadedIds = reloaded.getJWKsAsList().stream().map(JWK::getKeyId).sorted().toList();
        assertThat(reloadedIds).isEqualTo(issuedIds);
    }

    @Test
    void shouldFailToIssueCertificateIfParamIsNull() {
        CertificateOptions options = new CertificateOptions(JwsAlgorithm.PS256, 2048);
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(null, ORG_NAME, SOFTWARE_ID, options));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, null, SOFTWARE_ID, options));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, null, options));
        assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, null));
    }
}
