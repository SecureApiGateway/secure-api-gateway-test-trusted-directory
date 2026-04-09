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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URL;
import java.nio.file.Path;
import java.util.List;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.directory.ca.CertificateIssuerServiceTest;
import com.forgerock.sapi.gateway.directory.ca.CertificateOptions;

class SoftwareJwksServiceTest {

    private static final String ORG_ID = "Test-Corp-1234";
    private static final String ORG_NAME = "Test Corporation";
    private static final String SOFTWARE_ID = "software-1234";
    private static final CertificateOptions DEFAULT_CERT_OPTIONS = new CertificateOptions(JwsAlgorithm.PS256, 2048);

    @TempDir
    Path tempDir;

    private final CaCertificateResource caCertificateResource = CaCertificateResource.getInstance();
    private SoftwareJwksService softwareJwksService;

    @BeforeEach
    void beforeEach() {
        softwareJwksService = createService(tempDir.resolve("jwks-store.json"));
    }

    private SoftwareJwksService createService(Path storePath) {
        CertificateIssuerService certificateIssuerService = new CertificateIssuerService(
                caCertificateResource.getCertificate(),
                caCertificateResource.getPrivateKey(),
                CaCertificateResource.DEFAULT_CA_CERT_SIGNING_ALG);
        return new SoftwareJwksService(certificateIssuerService, storePath, new ObjectMapper());
    }

    @Nested
    class IssueSoftwareCertificates {

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
        void shouldOnlyReturnNewlyCreatedCertsOnReissue() {
            softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS);
            JWKSet reissued = softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS);
            assertThat(reissued.getJWKsAsList()).hasSize(2);
        }

        @Test
        void shouldThrowWhenIssueCertParamIsNull() {
            assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(null, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS));
            assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, null, SOFTWARE_ID, DEFAULT_CERT_OPTIONS));
            assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, null, DEFAULT_CERT_OPTIONS));
            assertThrows(NullPointerException.class, () -> softwareJwksService.issueSoftwareCertificates(ORG_ID, ORG_NAME, SOFTWARE_ID, null));
        }
    }

    @Nested
    class GetPublicSoftwareJwks {

        @Test
        void shouldReturnPublicJwksOnly() {
            JWKSet issued = softwareJwksService.issueSoftwareCertificates(
                    ORG_ID, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS);

            JWKSet publicJwks = softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID);

            assertThat(publicJwks.getJWKsAsList()).hasSize(issued.getJWKsAsList().size());
            assertThat(publicJwks.getJWKsAsList()).noneMatch(JWK::isPrivate);
            assertThat(issued.getJWKsAsList()).map(jwk -> jwk.toPublicJwk().get().toJsonString())
                    .containsExactlyInAnyOrderElementsOf(
                            publicJwks.getJWKsAsList().stream().map(JWK::toJsonString).toList());
        }

        @Test
        void shouldReturnNullWhenNoJwksExists() {
            assertThat(softwareJwksService.getPublicSoftwareJwks(ORG_ID, "unknown-software")).isNull();
        }
    }

    @Nested
    class RemoveCertificate {

        @Test
        void shouldRemoveCertificates() {
            JWKSet softwareJwks = softwareJwksService.issueSoftwareCertificates(
                    ORG_ID, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS);

            List<JWK> jwks = softwareJwks.getJWKsAsList();
            assertThat(jwks).hasSize(2);

            softwareJwksService.removeCertificate(ORG_ID, SOFTWARE_ID, jwks.get(0).getKeyId());
            assertThat(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID).getJWKsAsList()).hasSize(1);

            softwareJwksService.removeCertificate(ORG_ID, SOFTWARE_ID, jwks.get(1).getKeyId());
            assertThat(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).isNull();
        }
    }

    @Nested
    class Persistence {

        @Test
        void shouldPersistAndReloadFromFile() {
            JWKSet issued = softwareJwksService.issueSoftwareCertificates(
                    ORG_ID, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS);

            Path storePath = tempDir.resolve("jwks-store.json");
            assertThat(storePath).exists();

            SoftwareJwksService reloadedService = createService(storePath);
            JWKSet reloaded = reloadedService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID);

            assertThat(reloaded).isNotNull();
            assertThat(reloaded.getJWKsAsList()).hasSize(issued.getJWKsAsList().size());
            List<String> issuedIds = issued.getJWKsAsList().stream().map(JWK::getKeyId).sorted().toList();
            List<String> reloadedIds = reloaded.getJWKsAsList().stream().map(JWK::getKeyId).sorted().toList();
            assertThat(reloadedIds).isEqualTo(issuedIds);
        }

        @Test
        void shouldThrowWhenStorageFileIsCorrupted() throws Exception {
            URL resource = getClass().getClassLoader().getResource("test-corrupted-jwks.json");
            assertThat(resource).as("test-corrupted-jwks.json must exist in test resources").isNotNull();

            assertThatThrownBy(() -> createService(Path.of(resource.toURI())))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Failed to load JWKS store");
        }
    }

    @Nested
    class ExtractCertAsPem {

        @Test
        void shouldReturnPemForSigningKey() throws Exception {
            JWKSet jwkSet = softwareJwksService.issueSoftwareCertificates(
                    ORG_ID, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS);
            String jwksJson = jwkSet.toJsonValue().toString();

            String pem = softwareJwksService.extractCertAsPem(jwksJson, "sig");

            assertThat(pem).contains("-----BEGIN CERTIFICATE-----");
            assertThat(pem).satisfies(p ->
                    assertThat(p.contains("-----BEGIN RSA PRIVATE KEY-----") || p.contains("-----BEGIN PRIVATE KEY-----")).isTrue());
        }

        @Test
        void shouldReturnPemForTransportKey() throws Exception {
            JWKSet jwkSet = softwareJwksService.issueSoftwareCertificates(
                    ORG_ID, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS);
            String jwksJson = jwkSet.toJsonValue().toString();

            String pem = softwareJwksService.extractCertAsPem(jwksJson, "tls");

            assertThat(pem).contains("-----BEGIN CERTIFICATE-----");
            assertThat(pem).satisfies(p ->
                    assertThat(p.contains("-----BEGIN RSA PRIVATE KEY-----") || p.contains("-----BEGIN PRIVATE KEY-----")).isTrue());
        }

        @Test
        void shouldThrowWhenExtractingPemFromInvalidJson() {
            assertThrows(IllegalArgumentException.class,
                    () -> softwareJwksService.extractCertAsPem("not-valid-json", "sig"));
        }

        @Test
        void shouldThrowWhenExtractingPemAndKeyUseNotFound() throws Exception {
            JWKSet jwkSet = softwareJwksService.issueSoftwareCertificates(
                    ORG_ID, ORG_NAME, SOFTWARE_ID, DEFAULT_CERT_OPTIONS);
            String jwksJson = jwkSet.toJsonValue().toString();

            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> softwareJwksService.extractCertAsPem(jwksJson, "enc"));
            assertThat(ex.getMessage()).contains("Couldn't find enc key in JWK set");
        }
    }
}
