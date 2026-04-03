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
package com.forgerock.sapi.gateway.test.trusted.directory.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.FileOutputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;

import org.forgerock.json.jose.jwk.JWKSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaSigningService;

class TrustedDirectoryConfigTest {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String STORE_PWD = "storepass";
    private static final String KEY_ALIAS = "test-key";

    @TempDir
    static Path tempDir;

    private static String caKeystorePath;
    private static String signingKeystorePath;

    @BeforeAll
    static void createTestKeystores() throws Exception {
        CaCertificateResource ca = CaCertificateResource.getInstance();

        caKeystorePath = tempDir.resolve("ca.p12").toString();
        writeKeystore(caKeystorePath, KEY_ALIAS, ca);

        signingKeystorePath = tempDir.resolve("signing.p12").toString();
        writeKeystore(signingKeystorePath, KEY_ALIAS, ca);
    }

    private static void writeKeystore(String path, String alias, CaCertificateResource ca) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        ks.load(null, null);
        ks.setKeyEntry(alias, ca.getPrivateKey(), STORE_PWD.toCharArray(),
                new Certificate[]{ca.getCertificate()});
        try (FileOutputStream fos = new FileOutputStream(path)) {
            ks.store(fos, STORE_PWD.toCharArray());
        }
    }

    private TrustedDirectoryProperties buildProperties() {
        return new TrustedDirectoryProperties(
                "Test Issuer", "localhost:8080",
                new TrustedDirectoryProperties.SigningProperties(signingKeystorePath, KEYSTORE_TYPE, STORE_PWD, STORE_PWD, KEY_ALIAS),
                new TrustedDirectoryProperties.CaProperties(caKeystorePath, KEYSTORE_TYPE, STORE_PWD, STORE_PWD, KEY_ALIAS, "SHA256withRSA"),
                new TrustedDirectoryProperties.StorageProperties(tempDir.resolve("jwks.json").toString()),
                new TrustedDirectoryProperties.CertProperties(2048, 365));
    }

    @Test
    void certificateIssuerService_createsBean() throws Exception {
        TrustedDirectoryConfig config = new TrustedDirectoryConfig();
        CertificateIssuerService service = config.certificateIssuerService(buildProperties());

        assertThat(service).isNotNull();
    }

    @Test
    void ssaSigningService_createsBean_withCorrectPublicJwks() throws Exception {
        TrustedDirectoryConfig config = new TrustedDirectoryConfig();
        SsaSigningService service = config.ssaSigningService(buildProperties());

        assertThat(service).isNotNull();
        JWKSet publicJwks = service.getPublicJwks();
        assertThat(publicJwks.getJWKsAsList()).hasSize(1);
        var jwk = publicJwks.getJWKsAsList().get(0);
        assertThat(jwk.getUse()).isEqualTo("sig");
        assertThat(jwk.toJsonString()).contains("\"alg\": \"PS256\"");
        assertThat(jwk.getKeyId()).isNotBlank();
    }

    @Test
    void softwareJwksService_createsBean() throws Exception {
        TrustedDirectoryConfig config = new TrustedDirectoryConfig();
        CertificateIssuerService certificateIssuerService = config.certificateIssuerService(buildProperties());
        SoftwareJwksService service = config.softwareJwksService(certificateIssuerService, buildProperties(), new ObjectMapper());

        assertThat(service).isNotNull();
    }

    @Test
    void certificateIssuerService_throwsWhenKeystoreFileMissing() {
        TrustedDirectoryConfig config = new TrustedDirectoryConfig();
        TrustedDirectoryProperties props = new TrustedDirectoryProperties(
                "Test Issuer", "localhost:8080",
                new TrustedDirectoryProperties.SigningProperties("/nonexistent/signing.p12", KEYSTORE_TYPE, STORE_PWD, STORE_PWD, KEY_ALIAS),
                new TrustedDirectoryProperties.CaProperties("/nonexistent/ca.p12", KEYSTORE_TYPE, STORE_PWD, STORE_PWD, KEY_ALIAS, "SHA256withRSA"),
                new TrustedDirectoryProperties.StorageProperties("/tmp/jwks.json"),
                new TrustedDirectoryProperties.CertProperties(2048, 365));

        assertThatThrownBy(() -> config.certificateIssuerService(props))
                .isInstanceOf(Exception.class);
    }

    @Test
    void ssaSigningService_throwsWhenKeystoreFileMissing() {
        TrustedDirectoryConfig config = new TrustedDirectoryConfig();
        TrustedDirectoryProperties props = new TrustedDirectoryProperties(
                "Test Issuer", "localhost:8080",
                new TrustedDirectoryProperties.SigningProperties("/nonexistent/signing.p12", KEYSTORE_TYPE, STORE_PWD, STORE_PWD, KEY_ALIAS),
                new TrustedDirectoryProperties.CaProperties("/nonexistent/ca.p12", KEYSTORE_TYPE, STORE_PWD, STORE_PWD, KEY_ALIAS, "SHA256withRSA"),
                new TrustedDirectoryProperties.StorageProperties("/tmp/jwks.json"),
                new TrustedDirectoryProperties.CertProperties(2048, 365));

        assertThatThrownBy(() -> config.ssaSigningService(props))
                .isInstanceOf(Exception.class);
    }
}
