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

import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;

/**
 * Tests for {@link TrustedDirectoryServices}: verifies that services are correctly wired from
 * {@link TrustedDirectoryConfig} and explicit passwords (bypassing env vars).
 */
class TrustedDirectoryServicesTest {

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

    private TrustedDirectoryConfig buildProperties() {
        return new TrustedDirectoryConfig(
                "Test Issuer", "localhost:8080",
                new TrustedDirectoryConfig.SigningConfig(signingKeystorePath, KEYSTORE_TYPE, KEY_ALIAS, STORE_PWD, STORE_PWD),
                new TrustedDirectoryConfig.CaConfig(caKeystorePath, KEYSTORE_TYPE, KEY_ALIAS, "SHA256withRSA", STORE_PWD, STORE_PWD),
                tempDir.resolve("jwks.json").toString(),
                new TrustedDirectoryConfig.CertConfig(2048, 365));
    }

    private TrustedDirectoryServices buildTrustedDirectoryServices() throws Exception {
        return new TrustedDirectoryServices(buildProperties());
    }

    @Test
    void appConfig_createsCertificateIssuerService() throws Exception {
        assertThat(buildTrustedDirectoryServices().getCertificateIssuerService()).isNotNull();
    }

    @Test
    void appConfig_createsSsaSigningService_withCorrectPublicJwks() throws Exception {
        TrustedDirectoryServices config = buildTrustedDirectoryServices();

        assertThat(config.getSsaSigningService()).isNotNull();
        JWKSet publicJwks = config.getSsaSigningService().getPublicJwks();
        assertThat(publicJwks.getJWKsAsList()).hasSize(1);
        var jwk = publicJwks.getJWKsAsList().get(0);
        assertThat(jwk.getUse()).isEqualTo("sig");
        assertThat(jwk.toJsonString()).contains("\"alg\": \"PS256\"");
        assertThat(jwk.getKeyId()).isNotBlank();
    }

    @Test
    void appConfig_createsSoftwareJwksService() throws Exception {
        assertThat(buildTrustedDirectoryServices().getSoftwareJwksService()).isNotNull();
    }

    @Test
    void appConfig_throwsWhenCaKeystoreFileMissing() {
        TrustedDirectoryConfig props = new TrustedDirectoryConfig(
                "Test Issuer", "localhost:8080",
                new TrustedDirectoryConfig.SigningConfig(signingKeystorePath, KEYSTORE_TYPE, KEY_ALIAS, STORE_PWD, STORE_PWD),
                new TrustedDirectoryConfig.CaConfig("/nonexistent/ca.p12", KEYSTORE_TYPE, KEY_ALIAS, "SHA256withRSA", STORE_PWD, STORE_PWD),
                "/tmp/jwks.json",
                new TrustedDirectoryConfig.CertConfig(2048, 365));

        assertThatThrownBy(() -> new TrustedDirectoryServices(props))
                .isInstanceOf(Exception.class);
    }

    @Test
    void appConfig_throwsWhenSigningKeystoreFileMissing() {
        TrustedDirectoryConfig props = new TrustedDirectoryConfig(
                "Test Issuer", "localhost:8080",
                new TrustedDirectoryConfig.SigningConfig("/nonexistent/signing.p12", KEYSTORE_TYPE, KEY_ALIAS, STORE_PWD, STORE_PWD),
                new TrustedDirectoryConfig.CaConfig(caKeystorePath, KEYSTORE_TYPE, KEY_ALIAS, "SHA256withRSA", STORE_PWD, STORE_PWD),
                "/tmp/jwks.json",
                new TrustedDirectoryConfig.CertConfig(2048, 365));

        assertThatThrownBy(() -> new TrustedDirectoryServices(props))
                .isInstanceOf(Exception.class);
    }
}
