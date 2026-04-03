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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeystoreLoaderTest {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String STORE_PWD = "storepass";
    private static final String KEY_PWD = "keypass";
    private static final String KEY_ALIAS = "test-key";

    @TempDir
    static Path tempDir;

    private static String keystorePath;

    @BeforeAll
    static void createTestKeystore() throws Exception {
        // Generate a key pair and self-signed cert
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        // Reuse the CA cert helper to get a signed certificate
        X509Certificate caCert = CaCertificateResource.getInstance().getCertificate();

        // Build a PKCS12 keystore with separate key password
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        ks.load(null, null);
        ks.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), KEY_PWD.toCharArray(), new Certificate[]{caCert});

        keystorePath = tempDir.resolve("test-keystore.p12").toString();
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            ks.store(fos, STORE_PWD.toCharArray());
        }
    }

    @Test
    void loadsPrivateKeyEntrySuccessfully() throws Exception {
        KeyStore.PrivateKeyEntry entry = KeystoreLoader.loadPrivateKeyEntry(
                keystorePath, KEYSTORE_TYPE, STORE_PWD, KEY_ALIAS, KEY_PWD);

        assertThat(entry).isNotNull();
        assertThat(entry.getPrivateKey()).isInstanceOf(PrivateKey.class);
        assertThat(entry.getCertificateChain()).hasSize(1);
    }

    @Test
    void loadsEntryWhenKeyPwdEqualsStorePwd() throws Exception {
        // Create a keystore where key password == store password (common case)
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();
        X509Certificate caCert = CaCertificateResource.getInstance().getCertificate();

        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        ks.load(null, null);
        ks.setKeyEntry("same-pwd-alias", keyPair.getPrivate(), STORE_PWD.toCharArray(), new Certificate[]{caCert});

        String singlePwdPath = tempDir.resolve("single-pwd-keystore.p12").toString();
        try (FileOutputStream fos = new FileOutputStream(singlePwdPath)) {
            ks.store(fos, STORE_PWD.toCharArray());
        }

        KeyStore.PrivateKeyEntry entry = KeystoreLoader.loadPrivateKeyEntry(
                singlePwdPath, KEYSTORE_TYPE, STORE_PWD, "same-pwd-alias", STORE_PWD);

        assertThat(entry).isNotNull();
        assertThat(entry.getPrivateKey()).isNotNull();
    }

    @Test
    void throwsWhenStorePwdIsWrong() {
        assertThatThrownBy(() -> KeystoreLoader.loadPrivateKeyEntry(
                keystorePath, KEYSTORE_TYPE, "wrong-password", KEY_ALIAS, KEY_PWD))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("password");
    }

    @Test
    void throwsIllegalStateWhenAliasNotFound() {
        assertThatThrownBy(() -> KeystoreLoader.loadPrivateKeyEntry(
                keystorePath, KEYSTORE_TYPE, STORE_PWD, "unknown-alias", KEY_PWD))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unknown-alias");
    }

    @Test
    void throwsWhenKeystoreFileDoesNotExist() {
        assertThatThrownBy(() -> KeystoreLoader.loadPrivateKeyEntry(
                "/non/existent/keystore.p12", KEYSTORE_TYPE, STORE_PWD, KEY_ALIAS, KEY_PWD))
                .isInstanceOf(Exception.class);
    }
}
