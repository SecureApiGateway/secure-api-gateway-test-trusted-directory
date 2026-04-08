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

import java.net.URL;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

/**
 * Tests for {@link SecretLoader}: verifies YAML loading, optional file handling,
 * and {@code ${VAR}} environment variable substitution.
 */
@ExtendWith(SystemStubsExtension.class)
class SecretLoaderTest {

    @SystemStub
    private EnvironmentVariables envVars;

    private Vertx vertx;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (vertx != null) {
            vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        }
    }

    private JsonObject load(String secretPath) throws Exception {
        return new SecretLoader(vertx, secretPath)
                .load()
                .toCompletionStage()
                .toCompletableFuture()
                .get(5, TimeUnit.SECONDS);
    }

    // -------------------------------------------------------------------------
    // Plain-value loading
    // -------------------------------------------------------------------------

    @Test
    void load_readsPlainValuesFromSecretFile() throws Exception {
        URL resource = getClass().getClassLoader().getResource("test-secret.yml");
        assertThat(resource).as("test-secret.yml must exist in test resources").isNotNull();

        JsonObject secrets = load(resource.getPath());

        JsonObject signing = secrets.getJsonObject("trustedDirectory").getJsonObject("signing");
        assertThat(signing.getString("keystorePwd")).isEqualTo("signing-store-pwd");
        assertThat(signing.getString("keystoreKeyPwd")).isEqualTo("signing-key-pwd");
        JsonObject ca = secrets.getJsonObject("trustedDirectory").getJsonObject("ca");
        assertThat(ca.getString("keystorePwd")).isEqualTo("ca-store-pwd");
        assertThat(ca.getString("keystoreKeyPwd")).isEqualTo("ca-key-pwd");
    }

    // -------------------------------------------------------------------------
    // Env var substitution
    // -------------------------------------------------------------------------

    @Test
    void load_substitutesEnvVarPlaceholders() throws Exception {
        URL resource = getClass().getClassLoader().getResource("test-secret-placeholder.yml");
        assertThat(resource).as("test-secret-placeholder.yml must exist in test resources").isNotNull();
        envVars.set("TEST_SIGNING_PWD", "resolved-signing-pwd");
        envVars.set("TEST_SIGNING_KEY_PWD", "resolved-signing-key-pwd");
        envVars.set("TEST_CA_PWD", "resolved-ca-pwd");
        envVars.set("TEST_CA_KEY_PWD", "resolved-ca-key-pwd");

        JsonObject secrets = load(resource.getPath());

        assertThat(secrets.getJsonObject("trustedDirectory")
                .getJsonObject("signing")
                .getString("keystorePwd"))
                .isEqualTo("resolved-signing-pwd");
    }

    @Test
    void load_throwsWhenRequiredEnvVarNotSet() throws Exception {
        URL resource = getClass().getClassLoader().getResource("test-secret-placeholder.yml");
        assertThat(resource).as("test-secret-placeholder.yml must exist in test resources").isNotNull();
        // No env vars set → all ${TEST_*} placeholders are required → should throw

        assertThatThrownBy(() -> load(resource.getPath()))
                .hasCauseInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("TEST_SIGNING_PWD");
    }

    @Test
    void load_usesDefaultSecretYmlWithEnvVarPlaceholders() throws Exception {
        // secret.yml from src/main/resources (resolved via classpath URL) uses ${TTD_*} placeholders
        URL resource = getClass().getClassLoader().getResource("secret.yml");
        assertThat(resource).as("secret.yml must exist on classpath").isNotNull();

        envVars.set("TTD_SIGNING_KEYSTORE_PWD", "signing-pwd");
        envVars.set("TTD_SIGNING_KEYSTORE_KEY_PWD", "signing-key-pwd");
        envVars.set("TTD_CA_KEYSTORE_PWD", "ca-pwd");
        envVars.set("TTD_CA_KEYSTORE_KEY_PWD", "ca-key-pwd");

        JsonObject secrets = load(resource.getPath());

        JsonObject signing = secrets.getJsonObject("trustedDirectory").getJsonObject("signing");
        assertThat(signing.getString("keystorePwd")).isEqualTo("signing-pwd");
        assertThat(signing.getString("keystoreKeyPwd")).isEqualTo("signing-key-pwd");
        JsonObject ca = secrets.getJsonObject("trustedDirectory").getJsonObject("ca");
        assertThat(ca.getString("keystorePwd")).isEqualTo("ca-pwd");
        assertThat(ca.getString("keystoreKeyPwd")).isEqualTo("ca-key-pwd");
    }

    // -------------------------------------------------------------------------
    // Optional file handling
    // -------------------------------------------------------------------------

    @Test
    void load_returnsEmptyJsonWhenSecretFileNotFound() throws Exception {
        JsonObject secrets = load("/nonexistent/secret.yml");
        assertThat(secrets.isEmpty()).isTrue();
    }

    @Test
    void load_returnsEmptyJsonWhenPathIsNull() throws Exception {
        JsonObject secrets = load(null);
        assertThat(secrets.isEmpty()).isTrue();
    }

    // -------------------------------------------------------------------------
    // TTD_SECRET_PATH env var
    // -------------------------------------------------------------------------

    @Test
    void load_usesSecretPathFromEnvVar() throws Exception {
        URL resource = getClass().getClassLoader().getResource("test-secret.yml");
        assertThat(resource).as("test-secret.yml must exist in test resources").isNotNull();
        envVars.set(SecretLoader.SECRET_PATH_ENV, resource.getPath());

        JsonObject secrets = new SecretLoader(vertx).load()
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(secrets.getJsonObject("trustedDirectory")
                .getJsonObject("signing")
                .getString("keystorePwd"))
                .isEqualTo("signing-store-pwd");
    }
}
