/*
 * Copyright © 2026 Ping Identity Corporation (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.directory.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.net.URL;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import com.forgerock.sapi.gateway.directory.config.ConfigLoader.LoadedConfig;

import io.vertx.core.Vertx;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

/**
 * Tests for {@link ConfigLoader}: verifies YAML loading, filesystem override, password
 * injection from environment variables, and the {@code keystoreKeyPwd} fallback behaviour.
 */
@ExtendWith(SystemStubsExtension.class)
class ConfigLoaderTest {

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

    private LoadedConfig load(String yamlPath) throws Exception {
        return load(yamlPath, null);
    }

    private LoadedConfig load(String yamlPath, String secretPath) throws Exception {
        SecretLoader secretLoader = secretPath != null
                ? new SecretLoader(vertx, secretPath)
                : new SecretLoader(vertx, (String) null); // no secrets
        return new ConfigLoader(vertx, yamlPath, secretLoader)
                .load()
                .toCompletionStage()
                .toCompletableFuture()
                .get(5, TimeUnit.SECONDS);
    }

    private String testConfigPath() {
        URL resource = getClass().getClassLoader().getResource("test-config.yml");
        assumeThat(resource).as("test-config.yml must exist in test resources").isNotNull();
        return resource.getPath();
    }

    private String testSecretPath() {
        URL resource = getClass().getClassLoader().getResource("test-secret.yml");
        assumeThat(resource).as("test-secret.yml must exist in test resources").isNotNull();
        return resource.getPath();
    }

    @Nested
    class YamlLoading {

        @Test
        void shouldReadDefaultConfigWhenNoPathProvided() throws Exception {
            URL resource = getClass().getClassLoader().getResource("config.yml");
            assertThat(resource).as("config.yml must exist on classpath").isNotNull();

            LoadedConfig config = load(resource.getPath());

            assertThat(config.port()).isEqualTo(8080);
            TrustedDirectoryConfig props = config.properties();
            assertThat(props.issuerName()).isEqualTo("SAPI-G Test Trusted Directory");
            assertThat(props.fqdn()).isEqualTo("localhost:8080");
            assertThat(props.storageFilePath()).isEqualTo("/var/trusted-directory/trusted-directory-jwks.json");
            assertThat(props.signing().keystoreType()).isEqualTo("PKCS12");
            assertThat(props.ca().certSigningAlg()).isEqualTo("SHA256withRSA");
        }

        @Test
        void shouldReadCustomYamlWhenFoundOnClasspath() throws Exception {
            LoadedConfig config = load(testConfigPath());

            assertThat(config.port()).isEqualTo(9090);
            TrustedDirectoryConfig props = config.properties();
            assertThat(props.issuerName()).isEqualTo("Test Issuer");
            assertThat(props.fqdn()).isEqualTo("test.example.com:9090");
            assertThat(props.storageFilePath()).isEqualTo("/test/jwks.json");
            assertThat(props.signing().keystorePath()).isEqualTo("/test/signing.p12");
            assertThat(props.signing().keyAlias()).isEqualTo("test-signing");
            assertThat(props.ca().keystorePath()).isEqualTo("/test/ca.p12");
            assertThat(props.cert().keySize()).isEqualTo(2048);
            assertThat(props.cert().validityDays()).isEqualTo(30);
        }

        @Test
        void shouldReadYamlFromFilesystem() throws Exception {
            LoadedConfig config = load(testConfigPath());

            assertThat(config.port()).isEqualTo(9090);
            assertThat(config.properties().issuerName()).isEqualTo("Test Issuer");
        }

        @Test
        void shouldUseConfigPathFromEnvVar() throws Exception {
            envVars.set(ConfigLoader.CONFIG_PATH_ENV, testConfigPath());
            envVars.set(SecretLoader.SECRET_PATH_ENV, testSecretPath());

            LoadedConfig config = new ConfigLoader(vertx).load()
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(config.port()).isEqualTo(9090);
            assertThat(config.properties().issuerName()).isEqualTo("Test Issuer");
        }
    }

    @Nested
    class PasswordInjection {

        @Test
        void shouldInjectPasswordsFromSecretFile() throws Exception {
            LoadedConfig config = load(testConfigPath(), testSecretPath());

            TrustedDirectoryConfig props = config.properties();
            assertThat(props.signing().keystorePwd()).isEqualTo("signing-store-pwd");
            assertThat(props.signing().keystoreKeyPwd()).isEqualTo("signing-key-pwd");
            assertThat(props.ca().keystorePwd()).isEqualTo("ca-store-pwd");
            assertThat(props.ca().keystoreKeyPwd()).isEqualTo("ca-key-pwd");
        }

        @Test
        void shouldFallBackToKeystorePasswordWhenKeyPasswordNotSet() throws Exception {
            URL resource = getClass().getClassLoader().getResource("test-secret-partial.yml");
            assertThat(resource).as("test-secret-partial.yml must exist in test resources").isNotNull();

            LoadedConfig config = load(testConfigPath(), resource.getPath());

            TrustedDirectoryConfig props = config.properties();
            assertThat(props.signing().keystorePwd()).isEqualTo("signing-store-pwd");
            assertThat(props.signing().keystoreKeyPwd())
                    .as("keystoreKeyPwd should fall back to keystorePwd")
                    .isEqualTo("signing-store-pwd");
            assertThat(props.ca().keystorePwd()).isEqualTo("ca-store-pwd");
            assertThat(props.ca().keystoreKeyPwd())
                    .as("keystoreKeyPwd should fall back to keystorePwd")
                    .isEqualTo("ca-store-pwd");
        }

        @Test
        void shouldLoadConfigWhenNoSecretFileProvided() throws Exception {
            LoadedConfig config = load(testConfigPath(), null);

            TrustedDirectoryConfig props = config.properties();
            assertThat(props.signing().keystorePwd()).isNull();
            assertThat(props.ca().keystorePwd()).isNull();
        }
    }

    @Nested
    class Defaults {

        @Test
        void shouldApplyDefaultsWhenFieldsOmittedFromYaml() throws Exception {
            LoadedConfig config = load(testConfigPath());

            TrustedDirectoryConfig props = config.properties();
            assertThat(props.signing().keystoreType()).isEqualTo(TrustedDirectoryConfig.DEFAULT_KEYSTORE_TYPE);
            assertThat(props.ca().certSigningAlg()).isEqualTo(TrustedDirectoryConfig.DEFAULT_CERT_SIGNING_ALG);
        }
    }
}
