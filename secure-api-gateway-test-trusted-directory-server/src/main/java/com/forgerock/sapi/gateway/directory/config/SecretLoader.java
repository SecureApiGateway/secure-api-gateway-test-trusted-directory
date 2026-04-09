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

import static java.util.Objects.requireNonNull;

import org.forgerock.util.annotations.VisibleForTesting;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

/**
 * Loads secrets from a YAML file and substitutes {@code ${VAR}} or {@code ${VAR:default}}
 * placeholders with the corresponding environment variable values via {@link EnvVarSubstitutor}.
 * <p>
 * The secret file path can be overridden via the {@value #SECRET_PATH_ENV} environment
 * variable; if not set, the default {@value #DEFAULT_SECRET_PATH} is resolved from the
 * working directory (or classpath in development).
 * The file is optional: if it does not exist, an empty {@link JsonObject} is returned.
 * <p>
 * The default {@code secret.yml} shipped with the application maps
 * {@code TTD_SIGNING_KEYSTORE_PWD}, {@code TTD_SIGNING_KEYSTORE_KEY_PWD},
 * {@code TTD_CA_KEYSTORE_PWD} and {@code TTD_CA_KEYSTORE_KEY_PWD} environment variables
 * to the nested {@link TrustedDirectoryConfig} structure. All four variables are required
 * (no default value); an {@link IllegalArgumentException} is thrown at startup if any is absent.
 */
public class SecretLoader {

    private static final Logger logger = LoggerFactory.getLogger(SecretLoader.class);

    public static final String SECRET_PATH_ENV = "TTD_SECRET_PATH";
    public static final String DEFAULT_SECRET_PATH = "secret.yml";

    private final Vertx vertx;
    private final String secretPath;

    /**
     * Production constructor — reads {@value #SECRET_PATH_ENV} from the environment,
     * defaulting to {@value #DEFAULT_SECRET_PATH}.
     *
     * @param vertx the Vert.x instance used for async I/O
     */
    public SecretLoader(final Vertx vertx) {
        this(vertx, resolveSecretPath());
    }

    /**
     * Test constructor — overrides the secret file path.
     *
     * @param vertx      the Vert.x instance used for async I/O
     * @param secretPath filesystem or classpath path to the secret YAML file
     */
    @VisibleForTesting
    SecretLoader(final Vertx vertx, final String secretPath) {
        this.vertx = requireNonNull(vertx, "vertx must be provided");
        this.secretPath = secretPath;
    }

    private static String resolveSecretPath() {
        String envPath = System.getenv(SECRET_PATH_ENV);
        return (envPath != null && !envPath.isBlank()) ? envPath : DEFAULT_SECRET_PATH;
    }

    /**
     * Loads the secret file and substitutes {@code ${VAR}} placeholders with
     * environment variable values. Returns an empty {@link JsonObject} if the
     * file does not exist or if no secret path is configured.
     *
     * @return a future resolving to a {@link JsonObject} of resolved secret values
     */
    public Future<JsonObject> load() {
        if (secretPath == null) {
            return Future.succeededFuture(new JsonObject());
        }
        logger.info("Loading secrets from: {}", secretPath);
        ConfigStoreOptions secretStore = new ConfigStoreOptions()
                .setType("file")
                .setFormat("yaml")
                .setOptional(true)
                .setConfig(new JsonObject().put("path", secretPath));
        return ConfigRetriever.create(vertx, new ConfigRetrieverOptions().addStore(secretStore))
                .getConfig()
                .map(EnvVarSubstitutor::substitute);
    }
}
