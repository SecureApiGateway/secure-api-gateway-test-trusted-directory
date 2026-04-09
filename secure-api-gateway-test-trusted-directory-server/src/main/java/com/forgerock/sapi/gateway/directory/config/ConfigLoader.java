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
 * Loads and assembles application configuration from a YAML file, merged with
 * secrets provided by a {@link SecretLoader}.
 * <p>
 * The YAML file path can be overridden via the {@value #CONFIG_PATH_ENV} environment
 * variable; if not set, {@value #DEFAULT_CONFIG_PATH} is used.
 */
public class ConfigLoader {

    private static final Logger logger = LoggerFactory.getLogger(ConfigLoader.class);

    public static final String CONFIG_PATH_ENV = "TTD_CONFIG_PATH";
    public static final String DEFAULT_CONFIG_PATH = "config.yml";

    /**
     * Result of a successful configuration load.
     *
     * @param port       HTTP server port
     * @param properties fully-assembled {@link TrustedDirectoryConfig}
     */
    public record LoadedConfig(int port, TrustedDirectoryConfig properties) {
    }

    private final Vertx vertx;
    private final String yamlConfigPath;
    private final SecretLoader secretLoader;

    /**
     * Production constructor — reads {@value #CONFIG_PATH_ENV} from the environment
     * to locate the YAML config file, defaulting to {@value #DEFAULT_CONFIG_PATH}.
     * Secrets are loaded via a default {@link SecretLoader}.
     *
     * @param vertx the Vert.x instance used for async I/O
     */
    public ConfigLoader(final Vertx vertx) {
        this(vertx, resolveYamlPath(), new SecretLoader(vertx));
    }

    private static String resolveYamlPath() {
        String envPath = System.getenv(CONFIG_PATH_ENV);
        return (envPath != null && !envPath.isBlank()) ? envPath : DEFAULT_CONFIG_PATH;
    }

    /**
     * Test constructor — overrides the YAML config file path and secret loader.
     *
     * @param vertx          the Vert.x instance used for async I/O
     * @param yamlConfigPath filesystem path to the YAML file to load
     * @param secretLoader   secret loader to use
     */
    @VisibleForTesting
    ConfigLoader(final Vertx vertx, final String yamlConfigPath, final SecretLoader secretLoader) {
        this.vertx = requireNonNull(vertx, "vertx must be provided");
        this.yamlConfigPath = requireNonNull(yamlConfigPath, "yamlConfigPath must be provided");
        this.secretLoader = requireNonNull(secretLoader, "secretLoader must be provided");
    }

    /**
     * Loads configuration merged with secrets, and returns a {@link LoadedConfig}.
     *
     * @return a future that resolves to the fully-assembled {@link LoadedConfig}
     */
    public Future<LoadedConfig> load() {
        return buildConfigRetriever().getConfig()
                .map(EnvVarSubstitutor::substitute)
                .compose(config -> secretLoader.load()
                        .map(secrets -> config.copy().mergeIn(secrets, true)))
                .map(this::buildLoadedConfig);
    }

    private ConfigRetriever buildConfigRetriever() {
        logger.info("Loading configuration from: {}", yamlConfigPath);
        ConfigStoreOptions yamlStore = new ConfigStoreOptions()
                .setType("file")
                .setFormat("yaml")
                .setConfig(new JsonObject().put("path", yamlConfigPath));
        return ConfigRetriever.create(vertx, new ConfigRetrieverOptions().addStore(yamlStore));
    }

    private LoadedConfig buildLoadedConfig(JsonObject config) {
        int port = config.getJsonObject("server", new JsonObject()).getInteger("port", 8080);
        TrustedDirectoryConfig properties = config
                .getJsonObject("trustedDirectory", new JsonObject())
                .mapTo(TrustedDirectoryConfig.class);
        return new LoadedConfig(port, properties);
    }
}
