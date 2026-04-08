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
package com.forgerock.sapi.gateway.test.trusted.directory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.test.trusted.directory.config.ConfigLoader;
import com.forgerock.sapi.gateway.test.trusted.directory.config.ConfigLoader.LoadedConfig;
import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryConfig;
import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryServices;
import com.forgerock.sapi.gateway.test.trusted.directory.router.ApiClientRouter;
import com.forgerock.sapi.gateway.test.trusted.directory.router.DirectoryRouter;
import com.forgerock.sapi.gateway.test.trusted.directory.router.HealthRouter;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.ext.web.Router;

/**
 * Main Vert.x verticle for the Test Trusted Directory.
 * <p>
 * Loads configuration from a YAML file (path from env var {@code TTD_CONFIG_PATH},
 * defaulting to classpath {@code config.yml}), creates application services via
 * {@link TrustedDirectoryServices}, registers routes, and starts the HTTP server.
 */
public class TrustedDirectoryVerticle extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(TrustedDirectoryVerticle.class);

    @Override
    public void start(final Promise<Void> startPromise) {
        new ConfigLoader(vertx)
                .load()
                .compose(this::initialize)
                .onSuccess(v -> startPromise.complete())
                .onFailure(startPromise::fail);
    }

    private Future<Void> initialize(final LoadedConfig loadedConfig) {
        try {
            TrustedDirectoryConfig properties = loadedConfig.properties();
            TrustedDirectoryServices appConfig = new TrustedDirectoryServices(properties);

            Router router = Router.router(vertx);
            new HealthRouter(properties).mount(router);
            new DirectoryRouter(appConfig.getSsaSigningService()).mount(router);
            new ApiClientRouter(
                    appConfig.getSoftwareJwksService(),
                    appConfig.getSsaService(),
                    properties
            ).mount(router);

            return vertx.createHttpServer()
                    .requestHandler(router)
                    .listen(loadedConfig.port())
                    .onSuccess(s -> logger.info("HTTP server started on port {}", s.actualPort()))
                    .mapEmpty();
        } catch (Exception e) {
            return Future.failedFuture(e);
        }
    }
}
