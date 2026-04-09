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
package com.forgerock.sapi.gateway.directory.router;

import static java.util.Objects.requireNonNull;

import java.nio.file.Files;
import java.nio.file.Path;

import com.forgerock.sapi.gateway.directory.config.TrustedDirectoryConfig;

import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;

/**
 * Registers health check routes.
 * <ul>
 *   <li>{@code GET /health/liveness} — always {@code 200} if the process is alive</li>
 *   <li>{@code GET /health/readiness} — {@code 200} if the JWKS storage file (or its parent directory)
 *       exists and is writable, {@code 503} otherwise</li>
 * </ul>
 */
public class HealthRouter {

    private final Path storageFilePath;

    /**
     * Creates the router with the application configuration.
     *
     * @param properties application configuration providing the storage file path
     */
    public HealthRouter(final TrustedDirectoryConfig properties) {
        this.storageFilePath = Path.of(requireNonNull(properties, "properties must be provided").storageFilePath());
    }

    /**
     * Mounts {@code /health/liveness} and {@code /health/readiness} on the given router.
     *
     * @param router the parent router to mount onto
     */
    public void mount(final Router router) {
        router.get("/health/liveness").handler(ctx ->
                ctx.response()
                   .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                   .end(new JsonObject().put("status", "UP").encode()));

        router.get("/health/readiness").handler(ctx -> {
            boolean storageReady = isStorageWritable();
            if (storageReady) {
                ctx.response()
                   .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                   .end(new JsonObject().put("status", "UP").encode());
            } else {
                ctx.response()
                   .setStatusCode(503)
                   .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                   .end(new JsonObject().put("status", "DOWN")
                                        .put("reason", "storage is not writable")
                                        .encode());
            }
        });
    }

    private boolean isStorageWritable() {
        if (Files.exists(storageFilePath)) {
            return Files.isWritable(storageFilePath);
        }
        Path parent = storageFilePath.getParent() != null ? storageFilePath.getParent() : storageFilePath;
        return Files.exists(parent) && Files.isWritable(parent);
    }
}
