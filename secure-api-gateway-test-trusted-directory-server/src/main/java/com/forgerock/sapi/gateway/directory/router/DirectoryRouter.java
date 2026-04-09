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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.directory.service.SsaSigningService;

import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.Json;
import io.vertx.ext.web.Router;

/**
 * Registers routes for the directory JWKS endpoint under {@code /jwkms/testdirectory}.
 */
public class DirectoryRouter {

    private static final Logger logger = LoggerFactory.getLogger(DirectoryRouter.class);

    private final SsaSigningService ssaSigningService;

    /**
     * Creates the router with the directory's SSA signing service.
     *
     * @param ssaSigningService exposes the directory's public JWKS
     */
    public DirectoryRouter(final SsaSigningService ssaSigningService) {
        this.ssaSigningService = requireNonNull(ssaSigningService, "ssaSigningService must be provided");
    }

    /**
     * Mounts the directory routes on the given router.
     *
     * @param router the parent router to mount onto
     */
    public void mount(final Router router) {
        router.get("/jwkms/testdirectory/jwks").handler(ctx -> {
            try {
                Object jwks = ssaSigningService.getPublicJwks().toJsonValue().getObject();
                ctx.response()
                   .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                   .end(Json.encode(jwks));
            } catch (Exception e) {
                logger.error("Failed to retrieve directory JWKS", e);
                RouterHelper.sendError(ctx, 500, "Failed to retrieve directory JWKS");
            }
        });
    }
}
