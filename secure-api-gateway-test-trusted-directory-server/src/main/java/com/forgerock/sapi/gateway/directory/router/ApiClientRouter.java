/*
 * Copyright © 2024-2026 Ping Identity Corporation (obst@forgerock.com)
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

import java.util.UUID;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.directory.config.TrustedDirectoryConfig;
import com.forgerock.sapi.gateway.directory.dto.IssueCertRequest;
import com.forgerock.sapi.gateway.directory.dto.RevokeCertRequest;
import com.forgerock.sapi.gateway.directory.dto.SsaRequest;
import com.forgerock.sapi.gateway.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.directory.service.SsaService;

import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.Json;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;

/**
 * Registers routes for the API-client management endpoints under {@code /jwkms/apiclient}.
 * Each handler validates inputs, delegates to services, and maps exceptions to HTTP error responses.
 */
public class ApiClientRouter {

    private static final Logger logger = LoggerFactory.getLogger(ApiClientRouter.class);

    private final SoftwareJwksService softwareJwksService;
    private final SsaService ssaService;
    private final TrustedDirectoryConfig properties;

    /**
     * Creates the router with its required service dependencies.
     *
     * @param softwareJwksService manages software JWKS storage
     * @param ssaService          generates Software Statement Assertions
     * @param properties          application configuration
     */
    public ApiClientRouter(final SoftwareJwksService softwareJwksService,
                           final SsaService ssaService,
                           final TrustedDirectoryConfig properties) {
        this.softwareJwksService = requireNonNull(softwareJwksService, "softwareJwksService must be provided");
        this.ssaService = requireNonNull(ssaService, "ssaService must be provided");
        this.properties = requireNonNull(properties, "properties must be provided");
    }

    /**
     * Mounts all {@code /jwkms/apiclient/*} routes on the given router.
     * <p>
     * Endpoints performing crypto or file I/O are registered as blocking handlers to avoid
     * stalling the Vert.x event loop.
     *
     * @param router the parent router to mount onto
     */
    public void mount(final Router router) {
        router.route("/jwkms/apiclient/*").handler(BodyHandler.create());

        router.post("/jwkms/apiclient/issuecert").blockingHandler(ctx -> {
            try {
                IssueCertRequest request = Json.decodeValue(ctx.body().asString(), IssueCertRequest.class);
                if (request.orgId() == null || request.orgId().isBlank()
                        || request.orgName() == null || request.orgName().isBlank()) {
                    RouterHelper.sendBadRequest(ctx, "org_id and org_name are required");
                    return;
                }
                String softwareId = (request.softwareId() != null && !request.softwareId().isBlank())
                        ? request.softwareId() : UUID.randomUUID().toString();
                CertificateOptions options = new CertificateOptions(JwsAlgorithm.PS256,
                        properties.cert().keySize(), properties.cert().validityDays());
                JWKSet jwkSet = softwareJwksService.issueSoftwareCertificates(
                        request.orgId(), request.orgName(), softwareId, options);
                ctx.response()
                   .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                   .end(Json.encode(jwkSet.toJsonValue().getObject()));
            } catch (IllegalArgumentException e) {
                RouterHelper.sendBadRequest(ctx, e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error on POST /jwkms/apiclient/issuecert", e);
                RouterHelper.sendError(ctx, 500, "An unexpected error occurred");
            }
        });

        router.get("/jwkms/apiclient/jwks/:orgId/:softwareId").handler(ctx -> {
            try {
                String orgId = ctx.pathParam("orgId");
                String softwareId = ctx.pathParam("softwareId");
                JWKSet jwkSet = softwareJwksService.getPublicSoftwareJwks(orgId, softwareId);
                if (jwkSet == null) {
                    ctx.response().setStatusCode(404).end();
                    return;
                }
                ctx.response()
                   .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                   .end(Json.encode(jwkSet.toJsonValue().getObject()));
            } catch (Exception e) {
                logger.error("Unexpected error on GET /jwkms/apiclient/jwks", e);
                RouterHelper.sendError(ctx, 500, "An unexpected error occurred");
            }
        });

        router.post("/jwkms/apiclient/getssa").blockingHandler(ctx -> {
            try {
                String certHeader = ctx.request().getHeader("ssl-client-cert");
                if (certHeader == null || certHeader.isBlank()) {
                    RouterHelper.sendBadRequest(ctx, "No client certificate provided in ssl-client-cert header");
                    return;
                }
                SsaRequest request = Json.decodeValue(ctx.body().asString(), SsaRequest.class);
                String jwt = ssaService.generateSsa(certHeader, request);
                ctx.response()
                   .putHeader(HttpHeaders.CONTENT_TYPE, "text/plain")
                   .end(jwt);
            } catch (IllegalArgumentException e) {
                RouterHelper.sendBadRequest(ctx, e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error on POST /jwkms/apiclient/getssa", e);
                RouterHelper.sendError(ctx, 500, "An unexpected error occurred");
            }
        });

        router.post("/jwkms/apiclient/gettlscert").blockingHandler(ctx -> {
            try {
                String pem = softwareJwksService.extractCertAsPem(ctx.body().asString(), "tls");
                ctx.response()
                   .putHeader(HttpHeaders.CONTENT_TYPE, "text/plain")
                   .end(pem);
            } catch (IllegalArgumentException e) {
                RouterHelper.sendBadRequest(ctx, e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error on POST /jwkms/apiclient/gettlscert", e);
                RouterHelper.sendError(ctx, 500, "An unexpected error occurred");
            }
        });

        router.post("/jwkms/apiclient/getsigcert").blockingHandler(ctx -> {
            try {
                String pem = softwareJwksService.extractCertAsPem(ctx.body().asString(), "sig");
                ctx.response()
                   .putHeader(HttpHeaders.CONTENT_TYPE, "text/plain")
                   .end(pem);
            } catch (IllegalArgumentException e) {
                RouterHelper.sendBadRequest(ctx, e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error on POST /jwkms/apiclient/getsigcert", e);
                RouterHelper.sendError(ctx, 500, "An unexpected error occurred");
            }
        });

        router.post("/jwkms/apiclient/jwks/revokecert").blockingHandler(ctx -> {
            try {
                RevokeCertRequest request = Json.decodeValue(ctx.body().asString(), RevokeCertRequest.class);
                if (request.orgId() == null || request.softwareId() == null || request.keyId() == null) {
                    RouterHelper.sendBadRequest(ctx, "Json body must contain fields: [org_id, software_id, key_id]");
                    return;
                }
                softwareJwksService.removeCertificate(request.orgId(), request.softwareId(), request.keyId());
                ctx.response()
                   .setStatusCode(200)
                   .end();
            } catch (IllegalArgumentException e) {
                RouterHelper.sendBadRequest(ctx, e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error on POST /jwkms/apiclient/jwks/revokecert", e);
                RouterHelper.sendError(ctx, 500, "An unexpected error occurred");
            }
        });
    }
}
