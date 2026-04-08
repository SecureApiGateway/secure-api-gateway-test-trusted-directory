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
package com.forgerock.sapi.gateway.test.trusted.directory.router;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaSigningService;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.client.WebClient;

@ExtendWith(MockitoExtension.class)
class DirectoryRouterTest {

    @Mock private SsaSigningService ssaSigningService;

    private Vertx vertx;
    private HttpServer server;
    private WebClient client;
    private int port;

    @BeforeEach
    void setUp() throws Exception {
        vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        new DirectoryRouter(ssaSigningService).mount(router);
        server = vertx.createHttpServer().requestHandler(router).listen(0).toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        port = server.actualPort();
        client = WebClient.create(vertx);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (server != null) server.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        if (vertx != null) vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
    }

    @Test
    void getDirectoryJwks_returnsPublicJwks() throws Exception {
        CaCertificateResource ca = CaCertificateResource.getInstance();
        CertificateIssuerService issuer = new CertificateIssuerService(ca.getCertificate(), ca.getPrivateKey(), "SHA256withRSA");
        CertificateOptions opts = new CertificateOptions(JwsAlgorithm.PS256, 2048, 365);
        var sigKey = issuer.issueSigningCertificate("PSDGB-FCA-123456", "Test Bank", opts);
        var publicJwks = new org.forgerock.json.jose.jwk.JWKSet(java.util.Collections.singletonList(sigKey));
        when(ssaSigningService.getPublicJwks()).thenReturn(publicJwks);

        var response = client.get(port, "localhost", "/jwkms/testdirectory/jwks")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.bodyAsString()).contains("keys");
    }

    @Test
    void getDirectoryJwks_returns500WhenServiceThrows() throws Exception {
        when(ssaSigningService.getPublicJwks()).thenThrow(new RuntimeException("service failure"));

        var response = client.get(port, "localhost", "/jwkms/testdirectory/jwks")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(500);
    }
}
