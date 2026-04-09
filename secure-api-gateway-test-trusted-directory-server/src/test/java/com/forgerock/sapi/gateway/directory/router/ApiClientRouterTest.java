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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.directory.config.TrustedDirectoryConfig;
import com.forgerock.sapi.gateway.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.directory.service.SsaService;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.impl.HttpClientImpl;
import io.vertx.core.http.impl.HttpServerImpl;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;

@ExtendWith(MockitoExtension.class)
class ApiClientRouterTest {

    private static final String ORG_ID = "PSDGB-FCA-123456";
    private static final String ORG_NAME = "Test Bank Ltd";
    private static final String SOFTWARE_ID = "test-software-id";

    @Mock private SoftwareJwksService softwareJwksService;
    @Mock private SsaService ssaService;

    private Vertx vertx;
    private HttpServer server;
    private WebClient client;

    private final TrustedDirectoryConfig properties = new TrustedDirectoryConfig(
            "Test Issuer", "localhost:8080",
            new TrustedDirectoryConfig.SigningConfig(null, "PKCS12", "jwt-signing", null, null),
            new TrustedDirectoryConfig.CaConfig(null, "PKCS12", "ca", "SHA256withRSA", null, null),
            "/tmp/jwks.json",
            new TrustedDirectoryConfig.CertConfig(2048, 365));

    @BeforeEach
    void setUp() throws Exception {
        vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        new ApiClientRouter(softwareJwksService, ssaService, properties).mount(router);
        server = vertx.createHttpServer().requestHandler(router).listen(0).toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        int port = server.actualPort();
        System.out.printf("port: %d\n", port);
        client = WebClient.create(vertx, new WebClientOptions().setDefaultHost("localhost").setDefaultPort(port));
    }

    @AfterEach
    void tearDown() throws Exception {
        if (vertx != null) vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
    }

    private JWKSet buildTestJwkSet() throws Exception {
        CaCertificateResource ca = CaCertificateResource.getInstance();
        CertificateIssuerService issuer = new CertificateIssuerService(ca.getCertificate(), ca.getPrivateKey(), "SHA256withRSA");
        CertificateOptions opts = new CertificateOptions(JwsAlgorithm.PS256, 2048, 365);
        var sigKey = issuer.issueSigningCertificate(ORG_ID, ORG_NAME, opts);
        var tlsKey = issuer.issueTransportCertificate(ORG_ID, ORG_NAME, opts);
        return new JWKSet(Arrays.asList(sigKey, tlsKey));
    }

    static Stream<Arguments> blankIssueCertBodies() {
        return Stream.of(
                Arguments.of("org_id", Map.of("org_id", "", "org_name", ORG_NAME)),
                Arguments.of("org_name", Map.of("org_id", ORG_ID, "org_name", " "))
        );
    }

    static Stream<Arguments> incompleteRevokeCertBodies() {
        return Stream.of(
                Arguments.of(Map.of("org_id", ORG_ID)),
                Arguments.of(Map.of("org_id", ORG_ID, "software_id", SOFTWARE_ID)),
                Arguments.of(Map.of("software_id", SOFTWARE_ID, "key_id", "kid-1"))
        );
    }

    @Nested
    class IssueCert {

        @Test
        void shouldReturnJwksWhenIssueCertSucceeds() throws Exception {
            when(softwareJwksService.issueSoftwareCertificates(anyString(), anyString(), anyString(), any()))
                    .thenReturn(buildTestJwkSet());

            var response = client.post("/jwkms/apiclient/issuecert")
                    .sendJson(Map.of("org_id", ORG_ID, "org_name", ORG_NAME))
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.bodyAsString()).contains("keys");
        }

        @Test
        void shouldUseSoftwareIdWhenProvided() throws Exception {
            when(softwareJwksService.issueSoftwareCertificates(anyString(), anyString(), anyString(), any()))
                    .thenReturn(buildTestJwkSet());

            client.post("/jwkms/apiclient/issuecert")
                    .sendJson(Map.of("org_id", ORG_ID, "org_name", ORG_NAME, "software_id", SOFTWARE_ID))
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            ArgumentCaptor<String> softwareIdCaptor = ArgumentCaptor.forClass(String.class);
            verify(softwareJwksService).issueSoftwareCertificates(eq(ORG_ID), eq(ORG_NAME), softwareIdCaptor.capture(), any());
            assertThat(softwareIdCaptor.getValue()).isEqualTo(SOFTWARE_ID);
        }

        @Test
        void shouldGenerateRandomSoftwareIdWhenNotProvided() throws Exception {
            when(softwareJwksService.issueSoftwareCertificates(anyString(), anyString(), anyString(), any()))
                    .thenReturn(buildTestJwkSet());

            client.post("/jwkms/apiclient/issuecert")
                    .sendJson(Map.of("org_id", ORG_ID, "org_name", ORG_NAME))
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            ArgumentCaptor<String> softwareIdCaptor = ArgumentCaptor.forClass(String.class);
            verify(softwareJwksService).issueSoftwareCertificates(eq(ORG_ID), eq(ORG_NAME), softwareIdCaptor.capture(), any());
            assertThat(softwareIdCaptor.getValue()).isNotBlank().isNotEqualTo(ORG_ID);
        }

        @ParameterizedTest(name = "blank {0}")
        @MethodSource("com.forgerock.sapi.gateway.directory.router.ApiClientRouterTest#blankIssueCertBodies")
        void shouldReturn400WhenIssueCertFieldIsBlank(String field, Map<String, Object> body) throws Exception {
            var response = client.post("/jwkms/apiclient/issuecert")
                    .sendJson(body)
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(400);
        }
    }

    @Nested
    class GetSoftwareJwks {

        @Test
        void shouldReturnPublicJwksWhenSoftwareExists() throws Exception {
            when(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).thenReturn(buildTestJwkSet());

            var response = client.get("/jwkms/apiclient/jwks/" + ORG_ID + "/" + SOFTWARE_ID)
                    .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.bodyAsString()).contains("keys");
        }

        @Test
        void shouldReturn404WhenSoftwareJwksNotFound() throws Exception {
            when(softwareJwksService.getPublicSoftwareJwks(anyString(), anyString())).thenReturn(null);

            var response = client.get("/jwkms/apiclient/jwks/unknown/unknown")
                    .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(404);
        }
    }

    @Nested
    class GetSsa {

        @Test
        void shouldReturnJwtStringWhenGeneratingSsa() throws Exception {
            when(ssaService.generateSsa(anyString(), any())).thenReturn("signed.jwt.token");

            CaCertificateResource ca = CaCertificateResource.getInstance();
            java.io.StringWriter sw = new java.io.StringWriter();
            try (org.bouncycastle.openssl.jcajce.JcaPEMWriter pw = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)) {
                pw.writeObject(ca.getCertificate());
            }
            String encodedCert = java.net.URLEncoder.encode(sw.toString(), "UTF-8");

            var response = client.post("/jwkms/apiclient/getssa")
                    .putHeader("ssl-client-cert", encodedCert)
                    .sendJson(Map.of("software_id", SOFTWARE_ID))
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.bodyAsString()).isEqualTo("signed.jwt.token");
        }

        @Test
        void shouldReturn400WhenNoCertHeaderProvided() throws Exception {
            var response = client.post("/jwkms/apiclient/getssa")
                    .sendJson(Map.of("software_id", SOFTWARE_ID))
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(400);
        }
    }

    @Nested
    class RevokeCert {

        @Test
        void shouldReturn200WhenRevokeCertSucceeds() throws Exception {
            var response = client.post("/jwkms/apiclient/jwks/revokecert")
                    .sendJson(Map.of("org_id", ORG_ID, "software_id", SOFTWARE_ID, "key_id", "kid-1"))
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(200);
            verify(softwareJwksService).removeCertificate(ORG_ID, SOFTWARE_ID, "kid-1");
        }

        @ParameterizedTest(name = "body={0}")
        @MethodSource("com.forgerock.sapi.gateway.directory.router.ApiClientRouterTest#incompleteRevokeCertBodies")
        void shouldReturn400WhenRevokeCertFieldsMissing(Map<String, Object> body) throws Exception {
            var response = client.post("/jwkms/apiclient/jwks/revokecert")
                    .sendJson(body)
                    .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(400);
        }
    }
}
