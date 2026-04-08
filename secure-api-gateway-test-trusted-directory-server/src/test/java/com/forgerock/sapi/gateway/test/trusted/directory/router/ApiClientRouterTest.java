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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryConfig;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaService;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.client.WebClient;

@ExtendWith(MockitoExtension.class)
class ApiClientRouterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ORG_ID = "PSDGB-FCA-123456";
    private static final String ORG_NAME = "Test Bank Ltd";
    private static final String SOFTWARE_ID = "test-software-id";

    @Mock private SoftwareJwksService softwareJwksService;
    @Mock private SsaService ssaService;

    private Vertx vertx;
    private HttpServer server;
    private WebClient client;
    private int port;

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
        port = server.actualPort();
        client = WebClient.create(vertx);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (server != null) server.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
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

    // ─────────────────────── issueCert ───────────────────────

    @Test
    void issueCert_returnsJwksOnSuccess() throws Exception {
        when(softwareJwksService.issueSoftwareCertificates(anyString(), anyString(), anyString(), any()))
                .thenReturn(buildTestJwkSet());

        var body = MAPPER.writeValueAsString(Map.of("org_id", ORG_ID, "org_name", ORG_NAME));
        var response = client.post(port, "localhost", "/jwkms/apiclient/issuecert")
                .putHeader("Content-Type", "application/json")
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.bodyAsString()).contains("keys");
    }

    @Test
    void issueCert_usesSoftwareIdWhenProvided() throws Exception {
        when(softwareJwksService.issueSoftwareCertificates(anyString(), anyString(), anyString(), any()))
                .thenReturn(buildTestJwkSet());

        var body = MAPPER.writeValueAsString(Map.of("org_id", ORG_ID, "org_name", ORG_NAME, "software_id", SOFTWARE_ID));
        client.post(port, "localhost", "/jwkms/apiclient/issuecert")
                .putHeader("Content-Type", "application/json")
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        ArgumentCaptor<String> softwareIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(softwareJwksService).issueSoftwareCertificates(eq(ORG_ID), eq(ORG_NAME), softwareIdCaptor.capture(), any());
        assertThat(softwareIdCaptor.getValue()).isEqualTo(SOFTWARE_ID);
    }

    @Test
    void issueCert_generatesRandomSoftwareIdWhenNotProvided() throws Exception {
        when(softwareJwksService.issueSoftwareCertificates(anyString(), anyString(), anyString(), any()))
                .thenReturn(buildTestJwkSet());

        var body = MAPPER.writeValueAsString(Map.of("org_id", ORG_ID, "org_name", ORG_NAME));
        client.post(port, "localhost", "/jwkms/apiclient/issuecert")
                .putHeader("Content-Type", "application/json")
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        ArgumentCaptor<String> softwareIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(softwareJwksService).issueSoftwareCertificates(eq(ORG_ID), eq(ORG_NAME), softwareIdCaptor.capture(), any());
        assertThat(softwareIdCaptor.getValue()).isNotBlank().isNotEqualTo(ORG_ID);
    }

    @Test
    void issueCert_shouldReturn400WhenOrgIdIsBlank() throws Exception {
        var body = MAPPER.writeValueAsString(Map.of("org_id", "", "org_name", ORG_NAME));
        var response = client.post(port, "localhost", "/jwkms/apiclient/issuecert")
                .putHeader("Content-Type", "application/json")
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(400);
    }

    @Test
    void issueCert_shouldReturn400WhenOrgNameIsBlank() throws Exception {
        var body = MAPPER.writeValueAsString(Map.of("org_id", ORG_ID, "org_name", " "));
        var response = client.post(port, "localhost", "/jwkms/apiclient/issuecert")
                .putHeader("Content-Type", "application/json")
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(400);
    }

    // ─────────────────────── getSoftwareJwks ───────────────────────

    @Test
    void getSoftwareJwks_returnsPublicJwks() throws Exception {
        when(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).thenReturn(buildTestJwkSet());

        var response = client.get(port, "localhost", "/jwkms/apiclient/jwks/" + ORG_ID + "/" + SOFTWARE_ID)
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.bodyAsString()).contains("keys");
    }

    @Test
    void getSoftwareJwks_returns404WhenNotFound() throws Exception {
        when(softwareJwksService.getPublicSoftwareJwks(anyString(), anyString())).thenReturn(null);

        var response = client.get(port, "localhost", "/jwkms/apiclient/jwks/unknown/unknown")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(404);
    }

    // ─────────────────────── getSsa ───────────────────────

    @Test
    void getSsa_returnsJwtString() throws Exception {
        when(ssaService.generateSsa(anyString(), any())).thenReturn("signed.jwt.token");

        CaCertificateResource ca = CaCertificateResource.getInstance();
        java.io.StringWriter sw = new java.io.StringWriter();
        try (org.bouncycastle.openssl.jcajce.JcaPEMWriter pw = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)) {
            pw.writeObject(ca.getCertificate());
        }
        String encodedCert = java.net.URLEncoder.encode(sw.toString(), "UTF-8");

        var body = MAPPER.writeValueAsString(Map.of("software_id", SOFTWARE_ID));
        var response = client.post(port, "localhost", "/jwkms/apiclient/getssa")
                .putHeader("Content-Type", "application/json")
                .putHeader("ssl-client-cert", encodedCert)
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.bodyAsString()).isEqualTo("signed.jwt.token");
    }

    @Test
    void getSsa_returns400WhenNoCertHeader() throws Exception {
        var body = MAPPER.writeValueAsString(Map.of("software_id", SOFTWARE_ID));
        var response = client.post(port, "localhost", "/jwkms/apiclient/getssa")
                .putHeader("Content-Type", "application/json")
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(400);
    }

    // ─────────────────────── revokeCert ───────────────────────

    @Test
    void revokeCert_returns200OnSuccess() throws Exception {
        var body = MAPPER.writeValueAsString(Map.of("org_id", ORG_ID, "software_id", SOFTWARE_ID, "key_id", "kid-1"));
        var response = client.post(port, "localhost", "/jwkms/apiclient/jwks/revokecert")
                .putHeader("Content-Type", "application/json")
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(200);
        verify(softwareJwksService).removeCertificate(ORG_ID, SOFTWARE_ID, "kid-1");
    }

    @Test
    void revokeCert_returns400WhenFieldsMissing() throws Exception {
        var body = MAPPER.writeValueAsString(Map.of("org_id", ORG_ID));
        var response = client.post(port, "localhost", "/jwkms/apiclient/jwks/revokecert")
                .putHeader("Content-Type", "application/json")
                .sendBuffer(io.vertx.core.buffer.Buffer.buffer(body))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(400);
    }
}
