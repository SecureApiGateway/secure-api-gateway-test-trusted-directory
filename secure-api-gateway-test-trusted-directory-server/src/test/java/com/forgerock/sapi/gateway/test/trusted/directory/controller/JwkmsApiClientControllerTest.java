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
package com.forgerock.sapi.gateway.test.trusted.directory.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.StringWriter;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryProperties;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaSigningService;

@WebMvcTest(JwkmsApiClientController.class)
@Import(JwkmsApiClientControllerTest.TestConfig.class)
class JwkmsApiClientControllerTest {

    private static final CaCertificateResource CA = CaCertificateResource.getInstance();
    private static final String ORG_ID = "PSDGB-FCA-123456";
    private static final String ORG_NAME = "Test Bank Ltd";
    private static final String SOFTWARE_ID = "software-abc-123";

    @TestConfiguration
    @EnableConfigurationProperties
    static class TestConfig {
        @Bean
        TrustedDirectoryProperties trustedDirectoryProperties() {
            return new TrustedDirectoryProperties(
                    "Test Trusted Directory",
                    "test.directory.example.com",
                    null, null,
                    new TrustedDirectoryProperties.StorageProperties("/tmp/test-jwks.json"),
                    new TrustedDirectoryProperties.CertProperties(2048, 365));
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private SoftwareJwksService softwareJwksService;

    @MockitoBean
    private SsaSigningService ssaSigningService;

    @MockitoBean
    private SsaService ssaService;

    /** A full JWKS (with private keys + x5c) issued for ORG_ID/SOFTWARE_ID, reused across tests. */
    private JWKSet issuedJwkSet;

    @BeforeEach
    void setUp() {
        CertificateIssuerService issuerService = new CertificateIssuerService(
                CA.getCertificate(), CA.getPrivateKey(), CaCertificateResource.DEFAULT_CA_CERT_SIGNING_ALG);
        CertificateOptions options = new CertificateOptions(JwsAlgorithm.PS256, 2048, 365);
        JWK sigKey = issuerService.issueSigningCertificate(ORG_ID, ORG_NAME, options);
        JWK tlsKey = issuerService.issueTransportCertificate(ORG_ID, ORG_NAME, options);
        issuedJwkSet = new JWKSet(Arrays.asList(sigKey, tlsKey));
    }

    // ─── issueCert ────────────────────────────────────────────────────────────

    @Test
    void issueCert_shouldReturn200WithPrivateJwks() throws Exception {
        when(softwareJwksService.issueSoftwareCertificates(eq(ORG_ID), eq(ORG_NAME), eq(SOFTWARE_ID), any()))
                .thenReturn(issuedJwkSet);

        mockMvc.perform(post("/jwkms/apiclient/issuecert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"org_id":"%s","org_name":"%s","software_id":"%s"}
                                """.formatted(ORG_ID, ORG_NAME, SOFTWARE_ID)))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys.length()").value(2));
    }

    @Test
    void issueCert_shouldAutoAssignSoftwareIdWhenMissing() throws Exception {
        when(softwareJwksService.issueSoftwareCertificates(eq(ORG_ID), eq(ORG_NAME), anyString(), any()))
                .thenReturn(issuedJwkSet);

        mockMvc.perform(post("/jwkms/apiclient/issuecert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"org_id":"%s","org_name":"%s"}
                                """.formatted(ORG_ID, ORG_NAME)))
                .andExpect(status().isOk());

        ArgumentCaptor<String> softwareIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(softwareJwksService).issueSoftwareCertificates(eq(ORG_ID), eq(ORG_NAME),
                softwareIdCaptor.capture(), any());
        assertThat(softwareIdCaptor.getValue())
                .isNotBlank()
                .matches("[0-9a-f-]{36}"); // UUID format
    }

    @Test
    void issueCert_shouldReturn400WhenOrgIdMissing() throws Exception {
        mockMvc.perform(post("/jwkms/apiclient/issuecert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"org_name":"%s","software_id":"%s"}
                                """.formatted(ORG_NAME, SOFTWARE_ID)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void issueCert_shouldReturn400WhenOrgIdIsBlank() throws Exception {
        mockMvc.perform(post("/jwkms/apiclient/issuecert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"org_id":"  ","org_name":"%s","software_id":"%s"}
                                """.formatted(ORG_NAME, SOFTWARE_ID)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void issueCert_shouldReturn400WhenOrgNameMissing() throws Exception {
        mockMvc.perform(post("/jwkms/apiclient/issuecert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"org_id":"%s","software_id":"%s"}
                                """.formatted(ORG_ID, SOFTWARE_ID)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void issueCert_shouldReturn400WhenOrgNameIsBlank() throws Exception {
        mockMvc.perform(post("/jwkms/apiclient/issuecert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"org_id":"%s","org_name":"","software_id":"%s"}
                                """.formatted(ORG_ID, SOFTWARE_ID)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    // ─── getSoftwareJwks ──────────────────────────────────────────────────────

    @Test
    void getSoftwareJwks_shouldReturn200WithPublicJwks() throws Exception {
        JWKSet publicJwks = new JWKSet(issuedJwkSet.getJWKsAsList().stream()
                .map(JWK::toPublicJwk)
                .flatMap(java.util.Optional::stream)
                .toList());
        when(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).thenReturn(publicJwks);

        mockMvc.perform(get("/jwkms/apiclient/jwks/{orgId}/{softwareId}", ORG_ID, SOFTWARE_ID))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys.length()").value(2));
    }

    @Test
    void getSoftwareJwks_shouldReturn404WhenNotFound() throws Exception {
        when(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).thenReturn(null);

        mockMvc.perform(get("/jwkms/apiclient/jwks/{orgId}/{softwareId}", ORG_ID, SOFTWARE_ID))
                .andExpect(status().isNotFound());
    }

    // ─── getSsa ───────────────────────────────────────────────────────────────

    @Test
    void getSsa_shouldReturn200JwtWithValidCert() throws Exception {
        when(ssaService.generateSsa(eq("any-cert"), any())).thenReturn("signed.ssa.jwt");

        MvcResult result = mockMvc.perform(post("/jwkms/apiclient/getssa")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("ssl-client-cert", "any-cert")
                        .content(objectMapper.writeValueAsString(Map.of(
                                "software_id", SOFTWARE_ID,
                                "software_client_name", "Test App"))))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).isEqualTo("signed.ssa.jwt");
    }

    @Test
    void getSsa_shouldReturn400WhenCertHeaderMissing() throws Exception {
        mockMvc.perform(post("/jwkms/apiclient/getssa")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("software_id", SOFTWARE_ID))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void getSsa_shouldReturn400WhenCertIsInvalid() throws Exception {
        when(ssaService.generateSsa(any(), any()))
                .thenThrow(new IllegalArgumentException("Invalid client certificate in ssl-client-cert header"));

        mockMvc.perform(post("/jwkms/apiclient/getssa")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("ssl-client-cert", "not-a-valid-cert")
                        .content(objectMapper.writeValueAsString(Map.of("software_id", SOFTWARE_ID))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Invalid client certificate in ssl-client-cert header"));
    }

    @Test
    void getSsa_shouldReturn400WhenNoJwksExistsForSoftware() throws Exception {
        when(ssaService.generateSsa(any(), any()))
                .thenThrow(new IllegalArgumentException(
                        "No JWKS exists for org_id: " + ORG_ID + " and software_id: " + SOFTWARE_ID
                                + " - Please issue certificates for this software first."));

        mockMvc.perform(post("/jwkms/apiclient/getssa")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("ssl-client-cert", "any-cert")
                        .content(objectMapper.writeValueAsString(Map.of("software_id", SOFTWARE_ID))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    // ─── signClaims ───────────────────────────────────────────────────────────

    @Test
    void signClaims_shouldReturn200Jwt() throws Exception {
        when(ssaSigningService.signClaims(any(), any())).thenReturn("signed.claims.jwt");

        @SuppressWarnings("unchecked")
        Map<String, Object> body = Map.of(
                "claims", Map.of("sub", "test"),
                "jwks", issuedJwkSet.toJsonValue().getObject());

        MvcResult result = mockMvc.perform(post("/jwkms/apiclient/signclaims")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).isEqualTo("signed.claims.jwt");
    }

    @Test
    void signClaims_shouldReturn400WhenClaimsMissing() throws Exception {
        mockMvc.perform(post("/jwkms/apiclient/signclaims")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("jwks", Map.of()))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void signClaims_shouldReturn400WhenJwksMissing() throws Exception {
        mockMvc.perform(post("/jwkms/apiclient/signclaims")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("claims", Map.of("sub", "test")))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void signClaims_shouldReturn400WhenNoSigKeyInJwks() throws Exception {
        JWK tlsOnly = issuedJwkSet.getJWKsAsList().stream()
                .filter(k -> "tls".equals(k.getUse()))
                .findFirst().orElseThrow();
        JWKSet tlsOnlyJwks = new JWKSet(List.of(tlsOnly));

        Map<String, Object> body = Map.of("claims", Map.of("sub", "test"), "jwks", tlsOnlyJwks.toJsonValue().getObject());

        mockMvc.perform(post("/jwkms/apiclient/signclaims")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    // ─── getTlsCert / getSigCert ──────────────────────────────────────────────

    @Test
    void getTlsCert_shouldReturnPemForTlsKey() throws Exception {
        String jwksJson = objectMapper.writeValueAsString(issuedJwkSet.toJsonValue().getObject());
        String fakePem = "-----BEGIN CERTIFICATE-----\nMIIFake\n-----END CERTIFICATE-----\n" +
                "-----BEGIN RSA PRIVATE KEY-----\nMIIFake\n-----END RSA PRIVATE KEY-----\n";
        when(softwareJwksService.extractCertAsPem(jwksJson, "tls")).thenReturn(fakePem);

        MvcResult result = mockMvc.perform(post("/jwkms/apiclient/gettlscert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jwksJson))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).isEqualTo(fakePem);
        verify(softwareJwksService).extractCertAsPem(jwksJson, "tls");
    }

    @Test
    void getSigCert_shouldReturnPemForSigKey() throws Exception {
        String jwksJson = objectMapper.writeValueAsString(issuedJwkSet.toJsonValue().getObject());
        String fakePem = "-----BEGIN CERTIFICATE-----\nMIIFake\n-----END CERTIFICATE-----\n" +
                "-----BEGIN RSA PRIVATE KEY-----\nMIIFake\n-----END RSA PRIVATE KEY-----\n";
        when(softwareJwksService.extractCertAsPem(jwksJson, "sig")).thenReturn(fakePem);

        MvcResult result = mockMvc.perform(post("/jwkms/apiclient/getsigcert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jwksJson))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).isEqualTo(fakePem);
        verify(softwareJwksService).extractCertAsPem(jwksJson, "sig");
    }

    // ─── revokeCert ───────────────────────────────────────────────────────────

    @Test
    void revokeCert_shouldReturn200OnSuccess() throws Exception {
        String keyId = issuedJwkSet.getJWKsAsList().get(0).getKeyId();

        mockMvc.perform(post("/jwkms/apiclient/jwks/revokecert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"org_id":"%s","software_id":"%s","key_id":"%s"}
                                """.formatted(ORG_ID, SOFTWARE_ID, keyId)))
                .andExpect(status().isOk());

        verify(softwareJwksService).removeCertificate(ORG_ID, SOFTWARE_ID, keyId);
    }

    @Test
    void revokeCert_shouldReturn400WhenFieldsMissing() throws Exception {
        mockMvc.perform(post("/jwkms/apiclient/jwks/revokecert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"org_id":"%s"}
                                """.formatted(ORG_ID)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Extracts the first X509Certificate from the JWK's x5c chain by decoding the DER bytes.
     */
    private static java.security.cert.X509Certificate extractCert(JWK jwk) throws Exception {
        List<String> x5c = jwk.getX509Chain();
        assertThat(x5c).isNotEmpty();
        byte[] der = java.util.Base64.getDecoder().decode(x5c.get(0));
        return (java.security.cert.X509Certificate)
                java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    private static String toPem(Object obj) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(obj);
        }
        return writer.toString();
    }
}
