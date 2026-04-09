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
package com.forgerock.sapi.gateway.directory.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.forgerock.sapi.gateway.directory.crypto.BouncyCastleProviderHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.directory.ca.CaCertificateResource;
import com.forgerock.sapi.gateway.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.directory.config.TrustedDirectoryConfig;
import com.forgerock.sapi.gateway.directory.dto.SsaRequest;

class SsaServiceTest {

    private static final CaCertificateResource CA = CaCertificateResource.getInstance();
    private static final String ORG_ID = "PSDGB-FCA-123456";
    private static final String ORG_NAME = "Test Bank Ltd";
    private static final String SOFTWARE_ID = "software-abc-123";
    private static final String FQDN = "test.directory.example.com";

    private SsaSigningService ssaSigningService;
    private SoftwareJwksService softwareJwksService;
    private TrustedDirectoryConfig properties;
    private SsaService ssaService;

    /** A TLS certificate issued for ORG_ID/ORG_NAME, used as the ssl-client-cert header value. */
    private String encodedClientCertPem;

    /** A public JWKS for ORG_ID/SOFTWARE_ID. */
    private JWKSet publicJwks;

    @BeforeEach
    void setUp() throws Exception {
        String keyId = CA.getCertificate().getSerialNumber().toString(16);
        JWK publicJwk = RsaJWK.builder((RSAPublicKey) CA.getPublicKey())
                .keyId(keyId).keyUse("sig").algorithm(JwsAlgorithm.PS256).build();
        JWKSet directoryPublicJwks = new JWKSet(List.of(publicJwk));
        ssaSigningService = new SsaSigningService(CA.getPrivateKey(), keyId, directoryPublicJwks);

        softwareJwksService = mock(SoftwareJwksService.class);

        properties = new TrustedDirectoryConfig(
                "SAPI-G Test Trusted Directory", FQDN,
                null, null,
                "/tmp/test-jwks.json",
                new TrustedDirectoryConfig.CertConfig(2048, 365));

        ssaService = new SsaService(ssaSigningService, softwareJwksService, properties);

        // Issue a real TLS certificate for ORG_ID/ORG_NAME to use as the client cert
        CertificateIssuerService issuerService = new CertificateIssuerService(
                CA.getCertificate(), CA.getPrivateKey(), CaCertificateResource.DEFAULT_CA_CERT_SIGNING_ALG);
        JWK tlsJwk = issuerService.issueTransportCertificate(ORG_ID, ORG_NAME,
                new CertificateOptions(JwsAlgorithm.PS256, 2048));
        String certBase64 = tlsJwk.getX509Chain().get(0);
        byte[] der = Base64.getDecoder().decode(certBase64);
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(der));
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        encodedClientCertPem = URLEncoder.encode(pem, StandardCharsets.UTF_8);

        // Public JWKS for the software
        publicJwks = new JWKSet(List.of(issuerService.issueSigningCertificate(ORG_ID, ORG_NAME,
                new CertificateOptions(JwsAlgorithm.PS256, 2048)).toPublicJwk().orElseThrow()));
    }

    @Test
    void shouldReturnSignedJwtWhenJwksEndpointProvided() throws Exception {
        when(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).thenReturn(publicJwks);

        SsaRequest request = new SsaRequest(SOFTWARE_ID, "Test App", null, null, null,
                List.of("https://example.com/callback"), null, null, List.of("PISP"), null);

        String jwt = ssaService.generateSsa(encodedClientCertPem, request);
        assertThat(jwt).isNotBlank();

        SignedJwt signedJwt = new JwtReconstruction().reconstructJwt(jwt, SignedJwt.class);
        JwtClaimsSet claims = signedJwt.getClaimsSet();
        assertThat(claims.getClaim("org_id", String.class)).isEqualTo(ORG_ID);
        assertThat(claims.getClaim("org_name", String.class)).isEqualTo(ORG_NAME);
        assertThat(claims.getClaim("software_id", String.class)).isEqualTo(SOFTWARE_ID);
        assertThat(claims.getIssuer()).isEqualTo("SAPI-G Test Trusted Directory");
        assertThat(claims.getClaim("org_status", String.class)).isEqualTo("Active");
        assertThat(claims.getClaim("software_mode", String.class)).isEqualTo("TEST");
        assertThat(claims.getClaim("software_jwks_endpoint", String.class)).contains(FQDN);
    }

    @Test
    void shouldEmbedJwksInPayloadWhenInlineJwksProvided() throws Exception {
        Map<String, Object> inlineJwks = Map.of("keys", List.of());
        SsaRequest request = new SsaRequest(SOFTWARE_ID, "Test App", null, null, null,
                null, null, null, null, inlineJwks);

        String jwt = ssaService.generateSsa(encodedClientCertPem, request);

        SignedJwt signedJwt = new JwtReconstruction().reconstructJwt(jwt, SignedJwt.class);
        assertThat(signedJwt.getClaimsSet().getClaim("software_jwks", Object.class)).isNotNull();
    }

    @Test
    void shouldThrowWhenCertIsInvalid() {
        SsaRequest request = new SsaRequest(SOFTWARE_ID, null, null, null, null,
                null, null, null, null, null);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> ssaService.generateSsa("not-a-valid-cert", request))
                .withMessageContaining("Invalid client certificate");
    }

    @Test
    void shouldThrowWhenNoJwksExistsForSoftware() {
        when(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).thenReturn(null);
        SsaRequest request = new SsaRequest(SOFTWARE_ID, null, null, null, null,
                null, null, null, null, null);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> ssaService.generateSsa(encodedClientCertPem, request))
                .withMessageContaining("No JWKS exists for org_id: " + ORG_ID);
    }

    @Test
    void shouldDelegateSigningToSsaSigningService() throws Exception {
        when(softwareJwksService.getPublicSoftwareJwks(ORG_ID, SOFTWARE_ID)).thenReturn(publicJwks);

        SsaSigningService mockSigningService = mock(SsaSigningService.class);
        when(mockSigningService.sign(any())).thenReturn("mocked.signed.jwt");
        SsaService serviceWithMock = new SsaService(mockSigningService, softwareJwksService, properties);

        SsaRequest request = new SsaRequest(SOFTWARE_ID, "App", null, null, null,
                null, null, null, null, null);
        String result = serviceWithMock.generateSsa(encodedClientCertPem, request);

        assertThat(result).isEqualTo("mocked.signed.jwt");
        verify(mockSigningService).sign(any());
    }

    @Test
    void shouldThrowWhenCertMissingOrganisationIdentifier() throws Exception {
        // CA cert has DN "CN=Test CA Cert" — no OID.2.5.4.97 (organisationIdentifier)
        String certPem = toPem(CA.getCertificate());
        String encodedPem = URLEncoder.encode(certPem, StandardCharsets.UTF_8);

        SsaRequest request = new SsaRequest(SOFTWARE_ID, null, null, null, null,
                null, null, null, null, null);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> ssaService.generateSsa(encodedPem, request))
                .withMessageContaining("No org identifier");
    }

    @Test
    void shouldThrowWhenCertMissingCommonName() throws Exception {
        // Self-signed cert with only OID.2.5.4.97 in DN, no CN
        X509Certificate certNoCn = buildSelfSignedCert("OID.2.5.4.97=" + ORG_ID);
        String encodedPem = URLEncoder.encode(toPem(certNoCn), StandardCharsets.UTF_8);

        SsaRequest request = new SsaRequest(SOFTWARE_ID, null, null, null, null,
                null, null, null, null, null);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> ssaService.generateSsa(encodedPem, request))
                .withMessageContaining("No CN in cert");
    }

    private static String toPem(X509Certificate cert) throws Exception {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    private static X509Certificate buildSelfSignedCert(final String dn) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", BouncyCastleProviderHolder.PROVIDER);
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();

        Calendar cal = Calendar.getInstance();
        Date notBefore = cal.getTime();
        cal.add(Calendar.DATE, 1);
        Date notAfter = cal.getTime();

        X500Name subject = new X500Name(dn);
        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProviderHolder.PROVIDER)
                .build(kp.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject, new BigInteger(128, new SecureRandom()),
                notBefore, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo());
        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProviderHolder.PROVIDER)
                .getCertificate(holder);
    }
}
