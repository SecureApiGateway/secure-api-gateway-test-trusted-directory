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
package com.forgerock.sapi.gateway.test.trusted.directory.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.forgerock.json.jose.jwk.EcJWK;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.util.encode.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class CertificateIssuerServiceTest {

    private static final String ORG_ID = "Test-Corp-1234";
    private static final String ORG_NAME = "Test Corporation";

    private final CaCertificateResource caCertificateResource = CaCertificateResource.getInstance();
    private CertificateIssuerService service;

    @BeforeEach
    void beforeEach() {
        service = new CertificateIssuerService(
                caCertificateResource.getCertificate(),
                caCertificateResource.getPrivateKey(),
                CaCertificateResource.DEFAULT_CA_CERT_SIGNING_ALG);
    }

    static Object[][] rsaAlgorithms() {
        return new Object[][]{
                {JwsAlgorithm.PS256, 2048},
                {JwsAlgorithm.PS384, 2048},
                {JwsAlgorithm.PS512, 2048},
        };
    }

    static Object[][] ecAlgorithms() {
        return new Object[][]{
                {JwsAlgorithm.ES256, 256},
                {JwsAlgorithm.ES384, 384},
                {JwsAlgorithm.ES512, 521},
        };
    }

    @ParameterizedTest
    @MethodSource("rsaAlgorithms")
    void shouldIssueRsaSigningCertificate(JwsAlgorithm algorithm, int keySize) {
        JWK jwk = service.issueSigningCertificate(ORG_ID, ORG_NAME, new CertificateOptions(algorithm, keySize));
        assertThat(jwk).isInstanceOf(RsaJWK.class);
        assertThat(jwk.isPrivate()).isTrue();
        assertThat(jwk.getUse()).isEqualTo("sig");
        assertThat(jwk.getJwaAlgorithm().getJwaAlgorithmName()).isEqualTo(algorithm.getJwaAlgorithmName());
        validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, jwk);
        testSigningUsingKey(jwk);
    }

    @ParameterizedTest
    @MethodSource("ecAlgorithms")
    void shouldIssueEcSigningCertificate(JwsAlgorithm algorithm, int keySize) {
        JWK jwk = service.issueSigningCertificate(ORG_ID, ORG_NAME, new CertificateOptions(algorithm, keySize));
        assertThat(jwk).isInstanceOf(EcJWK.class);
        assertThat(jwk.isPrivate()).isTrue();
        assertThat(jwk.getUse()).isEqualTo("sig");
        validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, jwk);
        testSigningUsingKey(jwk);
    }

    @Test
    void shouldIssueTransportCertificate() {
        JWK jwk = service.issueTransportCertificate(ORG_ID, ORG_NAME, new CertificateOptions(JwsAlgorithm.PS256, 2048));
        assertThat(jwk.getUse()).isEqualTo("tls");
        validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, jwk);
    }

    @Test
    void shouldRespectCertValidityDays() {
        int validityDays = 90;
        JWK jwk = service.issueSigningCertificate(ORG_ID, ORG_NAME,
                new CertificateOptions(JwsAlgorithm.PS256, 2048, validityDays));

        X509Certificate cert;
        try {
            cert = parseCertFromBase64Der(Base64.decode(jwk.getX509Chain().get(0)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        assertThat(cert).isNotNull();
        try {
            cert.checkValidity(getDateInDaysFromNow(validityDays - 1));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        assertThatThrownBy(() -> cert.checkValidity(getDateInDaysFromNow(validityDays + 1)))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldRejectUnsupportedAlgorithm() {
        CertificateOptions options = new CertificateOptions(JwsAlgorithm.RS256, 2048);
        assertThatThrownBy(() -> service.issueSigningCertificate(ORG_ID, ORG_NAME, options))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("JwsAlgorithm not supported");
    }

    private void testSigningUsingKey(JWK jwk) {
        try {
            byte[] data = "test-payload".getBytes();
            String algName = jwk.getJwaAlgorithm().getJwaAlgorithmName();
            if (jwk instanceof RsaJWK rsaJwk) {
                RSAPrivateKey privateKey = rsaJwk.toRSAPrivateKey();
                RSAPublicKey publicKey = rsaJwk.toRSAPublicKey();
                String jcaAlg = toJcaRsaPssAlgorithm(algName);
                Signature sig = Signature.getInstance(jcaAlg, "BC");
                sig.initSign(privateKey);
                sig.update(data);
                byte[] sigBytes = sig.sign();
                sig.initVerify(publicKey);
                sig.update(data);
                assertThat(sig.verify(sigBytes)).isTrue();
            } else if (jwk instanceof EcJWK ecJwk) {
                ECPrivateKey privateKey = ecJwk.toECPrivateKey();
                ECPublicKey publicKey = ecJwk.toECPublicKey();
                String jcaAlg = toJcaEcAlgorithm(algName);
                Signature sig = Signature.getInstance(jcaAlg, "BC");
                sig.initSign(privateKey);
                sig.update(data);
                byte[] sigBytes = sig.sign();
                sig.initVerify(publicKey);
                sig.update(data);
                assertThat(sig.verify(sigBytes)).isTrue();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String toJcaRsaPssAlgorithm(String jwsAlgName) {
        return switch (jwsAlgName) {
            case "PS256" -> "SHA256withRSAandMGF1";
            case "PS384" -> "SHA384withRSAandMGF1";
            case "PS512" -> "SHA512withRSAandMGF1";
            default -> throw new IllegalArgumentException("Unsupported RSA-PSS algorithm: " + jwsAlgName);
        };
    }

    private static String toJcaEcAlgorithm(String jwsAlgName) {
        return switch (jwsAlgName) {
            case "ES256" -> "SHA256withECDSA";
            case "ES384" -> "SHA384withECDSA";
            case "ES512" -> "SHA512withECDSA";
            default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + jwsAlgName);
        };
    }

    public static void validateCertIssuedByCa(PublicKey caPublicKey, String expectedOrgId,
                                               String expectedOrgName, JWK issuedJwk) {
        try {
            assertThat(issuedJwk.getX509Chain()).isNotNull().hasSize(1);
            X509Certificate cert = parseCertFromBase64Der(Base64.decode(issuedJwk.getX509Chain().get(0)));
            assertThat(cert).isNotNull();
            cert.verify(caPublicKey);
            cert.checkValidity(new Date());

            X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());
            RDN[] cn = x500Name.getRDNs(BCStyle.CN);
            assertThat(cn).hasSize(1);
            assertThat(IETFUtils.valueToString(cn[0].getFirst().getValue())).isEqualTo(expectedOrgName);

            RDN[] orgIdRdn = x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.97"));
            assertThat(orgIdRdn).hasSize(1);
            assertThat(IETFUtils.valueToString(orgIdRdn[0].getFirst().getValue())).isEqualTo(expectedOrgId);
        } catch (Exception e) {
            throw new AssertionError("Certificate validation failed", e);
        }
    }

    private static Date getDateInDaysFromNow(int daysFromNow) {
        Calendar date = new GregorianCalendar();
        date.set(Calendar.HOUR_OF_DAY, 0);
        date.set(Calendar.MINUTE, 0);
        date.set(Calendar.SECOND, 0);
        date.set(Calendar.MILLISECOND, 0);
        date.add(Calendar.DAY_OF_MONTH, daysFromNow);
        return date.getTime();
    }

    private static X509Certificate parseCertFromBase64Der(byte[] derBytes) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(derBytes));
    }
}
