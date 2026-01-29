/*
 * Copyright © 2020-2026 ForgeRock AS (obst@forgerock.com)
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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;

public class CertificateIssuerServiceTest {

    private static final String ORG_ID = "Test-Org-1234";
    private static final String ORG_NAME = "ACME Test Corp";

    private static final CaCertificateResource caCertificateResource = CaCertificateResource.getInstance();

    private CertificateIssuerService certificateIssuerService;

    @BeforeEach
    void beforeEach() {
        certificateIssuerService = new CertificateIssuerService(caCertificateResource.getCertificate(),
                caCertificateResource.getPrivateKey(), CaCertificateResource.DEFAULT_CA_CERT_SIGNING_ALG);
    }

    @Test
    void shouldIssueSigningCertificateWithRsaKey() {
        final CertificateOptions certificateOptions = new CertificateOptions(JwsAlgorithm.PS256, 3096);

        final JWK jwk = certificateIssuerService.issueSigningCertificateString(ORG_ID, ORG_NAME, certificateOptions);

        assertThat(jwk).isNotNull();
        assertThat(jwk).isInstanceOf(RsaJWK.class);
        assertThat(jwk.getKeyId()).isNotNull();
        assertThat(jwk.isPrivate()).isTrue();
        assertThat(jwk.getUse()).isEqualTo("sig");
        assertThat(jwk.getJwaAlgorithm().getJwaAlgorithmName()).isEqualTo("PS256");
        validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, jwk);
        testSigningUsingKey(jwk);
    }

    @Test
    void shouldIssueTransportCertificateWithRsaKey() {
        final CertificateOptions certificateOptions = new CertificateOptions(JwsAlgorithm.PS256, 3096);

        final JWK jwk = certificateIssuerService.issueTransportCertificate(ORG_ID, ORG_NAME, certificateOptions);

        assertThat(jwk).isNotNull();
        assertThat(jwk).isInstanceOf(RsaJWK.class);
        assertThat(jwk.getKeyId()).isNotNull();
        assertThat(jwk.isPrivate()).isTrue();
        assertThat(jwk.getUse()).isEqualTo("tls");
        assertThat(jwk.getJwaAlgorithm().getJwaAlgorithmName()).isEqualTo("PS256");
        validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, jwk);
        testSigningUsingKey(jwk);
    }

    @Test
    void shouldIssueSigningCertificateWithEcKey() {
        final CertificateOptions certificateOptions = new CertificateOptions(JwsAlgorithm.ES256, 256);

        final JWK jwk = certificateIssuerService.issueSigningCertificateString(ORG_ID, ORG_NAME, certificateOptions);

        assertThat(jwk).isNotNull();
        assertThat(jwk).isInstanceOf(EcJWK.class);
        assertThat(jwk.getKeyId()).isNotNull();
        assertThat(jwk.isPrivate()).isTrue();
        assertThat(jwk.getUse()).isEqualTo("sig");
        assertThat(jwk.getJwaAlgorithm().getJwaAlgorithmName()).isEqualTo("ES256");
        validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, jwk);
        testSigningUsingKey(jwk);
    }

    @Test
    void shouldIssueTransportCertificateWithEcKey() {
        final CertificateOptions certificateOptions = new CertificateOptions(JwsAlgorithm.ES256, 256);

        final JWK jwk = certificateIssuerService.issueTransportCertificate(ORG_ID, ORG_NAME, certificateOptions);

        assertThat(jwk).isNotNull();
        assertThat(jwk).isInstanceOf(EcJWK.class);
        assertThat(jwk.getKeyId()).isNotNull();
        assertThat(jwk.isPrivate()).isTrue();
        assertThat(jwk.getUse()).isEqualTo("tls");
        assertThat(jwk.getJwaAlgorithm().getJwaAlgorithmName()).isEqualTo("ES256");
        validateCertIssuedByCa(caCertificateResource.getPublicKey(), ORG_ID, ORG_NAME, jwk);
        testSigningUsingKey(jwk);
    }

    private void testSigningUsingKey(JWK jwk) {
        try {
            final com.nimbusds.jose.jwk.JWK nimbusJwk = com.nimbusds.jose.jwk.JWK.parse(jwk.toJsonString());
            final Map<String, Object> payloadClaims = Map.of("claim1", "value1");
            final JWSAlgorithm alg = JWSAlgorithm.parse(jwk.getJwaAlgorithm().getJwaAlgorithmName());
            final JWSHeader header = new Builder(alg).keyID(nimbusJwk.getKeyID()).build();
            final JWSObject jwsObject = new JWSObject(header, new Payload(payloadClaims));

            if (nimbusJwk instanceof RSAKey) {
                signWithRsa(jwsObject, (RSAKey) nimbusJwk);
            } else if (nimbusJwk instanceof ECKey) {
                signWithEc(jwsObject, (ECKey) nimbusJwk);
            }
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private static void signWithRsa(JWSObject jwsObject, RSAKey rsaJwk) throws JOSEException, ParseException {
        jwsObject.sign(new RSASSASigner(rsaJwk));
        final String serializedJws = jwsObject.serialize();
        assertThat(JWSObject.parse(serializedJws).verify(new RSASSAVerifier(rsaJwk.toRSAPublicKey()))).isTrue();
    }

    private static void signWithEc(JWSObject jwsObject, ECKey ecKey) throws JOSEException, ParseException {
        jwsObject.sign(new ECDSASigner(ecKey));
        final String serializedJws = jwsObject.serialize();
        assertThat(JWSObject.parse(serializedJws).verify(new ECDSAVerifier(ecKey.toECPublicKey()))).isTrue();
    }

    public static void validateCertIssuedByCa(PublicKey caCertPublicKey, String expectedOrgId,
                                               String expectedOrgName, JWK issuedJwk)  {
        try {
            assertThat(issuedJwk.getX509Chain()).isNotNull().hasSize(1);
            X509Certificate cert = X509CertUtils.parse(Base64.decode(issuedJwk.getX509Chain().get(0)));
            cert.verify(caCertPublicKey);
            cert.checkValidity(new Date());
            cert.checkValidity(getDateInDaysFromNow(30));

            final X500Principal subjectX500Principal = cert.getSubjectX500Principal();
            X500Name x500Name = new X500Name(subjectX500Principal.getName());
            final RDN[] cn = x500Name.getRDNs(BCStyle.CN);
            assertThat(cn).hasSize(1);
            assertThat(IETFUtils.valueToString(cn[0].getFirst().getValue())).isEqualTo(expectedOrgName);

            final RDN[] orgIdRdn = x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.97"));
            assertThat(orgIdRdn).hasSize(1);
            assertThat(IETFUtils.valueToString(orgIdRdn[0].getFirst().getValue())).isEqualTo(expectedOrgId);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to validated cert was issued by CA", e);
        }
    }

    private static Date getDateInDaysFromNow(int daysFromNow) {
        // today
        Calendar date = new GregorianCalendar();
        // reset hour, minutes, seconds and millis
        date.set(Calendar.HOUR_OF_DAY, 0);
        date.set(Calendar.MINUTE, 0);
        date.set(Calendar.SECOND, 0);
        date.set(Calendar.MILLISECOND, 0);
        // next day
        date.add(Calendar.DAY_OF_MONTH, daysFromNow);
        return date.getTime();
    }

}