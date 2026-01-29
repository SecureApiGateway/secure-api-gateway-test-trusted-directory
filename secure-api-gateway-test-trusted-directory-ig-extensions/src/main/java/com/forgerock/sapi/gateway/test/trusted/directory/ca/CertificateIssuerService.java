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

import static java.util.Objects.requireNonNull;
import static org.forgerock.json.jose.jws.JwsAlgorithm.ES256;
import static org.forgerock.json.jose.jws.JwsAlgorithm.ES384;
import static org.forgerock.json.jose.jws.JwsAlgorithm.ES512;
import static org.forgerock.json.jose.jws.JwsAlgorithm.PS256;
import static org.forgerock.json.jose.jws.JwsAlgorithm.PS384;
import static org.forgerock.json.jose.jws.JwsAlgorithm.PS512;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.forgerock.json.jose.jwk.EcJWK;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsAlgorithmType;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

public class CertificateIssuerService {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final String SIGNING_KEY_USE = "sig";
    private static final String TRANSPORT_KEY_USE = "tls";

    private static final Set<JwsAlgorithm> SUPPORTED_ALG = Set.of(PS256, PS384, PS512,
                                                                  ES256, ES384, ES512);

    private static final String OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97";
    private final Provider provider;
    private final X509Certificate caCertificate;
    private final PrivateKey caPrivateKey;
    private final String certificateSigningAlg;


    public CertificateIssuerService(X509Certificate caCertificate, PrivateKey caPrivateKey, String certificateSigningAlg) {
        this.caCertificate = requireNonNull(caCertificate, "caCertificate must be provided");
        this.caPrivateKey = requireNonNull(caPrivateKey, "caPrivateKey must be provided");
        this.certificateSigningAlg = requireNonNull(certificateSigningAlg, "certificateSigningAlg must be provided");
        this.provider = BouncyCastleProviderSingleton.getInstance();
    }

    public JWK issueSigningCertificateString(String organisationId, String organisationName, CertificateOptions certificateOptions) {
        return issueCertificate(SIGNING_KEY_USE, organisationId, organisationName, certificateOptions);
    }

    public JWK issueTransportCertificate(String organisationId, String organisationName, CertificateOptions certificateOptions) {
        return issueCertificate(TRANSPORT_KEY_USE, organisationId, organisationName, certificateOptions);
    }

    protected JWK issueCertificate(String keyUse, String organisationId, String organisationName, CertificateOptions certificateOptions) {
        Reject.ifBlank(keyUse, "keyUse must be provided");
        Reject.ifBlank(organisationId, "organisationId must be provided");
        Reject.ifBlank(organisationName, "organisationName must be provided");
        requireNonNull(certificateOptions, "certificateOptions must be provided");

        validateCertificateOptions(certificateOptions);
        final JwsAlgorithmType algorithmType = certificateOptions.getJwsAlgorithm().getAlgorithmType();

        final KeyPair keyPair = generateKeyPair(certificateOptions, algorithmType);
        final JWK.Builder<?> jwkBuilder;
        if (keyPair.getPublic() instanceof RSAPublicKey) {
            jwkBuilder = createRsaJwkBuilder(keyPair);
        } else if (keyPair.getPublic() instanceof ECPublicKey) {
            jwkBuilder = createEcJwkBuilder(keyPair);
        } else {
            throw new UnsupportedOperationException("Unsupported key type: " + keyPair.getPublic().getAlgorithm());
        }
        final X509Certificate certificate = createCertificate(keyPair, organisationId, organisationName, certificateOptions);
        final JWK jwk = addCommonJwkValues(jwkBuilder, certificateOptions, certificate, keyUse).build();

        logger.info("Generated JWK for orgId: {}, orgName: {}, publicJwk: {}",
                organisationId, organisationName, jwk.toPublicJwk().get().toJsonString());

        return jwk;
    }

    private void validateCertificateOptions(CertificateOptions certificateOptions) {
        if (!SUPPORTED_ALG.contains(certificateOptions.getJwsAlgorithm())) {
            throw new IllegalArgumentException("JwsAlgorithm not supported: " + certificateOptions.getJwsAlgorithm());
        }
        Reject.ifTrue(certificateOptions.getCertValidityDays() <= 0, "certificateOptions.certValidityDays must be positive");
    }

    private static RsaJWK.Builder createRsaJwkBuilder(KeyPair keyPair) {
        return RsaJWK.builder((RSAPublicKey) keyPair.getPublic())
                .rsaPrivateCrtKey((RSAPrivateCrtKey) keyPair.getPrivate());
    }

    private EcJWK.Builder createEcJwkBuilder(KeyPair keyPair) {
        return EcJWK.builder((ECPublicKey) keyPair.getPublic()).privateKey((ECPrivateKey) keyPair.getPrivate());
    }

    private JWK.Builder<?> addCommonJwkValues(JWK.Builder<?> builder, CertificateOptions certificateOptions, X509Certificate certificate, String keyUse) {
        try {
            final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return builder.keyId(UUID.randomUUID().toString())
                    .algorithm(certificateOptions.getJwsAlgorithm())
                    .x509Chain(Collections.singletonList(Base64.encode(certificate.getEncoded()).toString()))
                    .x509ThumbprintS256(Base64URL.encode(sha256.digest(certificate.getEncoded())).toString())
                    .keyUse(keyUse);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Failed to generate JWK", e);
        }
    }

    private KeyPair generateKeyPair(CertificateOptions certificateOptions, JwsAlgorithmType algorithmType)  {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithmType.name(), provider);
            keyPairGenerator.initialize(certificateOptions.getKeySize());
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to generate keyPair", e);
        }
    }

    private X509Certificate createCertificate(KeyPair keyPair, String organisationId, String organisationName, CertificateOptions certificateOptions) {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);

        Date startDate = calendar.getTime();

        calendar.add(Calendar.DATE, certificateOptions.getCertValidityDays());
        Date endDate = calendar.getTime();

        // Generate a new KeyPair and CSR

        X500Name issuedCertSubject = new X500Name("CN=" + organisationName + ",OID." + OID_ORGANIZATIONAL_IDENTIFIER + "=" + organisationId);
        BigInteger issuedCertSerialNum = new BigInteger(128, new SecureRandom());
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, keyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(certificateSigningAlg).setProvider(provider);

        try {
            // Sign the CSR with the CA key
            ContentSigner csrContentSigner = csrBuilder.build(caPrivateKey);
            PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

            X500Name certIssuer = new X500Name(caCertificate.getSubjectX500Principal().getName());
            X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(
                    certIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

            JcaX509ExtensionUtils issuedCertExtUtils  = new JcaX509ExtensionUtils();
            // Add Extensions
            issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    issuedCertExtUtils.createAuthorityKeyIdentifier(caCertificate));
            issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
            issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
            issuedCertBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));


            X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
            X509Certificate issuedCert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(issuedCertHolder);

            // Verify the issued cert signature against the CA cert
            issuedCert.verify(caCertificate.getPublicKey(), provider);

            return issuedCert;
        } catch (OperatorCreationException | InvalidKeyException | SignatureException | CertIOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to issue certificate", e);
        }
    }

}
