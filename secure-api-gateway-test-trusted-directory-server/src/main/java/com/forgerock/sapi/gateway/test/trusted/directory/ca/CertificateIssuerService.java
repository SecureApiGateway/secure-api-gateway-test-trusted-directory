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

import static java.util.Objects.requireNonNull;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues X.509 certificates for software signing and transport keys.
 * <p>
 * Certificates are signed by the directory's own CA and embedded in ForgeRock
 * {@link org.forgerock.json.jose.jwk.JWK} objects. Supported key algorithms are
 * {@code PS256} and {@code ES256}.
 */
public class CertificateIssuerService {

    private static final Logger logger = LoggerFactory.getLogger(CertificateIssuerService.class);

    private static final String SIGNING_KEY_USE = "sig";
    private static final String TRANSPORT_KEY_USE = "tls";

    private static final Set<JwsAlgorithm> SUPPORTED_ALG = Set.of(
            JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512,
            JwsAlgorithm.ES256, JwsAlgorithm.ES384, JwsAlgorithm.ES512);

    private static final String OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97";

    private final Provider provider;
    private final X509Certificate caCertificate;
    private final PrivateKey caPrivateKey;
    private final String certificateSigningAlg;

    private static final Provider BC_PROVIDER;

    static {
        Provider existing = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        BC_PROVIDER = existing != null ? existing : new BouncyCastleProvider();
        if (existing == null) {
            Security.addProvider(BC_PROVIDER);
        }
    }

    /**
     * Constructs a new {@code CertificateIssuerService} backed by the given CA certificate and private key.
     *
     * @param caCertificate       the CA certificate used to sign issued certificates
     * @param caPrivateKey        the private key of the CA used to sign issued certificates
     * @param certificateSigningAlg the JCA algorithm name used to sign certificates (e.g. {@code "SHA256withRSA"})
     */
    public CertificateIssuerService(final X509Certificate caCertificate, final PrivateKey caPrivateKey,
            final String certificateSigningAlg) {
        this.caCertificate = requireNonNull(caCertificate, "caCertificate must be provided");
        this.caPrivateKey = requireNonNull(caPrivateKey, "caPrivateKey must be provided");
        this.certificateSigningAlg = requireNonNull(certificateSigningAlg,
                "certificateSigningAlg must be provided");
        this.provider = BC_PROVIDER;
    }

    /**
     * Issues a signing certificate (key use {@code sig}) for the given organisation and wraps it in a ForgeRock JWK
     * containing the full key pair and X.509 certificate chain.
     *
     * @param organisationId   the unique identifier of the organisation
     *                         (embedded in the certificate subject OID 2.5.4.97)
     * @param organisationName the display name of the organisation (embedded as the certificate CN)
     * @param options          algorithm, key size, and validity options for the certificate
     * @return a private ForgeRock JWK ({@code use=sig}) containing the generated key pair and certificate
     */
    public JWK issueSigningCertificate(final String organisationId, final String organisationName,
            final CertificateOptions options) {
        return issueCertificate(SIGNING_KEY_USE, organisationId, organisationName, options);
    }

    /**
     * Issues a transport/TLS certificate (key use {@code tls}) for the given organisation and wraps it in a ForgeRock
     * JWK containing the full key pair and X.509 certificate chain.
     *
     * @param organisationId   the unique identifier of the organisation
     * @param organisationName the display name of the organisation
     * @param options          algorithm, key size, and validity options for the certificate
     * @return a private ForgeRock JWK ({@code use=tls}) containing the generated key pair and certificate
     */
    public JWK issueTransportCertificate(final String organisationId, final String organisationName,
            final CertificateOptions options) {
        return issueCertificate(TRANSPORT_KEY_USE, organisationId, organisationName, options);
    }

    /**
     * Issues an X.509 certificate signed by the CA and wraps it in a ForgeRock JWK.
     *
     * @param keyUse           the intended key use ({@code "sig"} or {@code "tls"})
     * @param organisationId   the unique identifier of the organisation
     * @param organisationName the display name of the organisation
     * @param options          algorithm, key size, and validity options for the certificate
     * @return a private ForgeRock JWK containing the generated key pair and certificate
     */
    protected JWK issueCertificate(final String keyUse, final String organisationId,
            final String organisationName, final CertificateOptions options) {
        if (keyUse == null || keyUse.isBlank()) {
            throw new IllegalArgumentException("keyUse must be provided");
        }
        requireNonNull(organisationId, "organisationId must be provided");
        requireNonNull(organisationName, "organisationName must be provided");
        requireNonNull(options, "certificateOptions must be provided");

        validateCertificateOptions(options);

        final KeyPair keyPair = generateKeyPair(options);
        final X509Certificate certificate = createCertificate(keyPair, organisationId, organisationName, options);
        final JWK jwk = buildJwk(keyPair, certificate, options, keyUse);

        logger.info("Generated JWK for orgId: {}, orgName: {}, publicJwk: {}",
                organisationId, organisationName, jwk.toPublicJwk().get().toJsonString());

        return jwk;
    }

    private void validateCertificateOptions(final CertificateOptions options) {
        if (!SUPPORTED_ALG.contains(options.jwsAlgorithm())) {
            throw new IllegalArgumentException("JwsAlgorithm not supported: " + options.jwsAlgorithm());
        }
        if (options.certValidityDays() <= 0) {
            throw new IllegalArgumentException("certValidityDays must be positive");
        }
    }

    private KeyPair generateKeyPair(final CertificateOptions options) {
        try {
            final JwsAlgorithmType algorithmType = options.jwsAlgorithm().getAlgorithmType();
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithmType.name(), provider);
            keyPairGenerator.initialize(options.keySize());
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to generate keyPair", e);
        }
    }

    private JWK buildJwk(final KeyPair keyPair, final X509Certificate certificate,
            final CertificateOptions options, final String keyUse) {
        try {
            final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            final String x5c = Base64.getEncoder().encodeToString(certificate.getEncoded());
            final String x5t = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(sha256.digest(certificate.getEncoded()));

            if (keyPair.getPublic() instanceof RSAPublicKey rsaPub) {
                return RsaJWK.builder(rsaPub)
                        .rsaPrivateCrtKey((RSAPrivateCrtKey) keyPair.getPrivate())
                        .keyId(UUID.randomUUID().toString())
                        .algorithm(options.jwsAlgorithm())
                        .x509Chain(Collections.singletonList(x5c))
                        .x509ThumbprintS256(x5t)
                        .keyUse(keyUse)
                        .build();
            } else if (keyPair.getPublic() instanceof ECPublicKey ecPub) {
                return EcJWK.builder(ecPub)
                        .privateKey((ECPrivateKey) keyPair.getPrivate())
                        .keyId(UUID.randomUUID().toString())
                        .algorithm(options.jwsAlgorithm())
                        .x509Chain(Collections.singletonList(x5c))
                        .x509ThumbprintS256(x5t)
                        .keyUse(keyUse)
                        .build();
            } else {
                throw new UnsupportedOperationException("Unsupported key type: " + keyPair.getPublic().getAlgorithm());
            }
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Failed to generate JWK", e);
        }
    }

    private X509Certificate createCertificate(final KeyPair keyPair, final String organisationId,
            final String organisationName, final CertificateOptions options) {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.DATE, options.certValidityDays());
        Date endDate = calendar.getTime();

        X500Name issuedCertSubject = new X500Name("CN=" + organisationName
                + ",OID." + OID_ORGANIZATIONAL_IDENTIFIER + "=" + organisationId);
        BigInteger issuedCertSerialNum = new BigInteger(128, new SecureRandom());
        PKCS10CertificationRequestBuilder p10Builder =
                new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, keyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(certificateSigningAlg).setProvider(provider);

        try {
            ContentSigner csrContentSigner = csrBuilder.build(caPrivateKey);
            PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

            X500Name certIssuer = new X500Name(caCertificate.getSubjectX500Principal().getName());
            X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(
                    certIssuer, issuedCertSerialNum, startDate, endDate,
                    csr.getSubject(), csr.getSubjectPublicKeyInfo());

            JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
            issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    issuedCertExtUtils.createAuthorityKeyIdentifier(caCertificate));
            issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
            issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
            issuedCertBuilder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

            X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
            X509Certificate issuedCert = new JcaX509CertificateConverter()
                    .setProvider(provider).getCertificate(issuedCertHolder);
            issuedCert.verify(caCertificate.getPublicKey(), provider);
            return issuedCert;
        } catch (OperatorCreationException | InvalidKeyException | SignatureException | CertIOException
                | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to issue certificate", e);
        }
    }
}
