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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * Test helper that generates a self-signed CA certificate and private key.
 */
public class CaCertificateResource {

    public static final String DEFAULT_CA_CERT_SIGNING_ALG = "SHA256withRSA";

    private static final Provider BC_PROVIDER;

    static {
        Provider existing = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        BC_PROVIDER = existing != null ? existing : new BouncyCastleProvider();
        if (existing == null) {
            Security.addProvider(BC_PROVIDER);
        }
    }

    private static final CaCertificateResource INSTANCE = new CaCertificateResource();

    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    public static CaCertificateResource getInstance() {
        return INSTANCE;
    }

    private CaCertificateResource() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
            keyPairGenerator.initialize(2048);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();

            Calendar calendar = Calendar.getInstance();
            Date startDate = calendar.getTime();
            calendar.add(Calendar.DATE, 1);
            Date endDate = calendar.getTime();

            X500Name issuedCertSubject = new X500Name("CN=Test CA Cert");
            BigInteger issuedCertSerialNum = new BigInteger(128, new SecureRandom());

            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, keyPair.getPublic());
            JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(DEFAULT_CA_CERT_SIGNING_ALG).setProvider(BC_PROVIDER);

            ContentSigner csrContentSigner = csrBuilder.build(privateKey);
            PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);
            X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(
                    issuedCertSubject, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

            JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
            issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
            issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

            X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
            certificate = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate CA certificate and private key", e);
        }
    }

    public X509Certificate getCertificate() { return certificate; }
    public PublicKey getPublicKey() { return certificate.getPublicKey(); }
    public PrivateKey getPrivateKey() { return privateKey; }
}
