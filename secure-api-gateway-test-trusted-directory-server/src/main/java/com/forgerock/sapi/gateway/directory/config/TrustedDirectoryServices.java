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
package com.forgerock.sapi.gateway.directory.config;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.directory.service.SsaService;
import com.forgerock.sapi.gateway.directory.service.SsaSigningService;

/**
 * Pure-Java factory that creates and wires the application services from
 * {@link TrustedDirectoryConfig}.
 * <p>
 * Keystore passwords are read from {@code properties.signing().keystorePwd()} and
 * {@code properties.ca().keystorePwd()} — resolved from environment variables by
 * {@link com.forgerock.sapi.gateway.directory.config.SecretLoader} before
 * this class is instantiated.
 */
public class TrustedDirectoryServices {

    private static final Logger logger = LoggerFactory.getLogger(TrustedDirectoryServices.class);

    private final CertificateIssuerService certificateIssuerService;
    private final SsaSigningService ssaSigningService;
    private final SoftwareJwksService softwareJwksService;
    private final SsaService ssaService;
    private final TrustedDirectoryConfig properties;

    /**
     * Creates and wires all application services from the given configuration.
     *
     * @param properties the fully-resolved application configuration
     * @throws Exception if keystore loading or service initialisation fails
     */
    public TrustedDirectoryServices(final TrustedDirectoryConfig properties) throws Exception {
        this.properties = Objects.requireNonNull(properties, "properties must be provided");
        this.certificateIssuerService = buildCertificateIssuerService(properties);
        this.ssaSigningService = buildSsaSigningService(properties);
        this.softwareJwksService = buildSoftwareJwksService(certificateIssuerService, properties);
        this.ssaService = new SsaService(ssaSigningService, softwareJwksService, properties);
        StartupLogger.logConfiguration(properties);
    }

    private static CertificateIssuerService buildCertificateIssuerService(
            final TrustedDirectoryConfig properties) throws Exception {
        TrustedDirectoryConfig.CaConfig ca = properties.ca();
        logger.info("Loading CA keystore: path={}, type={}, alias={}",
                ca.keystorePath(), ca.keystoreType(), ca.keyAlias());
        KeyStore.PrivateKeyEntry entry = KeystoreLoader.loadPrivateKeyEntry(
                ca.keystorePath(), ca.keystoreType(), ca.keystorePwd(), ca.keyAlias(), ca.keystoreKeyPwd());
        PrivateKey caPrivateKey = entry.getPrivateKey();
        X509Certificate caCert = (X509Certificate) entry.getCertificateChain()[0];
        return new CertificateIssuerService(caCert, caPrivateKey, ca.certSigningAlg());
    }

    private static SsaSigningService buildSsaSigningService(
            final TrustedDirectoryConfig properties) throws Exception {
        TrustedDirectoryConfig.SigningConfig signing = properties.signing();
        logger.info("Loading signing keystore: path={}, type={}, alias={}",
                signing.keystorePath(), signing.keystoreType(), signing.keyAlias());
        KeyStore.PrivateKeyEntry entry = KeystoreLoader.loadPrivateKeyEntry(
                signing.keystorePath(), signing.keystoreType(),
                signing.keystorePwd(), signing.keyAlias(), signing.keystoreKeyPwd());
        PrivateKey signingPrivateKey = entry.getPrivateKey();
        X509Certificate cert = (X509Certificate) entry.getCertificateChain()[0];
        String keyId = cert.getSerialNumber().toString(16);
        JWK publicJwk = RsaJWK.builder((RSAPublicKey) cert.getPublicKey())
                .keyId(keyId)
                .keyUse("sig")
                .algorithm(JwsAlgorithm.PS256)
                .build();
        JWKSet publicJwks = new JWKSet(List.of(publicJwk));
        return new SsaSigningService(signingPrivateKey, keyId, publicJwks);
    }

    private static SoftwareJwksService buildSoftwareJwksService(
            final CertificateIssuerService certificateIssuerService,
            final TrustedDirectoryConfig properties) {
        return new SoftwareJwksService(certificateIssuerService,
                Path.of(properties.storageFilePath()),
                new ObjectMapper());
    }

    /**
     * Returns the certificate issuer service.
     *
     * @return the certificate issuer service
     */
    public CertificateIssuerService getCertificateIssuerService() {
        return certificateIssuerService;
    }

    /**
     * Returns the SSA signing service.
     *
     * @return the SSA signing service
     */
    public SsaSigningService getSsaSigningService() {
        return ssaSigningService;
    }

    /**
     * Returns the software JWKS service.
     *
     * @return the software JWKS service
     */
    public SoftwareJwksService getSoftwareJwksService() {
        return softwareJwksService;
    }

    /**
     * Returns the SSA service.
     *
     * @return the SSA service
     */
    public SsaService getSsaService() {
        return ssaService;
    }

    /**
     * Returns the application configuration properties.
     *
     * @return the application configuration properties
     */
    public TrustedDirectoryConfig getProperties() {
        return properties;
    }
}
