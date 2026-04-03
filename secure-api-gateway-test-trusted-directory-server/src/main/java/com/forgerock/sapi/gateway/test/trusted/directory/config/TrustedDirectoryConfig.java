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
package com.forgerock.sapi.gateway.test.trusted.directory.config;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaSigningService;

@Configuration
@EnableConfigurationProperties(TrustedDirectoryProperties.class)
public class TrustedDirectoryConfig {

    private static final Logger log = LoggerFactory.getLogger(TrustedDirectoryConfig.class);

    /**
     * Creates and configures the {@link CertificateIssuerService} bean by loading the CA private key
     * and certificate from the PKCS12 keystore specified in the application properties.
     *
     * @param properties application properties providing the CA keystore path, passwords, and signing algorithm
     * @return a fully initialised {@link CertificateIssuerService}
     * @throws Exception if the keystore cannot be loaded or the CA key alias is not found
     */
    @Bean
    public CertificateIssuerService certificateIssuerService(TrustedDirectoryProperties properties) throws Exception {
        TrustedDirectoryProperties.CaProperties ca = properties.ca();
        log.info("Loading CA keystore: path={}, type={}, alias={}, pwd-set={}",
                ca.keystorePath(), ca.keystoreType(), ca.keyAlias(),
                ca.keystorePwd() != null && !ca.keystorePwd().isEmpty());
        KeyStore.PrivateKeyEntry entry = KeystoreLoader.loadPrivateKeyEntry(
                ca.keystorePath(), ca.keystoreType(), ca.keystorePwd(), ca.keyAlias(), ca.keystoreKeyPwd());
        PrivateKey caPrivateKey = entry.getPrivateKey();
        X509Certificate caCert = (X509Certificate) entry.getCertificateChain()[0];
        return new CertificateIssuerService(caCert, caPrivateKey, ca.certSigningAlg());
    }

    /**
     * Creates and configures the {@link SsaSigningService} bean by loading the directory's signing private key
     * and building the corresponding public JWKS from the PKCS12 keystore specified in the application properties.
     *
     * @param properties application properties providing the signing keystore path, passwords, and key alias
     * @return a fully initialised {@link SsaSigningService}
     * @throws Exception if the keystore cannot be loaded or the signing key alias is not found
     */
    @Bean
    public SsaSigningService ssaSigningService(TrustedDirectoryProperties properties) throws Exception {
        TrustedDirectoryProperties.SigningProperties signing = properties.signing();
        log.info("Loading signing keystore: path={}, type={}, alias={}, pwd-set={}",
                signing.keystorePath(), signing.keystoreType(), signing.keyAlias(),
                signing.keystorePwd() != null && !signing.keystorePwd().isEmpty());
        KeyStore.PrivateKeyEntry entry = KeystoreLoader.loadPrivateKeyEntry(
                signing.keystorePath(), signing.keystoreType(), signing.keystorePwd(), signing.keyAlias(), signing.keystoreKeyPwd());
        PrivateKey signingPrivateKey = entry.getPrivateKey();
        X509Certificate cert = (X509Certificate) entry.getCertificateChain()[0];
        String keyId = cert.getSerialNumber().toString(16);
        JWK publicJwk = RsaJWK.builder((RSAPublicKey) cert.getPublicKey())
                .keyId(keyId)
                .keyUse("sig")
                .algorithm(JwsAlgorithm.PS256)
                .build();
        JWKSet publicJwks = new JWKSet(Collections.singletonList(publicJwk));
        return new SsaSigningService(signingPrivateKey, keyId, publicJwks);
    }

    /**
     * Creates and configures the {@link SoftwareJwksService} bean, wiring it with the storage file path
     * derived from the application properties.
     *
     * @param certificateIssuerService bean used to issue new signing and transport certificates
     * @param properties               application properties providing the storage file path
     * @param objectMapper             Jackson mapper used for JSON serialisation/deserialisation
     * @return a fully initialised {@link SoftwareJwksService}
     */
    @Bean
    public SoftwareJwksService softwareJwksService(CertificateIssuerService certificateIssuerService,
                                                    TrustedDirectoryProperties properties,
                                                    ObjectMapper objectMapper) {
        return new SoftwareJwksService(certificateIssuerService,
                Path.of(properties.storage().filePath()),
                objectMapper);
    }
}
