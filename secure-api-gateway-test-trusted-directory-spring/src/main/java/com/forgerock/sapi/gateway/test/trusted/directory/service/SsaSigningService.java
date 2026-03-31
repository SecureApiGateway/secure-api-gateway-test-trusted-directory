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
package com.forgerock.sapi.gateway.test.trusted.directory.service;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Map;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.springframework.stereotype.Service;

import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryProperties;

/**
 * Service that signs Software Statement Assertions (SSAs) using the directory's own signing key.
 * Also exposes the directory's public JWKS for signature verification.
 */
@Service
public class SsaSigningService {

    private final PrivateKey signingPrivateKey;
    private final String keyId;
    private final JWKSet publicJwks;

    public SsaSigningService(TrustedDirectoryProperties properties) throws Exception {
        TrustedDirectoryProperties.SigningProperties signing = properties.getSigning();
        KeyStore keyStore = KeyStore.getInstance(signing.getKeystoreType());
        try (InputStream is = new FileInputStream(signing.getKeystorePath())) {
            keyStore.load(is, signing.getKeystorePassword().toCharArray());
        }
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                signing.getKeyAlias(),
                new KeyStore.PasswordProtection(signing.getKeystoreKeyPassword().toCharArray()));
        if (entry == null) {
            throw new IllegalStateException("Signing key alias '" + signing.getKeyAlias() + "' not found in keystore");
        }
        this.signingPrivateKey = entry.getPrivateKey();
        X509Certificate cert = (X509Certificate) entry.getCertificateChain()[0];

        this.keyId = cert.getSerialNumber().toString(16);

        JWK publicJwk = RsaJWK.builder((RSAPublicKey) cert.getPublicKey())
                .keyId(keyId)
                .keyUse("sig")
                .algorithm(JwsAlgorithm.PS256)
                .build();
        this.publicJwks = new JWKSet(Collections.singletonList(publicJwk));
    }

    /**
     * Signs an SSA payload using the directory's private key (PS256).
     */
    public String sign(Map<String, Object> claimsMap) throws Exception {
        SigningHandler signingHandler = new SigningManager().newRsaSigningHandler(signingPrivateKey);
        JwtClaimsSet claims = new JwtClaimsSet(claimsMap);
        return new JwtBuilderFactory()
                .jws(signingHandler)
                .headers()
                .alg(JwsAlgorithm.PS256)
                .kid(keyId)
                .done()
                .claims(claims)
                .build();
    }

    /**
     * Signs claims using the private key extracted from the provided JWK (ForgeRock native, no Nimbus).
     */
    public String signClaims(Map<String, Object> claimsMap, JWK signingJwk) throws Exception {
        RSAPrivateKey privateKey = ((RsaJWK) signingJwk).toRSAPrivateKey();
        SigningHandler signingHandler = new SigningManager().newRsaSigningHandler(privateKey);
        JwtClaimsSet claims = new JwtClaimsSet(claimsMap);
        return new JwtBuilderFactory()
                .jws(signingHandler)
                .headers()
                .alg(JwsAlgorithm.PS256)
                .kid(signingJwk.getKeyId())
                .done()
                .claims(claims)
                .build();
    }

    public JWKSet getPublicJwks() {
        return publicJwks;
    }
}
