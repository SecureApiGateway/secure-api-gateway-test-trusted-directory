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

import static java.util.Objects.requireNonNull;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;

/**
 * Service that signs Software Statement Assertions (SSAs) using the directory's own signing key.
 * Also exposes the directory's public JWKS for signature verification.
 */
public class SsaSigningService {

    private final PrivateKey signingPrivateKey;
    private final String keyId;
    private final JWKSet publicJwks;

    /**
     * Constructs the service with the directory's pre-loaded signing key and public JWKS.
     * Infrastructure concerns (keystore loading) are handled by the Spring configuration.
     *
     * @param signingPrivateKey the directory's RSA private key used to sign SSA JWTs
     * @param keyId             the key identifier ({@code kid}) embedded in JWT headers
     * @param publicJwks        the public JWKS exposing the corresponding RSA public key
     */
    public SsaSigningService(PrivateKey signingPrivateKey, String keyId, JWKSet publicJwks) {
        this.signingPrivateKey = requireNonNull(signingPrivateKey, "signingPrivateKey must be provided");
        this.keyId = requireNonNull(keyId, "keyId must be provided");
        this.publicJwks = requireNonNull(publicJwks, "publicJwks must be provided");
    }

    /**
     * Signs a Software Statement Assertion (SSA) JWT using the directory's RSA private key (PS256 algorithm).
     *
     * @param claimsMap the claims to include in the SSA JWT payload
     * @return the compact-serialised signed JWT string
     * @throws Exception if signing fails
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
     * Signs the given claims using the RSA private key extracted from the provided ForgeRock JWK (PS256 algorithm).
     * The key ID ({@code kid}) of the signing JWK is embedded in the JWT header.
     *
     * @param claimsMap  the claims to include in the JWT payload
     * @param signingJwk a private {@link RsaJWK} whose private key will be used to sign the JWT
     * @return the compact-serialised signed JWT string
     * @throws Exception if signing fails or the JWK does not contain a private RSA key
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

    /**
     * Returns the directory's public JWKS, containing the RSA public key used to verify SSA signatures.
     *
     * @return the public JWKS of the directory
     */
    public JWKSet getPublicJwks() {
        return publicJwks;
    }
}
