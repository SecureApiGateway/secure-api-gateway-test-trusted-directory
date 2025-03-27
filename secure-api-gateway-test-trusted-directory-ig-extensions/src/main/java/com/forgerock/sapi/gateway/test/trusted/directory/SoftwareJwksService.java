/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.test.trusted.directory;

import static java.util.Objects.requireNonNull;
import static org.forgerock.openig.secrets.SecretsProviderHeaplet.secretsProvider;
import static org.forgerock.secrets.Purpose.purpose;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.KeyType;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.promise.Promise;

import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;

/**
 * Service which manages JWKS (Json Web Key Set) for pieces of Software.
 * <p>
 * Software is uniquely identified by the organisationId which owns the software and the softwareId.
 * <p>
 * This service supports issuing new JWKS, adding new keys to an existing JWKS and retrieving a JWKS.
 */
public class SoftwareJwksService {

    private final CertificateIssuerService certificateIssuerService;

    private final ConcurrentMap<String, JWKSet> softwareJwkSets = new ConcurrentHashMap<>();

    public SoftwareJwksService(CertificateIssuerService certificateIssuerService) {
        this.certificateIssuerService = requireNonNull(certificateIssuerService, "certificateIssuerService must be provided");
    }

    public JWKSet issueSoftwareCertificates(String organisationId, String organisationName, String softwareId, CertificateOptions certificateOptions) {
        requireNonNull(organisationId, "organisationId must be provided");
        requireNonNull(organisationName, "organisationName must be provided");
        requireNonNull(softwareId, "softwareId must be provided");
        requireNonNull(certificateOptions, "certificateOptions must be provided");
        return softwareJwkSets.compute(jwkSetKey(organisationId, softwareId), (cacheKey, existingJwks) -> {
            final JWK signingKey = certificateIssuerService.issueSigningCertificateString(organisationId, organisationName, certificateOptions);
            final JWK transportKey = certificateIssuerService.issueTransportCertificate(organisationId, organisationName, certificateOptions);
            if (existingJwks == null) {
                return new JWKSet(List.of(signingKey, transportKey));
            } else {
                final List<JWK> keys = Arrays.asList(signingKey, transportKey);
                return new JWKSet(keys);
            }
        });
    }

    private static String jwkSetKey(String organisationId, String softwareId) {
        return organisationId + "-" + softwareId;
    }

    public JWKSet getPublicSoftwareJwks(String organisationId, String softwareId) {
        requireNonNull(organisationId, "organisationId must be provided");
        requireNonNull(softwareId, "softwareId must be provided");
        final JWKSet jwkSet = softwareJwkSets.get(jwkSetKey(organisationId, softwareId));
        if (jwkSet != null) {
            // Only return the public key information
            return new JWKSet(jwkSet.getJWKsAsList().stream()
                                                    .map(JWK::toPublicJwk)
                                                    .flatMap(Optional::stream)
                                                    .toList());
        }
        return null;
    }

    public void removeCertificate(String organisationId, String softwareId, String keyId) {
        requireNonNull(organisationId, "organisationId must be provided");
        requireNonNull(softwareId, "softwareId must be provided");
        requireNonNull(keyId, "keyId must be provided");

        softwareJwkSets.computeIfPresent(jwkSetKey(organisationId, softwareId), (cacheKey, existingJwks) -> {
            final List<JWK> updatedJwks = existingJwks.findJwks(jwk -> !jwk.getKeyId().equals(keyId)).toList();
            // Remove the JWKSet from the map if no keys remain
            if (updatedJwks.isEmpty()) {
                return null;
            } else {
                return new JWKSet(updatedJwks);
            }
        });
    }

    public static class Heaplet extends GenericHeaplet {

        private static final String DEFAULT_CERT_SIGNING_ALG = "SHA256withRSA";

        @Override
        public Object create() throws HeapException {
            final String caSecretId = config.get("caSecretId")
                                            .required()
                                            .asString();
            final SecretsProvider provider = config.get("secretsProvider")
                                                   .required()
                                                   .as(secretsProvider(heap));

            final Promise<SigningKey, NoSuchSecretException> caPromise = provider.getActiveSecret(purpose(caSecretId, SigningKey.class));
            try {
                final SigningKey caSigningKey = caPromise.get();
                if (caSigningKey.getKeyType() != KeyType.PRIVATE) {
                    throw new IllegalStateException(caSecretId + " keystore alias must include a private key");
                }
                final PrivateKey caPrivateKey = caSigningKey.reveal(PrivateKey.class::cast);
                final X509Certificate caCert = caSigningKey.getCertificate(X509Certificate.class)
                        .orElseThrow(() -> new IllegalStateException("Failed to load certificate for " + caSecretId + " keystore alias"));

                final String certSigningAlg = config.get("certificateSigningAlg")
                                                    .defaultTo(DEFAULT_CERT_SIGNING_ALG)
                                                    .asString();
                return new SoftwareJwksService(new CertificateIssuerService(caCert, caPrivateKey, certSigningAlg));
            } catch (ExecutionException | InterruptedException e) {
                throw new RuntimeException(e);
            }

        }
    }
}
