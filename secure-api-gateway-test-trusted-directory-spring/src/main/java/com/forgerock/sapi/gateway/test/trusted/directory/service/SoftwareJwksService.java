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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;

/**
 * Service which manages JWKS (Json Web Key Set) for pieces of Software.
 * <p>
 * Software is uniquely identified by the organisationId which owns the software and the softwareId.
 * <p>
 * JWKs are persisted to a JSON file so that they survive application restarts.
 */
public class SoftwareJwksService {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final CertificateIssuerService certificateIssuerService;
    private final Path storageFile;
    private final ObjectMapper objectMapper;

    private final ConcurrentMap<String, JWKSet> softwareJwkSets = new ConcurrentHashMap<>();

    /**
     * Constructs the service, loading any previously persisted JWKS entries from the configured store file.
     *
     * @param certificateIssuerService service used to issue new signing and transport certificates
     * @param storageFile              path to the JSON file used to persist JWKS entries
     * @param objectMapper             Jackson mapper used for JSON serialisation/deserialisation
     */
    public SoftwareJwksService(CertificateIssuerService certificateIssuerService,
                                Path storageFile,
                                ObjectMapper objectMapper) {
        this.certificateIssuerService = requireNonNull(certificateIssuerService, "certificateIssuerService must be provided");
        this.storageFile = requireNonNull(storageFile, "storageFile must be provided");
        this.objectMapper = requireNonNull(objectMapper, "objectMapper must be provided");
        load();
    }

    private void load() {
        if (!Files.exists(storageFile)) {
            logger.info("JWKS store file not found at {}, starting with empty state", storageFile);
            return;
        }
        try {
            Map<String, Object> data = objectMapper.readValue(storageFile.toFile(),
                    new TypeReference<Map<String, Object>>() {});
            for (Map.Entry<String, Object> entry : data.entrySet()) {
                @SuppressWarnings("unchecked")
                JWKSet jwkSet = JWKSet.parse(new JsonValue(entry.getValue()));
                softwareJwkSets.put(entry.getKey(), jwkSet);
            }
            logger.info("Loaded {} JWKS entries from {}", softwareJwkSets.size(), storageFile);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load JWKS store from " + storageFile, e);
        }
    }

    @SuppressWarnings("unchecked")
    private synchronized void save() {
        try {
            if (storageFile.getParent() != null) {
                Files.createDirectories(storageFile.getParent());
            }
            Map<String, Object> data = new LinkedHashMap<>();
            softwareJwkSets.forEach((key, jwkSet) ->
                    data.put(key, jwkSet.toJsonValue().getObject()));
            objectMapper.writeValue(storageFile.toFile(), data);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to save JWKS store to " + storageFile, e);
        }
    }

    /**
     * Issues a new signing ({@code use=sig}) and transport ({@code use=tls}) key pair for the given software,
     * replaces any previously stored JWKS for that software, and persists the updated state to the store file.
     *
     * @param organisationId   the unique identifier of the owning organisation
     * @param organisationName the display name of the owning organisation
     * @param softwareId       the unique identifier of the software
     * @param options          algorithm, key size, and validity options for the new certificates
     * @return the full private JWKS (signing + transport keys) for the software
     */
    public synchronized JWKSet issueSoftwareCertificates(String organisationId, String organisationName,
                                                          String softwareId, CertificateOptions options) {
        requireNonNull(organisationId, "organisationId must be provided");
        requireNonNull(organisationName, "organisationName must be provided");
        requireNonNull(softwareId, "softwareId must be provided");
        requireNonNull(options, "certificateOptions must be provided");

        final JWK signingKey = certificateIssuerService.issueSigningCertificate(organisationId, organisationName, options);
        final JWK transportKey = certificateIssuerService.issueTransportCertificate(organisationId, organisationName, options);
        final JWKSet newJwkSet = new JWKSet(Arrays.asList(signingKey, transportKey));

        softwareJwkSets.put(jwkSetKey(organisationId, softwareId), newJwkSet);
        save();
        return newJwkSet;
    }

    /**
     * Returns the public JWKS (private key material stripped) for the given software.
     *
     * @param organisationId the unique identifier of the owning organisation
     * @param softwareId     the unique identifier of the software
     * @return the public-only JWKS, or {@code null} if no JWKS exists for the given software
     */
    public JWKSet getPublicSoftwareJwks(String organisationId, String softwareId) {
        requireNonNull(organisationId, "organisationId must be provided");
        requireNonNull(softwareId, "softwareId must be provided");

        final JWKSet jwkSet = softwareJwkSets.get(jwkSetKey(organisationId, softwareId));
        if (jwkSet == null) {
            return null;
        }
        return new JWKSet(jwkSet.getJWKsAsList().stream()
                .map(JWK::toPublicJwk)
                .flatMap(Optional::stream)
                .toList());
    }

    /**
     * Removes a specific key from the software's JWKS by key ID and persists the updated state.
     * If the JWKS becomes empty after removal, the entry for the software is deleted entirely.
     *
     * @param organisationId the unique identifier of the owning organisation
     * @param softwareId     the unique identifier of the software
     * @param keyId          the {@code kid} of the key to remove
     */
    public synchronized void removeCertificate(String organisationId, String softwareId, String keyId) {
        requireNonNull(organisationId, "organisationId must be provided");
        requireNonNull(softwareId, "softwareId must be provided");
        requireNonNull(keyId, "keyId must be provided");

        final String key = jwkSetKey(organisationId, softwareId);
        softwareJwkSets.computeIfPresent(key, (cacheKey, existingJwks) -> {
            final List<JWK> updatedJwks = existingJwks.findJwks(jwk -> !jwk.getKeyId().equals(keyId)).toList();
            return updatedJwks.isEmpty() ? null : new JWKSet(updatedJwks);
        });
        save();
    }

    /**
     * Parses a JWKS JSON string and extracts the first key matching the given {@code use}
     * ({@code "sig"} or {@code "tls"}), returning the full certificate chain and private key
     * encoded as a concatenated PEM string.
     *
     * @param jwksJson the JSON-serialised JWKS (as received in a request body)
     * @param keyUse   the key use to look for, typically {@code "sig"} or {@code "tls"}
     * @return PEM-encoded certificate chain followed by PEM-encoded private key
     * @throws IllegalArgumentException if the JSON cannot be parsed, the key is not found,
     *                                  or the key has no certificate chain
     */
    @SuppressWarnings("unchecked")
    public String extractCertAsPem(String jwksJson, String keyUse) throws Exception {
        JWKSet jwks;
        try {
            Map<String, Object> jwksMap = objectMapper.readValue(jwksJson, Map.class);
            jwks = JWKSet.parse(new JsonValue(jwksMap));
        } catch (Exception e) {
            throw new IllegalArgumentException("Couldn't parse request body as JWK set", e);
        }

        JWK key = jwks.getJWKsAsList().stream()
                .filter(k -> keyUse.equals(k.getUse()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Couldn't find " + keyUse + " key in JWK set"));

        List<String> x5c = key.getX509Chain();
        if (x5c == null || x5c.isEmpty()) {
            throw new IllegalArgumentException("Couldn't find cert chain in " + keyUse + " jwk");
        }

        PrivateKey privateKey = ((RsaJWK) key).toRSAPrivateKey();

        StringBuilder pem = new StringBuilder();
        for (String certBase64 : x5c) {
            byte[] derBytes = org.forgerock.util.encode.Base64.decode(certBase64);
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(derBytes));
            pem.append(toPem(cert));
        }
        pem.append(toPem(privateKey));

        return pem.toString();
    }

    private static String toPem(Object obj) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(obj);
        }
        return writer.toString();
    }

    private static String jwkSetKey(String organisationId, String softwareId) {
        return organisationId + "-" + softwareId;
    }
}
