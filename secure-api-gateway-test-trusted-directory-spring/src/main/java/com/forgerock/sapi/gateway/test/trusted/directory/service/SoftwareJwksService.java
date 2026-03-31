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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateIssuerService;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryProperties;

/**
 * Service which manages JWKS (Json Web Key Set) for pieces of Software.
 * <p>
 * Software is uniquely identified by the organisationId which owns the software and the softwareId.
 * <p>
 * JWKs are persisted to a JSON file so that they survive application restarts.
 */
@Service
public class SoftwareJwksService {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final CertificateIssuerService certificateIssuerService;
    private final Path storageFile;
    private final ObjectMapper objectMapper;

    private final ConcurrentMap<String, JWKSet> softwareJwkSets = new ConcurrentHashMap<>();

    public SoftwareJwksService(CertificateIssuerService certificateIssuerService,
                                TrustedDirectoryProperties properties,
                                ObjectMapper objectMapper) {
        this.certificateIssuerService = requireNonNull(certificateIssuerService, "certificateIssuerService must be provided");
        this.storageFile = Path.of(properties.getStorage().getFilePath());
        this.objectMapper = objectMapper;
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

    private static String jwkSetKey(String organisationId, String softwareId) {
        return organisationId + "-" + softwareId;
    }
}
