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
package com.forgerock.sapi.gateway.test.trusted.directory.controller;

import java.util.UUID;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryProperties;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.IssueCertRequest;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.RevokeCertRequest;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.SignClaimsRequest;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.SsaRequest;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaSigningService;

/**
 * REST controller exposing the API client management endpoints under {@code /jwkms/apiclient}.
 * <p>
 * Handles certificate issuance, JWKS retrieval, SSA generation, claim signing,
 * PEM export, and certificate revocation for software clients registered with the test trusted directory.
 */
@RestController
@RequestMapping("/jwkms/apiclient")
public class JwkmsApiClientController {

    private final SoftwareJwksService softwareJwksService;
    private final SsaSigningService ssaSigningService;
    private final SsaService ssaService;
    private final TrustedDirectoryProperties properties;

    /**
     * Creates the controller with its required service dependencies.
     *
     * @param softwareJwksService manages JWKS storage and certificate lifecycle for software clients
     * @param ssaSigningService   signs SSA JWTs and exposes the directory's public JWKS
     * @param ssaService          builds and signs SSA JWTs from client certificate and request
     * @param properties          application properties (issuer name, FQDN, cert defaults)
     */
    public JwkmsApiClientController(SoftwareJwksService softwareJwksService,
                                     SsaSigningService ssaSigningService,
                                     SsaService ssaService,
                                     TrustedDirectoryProperties properties) {
        this.softwareJwksService = softwareJwksService;
        this.ssaSigningService = ssaSigningService;
        this.ssaService = ssaService;
        this.properties = properties;
    }

    /**
     * Issues a new signing and transport key pair for a software client and returns the full private JWKS.
     * If no {@code software_id} is provided, a random UUID is assigned.
     *
     * @param request contains {@code org_id}, {@code org_name}, and optional {@code software_id}
     * @return {@code 200 OK} with the private JWKS, or {@code 400} if required fields are missing
     */
    @PostMapping(value = "/issuecert", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> issueCert(@RequestBody IssueCertRequest request) {
        if (request.orgId() == null || request.orgId().isBlank()
                || request.orgName() == null || request.orgName().isBlank()) {
            throw new IllegalArgumentException("org_id and org_name are required");
        }
        String softwareId = (request.softwareId() != null && !request.softwareId().isBlank())
                ? request.softwareId() : UUID.randomUUID().toString();

        CertificateOptions options = new CertificateOptions(JwsAlgorithm.PS256, properties.cert().keySize(),
                properties.cert().validityDays());

        JWKSet jwkSet = softwareJwksService.issueSoftwareCertificates(
                request.orgId(), request.orgName(), softwareId, options);

        return ResponseEntity.ok(jwkSet.toJsonValue().getObject());
    }

    /**
     * Returns the public JWKS (no private key material) for the given organisation and software client.
     *
     * @param orgId      the organisation identifier
     * @param softwareId the software identifier
     * @return {@code 200 OK} with the public JWKS, or {@code 404} if no JWKS is found
     * @throws Exception if JWKS serialisation fails (handled as 500 by {@code GlobalExceptionHandler})
     */
    @GetMapping(value = "/jwks/{orgId}/{softwareId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getSoftwareJwks(@PathVariable String orgId,
                                                   @PathVariable String softwareId) {
        JWKSet jwkSet = softwareJwksService.getPublicSoftwareJwks(orgId, softwareId);
        if (jwkSet == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(jwkSet.toJsonValue().getObject());
    }

    /**
     * Generates and signs a Software Statement Assertion (SSA) JWT.
     * <p>
     * The organisation identity ({@code org_id}, {@code org_name}) is extracted from the TLS client certificate
     * provided in the {@code ssl-client-cert} header. The SSA embeds the software's JWKS endpoint or, if a
     * {@code software_jwks} is supplied in the request body, the JWKS directly.
     * <p>
     * Claims construction and certificate parsing are delegated to {@link SsaService}.
     *
     * @param certHeader URL-encoded PEM of the client's TLS certificate (from {@code ssl-client-cert} header)
     * @param request    SSA payload fields (software ID, roles, redirect URIs, etc.)
     * @return {@code 200 OK} with the compact JWT string, or {@code 400} if the certificate or fields are invalid
     * @throws Exception if SSA signing fails (handled as 500 by {@code GlobalExceptionHandler})
     */
    @PostMapping(value = "/getssa", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getSsa(
            @RequestHeader(value = "ssl-client-cert", required = false) String certHeader,
            @RequestBody SsaRequest request) throws Exception {
        if (certHeader == null || certHeader.isBlank()) {
            throw new IllegalArgumentException("No client certificate provided in ssl-client-cert header");
        }
        String jwt = ssaService.generateSsa(certHeader, request);
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(jwt);
    }

    /**
     * Signs the provided claims using the signing key ({@code use=sig}) found in the provided JWKS.
     * The resulting JWT uses PS256 and includes the key's {@code kid} in the header.
     *
     * @param request contains the {@code claims} map and the {@code jwks} holding the private signing key
     * @return {@code 200 OK} with the compact JWT string, or {@code 400} if the payload is invalid
     * @throws Exception if JWT signing fails (handled as 500 by {@code GlobalExceptionHandler})
     */
    @PostMapping(value = "/signclaims", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> signClaims(@RequestBody SignClaimsRequest request) throws Exception {
        if (request.claims() == null) {
            throw new IllegalArgumentException("No claims payload in request");
        }
        if (request.jwks() == null) {
            throw new IllegalArgumentException("No jwks in request");
        }

        JWKSet jwks;
        try {
            jwks = JWKSet.parse(new JsonValue(request.jwks()));
        } catch (Exception e) {
            throw new IllegalArgumentException("Couldn't parse request body as JWK set", e);
        }

        JWK sigKey = jwks.getJWKsAsList().stream()
                .filter(k -> "sig".equals(k.getUse()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Couldn't find signing key (use=sig) in JWK set"));

        String jwt = ssaSigningService.signClaims(request.claims(), sigKey);
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(jwt);
    }

    /**
     * Extracts the TLS certificate chain and private key from the provided JWKS and returns them in PEM format.
     *
     * @param jwksJson the JSON body of the JWKS containing a key with {@code use=tls}
     * @return {@code 200 OK} with the PEM-encoded certificate chain and private key, or {@code 400} on invalid input
     * @throws Exception if PEM conversion fails (handled as 500 by {@code GlobalExceptionHandler})
     */
    @PostMapping(value = "/gettlscert", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getTlsCert(@RequestBody String jwksJson) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(softwareJwksService.extractCertAsPem(jwksJson, "tls"));
    }

    /**
     * Extracts the signing certificate chain and private key from the provided JWKS and returns them in PEM format.
     *
     * @param jwksJson the JSON body of the JWKS containing a key with {@code use=sig}
     * @return {@code 200 OK} with the PEM-encoded certificate chain and private key, or {@code 400} on invalid input
     * @throws Exception if PEM conversion fails (handled as 500 by {@code GlobalExceptionHandler})
     */
    @PostMapping(value = "/getsigcert", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getSigCert(@RequestBody String jwksJson) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(softwareJwksService.extractCertAsPem(jwksJson, "sig"));
    }

    /**
     * Revokes (removes) a certificate from a software client's JWKS by key ID.
     * If the JWKS becomes empty after removal, the software's entry is deleted entirely.
     *
     * @param request contains {@code org_id}, {@code software_id}, and the {@code key_id} to revoke
     * @return {@code 200 OK} on success, or {@code 400} if any required field is missing
     */
    @PostMapping(value = "/jwks/revokecert", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> revokeCert(@RequestBody RevokeCertRequest request) {
        if (request.orgId() == null || request.softwareId() == null || request.keyId() == null) {
            throw new IllegalArgumentException("Json body must contain fields: [org_id, software_id, key_id]");
        }
        softwareJwksService.removeCertificate(request.orgId(), request.softwareId(), request.keyId());
        return ResponseEntity.ok().build();
    }

}

