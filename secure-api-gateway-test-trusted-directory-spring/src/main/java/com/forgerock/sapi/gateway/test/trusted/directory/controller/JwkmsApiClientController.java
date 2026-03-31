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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions;
import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryProperties;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.IssueCertRequest;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.RevokeCertRequest;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.SignClaimsRequest;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.SsaRequest;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SoftwareJwksService;
import com.forgerock.sapi.gateway.test.trusted.directory.service.SsaSigningService;

@RestController
@RequestMapping("/jwkms/apiclient")
public class JwkmsApiClientController {

    private static final String OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final SoftwareJwksService softwareJwksService;
    private final SsaSigningService ssaSigningService;
    private final TrustedDirectoryProperties properties;
    private final ObjectMapper objectMapper;

    public JwkmsApiClientController(SoftwareJwksService softwareJwksService,
                                     SsaSigningService ssaSigningService,
                                     TrustedDirectoryProperties properties,
                                     ObjectMapper objectMapper) {
        this.softwareJwksService = softwareJwksService;
        this.ssaSigningService = ssaSigningService;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    // --- Route 71: Issue certificates ---

    @PostMapping(value = "/issuecert", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> issueCert(@RequestBody IssueCertRequest request) {
        if (request.getOrgId() == null || request.getOrgId().isBlank()
                || request.getOrgName() == null || request.getOrgName().isBlank()) {
            return badRequest("org_id and org_name are required");
        }
        String softwareId = (request.getSoftwareId() != null && !request.getSoftwareId().isBlank())
                ? request.getSoftwareId() : UUID.randomUUID().toString();

        CertificateOptions options = new CertificateOptions(JwsAlgorithm.PS256, properties.getCert().getKeySize())
                .certValidityDays(properties.getCert().getValidityDays());

        JWKSet jwkSet = softwareJwksService.issueSoftwareCertificates(
                request.getOrgId(), request.getOrgName(), softwareId, options);

        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(objectMapper.writeValueAsString(jwkSet.toJsonValue().getObject()));
        } catch (Exception e) {
            logger.error("Failed to serialize JWKS", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // --- Route 70: Get software JWKS (public keys only) ---

    @GetMapping(value = "/jwks/{orgId}/{softwareId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getSoftwareJwks(@PathVariable String orgId,
                                                   @PathVariable String softwareId) {
        JWKSet jwkSet = softwareJwksService.getPublicSoftwareJwks(orgId, softwareId);
        if (jwkSet == null) {
            return ResponseEntity.notFound().build();
        }
        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(objectMapper.writeValueAsString(jwkSet.toJsonValue().getObject()));
        } catch (Exception e) {
            logger.error("Failed to serialize JWKS", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // --- Route 72: Generate SSA ---

    @PostMapping(value = "/getssa", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getSsa(
            @RequestHeader(value = "ssl-client-cert", required = false) String certHeader,
            @RequestBody SsaRequest request) {
        if (certHeader == null || certHeader.isBlank()) {
            return badRequest("No client certificate provided in ssl-client-cert header");
        }

        X509Certificate cert;
        try {
            String pem = URLDecoder.decode(certHeader, StandardCharsets.UTF_8);
            cert = parsePemCertificate(pem);
        } catch (Exception e) {
            logger.error("Failed to parse client certificate", e);
            return badRequest("Invalid client certificate in ssl-client-cert header");
        }

        Map<String, String> dn = parseDn(cert.getSubjectX500Principal().getName());
        String orgId = dn.get("OI");
        String orgName = dn.get("CN");

        if (orgName == null || orgName.isBlank()) {
            return badRequest("No CN in cert");
        }
        if (orgId == null || orgId.isBlank()) {
            return badRequest("No org identifier (OID.2.5.4.97) in cert");
        }

        Map<String, Object> softwareFields = new LinkedHashMap<>();
        softwareFields.put("software_id", request.getSoftwareId());
        softwareFields.put("software_client_name", request.getSoftwareClientName());
        softwareFields.put("software_client_id", request.getSoftwareClientId());
        softwareFields.put("software_tos_uri", request.getSoftwareTosUri());
        softwareFields.put("software_client_description", request.getSoftwareClientDescription());
        softwareFields.put("software_redirect_uris", request.getSoftwareRedirectUris());
        softwareFields.put("software_policy_uri", request.getSoftwarePolicyUri());
        softwareFields.put("software_logo_uri", request.getSoftwareLogoUri());
        softwareFields.put("software_roles", request.getSoftwareRoles());

        if (request.getSoftwareJwks() != null) {
            softwareFields.put("software_jwks", request.getSoftwareJwks());
        } else {
            JWKSet existingJwks = softwareJwksService.getPublicSoftwareJwks(orgId, request.getSoftwareId());
            if (existingJwks == null) {
                return badRequest("No JWKS exists for org_id: " + orgId + " and software_id: "
                        + request.getSoftwareId() + " - Please issue certificates for this software first.");
            }
            softwareFields.put("software_jwks_endpoint",
                    "https://" + properties.getFqdn() + "/jwkms/apiclient/jwks/" + orgId + "/" + request.getSoftwareId());
        }

        try {
            long iat = Instant.now().getEpochSecond();
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", properties.getIssuerName());
            claims.put("iat", iat);
            claims.put("exp", iat + 300L);
            claims.put("org_id", orgId);
            claims.put("org_name", orgName);
            claims.put("org_status", "Active");
            claims.put("software_mode", "TEST");
            claims.putAll(softwareFields);

            String jwt = ssaSigningService.sign(claims);
            return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(jwt);
        } catch (Exception e) {
            logger.error("Failed to sign SSA", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\":\"Failed to sign SSA\"}");
        }
    }

    // --- Route 73: Sign claims ---

    @PostMapping(value = "/signclaims", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> signClaims(@RequestBody SignClaimsRequest request) {
        if (request.getClaims() == null) {
            return badRequest("No claims payload in request");
        }
        if (request.getJwks() == null) {
            return badRequest("No jwks in request");
        }

        JWKSet jwks;
        try {
            jwks = JWKSet.parse(new JsonValue(request.getJwks()));
        } catch (Exception e) {
            return badRequest("Couldn't parse request body as JWK set");
        }

        JWK sigKey = jwks.getJWKsAsList().stream()
                .filter(k -> "sig".equals(k.getUse()))
                .findFirst()
                .orElse(null);

        if (sigKey == null) {
            return badRequest("Couldn't find signing key (use=sig) in JWK set");
        }

        try {
            String jwt = ssaSigningService.signClaims(request.getClaims(), sigKey);
            return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(jwt);
        } catch (Exception e) {
            logger.error("Failed to sign claims", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\":\"Failed to sign claims\"}");
        }
    }

    // --- Route 74: Get TLS cert as PEM ---

    @PostMapping(value = "/gettlscert", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getTlsCert(@RequestBody String jwksJson) {
        return getCertAsPem(jwksJson, "tls");
    }

    // --- Route 75: Get signing cert as PEM ---

    @PostMapping(value = "/getsigcert", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getSigCert(@RequestBody String jwksJson) {
        return getCertAsPem(jwksJson, "sig");
    }

    // --- Route 76: Revoke certificate ---

    @PostMapping(value = "/jwks/revokecert", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> revokeCert(@RequestBody RevokeCertRequest request) {
        if (request.getOrgId() == null || request.getSoftwareId() == null || request.getKeyId() == null) {
            return badRequest("Json body must contain fields: [org_id, software_id, key_id]");
        }
        softwareJwksService.removeCertificate(request.getOrgId(), request.getSoftwareId(), request.getKeyId());
        return ResponseEntity.ok().build();
    }

    // --- Helpers ---

    @SuppressWarnings("unchecked")
    private ResponseEntity<String> getCertAsPem(String jwksJson, String keyUse) {
        JWKSet jwks;
        try {
            Map<String, Object> jwksMap = objectMapper.readValue(jwksJson, Map.class);
            jwks = JWKSet.parse(new JsonValue(jwksMap));
        } catch (Exception e) {
            return badRequest("Couldn't parse request body as JWK set");
        }

        JWK key = jwks.getJWKsAsList().stream()
                .filter(k -> keyUse.equals(k.getUse()))
                .findFirst()
                .orElse(null);

        if (key == null) {
            return badRequest("Couldn't find " + keyUse + " key in JWK set");
        }

        try {
            List<String> x5c = key.getX509Chain();
            if (x5c == null || x5c.isEmpty()) {
                return badRequest("Couldn't find cert chain in " + keyUse + " jwk");
            }

            // Use ForgeRock RsaJWK to extract the private key directly
            PrivateKey privateKey = ((RsaJWK) key).toRSAPrivateKey();

            StringBuilder pem = new StringBuilder();
            for (String certBase64 : x5c) {
                byte[] derBytes = org.forgerock.util.encode.Base64.decode(certBase64);
                X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(derBytes));
                pem.append(toPem(cert));
            }
            pem.append(toPem(privateKey));

            return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(pem.toString());
        } catch (Exception e) {
            logger.error("Failed to convert JWK to PEM", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\":\"Failed to convert JWK to PEM\"}");
        }
    }

    private static String toPem(Object obj) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(obj);
        }
        return writer.toString();
    }

    private static X509Certificate parsePemCertificate(String pem) throws Exception {
        String stripped = pem.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(stripped);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(decoded));
    }

    private static Map<String, String> parseDn(String dn) {
        Map<String, String> result = new HashMap<>();
        try {
            LdapName ln = new LdapName(dn);
            for (Rdn rdn : ln.getRdns()) {
                String type = rdn.getType();
                if (("OID." + OID_ORGANIZATIONAL_IDENTIFIER).equals(type)) {
                    type = "OI";
                }
                result.put(type, String.valueOf(rdn.getValue()));
            }
        } catch (Exception e) {
            // Return partial result
        }
        return result;
    }

    private static ResponseEntity<String> badRequest(String message) {
        return ResponseEntity.badRequest()
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"" + message + "\"}");
    }
}
