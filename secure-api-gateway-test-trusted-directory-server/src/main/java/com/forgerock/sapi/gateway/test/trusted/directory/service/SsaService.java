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

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.forgerock.json.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.forgerock.sapi.gateway.test.trusted.directory.config.TrustedDirectoryProperties;
import com.forgerock.sapi.gateway.test.trusted.directory.dto.SsaRequest;

/**
 * Business logic for generating Software Statement Assertions (SSAs).
 * <p>
 * Encapsulates certificate parsing, organisation identity extraction from the certificate DN,
 * SSA claims construction, and JWT signing. This service is used by the API client controller
 * to keep the controller focused on HTTP-level concerns.
 */
@Service
public class SsaService {

    private static final String OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97";

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final SsaSigningService ssaSigningService;
    private final SoftwareJwksService softwareJwksService;
    private final TrustedDirectoryProperties properties;

    /**
     * Creates the service with its required dependencies.
     *
     * @param ssaSigningService   signs the SSA JWT using the directory's private key
     * @param softwareJwksService retrieves the software's public JWKS when needed
     * @param properties          application properties (issuer name, FQDN)
     */
    public SsaService(SsaSigningService ssaSigningService,
                      SoftwareJwksService softwareJwksService,
                      TrustedDirectoryProperties properties) {
        this.ssaSigningService = ssaSigningService;
        this.softwareJwksService = softwareJwksService;
        this.properties = properties;
    }

    /**
     * Generates and signs a Software Statement Assertion (SSA) JWT.
     * <p>
     * The organisation identity ({@code org_id}, {@code org_name}) is extracted from the TLS client certificate
     * provided in the URL-encoded PEM header. The SSA embeds either an inline {@code software_jwks} from
     * the request or a {@code software_jwks_endpoint} pointing to the software's stored JWKS.
     *
     * @param certHeader URL-encoded PEM of the client's TLS certificate
     * @param request    SSA payload fields (software ID, roles, redirect URIs, etc.)
     * @return the signed compact JWT string
     * @throws IllegalArgumentException if the certificate is invalid, required DN fields are missing,
     *                                  or no JWKS exists for the software
     * @throws Exception                if JWT signing fails unexpectedly
     */
    public String generateSsa(String certHeader, SsaRequest request) throws Exception {
        X509Certificate cert = parseCertificateFromHeader(certHeader);

        Map<String, String> dn = parseDn(cert.getSubjectX500Principal().getName(
                "RFC2253", Map.of(OID_ORGANIZATIONAL_IDENTIFIER, "organizationIdentifier")));
        String orgId = dn.get("OI");
        String orgName = dn.get("CN");

        if (orgName == null || orgName.isBlank()) {
            throw new IllegalArgumentException("No CN in cert");
        }
        if (orgId == null || orgId.isBlank()) {
            throw new IllegalArgumentException("No org identifier (OID.2.5.4.97) in cert");
        }

        Map<String, Object> softwareFields = buildSoftwareFields(request, orgId);

        long iat = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", properties.issuerName());
        claims.put("iat", iat);
        claims.put("exp", iat + 300L);
        claims.put("org_id", orgId);
        claims.put("org_name", orgName);
        claims.put("org_status", "Active");
        claims.put("software_mode", "TEST");
        claims.putAll(softwareFields);

        return ssaSigningService.sign(claims);
    }

    private X509Certificate parseCertificateFromHeader(String certHeader) {
        try {
            String pem = URLDecoder.decode(certHeader, StandardCharsets.UTF_8);
            return parsePemCertificate(pem);
        } catch (Exception e) {
            log.warn("Failed to parse client certificate from ssl-client-cert header", e);
            throw new IllegalArgumentException("Invalid client certificate in ssl-client-cert header", e);
        }
    }

    private Map<String, Object> buildSoftwareFields(SsaRequest request, String orgId) {
        Map<String, Object> softwareFields = new LinkedHashMap<>();
        softwareFields.put("software_id", request.softwareId());
        softwareFields.put("software_client_name", request.softwareClientName());
        softwareFields.put("software_client_id", request.softwareClientId());
        softwareFields.put("software_tos_uri", request.softwareTosUri());
        softwareFields.put("software_client_description", request.softwareClientDescription());
        softwareFields.put("software_redirect_uris", request.softwareRedirectUris());
        softwareFields.put("software_policy_uri", request.softwarePolicyUri());
        softwareFields.put("software_logo_uri", request.softwareLogoUri());
        softwareFields.put("software_roles", request.softwareRoles());

        if (request.softwareJwks() != null) {
            softwareFields.put("software_jwks", request.softwareJwks());
        } else {
            JWKSet existingJwks = softwareJwksService.getPublicSoftwareJwks(orgId, request.softwareId());
            if (existingJwks == null) {
                throw new IllegalArgumentException(
                        "No JWKS exists for org_id: " + orgId + " and software_id: " + request.softwareId()
                                + " - Please issue certificates for this software first.");
            }
            softwareFields.put("software_jwks_endpoint",
                    "https://" + properties.fqdn() + "/jwkms/apiclient/jwks/" + orgId + "/" + request.softwareId());
        }
        return softwareFields;
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
                if ("organizationIdentifier".equalsIgnoreCase(type)
                        || ("OID." + OID_ORGANIZATIONAL_IDENTIFIER).equals(type)) {
                    type = "OI";
                }
                result.put(type, String.valueOf(rdn.getValue()));
            }
        } catch (Exception e) {
            // return partial result
        }
        return result;
    }
}
