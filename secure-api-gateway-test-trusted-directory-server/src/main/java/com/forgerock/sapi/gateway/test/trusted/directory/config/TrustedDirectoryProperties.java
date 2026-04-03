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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Externalized configuration properties for the Test Trusted Directory, bound from the {@code trusted-directory}
 * prefix in {@code application.yml} (or environment variables via Spring's relaxed binding).
 *
 * @param issuerName the {@code iss} claim value used in signed SSA JWTs
 * @param fqdn       fully-qualified domain name used to build the software JWKS endpoint URI
 * @param signing    properties for the directory's JWT signing keystore
 * @param ca         properties for the Certificate Authority keystore
 * @param storage    properties for the JSON file-based JWKS persistence
 * @param cert       default certificate generation settings
 */
@ConfigurationProperties(prefix = "trusted-directory")
public record TrustedDirectoryProperties(
        @DefaultValue("SAPI-G Test Trusted Directory") String issuerName,
        @DefaultValue("localhost:8080") String fqdn,
        SigningProperties signing,
        CaProperties ca,
        @DefaultValue StorageProperties storage,
        @DefaultValue CertProperties cert) {

    /**
     * Properties for the directory's JWT signing keystore.
     *
     * @param keystorePath    path to the PKCS12 keystore file
     * @param keystoreType    keystore type (default: {@code PKCS12})
     * @param keystorePwd    keystore store password
     * @param keystoreKeyPwd optional key-specific password; falls back to {@code keystorePwd} if absent
     * @param keyAlias        alias of the signing key entry (default: {@code jwt-signing})
     */
    public record SigningProperties(
            String keystorePath,
            @DefaultValue("PKCS12") String keystoreType,
            String keystorePwd,
            String keystoreKeyPwd,
            @DefaultValue("jwt-signing") String keyAlias) {

        /** Normalises {@code keystoreKeyPwd}: falls back to {@code keystorePwd} when absent. */
        public SigningProperties {
            keystoreKeyPwd = keystoreKeyPwd != null ? keystoreKeyPwd : keystorePwd;
        }
    }

    /**
     * Properties for the Certificate Authority (CA) keystore used to issue software certificates.
     *
     * @param keystorePath    path to the PKCS12 keystore file
     * @param keystoreType    keystore type (default: {@code PKCS12})
     * @param keystorePwd    keystore store password
     * @param keystoreKeyPwd optional key-specific password; falls back to {@code keystorePwd} if absent
     * @param keyAlias        alias of the CA key entry (default: {@code ca})
     * @param certSigningAlg  JCA algorithm used to sign issued certificates (default: {@code SHA256withRSA})
     */
    public record CaProperties(
            String keystorePath,
            @DefaultValue("PKCS12") String keystoreType,
            String keystorePwd,
            String keystoreKeyPwd,
            @DefaultValue("ca") String keyAlias,
            @DefaultValue("SHA256withRSA") String certSigningAlg) {

        /** Normalises {@code keystoreKeyPwd}: falls back to {@code keystorePwd} when absent. */
        public CaProperties {
            keystoreKeyPwd = keystoreKeyPwd != null ? keystoreKeyPwd : keystorePwd;
        }
    }

    /**
     * Properties for the JSON file-based JWKS storage.
     *
     * @param filePath path to the JSON store file (default: {@code /var/ttd/trusted-directory-jwks.json})
     */
    public record StorageProperties(
            @DefaultValue("/var/ttd/trusted-directory-jwks.json") String filePath) {}

    /**
     * Default certificate generation settings.
     *
     * @param keySize     RSA key size in bits (default: {@code 2048})
     * @param validityDays certificate validity in days (default: {@code 365})
     */
    public record CertProperties(
            @DefaultValue("2048") int keySize,
            @DefaultValue("365") int validityDays) {}
}
