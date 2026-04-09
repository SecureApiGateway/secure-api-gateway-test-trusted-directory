/*
 * Copyright © 2026 Ping Identity Corporation (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.directory.config;

/**
 * Configuration properties for the Test Trusted Directory.
 * Loaded from {@code config.yml} via Vert.x Config (camelCase keys).
 * Keystore passwords are NOT stored here — they are read from environment variables at runtime.
 *
 * @param issuerName      the {@code iss} claim in signed SSA JWTs
 * @param fqdn            fully-qualified domain name used to build the software JWKS URI
 * @param signing         JWT signing keystore properties
 * @param ca              CA keystore properties
 * @param storageFilePath path to the JSON file used for JWKS storage
 * @param cert            default certificate generation settings
 */
public record TrustedDirectoryConfig(
        String issuerName,
        String fqdn,
        SigningConfig signing,
        CaConfig ca,
        String storageFilePath,
        CertConfig cert) {

    private static final String DEFAULT_ISSUER_NAME = "SAPI-G Test Trusted Directory";
    private static final String DEFAULT_FQDN = "localhost:8080";
    private static final String DEFAULT_STORAGE_FILE_PATH = "/var/trusted-directory/trusted-directory-jwks.json";
    public static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";
    private static final String DEFAULT_SIGNING_KEY_ALIAS = "jwt-signing";
    private static final String DEFAULT_CA_KEY_ALIAS = "ca";
    public static final String DEFAULT_CERT_SIGNING_ALG = "SHA256withRSA";
    private static final int DEFAULT_KEY_SIZE = 2048;
    private static final int DEFAULT_VALIDITY_DAYS = 365;

    /** Validates and applies defaults to the top-level configuration. */
    public TrustedDirectoryConfig {
        issuerName = issuerName != null ? issuerName : DEFAULT_ISSUER_NAME;
        fqdn = fqdn != null ? fqdn : DEFAULT_FQDN;
        storageFilePath = storageFilePath != null ? storageFilePath : DEFAULT_STORAGE_FILE_PATH;
        if (cert == null) {
            cert = new CertConfig(0, 0);
        }
    }

    /**
     * JWT signing keystore properties.
     * Passwords are resolved from env vars {@code TTD_SIGNING_KEYSTORE_PWD} and
     * {@code TTD_SIGNING_KEYSTORE_KEY_PWD} via {@code secret.yml} and {@link SecretLoader}.
     *
     * @param keystorePath   path to the signing keystore file
     * @param keystoreType   keystore type (e.g. {@code PKCS12})
     * @param keyAlias       alias of the signing key entry
     * @param keystorePwd    password used to open the keystore
     * @param keystoreKeyPwd password for the private key entry
     */
    public record SigningConfig(
            String keystorePath,
            String keystoreType,
            String keyAlias,
            String keystorePwd,
            String keystoreKeyPwd) {

        /** Applies defaults to signing configuration fields. */
        public SigningConfig {
            keystoreType = keystoreType != null ? keystoreType : DEFAULT_KEYSTORE_TYPE;
            keyAlias = keyAlias != null ? keyAlias : DEFAULT_SIGNING_KEY_ALIAS;
            keystoreKeyPwd = keystoreKeyPwd != null ? keystoreKeyPwd : keystorePwd;
        }
    }

    /**
     * CA keystore properties.
     * Passwords are resolved from env vars {@code TTD_CA_KEYSTORE_PWD} and
     * {@code TTD_CA_KEYSTORE_KEY_PWD} via {@code secret.yml} and {@link SecretLoader}.
     *
     * @param keystorePath   path to the CA keystore file
     * @param keystoreType   keystore type (e.g. {@code PKCS12})
     * @param keyAlias       alias of the CA key entry
     * @param certSigningAlg JCA algorithm used to sign certificates
     * @param keystorePwd    password used to open the CA keystore
     * @param keystoreKeyPwd password for the CA private key entry
     */
    public record CaConfig(
            String keystorePath,
            String keystoreType,
            String keyAlias,
            String certSigningAlg,
            String keystorePwd,
            String keystoreKeyPwd) {

        /** Applies defaults to CA configuration fields. */
        public CaConfig {
            keystoreType = keystoreType != null ? keystoreType : DEFAULT_KEYSTORE_TYPE;
            keyAlias = keyAlias != null ? keyAlias : DEFAULT_CA_KEY_ALIAS;
            certSigningAlg = certSigningAlg != null ? certSigningAlg : DEFAULT_CERT_SIGNING_ALG;
            keystoreKeyPwd = keystoreKeyPwd != null ? keystoreKeyPwd : keystorePwd;
        }
    }

    /**
     * Default certificate generation settings.
     *
     * @param keySize      RSA key size in bits (defaults to {@value #DEFAULT_KEY_SIZE})
     * @param validityDays number of days the certificate is valid (defaults to {@value #DEFAULT_VALIDITY_DAYS})
     */
    public record CertConfig(int keySize, int validityDays) {
        /** Applies defaults to certificate generation settings. */
        public CertConfig {
            if (keySize <= 0) {
                keySize = DEFAULT_KEY_SIZE;
            }
            if (validityDays <= 0) {
                validityDays = DEFAULT_VALIDITY_DAYS;
            }
        }
    }
}
