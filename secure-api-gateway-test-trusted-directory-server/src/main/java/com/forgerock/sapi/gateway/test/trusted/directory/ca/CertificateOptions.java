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
package com.forgerock.sapi.gateway.test.trusted.directory.ca;

import org.forgerock.json.jose.jws.JwsAlgorithm;

/**
 * Configuration options for X.509 certificate generation.
 * <p>
 * Immutable configuration options for X.509 certificate generation.
 * <p>
 * Specifies the JWS algorithm, the key size in bits, and the certificate validity period.
 * Use the 2-argument constructor for a default validity of {@value DEFAULT_CERT_VALIDITY_DAYS} days.
 *
 * @param jwsAlgorithm     the JWS algorithm used to generate the key pair (e.g. {@code PS256}, {@code ES256})
 * @param keySize          the key size in bits (e.g. 2048 for RSA, 256 for EC P-256)
 * @param certValidityDays the number of days the certificate should be valid
 */
public record CertificateOptions(JwsAlgorithm jwsAlgorithm, int keySize, int certValidityDays) {

    private static final int DEFAULT_CERT_VALIDITY_DAYS = 30;

    /**
     * Creates certificate options with the given algorithm and key size,
     * using the default validity of {@value DEFAULT_CERT_VALIDITY_DAYS} days.
     *
     * @param jwsAlgorithm the JWS algorithm used to generate the key pair
     * @param keySize      the key size in bits
     */
    public CertificateOptions(JwsAlgorithm jwsAlgorithm, int keySize) {
        this(jwsAlgorithm, keySize, DEFAULT_CERT_VALIDITY_DAYS);
    }
}
