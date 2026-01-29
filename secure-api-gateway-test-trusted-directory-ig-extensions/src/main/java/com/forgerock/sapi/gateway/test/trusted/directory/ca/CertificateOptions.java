/*
 * Copyright © 2020-2026 ForgeRock AS (obst@forgerock.com)
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

public class CertificateOptions {

    private static final int DEFAULT_CERT_VALIDITY_DAYS = 30;

    private final JwsAlgorithm jwsAlgorithm;
    private final int keySize;

    private int certValidityDays = DEFAULT_CERT_VALIDITY_DAYS;

    public CertificateOptions(JwsAlgorithm jwsAlgorithm, int keySize) {
        this.jwsAlgorithm = jwsAlgorithm;
        this.keySize = keySize;
    }

    public JwsAlgorithm getJwsAlgorithm() {
        return jwsAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public CertificateOptions certValidityDays(int certValidityDays) {
        this.certValidityDays = certValidityDays;
        return this;
    }

    public int getCertValidityDays() {
        return certValidityDays;
    }

}
