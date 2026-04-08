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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logs the application configuration at startup, masking sensitive password fields.
 */
public final class StartupLogger {

    private static final Logger logger = LoggerFactory.getLogger(StartupLogger.class);

    private StartupLogger() {
    }

    /**
     * Masks a password value for display: returns {@code ***} if the value is set, {@code <not set>} otherwise.
     *
     * @param value the password value to mask
     * @return {@code ***} if non-null and non-blank, {@code <not set>} otherwise
     */
    static String maskPassword(final String value) {
        return (value != null && !value.isBlank()) ? "***" : "<not set>";
    }

    /**
     * Logs the resolved configuration, replacing password values with {@code ***} if set or {@code <not set>} if empty.
     *
     * @param properties the resolved application properties
     */
    public static void logConfiguration(final TrustedDirectoryConfig properties) {
        logger.info("""
                Starting Trusted Directory with configuration:
                  issuerName:                {}
                  fqdn:                      {}
                  signing.keystorePath:      {}
                  signing.keystoreType:      {}
                  signing.keyAlias:          {}
                  signing.keystorePwd:       {}
                  signing.keystoreKeyPwd:    {}
                  ca.keystorePath:           {}
                  ca.keystoreType:           {}
                  ca.keyAlias:               {}
                  ca.certSigningAlg:         {}
                  ca.keystorePwd:            {}
                  ca.keystoreKeyPwd:         {}
                  storageFilePath:           {}
                  cert.keySize:              {}
                  cert.validityDays:         {}""",
                properties.issuerName(),
                properties.fqdn(),
                properties.signing().keystorePath(),
                properties.signing().keystoreType(),
                properties.signing().keyAlias(),
                maskPassword(properties.signing().keystorePwd()),
                maskPassword(properties.signing().keystoreKeyPwd()),
                properties.ca().keystorePath(),
                properties.ca().keystoreType(),
                properties.ca().keyAlias(),
                properties.ca().certSigningAlg(),
                maskPassword(properties.ca().keystorePwd()),
                maskPassword(properties.ca().keystoreKeyPwd()),
                properties.storageFilePath(),
                properties.cert().keySize(),
                properties.cert().validityDays());
    }
}
