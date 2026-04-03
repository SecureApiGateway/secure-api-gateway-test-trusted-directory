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
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Logs the resolved {@link TrustedDirectoryProperties} at {@code INFO} level once the application is ready.
 * Sensitive fields (keystore passwords) are masked.
 */
@Component
public class StartupLogger {

    private static final Logger log = LoggerFactory.getLogger(StartupLogger.class);
    private static final String MASKED = "***";

    private final TrustedDirectoryProperties props;

    public StartupLogger(TrustedDirectoryProperties props) {
        this.props = props;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void logConfiguration() {
        TrustedDirectoryProperties.SigningProperties signing = props.signing();
        TrustedDirectoryProperties.CaProperties ca = props.ca();
        TrustedDirectoryProperties.StorageProperties storage = props.storage();
        TrustedDirectoryProperties.CertProperties cert = props.cert();

        log.info("""
                Trusted Directory configuration:
                  issuerName       = {}
                  fqdn             = {}
                  signing:
                    keystorePath   = {}
                    keystoreType   = {}
                    keystorePwd    = {}
                    keyAlias       = {}
                  ca:
                    keystorePath   = {}
                    keystoreType   = {}
                    keystorePwd    = {}
                    keyAlias       = {}
                    certSigningAlg = {}
                  storage:
                    filePath       = {}
                  cert:
                    keySize        = {}
                    validityDays   = {}""",
                props.issuerName(),
                props.fqdn(),
                signing.keystorePath(),
                signing.keystoreType(),
                signing.keystorePwd() != null ? MASKED : null,
                signing.keyAlias(),
                ca.keystorePath(),
                ca.keystoreType(),
                ca.keystorePwd() != null ? MASKED : null,
                ca.keyAlias(),
                ca.certSigningAlg(),
                storage.filePath(),
                cert.keySize(),
                cert.validityDays());
    }
}
