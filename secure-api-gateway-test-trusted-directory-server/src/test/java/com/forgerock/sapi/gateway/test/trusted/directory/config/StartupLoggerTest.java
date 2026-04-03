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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.util.List;

import org.junit.jupiter.api.Test;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

class StartupLoggerTest {

    private TrustedDirectoryProperties buildProps(String keystorePwd) {
        TrustedDirectoryProperties.SigningProperties signing = new TrustedDirectoryProperties.SigningProperties(
                "/var/ttd/signing.p12", "PKCS12", keystorePwd, null, "jwt-signing");
        TrustedDirectoryProperties.CaProperties ca = new TrustedDirectoryProperties.CaProperties(
                "/var/ttd/ca.p12", "PKCS12", keystorePwd, null, "ca", "SHA256withRSA");
        TrustedDirectoryProperties.StorageProperties storage = new TrustedDirectoryProperties.StorageProperties(
                "/var/ttd/trusted-directory-jwks.json");
        TrustedDirectoryProperties.CertProperties cert = new TrustedDirectoryProperties.CertProperties(2048, 365);
        return new TrustedDirectoryProperties("SAPI-G Test Trusted Directory", "localhost:8080",
                signing, ca, storage, cert);
    }

    @Test
    void logConfiguration_withPasswords_masksSecrets() {
        StartupLogger logger = new StartupLogger(buildProps("s3cr3t"));
        assertThatCode(logger::logConfiguration).doesNotThrowAnyException();
    }

    @Test
    void logConfiguration_withNullPasswords_doesNotThrow() {
        StartupLogger logger = new StartupLogger(buildProps(null));
        assertThatCode(logger::logConfiguration).doesNotThrowAnyException();
    }

    @Test
    void logConfiguration_passwordShouldBeMasked() {
        Logger logbackLogger = (Logger) LoggerFactory.getLogger(StartupLogger.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logbackLogger.addAppender(appender);
        try {
            new StartupLogger(buildProps("s3cr3t")).logConfiguration();

            List<String> messages = appender.list.stream()
                    .map(ILoggingEvent::getFormattedMessage)
                    .toList();
            assertThat(messages).anyMatch(msg -> msg.contains("***"));
            assertThat(messages).noneMatch(msg -> msg.contains("s3cr3t"));
        } finally {
            logbackLogger.detachAppender(appender);
        }
    }
}
