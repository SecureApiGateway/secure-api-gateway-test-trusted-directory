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

import static com.forgerock.sapi.gateway.test.trusted.directory.config.StartupLogger.maskPassword;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.util.List;

import org.junit.jupiter.api.Test;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

class StartupLoggerTest {

    private TrustedDirectoryConfig buildPropsWithPasswords() {
        return new TrustedDirectoryConfig(
                "SAPI-G Test Trusted Directory", "localhost:8080",
                new TrustedDirectoryConfig.SigningConfig("/var/ttd/signing.p12", "PKCS12", "jwt-signing",
                        "secret", "keySecret"),
                new TrustedDirectoryConfig.CaConfig("/var/ttd/ca.p12", "PKCS12", "ca", "SHA256withRSA",
                        "caSecret", "caKeySecret"),
                "/var/ttd/trusted-directory-jwks.json",
                new TrustedDirectoryConfig.CertConfig(2048, 365));
    }

    private TrustedDirectoryConfig buildPropsWithoutPasswords() {
        return new TrustedDirectoryConfig(
                "SAPI-G Test Trusted Directory", "localhost:8080",
                new TrustedDirectoryConfig.SigningConfig("/var/ttd/signing.p12", "PKCS12", "jwt-signing", null, null),
                new TrustedDirectoryConfig.CaConfig("/var/ttd/ca.p12", "PKCS12", "ca", "SHA256withRSA", null, null),
                "/var/ttd/trusted-directory-jwks.json",
                new TrustedDirectoryConfig.CertConfig(2048, 365));
    }

    @Test
    void maskPassword_returnsStarsWhenSet() {
        assertThat(maskPassword("secret")).isEqualTo("***");
        assertThat(maskPassword("  x  ")).isEqualTo("***");
    }

    @Test
    void maskPassword_returnsNotSetWhenNullOrBlank() {
        assertThat(maskPassword(null)).isEqualTo("<not set>");
        assertThat(maskPassword("")).isEqualTo("<not set>");
        assertThat(maskPassword("   ")).isEqualTo("<not set>");
    }

    @Test
    void logConfiguration_doesNotThrow() {
        assertThatCode(() -> StartupLogger.logConfiguration(buildPropsWithPasswords())).doesNotThrowAnyException();
        assertThatCode(() -> StartupLogger.logConfiguration(buildPropsWithoutPasswords())).doesNotThrowAnyException();
    }

    @Test
    void logConfiguration_passwordsSetShowsStars() {
        Logger logbackLogger = (Logger) LoggerFactory.getLogger(StartupLogger.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logbackLogger.addAppender(appender);
        try {
            StartupLogger.logConfiguration(buildPropsWithPasswords());

            List<String> messages = appender.list.stream()
                    .map(ILoggingEvent::getFormattedMessage)
                    .toList();
            assertThat(messages).anyMatch(msg -> msg.contains("signing.keystorePwd:       ***"));
            assertThat(messages).anyMatch(msg -> msg.contains("signing.keystoreKeyPwd:    ***"));
            assertThat(messages).anyMatch(msg -> msg.contains("ca.keystorePwd:            ***"));
            assertThat(messages).anyMatch(msg -> msg.contains("ca.keystoreKeyPwd:         ***"));
            assertThat(messages).noneMatch(msg -> msg.contains("secret") || msg.contains("caSecret"));
        } finally {
            logbackLogger.detachAppender(appender);
        }
    }

    @Test
    void logConfiguration_passwordsNotSetShowsNotSet() {
        Logger logbackLogger = (Logger) LoggerFactory.getLogger(StartupLogger.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logbackLogger.addAppender(appender);
        try {
            StartupLogger.logConfiguration(buildPropsWithoutPasswords());

            List<String> messages = appender.list.stream()
                    .map(ILoggingEvent::getFormattedMessage)
                    .toList();
            assertThat(messages).anyMatch(msg -> msg.contains("signing.keystorePwd:       <not set>"));
            assertThat(messages).anyMatch(msg -> msg.contains("ca.keystorePwd:            <not set>"));
        } finally {
            logbackLogger.detachAppender(appender);
        }
    }
}
