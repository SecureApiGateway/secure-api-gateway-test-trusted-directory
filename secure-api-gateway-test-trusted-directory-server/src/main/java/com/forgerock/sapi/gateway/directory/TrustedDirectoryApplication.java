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
package com.forgerock.sapi.gateway.directory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.core.Vertx;

/** Application entry point — deploys the {@link TrustedDirectoryVerticle}. */
public final class TrustedDirectoryApplication {

    private static final Logger logger = LoggerFactory.getLogger(TrustedDirectoryApplication.class);

    private TrustedDirectoryApplication() {
    }

    /**
     * Application entry point — deploys the {@link TrustedDirectoryVerticle} and exits on failure.
     *
     * @param args command-line arguments (unused)
     */
    public static void main(final String[] args) {
        Vertx.vertx().deployVerticle(new TrustedDirectoryVerticle())
                .onFailure(err -> {
                    logger.error("Failed to start", err);
                    System.exit(1);
                });
    }
}
