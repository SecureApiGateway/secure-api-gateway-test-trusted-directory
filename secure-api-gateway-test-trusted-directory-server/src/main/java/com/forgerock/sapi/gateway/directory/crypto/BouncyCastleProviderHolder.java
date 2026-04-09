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
package com.forgerock.sapi.gateway.directory.crypto;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Holds the single shared instance of the {@link BouncyCastleProvider}.
 * <p>
 * All cryptographic operations in this application that require BouncyCastle
 * should pass {@link #PROVIDER} explicitly to the relevant JCA/BC API calls,
 * rather than registering BC as a global JVM security provider.
 */
public final class BouncyCastleProviderHolder {

    /** The shared BouncyCastle {@link Provider} instance. */
    public static final Provider PROVIDER = new BouncyCastleProvider();

    private BouncyCastleProviderHolder() {
    }
}
