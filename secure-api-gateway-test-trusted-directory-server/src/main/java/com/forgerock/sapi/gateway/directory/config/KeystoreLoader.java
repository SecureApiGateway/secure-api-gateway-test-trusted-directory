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

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * Utility for loading a {@link KeyStore.PrivateKeyEntry} from a PKCS12 (or other) keystore file.
 */
public final class KeystoreLoader {

    private KeystoreLoader() {
    }

    /**
     * Loads a private key entry from a keystore file.
     *
     * @param keystorePath path to the keystore file
     * @param keystoreType keystore type (e.g. {@code PKCS12})
     * @param keystorePwd  password used to open the keystore
     * @param keyAlias     alias of the private key entry
     * @param keystoreKeyPwd password for the private key entry (may equal {@code keystorePwd})
     * @return the {@link KeyStore.PrivateKeyEntry} for the given alias
     * @throws IllegalStateException if the alias is not found in the keystore
     * @throws Exception             if the keystore cannot be opened or the password is incorrect
     */
    public static KeyStore.PrivateKeyEntry loadPrivateKeyEntry(
            final String keystorePath,
            final String keystoreType,
            final String keystorePwd,
            final String keyAlias,
            final String keystoreKeyPwd) throws Exception {

        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        try (InputStream is = new FileInputStream(keystorePath)) {
            keyStore.load(is, keystorePwd.toCharArray());
        }
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                keyAlias,
                new KeyStore.PasswordProtection(keystoreKeyPwd.toCharArray()));
        if (entry == null) {
            throw new IllegalStateException("Key alias '" + keyAlias + "' not found in keystore: " + keystorePath);
        }
        return entry;
    }
}
