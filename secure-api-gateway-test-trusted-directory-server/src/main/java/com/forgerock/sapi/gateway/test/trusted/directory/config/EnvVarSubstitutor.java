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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.vertx.core.json.JsonObject;

/**
 * Utility that resolves {@code ${VAR_NAME}} or {@code ${VAR_NAME:default}} placeholders
 * in a {@link JsonObject} by substituting them with the corresponding environment variable
 * values.
 * <p>
 * Resolution rules:
 * <ul>
 *   <li>{@code ${VAR}} — replaced with {@code System.getenv("VAR")} if the variable is set
 *       and non-blank. Throws {@link IllegalArgumentException} if the variable is absent or
 *       blank, as no default was provided.</li>
 *   <li>{@code ${VAR:default}} — replaced with {@code System.getenv("VAR")}, or
 *       {@code "default"} if the variable is absent. The default value may be empty
 *       ({@code ${VAR:}}).</li>
 * </ul>
 * The substitution is applied recursively to all string values in the object tree.
 */
public final class EnvVarSubstitutor {

    /**
     * Matches a full placeholder string: {@code ${VAR}} or {@code ${VAR:default}}.
     * <ul>
     *   <li>Group 1 — variable name (no {@code :} or {@code }})</li>
     *   <li>Group 2 — default value (optional; {@code null} when absent)</li>
     * </ul>
     */
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}:]+)(?::([^}]*))?}");

    private EnvVarSubstitutor() {
    }

    /**
     * Returns a new {@link JsonObject} where every string value matching a placeholder is
     * replaced with the resolved value according to the rules above.
     *
     * @param config the source JSON object (not modified)
     * @return a new object with all placeholders resolved
     * @throws IllegalArgumentException if a required placeholder (no default) references an
     *                                  environment variable that is absent or blank
     */
    public static JsonObject substitute(final JsonObject config) {
        JsonObject result = new JsonObject();
        for (String key : config.fieldNames()) {
            Object value = config.getValue(key);
            if (value instanceof JsonObject nested) {
                result.put(key, substitute(nested));
            } else if (value instanceof String str) {
                Matcher matcher = PLACEHOLDER.matcher(str);
                if (matcher.matches()) {
                    String varName = matcher.group(1);
                    String defaultValue = matcher.group(2);
                    String resolved = System.getenv(varName);
                    if ((resolved == null || resolved.isBlank()) && defaultValue == null) {
                        throw new IllegalArgumentException(
                                "Missing required environment variable: " + varName);
                    }
                    result.put(key, (resolved != null && !resolved.isBlank()) ? resolved : defaultValue);
                } else {
                    result.put(key, value);
                }
            } else {
                result.put(key, value);
            }
        }
        return result;
    }
}
