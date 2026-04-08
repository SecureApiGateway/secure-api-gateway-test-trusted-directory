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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import io.vertx.core.json.JsonObject;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

@ExtendWith(SystemStubsExtension.class)
class EnvVarSubstitutorTest {

    @SystemStub
    EnvironmentVariables env;

    @Test
    void substitute_replacesTopLevelPlaceholder() {
        env.set("MY_VAR", "hello");
        JsonObject input = new JsonObject().put("key", "${MY_VAR}");

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getString("key")).isEqualTo("hello");
    }

    @Test
    void substitute_replacesNestedPlaceholder() {
        env.set("NESTED_VAR", "deep-value");
        JsonObject input = new JsonObject()
                .put("outer", new JsonObject()
                        .put("inner", "${NESTED_VAR}"));

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getJsonObject("outer").getString("inner")).isEqualTo("deep-value");
    }

    @Test
    void substitute_throwsWhenRequiredEnvVarNotSet() {
        JsonObject input = new JsonObject().put("key", "${UNSET_VAR_XYZ}");

        assertThatThrownBy(() -> EnvVarSubstitutor.substitute(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("UNSET_VAR_XYZ");
    }

    @Test
    void substitute_throwsWhenRequiredEnvVarIsBlank() {
        env.set("BLANK_VAR", "   ");
        JsonObject input = new JsonObject().put("key", "${BLANK_VAR}");

        assertThatThrownBy(() -> EnvVarSubstitutor.substitute(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("BLANK_VAR");
    }

    @Test
    void substitute_throwsWhenRequiredEnvVarInNestedObject() {
        JsonObject input = new JsonObject()
                .put("outer", new JsonObject().put("inner", "${UNSET_NESTED_VAR}"));

        assertThatThrownBy(() -> EnvVarSubstitutor.substitute(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("UNSET_NESTED_VAR");
    }

    @Test
    void substitute_preservesNonPlaceholderStrings() {
        JsonObject input = new JsonObject().put("key", "literal-value");

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getString("key")).isEqualTo("literal-value");
    }

    @Test
    void substitute_preservesNonStringValues() {
        JsonObject input = new JsonObject()
                .put("intVal", 42)
                .put("boolVal", true);

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getInteger("intVal")).isEqualTo(42);
        assertThat(result.getBoolean("boolVal")).isTrue();
    }

    @Test
    void substitute_doesNotModifyOriginalObject() {
        env.set("SOME_VAR", "replaced");
        JsonObject input = new JsonObject().put("key", "${SOME_VAR}");

        EnvVarSubstitutor.substitute(input);

        assertThat(input.getString("key")).isEqualTo("${SOME_VAR}");
    }

    @Test
    void substitute_replacesMultiplePlaceholdersInSameObject() {
        env.set("VAR_A", "alpha");
        env.set("VAR_B", "beta");
        JsonObject input = new JsonObject()
                .put("a", "${VAR_A}")
                .put("b", "${VAR_B}")
                .put("c", "literal");

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getString("a")).isEqualTo("alpha");
        assertThat(result.getString("b")).isEqualTo("beta");
        assertThat(result.getString("c")).isEqualTo("literal");
    }

    @Test
    void substitute_doesNotReplacePartialPlaceholder() {
        JsonObject input = new JsonObject().put("key", "prefix_${MY_VAR}_suffix");

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getString("key")).isEqualTo("prefix_${MY_VAR}_suffix");
    }

    @Test
    void substitute_usesDefaultWhenEnvVarNotSet() {
        JsonObject input = new JsonObject().put("key", "${UNSET_VAR_XYZ:fallback-value}");

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getString("key")).isEqualTo("fallback-value");
    }

    @Test
    void substitute_usesEnvVarValueOverDefault() {
        env.set("MY_VAR_WITH_DEFAULT", "from-env");
        JsonObject input = new JsonObject().put("key", "${MY_VAR_WITH_DEFAULT:fallback-value}");

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getString("key")).isEqualTo("from-env");
    }

    @Test
    void substitute_supportsEmptyDefault() {
        JsonObject input = new JsonObject().put("key", "${UNSET_VAR_XYZ:}");

        JsonObject result = EnvVarSubstitutor.substitute(input);

        assertThat(result.getString("key")).isEqualTo("");
    }

    @Test
    void substitute_returnsEmptyObjectWhenInputIsEmpty() {
        JsonObject result = EnvVarSubstitutor.substitute(new JsonObject());

        assertThat(result.isEmpty()).isTrue();
    }
}
