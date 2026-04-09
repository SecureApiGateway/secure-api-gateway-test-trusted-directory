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
package com.forgerock.sapi.gateway.directory.router;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import com.forgerock.sapi.gateway.directory.config.TrustedDirectoryConfig;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.client.WebClient;

class HealthRouterTest {

    @TempDir
    Path tempDir;

    private Vertx vertx;
    private HttpServer server;
    private WebClient client;
    private int port;

    private TrustedDirectoryConfig buildProperties(String storagePath) {
        return new TrustedDirectoryConfig(
                "Test", "localhost:8080",
                new TrustedDirectoryConfig.SigningConfig(null, "PKCS12", "jwt-signing", null, null),
                new TrustedDirectoryConfig.CaConfig(null, "PKCS12", "ca", "SHA256withRSA", null, null),
                storagePath,
                new TrustedDirectoryConfig.CertConfig(2048, 365));
    }

    @BeforeEach
    void setUp() throws Exception {
        vertx = Vertx.vertx();
    }

    private void startServer(TrustedDirectoryConfig props) throws Exception {
        Router router = Router.router(vertx);
        new HealthRouter(props).mount(router);
        server = vertx.createHttpServer().requestHandler(router).listen(0).toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        port = server.actualPort();
        client = WebClient.create(vertx);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (vertx != null) vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
    }

    @Test
    void shouldReturn200ForLiveness() throws Exception {
        startServer(buildProperties(tempDir.resolve("jwks.json").toString()));

        var response = client.get(port, "localhost", "/health/liveness")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.bodyAsString()).contains("UP");
    }

    @Test
    void shouldReturn200WhenStorageDirectoryIsWritable() throws Exception {
        startServer(buildProperties(tempDir.resolve("jwks.json").toString()));

        var response = client.get(port, "localhost", "/health/readiness")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.bodyAsString()).contains("UP");
    }

    @Test
    void shouldReturn200WhenStorageFileExistsAndIsWritable() throws Exception {
        Path jwksFile = tempDir.resolve("jwks.json");
        Files.createFile(jwksFile);
        startServer(buildProperties(jwksFile.toString()));

        var response = client.get(port, "localhost", "/health/readiness")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.bodyAsString()).contains("UP");
    }

    @Test
    void shouldReturn503WhenStorageDirectoryMissing() throws Exception {
        startServer(buildProperties("/nonexistent/dir/jwks.json"));

        var response = client.get(port, "localhost", "/health/readiness")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.bodyAsString()).contains("DOWN");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void shouldReturn503WhenStorageDirectoryNotWritable() throws Exception {
        Path readOnlyDir = tempDir.resolve("readonly");
        Files.createDirectory(readOnlyDir);
        Files.setPosixFilePermissions(readOnlyDir, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_EXECUTE));
        startServer(buildProperties(readOnlyDir.resolve("jwks.json").toString()));

        var response = client.get(port, "localhost", "/health/readiness")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.bodyAsString()).contains("DOWN");
        assertThat(response.bodyAsString()).contains("not writable");

        // Restore permissions so TempDir cleanup can delete the directory
        Files.setPosixFilePermissions(readOnlyDir, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void shouldReturn503WhenStorageFileNotWritable() throws Exception {
        Path jwksFile = tempDir.resolve("jwks.json");
        Files.createFile(jwksFile);
        Files.setPosixFilePermissions(jwksFile, Set.of(PosixFilePermission.OWNER_READ));
        startServer(buildProperties(jwksFile.toString()));

        var response = client.get(port, "localhost", "/health/readiness")
                .send().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);

        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.bodyAsString()).contains("DOWN");
        assertThat(response.bodyAsString()).contains("not writable");

        // Restore permissions so TempDir cleanup can delete the file
        Files.setPosixFilePermissions(jwksFile, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
    }
}
