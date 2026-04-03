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
package com.forgerock.sapi.gateway.test.trusted.directory.dto;

/**
 * Standard JSON error body returned by the API for all error responses.
 *
 * <pre>{@code {"status": 400, "error": "org_id and org_name are required"}}</pre>
 *
 * @param status HTTP status code (mirrors the HTTP response status)
 * @param message  human-readable description of the error
 * @param details details of the error if present
 */
public record ErrorResponse(int status, String message, String details) {
}
