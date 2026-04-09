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

import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

/** Shared HTTP response helpers used by all routers. */
final class RouterHelper {

    private RouterHelper() {
    }

    static void sendError(final RoutingContext ctx, final int status, final String message) {
        ctx.response()
           .setStatusCode(status)
           .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
           .end(new JsonObject().put("status", status)
                                .put("message", message)
                                .encode());
    }

    static void sendBadRequest(final RoutingContext ctx, final String message) {
        sendError(ctx, 400, message);
    }
}
