/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.test.trusted.directory.certificate;

import java.security.cert.Certificate;

import org.forgerock.openig.el.Expression;
import org.forgerock.openig.fapi.certificate.ClientCertificateFilter;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.Heaplet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link Heaplet} to initialise {@link ClientCertificateFilter} in a heap environment.
 */
public class ClientCertificateFilterHeaplet extends GenericHeaplet {

    private static final Logger logger = LoggerFactory.getLogger(ClientCertificateFilterHeaplet.class);

    public static final String NAME = "ClientCertificateFilter";
    static final String CONFIG_CLIENT_CERTIFICATE = "clientCertificate";
    static final String CONFIG_MANDATORY = "mandatory";

    @Override
    public Object create() throws HeapException {
        Expression<Certificate> clientCertificateExpression = config.get(CONFIG_CLIENT_CERTIFICATE)
                                                                    .required()
                                                                    .as(expression(Certificate.class));
        boolean isMandatory = config.get(CONFIG_MANDATORY)
                                    .as(evaluatedWithHeapProperties())
                                    .defaultTo(true)
                                    .asBoolean();
        return new ClientCertificateFilter(clientCertificateExpression, isMandatory);
    }
}