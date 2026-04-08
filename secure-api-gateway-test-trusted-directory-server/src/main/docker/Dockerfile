#
# Copyright © 2020-2026 Ping Identity Corporation (obst@forgerock.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM gcr.io/forgerock-io/java-21:latest
ENV TTD_INSTALL_DIR=/opt/ttd
ENV TTD_INSTANCE_DIR=/var/ttd

RUN mkdir -p ${TTD_INSTALL_DIR} \
    && mkdir -p ${TTD_INSTANCE_DIR} \
    && chown -R forgerock:root ${TTD_INSTALL_DIR} ${TTD_INSTANCE_DIR} \
    && chmod -R g+rwx ${TTD_INSTALL_DIR} ${TTD_INSTANCE_DIR}

COPY --chown=forgerock:root maven/${project.build.finalName}.jar ${TTD_INSTALL_DIR}/server.jar

USER forgerock
ENTRYPOINT exec java -jar ${TTD_INSTALL_DIR}/server.jar
