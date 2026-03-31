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

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "trusted-directory")
public class TrustedDirectoryProperties {

    private String issuerName = "SAPI-G Test Trusted Directory";
    private String fqdn = "localhost:8080";

    private SigningProperties signing = new SigningProperties();
    private CaProperties ca = new CaProperties();
    private StorageProperties storage = new StorageProperties();
    private CertProperties cert = new CertProperties();

    public String getIssuerName() { return issuerName; }
    public void setIssuerName(String issuerName) { this.issuerName = issuerName; }
    public String getFqdn() { return fqdn; }
    public void setFqdn(String fqdn) { this.fqdn = fqdn; }
    public SigningProperties getSigning() { return signing; }
    public void setSigning(SigningProperties signing) { this.signing = signing; }
    public CaProperties getCa() { return ca; }
    public void setCa(CaProperties ca) { this.ca = ca; }
    public StorageProperties getStorage() { return storage; }
    public void setStorage(StorageProperties storage) { this.storage = storage; }
    public CertProperties getCert() { return cert; }
    public void setCert(CertProperties cert) { this.cert = cert; }

    public static class SigningProperties {
        private String keystorePath;
        private String keystoreType = "PKCS12";
        private String keystorePassword;
        private String keystoreKeyPassword;
        private String keyAlias = "jwt-signing";

        public String getKeystorePath() { return keystorePath; }
        public void setKeystorePath(String keystorePath) { this.keystorePath = keystorePath; }
        public String getKeystoreType() { return keystoreType; }
        public void setKeystoreType(String keystoreType) { this.keystoreType = keystoreType; }
        public String getKeystorePassword() { return keystorePassword; }
        public void setKeystorePassword(String keystorePassword) { this.keystorePassword = keystorePassword; }
        public String getKeystoreKeyPassword() { return keystoreKeyPassword != null ? keystoreKeyPassword : keystorePassword; }
        public void setKeystoreKeyPassword(String keystoreKeyPassword) { this.keystoreKeyPassword = keystoreKeyPassword; }
        public String getKeyAlias() { return keyAlias; }
        public void setKeyAlias(String keyAlias) { this.keyAlias = keyAlias; }
    }

    public static class CaProperties {
        private String keystorePath;
        private String keystoreType = "PKCS12";
        private String keystorePassword;
        private String keystoreKeyPassword;
        private String keyAlias = "ca";
        private String certSigningAlg = "SHA256withRSA";

        public String getKeystorePath() { return keystorePath; }
        public void setKeystorePath(String keystorePath) { this.keystorePath = keystorePath; }
        public String getKeystoreType() { return keystoreType; }
        public void setKeystoreType(String keystoreType) { this.keystoreType = keystoreType; }
        public String getKeystorePassword() { return keystorePassword; }
        public void setKeystorePassword(String keystorePassword) { this.keystorePassword = keystorePassword; }
        public String getKeystoreKeyPassword() { return keystoreKeyPassword != null ? keystoreKeyPassword : keystorePassword; }
        public void setKeystoreKeyPassword(String keystoreKeyPassword) { this.keystoreKeyPassword = keystoreKeyPassword; }
        public String getKeyAlias() { return keyAlias; }
        public void setKeyAlias(String keyAlias) { this.keyAlias = keyAlias; }
        public String getCertSigningAlg() { return certSigningAlg; }
        public void setCertSigningAlg(String certSigningAlg) { this.certSigningAlg = certSigningAlg; }
    }

    public static class StorageProperties {
        private String filePath = "/var/data/trusted-directory-jwks.json";

        public String getFilePath() { return filePath; }
        public void setFilePath(String filePath) { this.filePath = filePath; }
    }

    public static class CertProperties {
        private int keySize = 2048;
        private int validityDays = 365;

        public int getKeySize() { return keySize; }
        public void setKeySize(int keySize) { this.keySize = keySize; }
        public int getValidityDays() { return validityDays; }
        public void setValidityDays(int validityDays) { this.validityDays = validityDays; }
    }
}
