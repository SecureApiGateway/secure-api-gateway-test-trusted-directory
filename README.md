# Secure API Gateway Test Trusted Directory
The SAPI-G Test Trusted Directory is a development grade implementation of a [Trusted Directory](https://github.com/SecureApiGateway/SecureApiGateway/wiki/Trusted-Directories). 

This can be used for testing purposes, removing the dependency on external third party directories 
(such as the Open Banking Directory). It provides CA functionality, issuing certificates and private keys which can be
used by ApiClients to do DCR, and additional provides signed software statement assertions (SSAs) that a SAPI-G 
deployment can be configured to trust.

## Configuration

| Environment Variable                     | Description                                                                                                                                           | Example Value                                        |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| IG_TEST_DIRECTORY_CA_KEYSTORE_PATH       | Relative Path from the IG working directory (`/var/ig`) to the keystore containing the CA key                                                         | /secrets/test-trusted-directory/test-trusted-dir.p12 |
| IG_TEST_DIRECTORY_CA_KEYSTORE_TYPE       | Keystore type                                                                                                                                         | PKCS12                                               |
| IG_TEST_DIRECTORY_CA_KEYSTORE_ALIAS      | Alias of key in the keystore to use to sign certs issued. Matches the -alias arg supplied to keytool                                                  | ca                                                   |
| IG_TEST_DIRECTORY_CA_KEYSTORE_STOREPASS  | Keystore store password. Matches the -storepass arg supplied to keytool                                                                               | Passw0rd                                             |
| IG_TEST_DIRECTORY_CA_KEYSTORE_KEYPASS    | Keystore key password. Matches the -keypass arg supplied to keytool                                                                                   | Passw0rd                                             |
| IG_TEST_DIRECTORY_CA_SIGNING_STOREPASS   | Keystore store password. Matches the -storepass arg supplied to keytool                                                                               | Passw0rd                                             |
| IG_TEST_DIRECTORY_CA_SIGNING_KEYPASS     | Keystore key password. Matches the -keypass arg supplied to keytool                                                                                   | Passw0rd                                             |
| IG_TEST_DIRECTORY_ISSUER_NAME            | The Issuer (iss claim) used in SSAs produced by the Test Trusted Directory.<br/>The AS needs to be configured to trust this issuer for OAuth 2.0 DCR. | Default value: SAPI-G Test Trusted Directory         |
| IG_TEST_DIRECTORY_SIGNING_KEYSTORE_PATH  | Relative Path from the IG working directory (/var/ig) to the keystore containing the JWT Signing key                                                  | /secrets/test-trusted-directory/test-trusted-dir.p12 |
| IG_TEST_DIRECTORY_SIGNING_KEYSTORE_TYPE  | Keystore type                                                                                                                                         | PKCS12                                               |
| IG_TEST_DIRECTORY_SIGNING_KEYSTORE_ALIAS | Alias of key in the keystore to use to sign certs issued. Matches the -alias arg issued to keytool                                                    | jwt-signing                                          |


## API Documentation
TBC
