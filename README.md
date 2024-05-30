# Secure API Gateway Test Trusted Directory
The SAPI-G Test Trusted Directory is a development grade implementation of a [Trusted Directory](https://github.com/SecureApiGateway/SecureApiGateway/wiki/Trusted-Directories). 

This can be used for testing purposes, removing the dependency on external third party directories 
(such as the Open Banking Directory). It provides CA functionality, issuing certificates and private keys which can be
used by ApiClients to do DCR, and additional provides signed software statement assertions (SSAs) that a SAPI-G 
deployment can be configured to trust.

## Configuration

| Environment Variable                  | Description                                                                                                                                           | Default Value                 |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| IG_TEST_TRUSTED_DIRECTORY_ISSUER_NAME | The Issuer (iss claim) used in SSAs produced by the Test Trusted Directory.<br/>The AS needs to be configured to trust this issuer for OAuth 2.0 DCR. | SAPI-G Test Trusted Directory |
 | 


## API Documentation
TBC
