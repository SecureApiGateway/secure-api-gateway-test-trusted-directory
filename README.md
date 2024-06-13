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
### Issue client certificates

This is the first API that a client should call, it issues certificates and private keys for the client to use for
signing and transport (mTLS) purposes.

Make a POST to the `/jwkms/apiclient/issuecert` endpoint supplying a json entity with the following fields:
```json
{
"org_id": string,
"org_name": string,
"software_id": string
}
```
As this is a test directory then any values can be supplied, the org_id and software_id are the most important. The 
client needs to remember these in order to be able to issue new certificates for the software, and to be able to 
generate a Software Statement Assertion (SSA).

Example HTTP call:
```http request
POST /jwkms/apiclient/issuecert HTTP/1.1
Host: ${SAPI_G_HOST}
Content-Type: application/json

{
"org_id": "PSDGB-FFA-5f563e89742b2800145c7da1",
"org_name": "Acme Fintech",
"software_id": "test-app-1234"
}
```

The endpoint should responsd with a 200 OK, with a json entity containing a JWKS (Json Web Key Set). The JWKS will
contain a signing key (with "use": "sig") and a transport key (with "use": "tls").

Additional calls with the same org_id and software_id values results in additional keys being issued and added to the
JWKS.

### Generate a Software Statement Assertion (SSA)

This API generates a Software Statement Assertion (SSA) signed by the Test Trusted Directory. This can be used as part
of OAuth2.0 Dynamic Client registration to register a new OAuth2.0 client.

This endpoint requires mTLS, the client needs to supply a transport certificate that belongs to their JWKS.

Make a POST to the `/jwkms/apiclient/genssa` endpoint supplying a json entity with the following fields:
```json
{
  "software_id": string,
  "software_client_name": string,
  "software_client_id": string,
  "software_tos_uri": string,
  "software_client_description": string,
  "software_redirect_uris": [string, ...],
  "software_policy_uri": string,
  "software_logo_uri": string,
  "software_roles": [string, ...]
}
```

The software_id field must match the value used when calling the `/jwkms/apiclient/issuecert` endpoint. As this data
is used to construct the jwks_uri for the software, which gets set in the `software_jwks_endpoint` SSA claim.

Example HTTP call:
```http request
POST /jwkms/apiclient/getssa HTTP/1.1
Host: ${SAPI_G_HOST}
Content-Type: application/json

{
    "software_id": "dd44cb4f-173b-4d0f-bb97-b21f4238bbda",
    "software_client_name": "Secure API Gateway Test client",
    "software_client_id": "dd44cb4f-173b-4d0f-bb97-b21f4238bbda",
    "software_tos_uri": "https://github.com/SecureApiGateway",
    "software_client_description": "Secure API Gateway Test client to be used to run postman tests",
    "software_redirect_uris": ["https://www.google.com", "https://postman-echo.com/get"],
    "software_policy_uri": "https://github.com/SecureApiGateway",
    "software_logo_uri": "https://avatars.githubusercontent.com/u/74596995?s=96&v=4",
    "software_roles": [    
        "DATA",
        "AISP",
        "CBPII",
        "PISP"]
}
```

The endpoint should respond with a 200 OK, with the SSA returned as a signed JWT in compat serialized form. If no
JWKS exists for the software, then a 400 BAD_REQUEST response is returned, in this case the client should call the
`/jwkms/apiclient/issuecert` endpoint and then retry this call.

The SSA can then be used as the software_statement value in Dynamic Registration Requests.

### Get Test Trusted Directory JWKS
This endpoint is used to retrieve the JWKS belonging to the directory itself. This can be used to validate signatures
produced by the directory, such as Software Statement Assertions (SSAs). Secure API Gateway deployments configure
the TrustedDirectory.directoryJwksUri field for the Test Trusted Directory to call this endpoint.

The JWKS can be retrieved by making a Get request to `/jwkms/testdirectory/jwks`

Example HTTP call:
```http request
GET /jwkms/testdirectory/jwks HTTP/1.1
Host: ${SAPI_G_HOST}
```

The JWKS is returned as a json entity.

### Get software JWKS
This endpoint is used to retrieve the JWKS belong to a piece of software. This JWKS will have been issued by the Test
Trusted Directory. The JWKS can be used by Secure API Gateway to verify signatures for signed JWTs produced by an
ApiClient that has registered with that JWKS, and to check that the mTLS certificate is mapped to the software.

The JWKS can be retrieved by making a Get request to `/jwkms/apiclient/jwks/$organisationId/$softwareId`, replacing
the organisationId and softwareId path params with valid values.

Example HTTP call:
```http request
GET /jwkms/apiclient/jwks/PSDGB-FFA-5f563e89742b2800145c7da1/test-app-1234 HTTP/1.1
Host: ${SAPI_G_HOST}
```

The JWKS is returned as a json entity.

### Revoke Certificate
The certificate revocation functionality removes a certificate from a JWKS. This can be used as part of testing to 
ensure that SAPI-G rejects requests which use keys that are no longer mapped to the ApiClient's JWKS (for either signing
or mTLS purposes).

A POST request can be made to `/jwkms/apiclient/jwks/revokecert`, endpoint supplying a json entity with the following fields:
```json
{
  "org_id": string,
  "software_id": string,
  "key_id": string
}
```

Example HTTP call:
```http request
POST /jwkms/apiclient/jwks/revokecert HTTP/1.1
Host: ${SAPI_G_HOST}
Content-Type: application/json

{
    "org_id": "0015800001041REAAY",
    "software_id": "Y6NjA9TOn3aMm9GaPtLwkp",
    "key_id": "505ed9dd-768c-476e-b02d-9d60547a8f5e"
}
```
