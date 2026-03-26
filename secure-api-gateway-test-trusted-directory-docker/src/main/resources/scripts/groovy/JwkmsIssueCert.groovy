import com.forgerock.sapi.gateway.test.trusted.directory.ca.CertificateOptions
import org.forgerock.json.jose.jws.JwsAlgorithm
import java.util.UUID

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id")
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[JwkmsIssueCert] (" + fapiInteractionId + ") - "

if (!softwareJwksService) {
    logger.error(SCRIPT_NAME + "No softwareJwksService configured")
    return new Response(Status.INTERNAL_SERVER_ERROR)
}

def requestObj = request.entity.getJson()

String orgName = requestObj.org_name
String orgId = requestObj.org_id

// For backwards compatibility software_id is not mandatory, generate a unique value if one is not provided
String softwareId = requestObj.software_id ?: UUID.randomUUID().toString()

logger.debug(SCRIPT_NAME + "Issuing certificate for orgId {} orgName {} softwareId {}", orgId, orgName, softwareId)

if (!(orgName && orgId)) {
    // response object
    response = new Response(Status.BAD_REQUEST)
    response.headers['Content-Type'] = "application/json"
    message = "Json body must contain fields: [org_id, org_name]"
    logger.error(SCRIPT_NAME + message)
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}
def certOptions = new CertificateOptions(JwsAlgorithm.PS256, keySize).certValidityDays(validityDays)
def jwks = softwareJwksService.issueSoftwareCertificates(orgId, orgName, softwareId, certOptions)

Response response = new Response(Status.OK)
response.setEntity(jwks.toJsonValue())

return response