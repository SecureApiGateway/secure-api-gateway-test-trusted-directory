def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id")
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ApiClientRevokeCert] (" + fapiInteractionId + ") - "

if (!softwareJwksService) {
    logger.error(SCRIPT_NAME + "No softwareJwksService configured")
    return new Response(Status.INTERNAL_SERVER_ERROR)
}

if (request.method.toUpperCase() != "POST") {
    return new Response(Status.METHOD_NOT_ALLOWED)
}

// Expect a JSON entity containing org_id, software_id, key_id
def requestObj = request.entity.getJson()
def orgId = requestObj.org_id
def softwareId = requestObj.software_id
def keyId = requestObj.key_id

if (!(orgId && softwareId && keyId)) {
    // response object
    response = new Response(Status.BAD_REQUEST)
    response.headers['Content-Type'] = "application/json"
    message = "Json body must contain fields: [org_id, software_id, key_id]"
    logger.error(SCRIPT_NAME + message)
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

logger.debug(SCRIPT_NAME + " revoking cert [orgId: $orgId, softwareId: $softwareId, keyId: $keyId]")
softwareJwksService.removeCertificate(orgId, softwareId, keyId)

return new Response(Status.OK)

