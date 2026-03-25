def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id")
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ApiClientJwksUriHandler] (" + fapiInteractionId + ") - "

if (!softwareJwksService) {
    logger.error(SCRIPT_NAME + "No softwareJwksService configured")
    return new Response(Status.INTERNAL_SERVER_ERROR)
}

// Expect path to end with /$orgId/$softwareId
def pathElements = request.uri.pathElements
if (pathElements.size() < 2) {
    logger.error(SCRIPT_NAME + "Invalid request, uri does not end with /orgId/softwareId")
    return new Response(Status.INTERNAL_SERVER_ERROR)
}
def orgId = pathElements[-2]
def softwareId = pathElements[-1]

def jwks = softwareJwksService.getPublicSoftwareJwks(orgId, softwareId)
if (!jwks) {
    logger.warn(SCRIPT_NAME + "no JWKS found for orgId: $orgId, softwareId: $softwareId")
    return new Response(Status.NOT_FOUND)
}

Response response = new Response(Status.OK)
response.setEntity(jwks.toJsonValue())

return response
