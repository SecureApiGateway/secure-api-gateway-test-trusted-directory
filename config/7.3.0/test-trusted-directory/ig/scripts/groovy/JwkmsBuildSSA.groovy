
import static java.util.Objects.requireNonNull;

import java.security.cert.X509Certificate;

import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*
import org.forgerock.openig.fapi.certificate.ClientCertificateFapiContext

import javax.naming.ldap.LdapName
import javax.naming.ldap.Rdn

class CertificateParserHelper {
    private static final OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97"
    private static final TYPE_ORGANIZATIONAL_IDENTIFIER = "OI"

    static parseDN(String dn) {
        def result = [:]
        LdapName ln = new LdapName(dn);

        for(Rdn rdn : ln.getRdns()) {
            def rdnType = rdn.getType();
            // LdapName doesn't know about OrganizationalIdentifier
            if (rdnType == ("OID." + OID_ORGANIZATIONAL_IDENTIFIER)) {
                rdnType = TYPE_ORGANIZATIONAL_IDENTIFIER
            }
            result.put(rdnType,rdn.getValue());
        }
        return result;
    }
}

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[JwkmsBuildSSA] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

logger.debug(SCRIPT_NAME + "Creating SSA")

// Validate args
requireNonNull(clock)
requireNonNull(routeArgJwtIssuer)
requireNonNull(routeArgJwtValidity)
requireNonNull(routeArgGetJwksUriPrefix)
requireNonNull(softwareJwksService)

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

def requestObj = request.entity.getJson()

def iss = routeArgJwtIssuer
def iat = clock.instant().getEpochSecond();
def exp = iat + routeArgJwtValidity;


// Check we have everything we need from the client certificate

X509Certificate certificate = context.as(ClientCertificateFapiContext.class)
                                     .map(ClientCertificateFapiContext::getClientCertificate)
                                     .orElse(null);
if (certificate == null) {
    message = "No client certificate for registration"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def subjectDNComponents = CertificateParserHelper.parseDN(certificate.getSubjectX500Principal().toString())
if (!subjectDNComponents.CN) {
    message = "No CN in cert"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def org_id = subjectDNComponents.OI

if (!org_id) {
    message = "No org identifier in cert"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def org_name = subjectDNComponents.CN;

def payload = [
    "iss": iss,
    "iat": iat,
    "exp": exp,
    "org_id": org_id,
    "org_name": org_name,
    "org_status": "Active",
    "software_mode": "TEST",
    "software_id": requestObj.software_id,
    "software_client_name": requestObj.software_client_name,
    "software_client_id": requestObj.software_client_id,
    "software_tos_uri": requestObj.software_tos_uri,
    "software_client_description": requestObj.software_client_description,
    "software_redirect_uris": requestObj.software_redirect_uris,
    "software_policy_uri": requestObj.software_policy_uri,
    "software_logo_uri": requestObj.software_logo_uri,
    "software_roles": requestObj.software_roles
]

// Embed the jwks if it is provided in the request otherwise set the jwks endpoint uri
if (requestObj.software_jwks) {
    payload["software_jwks"] = requestObj.software_jwks
} else {
    // validate that a JWKS exists
    if (!softwareJwksService.getPublicSoftwareJwks(org_id, requestObj.software_id)) {
        response = new Response(Status.BAD_REQUEST)
        response.headers['Content-Type'] = "application/json"
        message = "No JWKS exists for org_id: ${org_id} and software_id: ${requestObj.software_id} - " +
                "Please issue certificates for this software first."
        logger.error(SCRIPT_NAME + message)
        response.entity = "{ \"error\":\"" + message + "\"}"
        return response
    }
    payload["software_jwks_endpoint"] = routeArgGetJwksUriPrefix + "/" + org_id + "/" + requestObj.software_id
}

logger.debug(SCRIPT_NAME + "Built SSA payload " + payload)
attributes.ssaPayload = payload

next.handle(context,request)
