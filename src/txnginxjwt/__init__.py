from jwcrypto import jwt
from twisted.logger import Logger
from twisted.web import server, resource

import json


class JWTClientIPAuthResource(resource.Resource):
    """
    Validates JWT token passed in via HTTP user field. Also extracts `clientip'
    field from JWT claims and compares it to the value in a configurable
    request header.
    """
    isLeaf = True

    def __init__(self, header: str, keyfile: str):
        self.log = Logger()
        self.key = jwt.JWK()

        self.header = header
        with open(keyfile, 'rb') as stream:
            self.key.import_from_pem(stream.read())

    def render(self, request: server.Request) -> bytes:
        # Deny by default.
        request.setResponseCode(401)

        # Token is passed as the HTTP user in order to simplify URL
        # construction, E.g. https://<token>@example.com/internal-stuff
        user = request.getUser()
        if user == b"":
            self.log.error("Request: User missing")
            return b""

        try:
            token = jwt.JWT(key=self.key, jwt=user.decode())
        except (jwt.JWTExpired, jwt.JWTNotYetValid, jwt.JWTMissingClaim,
                jwt.JWTInvalidClaimValue, jwt.JWTInvalidClaimFormat,
                jwt.JWTMissingKeyID, jwt.JWTMissingKey) as error:
            self.log.error("JWT token: {error}", error=error)
            return b""
        except Exception:
            self.log.failure("JWT token: Unknown exception")
            return b""

        try:
            claims = json.loads(token.claims)
        except json.JSONDecodeError:
            self.log.failure("JWT token: Claim deserialization failed")
            return b""

        # Token claim contains a client ip. Ensure that this matches the
        # $remote_addr set by nginx.
        headerip = request.getHeader(self.header)
        if headerip is None or headerip == "":
            self.log.error("Request: Header {header} missing",
                           header=self.header)
            return b""

        claimip = claims.get("clientip")
        if claimip is None or claimip == "":
            self.log.error("JWT token: Client IP claim missing")
            return b""

        if headerip != claimip:
            self.log.error("Request: Header `{header}` unexpected: "
                           "`{headerip}`. JWT claim requires `{claimip}`",
                           claimip=claimip,
                           header=self.header,
                           headerip=headerip)
            return b""
        else:
            request.setResponseCode(200)
            self.log.info("JWT token: Validation succeeded")
            return b""
