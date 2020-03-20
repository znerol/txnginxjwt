from jwcrypto import jwt
from twisted.internet import reactor
from twisted.logger import Logger
from twisted.web import server, resource

import json
import secrets


class JWTClientIPAuthResource(resource.Resource):
    """
    Validates JWT token passed in via a HTTP query parameter. Sets a session
    cookie in order to authenticate subsequent requests. Also extracts
    `clientip' field from JWT claims and compares it to the value in a
    configurable request header.
    """
    isLeaf = True

    def __init__(self, param: bytes, cookie: bytes, header: str,
                 keyfile: str, sessttl: int):
        self.log = Logger()
        self.key = jwt.JWK()

        self.param = param
        self.cookie = cookie
        self.header = header

        # Very naive session store. Extract and improve if necessary.
        self.sessttl = sessttl
        self.sessions = set()

        with open(keyfile, 'rb') as stream:
            self.key.import_from_pem(stream.read())

    def render(self, request: server.Request) -> bytes:
        # Deny by default.
        request.setResponseCode(401)

        # Get session cookie value if any.
        sessionid = request.getCookie(self.cookie)
        if sessionid is not None:
            if sessionid in self.sessions:
                request.setResponseCode(200)
                self.log.info("Session: Validation succeeded")
                return b""
            else:
                self.log.info("Session: Invalid session id")

        # Token is passed as an URL query parameter.
        args = request.args.get(self.param, [])
        if len(args) != 1:
            self.log.error("Request: Token {param} missing", param=self.param)
            return b""

        try:
            token = jwt.JWT(key=self.key, jwt=args[0].decode())
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
            # Generate a new session id and remember it. Also clean it up after
            # ttl seconds.
            sessionid = secrets.token_urlsafe(nbytes=16).encode()
            self.sessions.add(sessionid)
            reactor.callLater(self.sessttl, self._session_remove, sessionid)
            self.log.info("Session: Created, num sessions: {sessions}",
                          sessions=len(self.sessions))

            # Set cookie in the browser.
            request.addCookie(self.cookie, sessionid, path="/", secure=True,
                              httpOnly=True)

            request.setResponseCode(200)
            self.log.info("JWT token: Validation succeeded")
            return b""

    def _session_remove(self, sessionid: bytes):
        self.sessions.remove(sessionid)
        self.log.info("Session: Removed, num sessions: {sessions}",
                      sessions=len(self.sessions))
