from jwcrypto import jwt
from twisted.internet import reactor
from twisted.logger import Logger
from twisted.web import server, resource

import secrets


class JWTClientIPAuthResource(resource.Resource):
    """
    Validates JWT token passed in via a HTTP query parameter. Sets a session
    cookie in order to authenticate subsequent requests.
    """
    isLeaf = True

    def __init__(self, param: bytes, cookie: bytes, keyfile: str,
                 sessttl: int):
        self.log = Logger()
        self.key = jwt.JWK()

        self.param = param
        self.cookie = cookie

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
            _ = jwt.JWT(key=self.key, jwt=args[0].decode())
        except (jwt.JWTExpired, jwt.JWTNotYetValid, jwt.JWTMissingClaim,
                jwt.JWTInvalidClaimValue, jwt.JWTInvalidClaimFormat,
                jwt.JWTMissingKeyID, jwt.JWTMissingKey) as error:
            self.log.error("JWT token: {error}", error=error)
            return b""
        except Exception:
            self.log.failure("JWT token: Unknown exception")
            return b""

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
