from twisted.python import usage
from twisted.application import internet
from twisted.web import server


from txnginxjwt import JWTClientIPAuthResource


class Options(usage.Options):
    optParameters = [
        ["port", "p", 8081, "The port number to listen on."],
        ["param", "q", "token", "JWT token query parameter."],
        ["cookie", "c", "txngjwt", "Session cookie name."],
        ["ttl", "t", 43200, "Session cookie ttl in seconds."],
        ["header", "h", "X-Real-IP", ("Header where nginx supplies the client "
                                      "ip address.")],
        ["keyfile", "k", "jwt.pub.pem", "The JWT public key in PEM format."],
    ]


def makeService(options):
    """
    Construct a TCPServer from JWT client IP authentication resource.
    """
    resource = JWTClientIPAuthResource(options["param"].encode(),
                                       options["cookie"].encode(),
                                       options["header"],
                                       options["keyfile"],
                                       int(options["ttl"]))
    factory = server.Site(resource)
    return internet.TCPServer(int(options["port"]), factory)
