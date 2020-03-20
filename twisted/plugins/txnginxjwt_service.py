from twisted.application.service import ServiceMaker

TxNginxJWTService = ServiceMaker(
    "NginxJWT Service",
    "txnginxjwt.service",
    "Nginx auth_request backend for JWT passed in via HTTP user field",
    "nginxjwt")
