JWT authentication for NGINX
============================

A Twisted application plugin capable of validating JWT tokens passed in via a
HTTP query parameter (`token` by default). Also extracts `clientip` field from
JWT claims and compares it to the value in a configurable request header
(`X-Real-IP` by default).

Usage
-----

```
Usage: twistd [options] nginxjwt [options]
Options:
  -c, --cookie=   Session cookie name. [default: txngjwt]
  -h, --header=   Header where nginx supplies the client ip address. [default:
                  X-Real-IP]
      --help      Display this help and exit.
  -k, --keyfile=  The JWT public key in PEM format. [default: jwt.pub.pem]
  -p, --port=     The port number to listen on. [default: 8081]
  -q, --param=    JWT token query parameter. [default: token]
  -t, --ttl=      Session cookie ttl in seconds. [default: 43200]
      --version   Display Twisted version and exit.
```

License
-------

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
