JWT authentication for NGINX
============================

A Twisted application plugin capable of validating JWT tokens passed in via a
HTTP query parameter (`token` by default).

If token validation succeeds a session cookie is set in the browser and
subsequent requests with that cookie are accepted as well. Session cookie
parameters can be passed in an optional `session` claim, an object with the
following keys (all optional):

    "session" = {
        "expires": "Wed, 21 Oct 2015 07:28:00 GMT",
        "maxAge": 2592000,
        "domain": "foo.example.com",
        "path": "/site",
        "secure": 1,
        "httpOnly": 1,
        "sameSite": "strict"
    }

The `exp` and `nbf` claims are checked if they are set on the token but not
enforced if not set.

Usage
-----

```
Usage: twistd [options] nginxjwt [options]
Options:
  -c, --cookie=   Session cookie name. [default: txngjwt]
  -h, --header=   Header where nginx supplies the original url. [default:
                  X-Original-URI]
      --help      Display this help and exit.
  -k, --keyfile=  The JWT public key in PEM format. [default: jwt.pub.pem]
  -p, --port=     The port number to listen on. [default: 8081]
  -q, --param=    JWT token query parameter. [default: token]
  -t, --ttl=      Session cookie ttl in seconds. [default: 43200]
      --version   Display Twisted version and exit.
```


Nginx Configuration
-------------------

    location @jwt-auth {
        internal;

        proxy_pass http://twisted-nginx-jwt-upstream;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;

        include /etc/nginx/proxy_params;
    }

    location /protected-resource {
        auth_request @jwt-auth;
        auth_request_set $saved_set_cookie $upstream_http_set_cookie;
        add_header Set-Cookie $saved_set_cookie;
    }

More details in [Nginx Docs](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/).


Similar Projects
----------------

* [pusher/oauth2_proxy](https://pusher.github.io/oauth2_proxy/)
  A reverse proxy that provides authentication with Google, Github or other
  providers.
* [vouch/vouch-proxy](https://github.com/vouch/vouch-proxy/)
  An SSO solution for Nginx using the `auth_request` module.
* [auth0/nginx-jwt](https://github.com/auth0/nginx-jwt)
  (Archived) Lua script for Nginx that performs reverse proxy auth using JWT's
* [Nginx Plus](https://www.nginx.com/blog/authenticating-api-clients-jwt-nginx-plus/)
  (Proprietary)


License
-------

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
