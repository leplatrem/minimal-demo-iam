import functools
import json
import re
import os
from urllib.request import urlopen

from flask import Flask, request, jsonify, _app_ctx_stack
from flask_cors import cross_origin
from jose import jwt


AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_AUDIENCE = os.getenv("API_ID")
ALGORITHMS = ["RS256"]
APP = Flask(__name__)


# Format error response and append status code.
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def get_token_auth_header():
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if auth is None:
        raise AuthError({
            "code": "authorization_header_missing",
            "description": "Authorization header is expected"
        }, 401)

    s = re.match(r"^Bearer ([^\s]+)$", auth, re.I)
    if s is None:
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization header must be 'Bearer <token>'"
        }, 401)

    token = s.group(1)
    return token


def requires_auth(f):
    """Determines if the access token is valid
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError as e:
            raise AuthError({
                "code": "invalid_header",
                "description": "Invalid header. " + str(e)
            }, 401)
        if unverified_header["alg"] != "RS256":
            raise AuthError({
                "code": "invalid_header",
                "description": "Invalid header. Use an RS256 signed JWT Access Token"
            }, 401)

        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read().decode("utf-8"))
        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key is None:
            raise AuthError({
                "code": "invalid_header",
                "description": "Unable to find appropriate key"
            }, 400)
        try:
            payload = jwt.decode(token,
                                 rsa_key,
                                 algorithms=ALGORITHMS,
                                 audience=API_AUDIENCE,
                                 issuer="https://" + AUTH0_DOMAIN + "/")
        except jwt.ExpiredSignatureError:
            raise AuthError({
                "code": "token_expired",
                "description": "Token is expired"
            }, 401)
        except jwt.JWTClaimsError:
            raise AuthError({
                "code": "invalid_claims",
                "description": "Incorrect claims, please check the audience and issuer"
            }, 401)
        except Exception:
            raise AuthError({
                "code": "invalid_header",
                "description": "Unable to parse authentication token."
            }, 400)

        _app_ctx_stack.top.current_user = payload
        return f(*args, **kwargs)

    return decorated


@APP.route("/")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@requires_auth
def hello():
    """A valid access token is required to access this route
    """
    top = _app_ctx_stack.top
    return jsonify({
        "success": True,
        "user": top.current_user
    })


if __name__ == "__main__":
    print("AUTH0_DOMAIN", AUTH0_DOMAIN)
    print("API_ID", API_AUDIENCE)
    APP.run(host="0.0.0.0", port=os.getenv("PORT", 8000))
