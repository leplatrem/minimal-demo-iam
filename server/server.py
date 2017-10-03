#
# https://auth0.com/docs/quickstart/backend/python#add-api-authorization
# https://github.com/auth0-samples/auth0-python-api-samples/tree/master/00-Starter-Seed

import functools
import json
import re
import os
from urllib.request import urlopen, Request

from flask import Flask, request, jsonify, _app_ctx_stack
from flask_cors import cross_origin


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


def authorized(resource, action):
    def wrapped(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            body = json.dumps({
                "resource": resource,
                "action": action,
            })
            headers = {
                "Authorization": request.headers.get("Authorization", None),
                "Auth0-Audience": API_AUDIENCE,
                "Auth0-Domain": AUTH0_DOMAIN,
            }
            r = Request(IAM_SERVER + "/allowed", data=body, headers=headers)
            resp = urlopen(r)
            payload = json.loads(resp.read().decode("utf-8"))

            if not payload["allowed"]:
                raise AuthError({
                    "code": "not_allowed",
                    "description": "This JWT Access Token is not authorized."
                }, 403)

            _app_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)

        return wrapper
    return wrapped


@APP.route("/")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@authorized(resource="demo:hello", action="read")
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
