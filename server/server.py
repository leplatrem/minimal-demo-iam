#
# https://auth0.com/docs/quickstart/backend/python#add-api-authorization
# https://github.com/auth0-samples/auth0-python-api-samples/tree/master/00-Starter-Seed

import functools
import json
import re
import os
import urllib

from flask import Flask, request, jsonify, _app_ctx_stack
from flask_cors import cross_origin


IAM_SERVER = os.getenv("IAM_SERVER")
API_AUDIENCE = os.getenv("API_AUDIENCE")

app = Flask(__name__)


# Format error response and append status code.
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def authorized(resource, action):
    def wrapped(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            iam_url = IAM_SERVER + "/allowed"
            body = json.dumps({
                "resource": resource,
                "action": action,
            }).encode("utf-8")
            headers = {
                "Authorization": request.headers.get("Authorization", None),
                "Auth0-Audience": API_AUDIENCE,
            }
            r = urllib.request.Request(iam_url, data=body, headers=headers)
            try:
                resp = urllib.request.urlopen(r)
            except urllib.error.HTTPError as e:
                raise AuthError(e.read().decode("utf-8"), e.code)

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


@app.route("/")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@authorized(resource="demo:hello", action="read")
def hello():
    """A valid access token is required to access this route
    """
    top = _app_ctx_stack.top
    return jsonify(top.current_user)


if __name__ == "__main__":
    print("API_AUDIENCE", API_AUDIENCE)
    app.run(host="0.0.0.0", port=os.getenv("PORT", 8000))
