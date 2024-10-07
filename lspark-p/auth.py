import jwt
import requests
from flask import json, request, jsonify
from functools import wraps
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidTokenError

AUTH0_DOMAIN = "dev-w4mhfi5sg7rm3bcl.us.auth0.com"
API_IDENTIFIER = "http://localhost:3033"
ALGORITHMS = ["RS256"]

def get_rsa_key(jwks, kid):
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == kid:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
            break
    if rsa_key:
        return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(rsa_key))
    return None

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header:
            return jsonify({"message": "Authorization header is expected"}), 401

        parts = auth_header.split()

        if parts[0].lower() != "bearer":
            return jsonify({"message": "Authorization header must start with Bearer"}), 401
        elif len(parts) == 1:
            return jsonify({"message": "Token not found"}), 401
        elif len(parts) > 2:
            return jsonify({"message": "Authorization header must be Bearer token"}), 401

        token = parts[1]
        jsonurl = requests.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
        jwks = jsonurl.json()
        unverified_header = jwt.get_unverified_header(token)

        rsa_key = get_rsa_key(jwks, unverified_header["kid"])
        
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_IDENTIFIER,
                    issuer=f"https://{AUTH0_DOMAIN}/"
                )
            except ExpiredSignatureError:
                return jsonify({"message": "Token is expired"}), 401
            except InvalidAudienceError:
                return jsonify({"message": "Incorrect claims, please check the audience and issuer"}), 401
            except InvalidTokenError:
                return jsonify({"message": "Unable to parse authentication token"}), 401

            request.user = payload
            return f(*args, **kwargs)

        return jsonify({"message": "Unable to find appropriate key"}), 401

    return decorated
