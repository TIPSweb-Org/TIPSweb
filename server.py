
import base64
import json
import os
from os import environ as env
from typing import Annotated, Tuple, Union
from urllib.parse import quote_plus, urlencode
from urllib.request import urlopen

from authlib.integrations.flask_client import OAuth
import flask
import requests
from requests_oauthlib import OAuth2Session
from dotenv import find_dotenv, load_dotenv
from flask import Flask, jsonify, logging, redirect, render_template, session, url_for
from functools import wraps
from flask_cors import cross_origin, CORS
from six.moves import http_client
import logging

import requests
from flask import request

from jose import ExpiredSignatureError, JWSError, JWTError, jws, jwt
from jose.exceptions import JWTClaimsError
import werkzeug

import sys

# from werkzeug.middleware.proxy_fix import ProxyFix


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    stream=sys.stdout,
    force=True
)

## protecting information from .env file
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


auth0_jwks_endpoint = env.get("JWKS_ENDPOINT")
auth0_jwks = requests.get(auth0_jwks_endpoint).json()["keys"]

# Google JWKS endpoint
google_jwks_endpoint = "https://www.googleapis.com/oauth2/v3/certs"
google_jwks = requests.get(google_jwks_endpoint).json()["keys"]


# def find_public_key(kid):
#     for key in jwks:
#         if key.get("kid") == kid:
#             print(f"Found public key for kid: {kid}")
#             return key
#     print(f"No public key found for kid: {kid}")
#     return None

def find_public_key(kid, provider="auth0"):
    keys = auth0_jwks if provider == "auth0" else google_jwks
    for key in keys:
        if key.get("kid") == kid:
            return key
    return None

def validate_token(token):
    try:
        header = jws.get_unverified_header(token)
        kid = header.get("kid")
        public_key = find_public_key(kid)
        token_payload = jwt.decode(
            token=token,
            key=public_key,
            audience=env.get("AUTH0_AUDIENCE"),
            issuer=f'https://{env.get("AUTH0_DOMAIN")}/',
            algorithms="RS256",
        )
        return token_payload
    except (ExpiredSignatureError, JWTError, JWSError, JWTClaimsError) as error:
        return None
    
         
def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = session.get("user")
        if not user or "token" not in user:
            return redirect(url_for("login"))
            
        token_payload = validate_token(user["token"]["access_token"])
        if token_payload and "admin" in token_payload.get("permissions", []):
            return f(*args, **kwargs)
        return redirect(url_for("index"))
    return decorated


 ## LE APPLICACIÓN ##
app = Flask(__name__, template_folder='Frontend')

CORS(app, resources={r"/*": {"origins": ["https://tipsweb.me","https://tips-173404681190.us-central1.run.app", "http://localhost:3000", "https://tips-lrebn2rkuq-uc.a.run.app"]}}, supports_credentials=True, allow_headers=["Authorization", "Content-Type"])

app.secret_key = env.get("APP_SECRET_KEY")
#app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_SAMESITE="None", ## relaxxxxx cookies, chilll
    SESSION_COOKIE_SECURE=True,  # Ensure cookies are only sent over HTTPS
    # SESSION_COOKIE_DOMAIN="tips-173404681190.us-central1.run.app"

)

oauth = OAuth(app)

#oauth registration
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "offline_access openid profile email",
        "audience": env.get("AUTH0_AUDIENCE"),
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
    token_endpoint=f'https://{env.get("AUTH0_DOMAIN")}/oauth/token'
)


# Controllers API
@app.route("/")
def index():
    return render_template(
        "index.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    logging.info("Starting callback process")
    logging.info(f"Request args: {request.args}")
    logging.info(f"Callback URL: {url_for('callback', _external=True)}")
    logging.info(f"Session state: {request.args.get('state')}")

    try:
        # # Exchange authorization code for access token
        # payload = {
        #     "grant_type": "authorization_code",
        #     "code": request.args.get("code"),
        #     "redirect_uri": url_for("callback", _external=True),
        #     "client_id": env.get("AUTH0_CLIENT_ID"),
        #     "client_secret": env.get("AUTH0_CLIENT_SECRET")
        # }
        
        # token_response = requests.post(
        #     f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
        #     headers={"Content-Type": "application/x-www-form-urlencoded"},
        #     data=payload
        # )
        
        # token_response.raise_for_status()  # Raise an exception for bad status codes
        
        # token = token_response.json()
        
        # # Validate access token
        # token_payload = validate_token(token["access_token"])
        # logging.info(f"Decoded token payload: {json.dumps(token_payload, indent=2)}")
        token = oauth.auth0.authorize_access_token()
        logging.info(f"Auth0 API Response: {token['access_token']}")

        token_payload = validate_token(token['access_token'])
        logging.info(f"Decoded token payload: {json.dumps(token_payload, indent=2)}")
    
        session["user"] = {
            "token": token,
            "permissions": token_payload.get("permissions", []) if token_payload else []
        }

        return redirect("/")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error: {http_err}")
        return str(http_err), 401
    except Exception as e:
        logging.error(f"Token exchange failed: {str(e)}")
        logging.error(f"Full error details: {repr(e)}")
        return str(e), 401
    

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True),
        audience=env.get("AUTH0_AUDIENCE"),
        response_type="code",
        scope="offline_access openid profile email"
    )

    

    # auth0_url = f"https://{env.get('AUTH0_DOMAIN')}/authorize"
    # params = {
    #     "response_type": "code",
    #     "client_id": env.get("AUTH0_CLIENT_ID"),
    #     "redirect_uri": url_for("callback", _external=True),
    #     "scope": "openid profile email"
    # }
    
    # return redirect(auth0_url + "?" + urlencode(params))



@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


@app.route('/admin')
@requires_admin
def admin_dashboard():
    #print("Current session user:", json.dumps(session.get("user"), indent=2))

    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "read:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()
    
    if 'error' in token:
        return render_template('admin-dash.html', error=token['error_description'])
        
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    users_response = requests.get(
        f'https://{env.get("AUTH0_DOMAIN")}/api/v2/users',
        headers=headers
    ).json()

    #users = users_response.json()
    
    return render_template('admin-dash.html', users=users_response)


@app.route('/admin/delete-user/<user_id>', methods=['DELETE'])
@requires_admin
def delete_user(user_id):
    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "delete:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()
    
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    delete_response = requests.delete(
        f'https://{env.get("AUTH0_DOMAIN")}/api/v2/users/{user_id}',
        headers=headers
    )
    
    return jsonify({"status": "success" if delete_response.ok else "error"})


@app.route('/admin/create-user', methods=['POST'])
@requires_admin
def create_user():
    data = request.get_json()
    
    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "create:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()

    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    user_data = {
        "email": data['email'],
        "password": data['password'],
        "connection": "Username-Password-Authentication"
    }
    
    create_response = requests.post(
        f'https://{env.get("AUTH0_DOMAIN")}/api/v2/users',
        headers=headers,
        json=user_data
    )
    
    response_data = create_response.json()
    
    if create_response.ok:
        return jsonify({"status": "success"})
    else:
        return jsonify({
            "status": "error",
            "message": response_data.get('message', 'Unknown error occurred')
        }), 400

 
@app.route("/auth/info", methods=["GET"])
def auth_info():
    auth_header = request.headers.get("Authorization", None)
    if not auth_header:
        return jsonify({"error": "Authorization header is missing"}), 401

    parts = auth_header.split()
    if parts[0].lower() != "bearer" or len(parts) != 2:
        return jsonify({"error": "Invalid Authorization header"}), 401

    token = parts[1]
    try:
        token_payload = validate_token(token)
        return jsonify(token_payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 400



# # Google Cloud Endpoints Authentication Information Retrieval
# def _base64_decode(encoded_str):
#     if encoded_str[0] == "b":
#         encoded_str = encoded_str[1:]
#     num_missed_paddings = 4 - len(encoded_str) % 4
#     if num_missed_paddings != 4:
#         encoded_str += "=" * num_missed_paddings
#     return base64.b64decode(encoded_str).decode("utf-8")

# def auth_info():
#     encoded_info = request.headers.get("X-Endpoint-API-UserInfo", None)
#     if encoded_info:
#         info_json = _base64_decode(encoded_info)
#         user_info = json.loads(info_json)
#     else:
#         user_info = {"id": "anonymous"}
#     return jsonify(user_info)

# @app.route("/auth/info/googlejwt", methods=["GET"])
# def auth_info_google_jwt():
#     return auth_info()

# @app.route("/auth/info/googleidtoken", methods=["GET"])
# def auth_info_google_id_token():
#     return auth_info()

# @app.route("/auth/info/firebase", methods=["GET"])
# @cross_origin(send_wildcard=True)
# def auth_info_firebase():
#     return auth_info()

# @app.errorhandler(http_client.INTERNAL_SERVER_ERROR)
# def unexpected_error(e):
#     logging.getLogger().error("An error occurred while processing the request.", exc_info=True)
#     response = jsonify(
#         {"code": http_client.INTERNAL_SERVER_ERROR, "message": f"Exception: {e}"}
#     )
#     response.status_code = http_client.INTERNAL_SERVER_ERROR
#     return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
    #app.run(host="0.0.0.0", port=3000)

