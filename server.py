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
from flask import Flask, jsonify, logging, redirect, render_template, session, url_for, request
from functools import wraps
from flask_cors import cross_origin, CORS
import logging
import sys

from jose import ExpiredSignatureError, JWSError, JWTError, jws, jwt
from jose.exceptions import JWTClaimsError
import werkzeug

# from werkzeug.middleware.proxy_fix import ProxyFix
###TODO: change aut0 from single page app to regular web app
##TODO: back button for admin dashboard

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    stream=sys.stdout,
    force=True
)

## Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# Log environment load confirmation (be cautious not to log secrets)
logging.info("Environment variables loaded.")

jwks_endpoint = env.get("JWKS_ENDPOINT")
jwks = requests.get(jwks_endpoint).json()["keys"]
logging.info("Retrieved Auth0 JWKS.")


def find_public_key(kid, provider="auth0"):
    keys = jwks 
    for key in keys:
        if key.get("kid") == kid:
            logging.info(f"Found public key for kid: {kid} from {provider}")
            return key
    logging.error(f"No public key found for kid: {kid} from {provider}")
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
        logging.info("Token validated successfully.")
        return token_payload
    except ( JWTError, JWSError) as error:
        logging.error(f"Token validation error: {error}")
        return None

def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = session.get("user")
        if not user or "token" not in user:
            logging.warning("Unauthorized access attempt to admin area - user not logged in.")
            return redirect(url_for("login"))
            
        token_payload = validate_token(user["token"]["access_token"])
        if token_payload and "admin" in token_payload.get("permissions", []):
            return f(*args, **kwargs)
        logging.warning("Unauthorized access attempt to admin area - insufficient permissions.")
        return redirect(url_for("index"))
    return decorated

## Initialize Flask App
app = Flask(__name__, template_folder='Frontend')
CORS(app, resources={r"/*": {"origins": [f"https://{env.get('AUTH0_DOMAIN')}", "https://dev-ham70vsz2hjzbwgm.us.auth0.com","https://tipsweb.me","https://tips-173404681190.us-central1.run.app", "https://tipsweb-173404681190.us-central1.run.app", "http://localhost:3000", "https://tips-lrebn2rkuq-uc.a.run.app", "https://tipsweb-lrebn2rkuq-uc.a.run.app"]}},
     supports_credentials=True, allow_headers=["Authorization", "Content-Type"])

app.secret_key = env.get("APP_SECRET_KEY")
is_local = env.get('FLASK_ENV') == 'development'
# Uncomment and configure ProxyFix if needed
# app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

## CONFIGURING SESSION COOKIE SAMESITE CAUSES MISMATCH STATE ERROR IN LOCAL HOST DEPLOYMENT 
# app.config.update(
#     SESSION_COOKIE_SAMESITE="None",
#     SESSION_COOKIE_SECURE=True,
#     SESSION_COOKIE_HTTPONLY=True
# )

app.config['PREFERRED_URL_SCHEME'] = 'https'
oauth = OAuth(app)

# OAuth registration
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "offline_access openid profile email",
        "audience": env.get("AUTH0_AUDIENCE"),
        # "__tenant": env.get("AUTH0_DOMAIN"),
        # "__token_issuer": f"https://{env.get("AUTH0_ISSUER")}"
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
    token_endpoint=f'https://{env.get("AUTH0_DOMAIN")}/oauth/token'
)

# Routes
@app.route("/")
def index():
    logging.info("Rendering index page.")
    return render_template(
        "index.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )

@app.route("/login")
def login():
    ##for gke app if user not logged in
    return_to = request.args.get('return_to')
    if return_to:
        session['return_to'] = return_to

    auth_redirect = oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True, _scheme='http' if is_local else 'https'),
        audience=env.get("AUTH0_AUDIENCE"),
        response_type="code",
        scope="offline_access openid profile email"
    )
    return auth_redirect 

@app.route("/callback", methods=["GET", "POST"])
def callback():
    try:
        token = oauth.auth0.authorize_access_token()

        token_payload = validate_token(token['access_token'])

        session["user"] = {
            "token": token,
            "permissions": token_payload.get("permissions", [])
        }

        return_to = session.pop('return_to', None)
    
        # If return_to exists, redirect there; otherwise go to home page
        if return_to:
            return redirect(return_to)
        else:
            return redirect('/')
        #return redirect("/")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error during token exchange: {http_err}")
        return str(http_err), 401
    except Exception as e:
        logging.error(f"Token exchange failed: {str(e)}")
        logging.error(f"Full error details: {repr(e)}")
        return str(e), 401

@app.route("/logout")
def logout():
    logging.info("User logging out, clearing session.")
    session.clear()
    logout_url = (
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
    logging.info(f"Redirecting to logout URL: {logout_url}")
    return redirect(logout_url)

@app.route('/gke-app')
def gke_app():
    # This is a placeholder route that will eventually redirect to the GKE deployment
    # For now, it shows a message indicating the GKE deployment is coming soon
    if not session.get('user'):
        # Redirect to login page with a return_to parameter
        return redirect(url_for('login', return_to='/gke-app'))
      
    gke_url = "https://media.istockphoto.com/id/1418210562/photo/brazil-wildlife-capybara-hydrochoerus-hydrochaeris-biggest-mouse-near-the-water-with-evening.jpg?s=1024x1024&w=is&k=20&c=AzD8FahPVht7LfDs1WT5snMDHHi1pMvH7lnsgmzgfpA="
    return render_template('gke-app.html', gke_url=gke_url)


@app.route('/admin')
@requires_admin
def admin_dashboard():
    logging.info("Accessing admin dashboard.")
    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('M2M_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "read:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('M2M_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()
    
    if 'error' in token:
        logging.error(f"Error obtaining M2M token: {token.get('error_description')}")
        return render_template('admin-dash.html', error=token['error_description'])
        
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    users_response = requests.get(
        f'https://{env.get("M2M_DOMAIN")}/api/v2/users',
        headers=headers
    ).json()
    
    logging.info("Fetched admin users successfully.")
    return render_template('admin-dash.html', users=users_response)

@app.route('/admin/delete-user/<user_id>', methods=['DELETE'])
@requires_admin
def delete_user(user_id):
    ##added to protect against vulneribility
    import re
    if not re.match(r'^[a-zA-Z0-9_-]+$', user_id):
        return jsonify({"status": "error", "message": "Invalid user ID format"}), 400
    ##

    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('M2M_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "delete:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('M2M_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()
    
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    # delete_response = requests.delete(
    #     f'https://{env.get("M2M_DOMAIN")}/api/v2/users/{user_id}',
    #     headers=headers
    # )

    ##Avoiding URL construction from user data
    base_url = f'https://{env.get("M2M_DOMAIN")}/api/v2/users/'
    delete_response = requests.delete(
        base_url + user_id,
        headers=headers
    )
    ##

    return jsonify({"status": "success" if delete_response.ok else "error"})


@app.route('/admin/create-user', methods=['POST'])
@requires_admin
def create_user():
    data = request.get_json()
    
    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('M2M_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "create:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('M2M_DOMAIN')}/oauth/token",
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
        f'https://{env.get("M2M_DOMAIN")}/api/v2/users',
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



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    logging.info(f"Starting Flask app on port {port}")
    app.run(debug=True, host="0.0.0.0", port=port)