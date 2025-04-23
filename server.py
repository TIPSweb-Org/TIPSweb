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
from flask import Flask, jsonify, logging, redirect, render_template, session, url_for, request, make_response
from functools import wraps
from flask_cors import cross_origin, CORS
import logging
import sys

from jose import ExpiredSignatureError, JWSError, JWTError, jws, jwt
from jose.exceptions import JWTClaimsError


##       global vars       ##

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

jwks_endpoint = env.get("JWKS_ENDPOINT")
jwks = requests.get(jwks_endpoint).json()["keys"]

BACKEND_URL = f"http://{env.get('BACKEND_HOST')}:{env.get('BACKEND_PORT')}"

# maintainable string URL vars
JSON_CONTENT_TYPE = "application/json"
ERROR_NOT_AUTHENTICATED = "Not authenticated"

##                        ##


##     helper functions   ##

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

def get_current_user_id():
    """Helper function to extract user ID from the current session"""
    user = session.get("user")
    if not user:
        logging.warning("get_current_user_id: No user in session")
        return None
    
    if "token" not in user:
        logging.warning("get_current_user_id: No token in user session")
        return None
    
    logging.info("get_current_user_id: Attempting to validate token")
    token_payload = validate_token(user["token"]["access_token"])
    
    if not token_payload:
        logging.warning("get_current_user_id: Token validation failed")
        return None
    
    user_id = token_payload.get("sub")
    logging.info(f"get_current_user_id: Successfully extracted user_id: {user_id}")
    return user_id

def get_user_email_from_auth0(user_id):
    """Retrieve the user's email from Auth0 using the Management API."""
    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('M2M_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials"
    }

    # Get the M2M token
    token_response = requests.post(
        f"https://{env.get('M2M_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()
    if "access_token" not in token:
        logging.error(f"Error obtaining M2M token: {token.get('error_description')}")
        return None

    # Query the Auth0 Management API for the user's email
    headers = {"Authorization": f"Bearer {token['access_token']}"}
    user_response = requests.get(
        f'https://{env.get("M2M_DOMAIN")}/api/v2/users/{user_id}',
        headers=headers
    )
    user_data = user_response.json()
    if "email" not in user_data:
        logging.error(f"Failed to retrieve email for user_id {user_id}: {user_data}")
        return None

    return user_data["email"]

##                                  ##

##      Initialize Flask App        ##

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

##                     ##

##       Routes        ##
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
    ##for launch  app if user not logged in
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

##TODO: disregard all error checks/ reduce steps for ending session. 
@app.route("/logout")
def logout():
    """Log out the user, delete the simulation session, and redirect to the logout URL."""
    logging.info("User logging out, attempting to delete simulation session.")

    # Attempt to delete the simulation session
    user_id = get_current_user_id()
    if user_id:
        try:
            email = get_user_email_from_auth0(user_id)
            if email:
                backend_url = f"{BACKEND_URL}/delete_session"
                response = requests.delete(
                    backend_url,
                    json={"user": email},  # Send email in the request body
                    headers={"Content-Type": JSON_CONTENT_TYPE}
                )
                if response.status_code == 200:
                    logging.info("logout: Simulation session deleted successfully.")
                else:
                    logging.warning(f"logout: Failed to delete simulation session: {response.text}")
            else:
                logging.warning("logout: Failed to retrieve email for session deletion.")
        except requests.RequestException as e:
            logging.error(f"logout: Error deleting simulation session: {str(e)}")
    else:
        logging.warning("logout: No authenticated user found, skipping session deletion.")
    
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

##session management 

##Testing user id extraction for comm with session management
##TODO: comment/uncomment

# @app.route("/test/user-id")
# def test_user_id():
#     logging.info("test_user_id endpoint called")
#     user_id = get_current_user_id()
#     if user_id:
#         logging.info(f"test_user_id: Found user_id: {user_id}")
#         return jsonify({"user_id": user_id})
#     else:
#         logging.warning("test_user_id: No user_id found")
#         return jsonify({"error": "No user ID found"}), 401
    
##store user session data
##user id,  Docker id, Port and co-port
##start session starts session based on user id spits out docker image
#launch tips 

##TODO: clean up this function, reduce lines used for user_email json extraction

@app.route("/api/start-simulation-session", methods=["POST"])
def start_simulation_session():
    """Start simulation session by sending user ID to the backend"""
    # get id, use the helper function
    user_id = get_current_user_id()
    if not user_id:
        logging.warning("start_simulation_session: No authenticated user found")
        return jsonify({"error": ERROR_NOT_AUTHENTICATED}), 401
    
    # Prepare user info with just the user_id
    ##can add more info from user if needed 
    user = session.get("user")
    token_payload = validate_token(user["token"]["access_token"])

    email = token_payload.get("email")

    if not email: ##TODO: check if this is being entered (probably)
        logging.info("Email not found in token payload, fetching from Auth0")
        email = get_user_email_from_auth0(user_id)
        if not email:
            return jsonify({"error": "Failed to retrieve email"}), 400

    user_info = {
        "user": email
    }
        
    print(f"Payload being sent to backend: {user_info}")
    
    backend_url = f"{BACKEND_URL}/start_session"
    logging.info(f"start_simulation_session: Sending user_id to {backend_url}") 
    
    try:
        response = requests.post(
            backend_url,
            json=user_info,
            headers={"Content-Type": JSON_CONTENT_TYPE}
        )
        
        if response.status_code == 200:
            session_data = response.json()
            # Store the session info in our session for later use
            session["simulation_session"] = session_data
            logging.info(f"start_simulation_session: Successfully started session: {session_data}")
            return jsonify(session_data)
        else:
            error_msg = f"Backend service returned {response.status_code}: {response.text}"
            logging.error(f"start_simulation_session: {error_msg}")
            return jsonify({"error": error_msg}), response.status_code
    
    except requests.RequestException as e:
        error_msg = f"Failed to connect to backend service: {str(e)}"
        logging.error(f"start_simulation_session: {error_msg}")
        return jsonify({"error": error_msg}), 503


@app.route("/get_session", methods=["GET"])
def get_session():
    """Retrieve the simulation session for the current user"""
    user_id = get_current_user_id()
    if not user_id:
        logging.warning("get_session: No authenticated user found")
        return jsonify({"error": ERROR_NOT_AUTHENTICATED}), 401

    # Send request to the backend
    backend_url = f"{BACKEND_URL}/get_session"
    try:
        response = requests.get(
            backend_url,
            ##params not accepted in backend, if json body param doesnt work need to change backend
            #params={"user": get_user_email_from_auth0(user_id)},  # Send eamil as a query parameter
            json={"user": get_user_email_from_auth0(user_id)},  # Send user_id in the request body
            headers={"Content-Type": JSON_CONTENT_TYPE}
        )
        if response.status_code == 200:
            session_data = response.json()
            logging.info(f"get_session: Retrieved session: {session_data}")
            return jsonify(session_data)
        else:
            error_msg = f"Backend service returned {response.status_code}: {response.text}"
            logging.error(f"get_session: {error_msg}")
            return jsonify({"error": error_msg}), response.status_code
    except requests.RequestException as e:
        error_msg = f"Failed to connect to backend service: {str(e)}"
        logging.error(f"get_session: {error_msg}")
        return jsonify({"error": error_msg}), 503


@app.route("/delete_session", methods=["POST"])
def delete_session():
    """Delete the simulation session for the current user"""
    user_id = get_current_user_id()
    if not user_id:
        logging.warning("delete_session: No authenticated user found")
        return jsonify({"error": ERROR_NOT_AUTHENTICATED}), 401

    # Send request to the backend
    backend_url = f"{BACKEND_URL}/delete_session"
    try:
        response = requests.delete(
            backend_url,
            json={"user": get_user_email_from_auth0(user_id)},  # Send user_id in the request body
            headers={"Content-Type": JSON_CONTENT_TYPE}
        )
        if response.status_code == 200:
            if "simulation_session" in session:
                session.pop("simulation_session")
                logging.info("delete_session: Removed simulation_session from Flask session")

            logging.info("delete_session: Session deleted successfully")
            return jsonify({"status": "success"})
        else:
            error_msg = f"Backend service returned {response.status_code}: {response.text}"
            logging.error(f"delete_session: {error_msg}")
            return jsonify({"error": error_msg}), response.status_code
    except requests.RequestException as e:
        error_msg = f"Failed to connect to backend service: {str(e)}"
        logging.error(f"delete_session: {error_msg}")
        return jsonify({"error": error_msg}), 503
    
## app routing to simulation upon user input
@app.route('/launch-app')
def launch_app():
    if not session.get('user'):
        # Redirect to login page with a return_to parameter
        return redirect(url_for('login', return_to='/launch-app'))

    return render_template('launch-app.html')


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
    if not re.match(r'^[a-zA-Z0-9|_-]+$', user_id):

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
    app.run(host="0.0.0.0", port=port)