"""The authentication state."""
import os
from dotenv import load_dotenv
import yaml
import reflex as rx
from typing import Optional
import logging
import time
import secrets
import urllib.parse
import requests
import jwt
from backend.user import User


# Read environment variables.
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/tmp/logs.log", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

config_oauth2_providers = {
    # PeeringDB OAuth 2.0 documentation:
    # https://docs.peeringdb.com/oauth/
    'peeringdb': {
        'client_id': os.getenv('OAUTH2_PEERINGDB_CLIENT_ID'),
        'client_secret': os.getenv('OAUTH2_PEERINGDB_CLIENT_SECRET'),
        'authorize_url': 'https://auth.peeringdb.com/oauth2/authorize/',
        'token_url': 'https://auth.peeringdb.com/oauth2/token/',
        'userinfo': {
            'url': 'https://auth.peeringdb.com/profile/v1',
            'email': lambda json: json['email'],
            'first_name': lambda json: json['given_name'],
            'last_name': lambda json: json['family_name'],
            'networks': lambda json: json['networks'],
        },
        'scopes': ['email', 'profile', 'networks'],
    },
}

# For session-based authentification.
secret_key = os.getenv('SESSION_AUTHENTIFICATION_SECRET_KEY')
connections = {}
COOKIE_MAX_AGE = int(os.getenv('COOKIE_MAX_AGE')) # Minutes
new_users_buffer = {}

# Needed to oauth, especially for safari..
oauth2_server_state = {}


class AuthState(rx.State):
    """The authentication state for sign up and login page."""

    is_authenticated: bool = False
    session_token: str = rx.Cookie(name='session_token', max_age=COOKIE_MAX_AGE, path='/', secure=True, same_site='strict')
    session_oauth_state: str = rx.Cookie(name='session_oauth_state', max_age=COOKIE_MAX_AGE, path='/', secure=True, same_site='strict')

    user: Optional[User] = None
    email: Optional[str] = None
    password: Optional[str]
    confirm_password: Optional[str]
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    country: Optional[str] = None
    asns_info: list[list] = []
    asns: list[str] = []

    oauth2_state: Optional[str] = None
    is_loading: bool = False

    # --- dialog state for auth flow ---
    show_auth_dialog: bool = False                   # Controls dialog visibility
    auth_status: str = "idle"                        # "idle" | "loading" | "success" | "error"
    auth_error: str | None = None

    @rx.event
    def obtain_cookie(self):
        # self.email = 'thomasholterbach@gmail.com'
        # self.asns_info = [['2914', 'ntt'], ['4128', 'rgnet1'], ['3927', 'rgnet2']]
        # self.asns = ['2914', '4128', '3927'] 
        # self.asns_info = [['4128', 'rgnet1'], ['3927', 'rgnet2'], ['3130', 'rgnet3']]
        # self.asns = ['4128', '3927', '3130'] 
        self.asns_info = [['2914', 'rgnet1']]
        self.asns = ['263444'] 
        
        self.is_authenticated = True
        return


        """Cookie handler."""
        logging.info("Begin obtain_cookie for user: %s", self.email)
        if self.session_token:
            try:
                content = jwt.decode(self.session_token, secret_key, algorithms=["HS256"])
                logging.info("Decoded JWT for email: %s, session_id: %s", content.get('email'), content.get('session_id'))
                if content and content['email'] in connections:
                    # If the user in the cookie has the session_id (legitimate case).
                    if content['session_id'] in connections[content['email']]:
                        # If the session has not expired.
                        if time.time() - connections[content['email']][content['session_id']] < COOKIE_MAX_AGE:
                            if not self.is_authenticated:
                                self.email = content['email']

                                # Load user details from the database.
                                with rx.session() as session:
                                    self.user = session.exec(User.select().where(User.email == self.email)).first()

                                # Get the AS numbers associtated to the user's email.
                                self.asns_info = content['asns_info']
                                self.asns = content['asns']

                                self.is_authenticated = True
                                logging.info(f'User: {self.email} ASN: {self.asns_info} {self.asns}')

                            # Update the connection time.
                            connections[self.user.email][content['session_id']] = time.time()
                            logging.info("Updated session time for %s, session_id %s", self.user.email, content['session_id'])
                        # If the cookie has timeout, logout.
                        else:
                            logging.info(f'Cookie has timeout for user {self.email}')
                            self.logout()
                    # If the content in the cookie is bogus, logout.
                    else:
                        logging.warning(f'Cookie session_id is bogus for user {self.email}')
                        self.logout()
                # If the content in the cookie is bogus, logout.
                else:
                    logging.warning(f'Cookie could not be decoded or user not in connections: {self.email}')
                    self.logout()
            except jwt.ExpiredSignatureError:
                logging.error('JWT: Expired signature error for user: %s', self.email)
                return None
            except jwt.InvalidTokenError:
                logging.error('JWT: Invalid token error for user: %s', self.email)
                return None
        # If there is no cookie (e.g., after logout).
        elif self.is_authenticated:
            logging.info(f'Logout {self.email} because no cookie')
            self.logout()



    def logout(self):
        """Log out a user."""

        # Remove the cookie information.
        logging.info("Logging out user: %s", self.email)
        if self.is_authenticated and self.email in connections:
            if self.session_token:
                try:
                    content = jwt.decode(self.session_token, secret_key, algorithms=["HS256"])
                    if content['session_id'] in connections[content['email']]:
                        del connections[content['email']][content['session_id']]
                        logging.info("Removed session_id %s for user %s", content['session_id'], content['email'])
                except jwt.ExpiredSignatureError:
                    logging.error('JWT: Expired signature error during logout for user: %s', self.email)
                    return None
                except jwt.InvalidTokenError:
                    logging.error('JWT: Invalid token error during logout for user: %s', self.email)
                    return None

            if len(connections[self.email]) == 0:
                del connections[self.email]
                logging.info("Removed all sessions for user %s", self.email)

        # Remove cookie from the client browser.
        rx.remove_cookie('session_token')
        logging.info("Cookies removed for user %s", self.email)

        # Reset all state variables.
        self.reset()
        self.reset_loading()

        return rx.redirect("/")



    def reset_loading(self):
        self.is_loading = False



    def oauth2_authorize_peeringdb(self):
        provider_data = config_oauth2_providers['peeringdb']
        logging.info("Initiating OAuth2 authorize for PeeringDB")

        # Generate and store server-side state
        state = secrets.token_urlsafe(32)
        self.is_loading = True
        oauth2_server_state[state] = {
            'provider': 'peeringdb',
            'timestamp': time.time(),
        }

        qs = urllib.parse.urlencode({
            'client_id': provider_data['client_id'],
            'redirect_uri': os.getenv('WEBSITE_URL'),
            'scope': ' '.join(provider_data['scopes']),
            'state': state,
            'response_type': 'code',
        })
        url = provider_data['authorize_url'] + '?' + qs
        logging.info("Redirecting to PeeringDB OAuth2 URL: %s", url)
        return rx.redirect(url)



    @rx.event
    async def oauth2_callback(self):
        """Handle OAuth2 redirect after the user authorizes at the provider."""
        logging.info("Starting OAuth2 callback")

        # First check if there is a cookie, in which case the users logged in already in another tab.
        self.obtain_cookie()
        if self.is_authenticated:
            # If this was an OAuth redirect URL, remove the query params.
            # if any(self.router.page.params.get(k) for k in ("state", "code", "error")):
            #     return rx.redirect("/")   # drops ?state&code&error
            return

        # 1) Read URL params FIRST (do nothing if user just landed on the site)
        state = self.router.page.params.get("state")
        code = self.router.page.params.get("code")
        provider_error = self.router.page.params.get("error")  # e.g., access_denied

        if not state and not code and not provider_error:
            logging.info("No OAuth2 params found; skipping callback.")
            return

        # 2) Show dialog as soon as we know this *is* an OAuth callback
        self.open_auth_dialog("loading")
        self.is_loading = True
        logging.info("OAuth2 params detected. state=%s code=%s error=%s",
                    state, "present" if code else None, provider_error)

        # If the provider returned an explicit error (user cancelled, etc.)
        if provider_error:
            self.auth_status = "error"
            self.auth_error = f"Sign-in was cancelled or failed: {provider_error}."
            self.is_loading = False
            return

        # 3) Prune expired server-side states
        try:
            timeout = int(os.getenv('OAUTH2_SERVER_STATE_TIMEOUT', '600'))  # default 10 min
        except Exception:
            timeout = 600
        try:
            expired = [k for k, v in oauth2_server_state.items()
                    if time.time() - v.get('timestamp', 0) > timeout]
            for k in expired:
                oauth2_server_state.pop(k, None)
        except Exception as e:
            logging.error("Error pruning oauth2_server_state: %s", e)

        # 4) Validate required params
        if not state or not code:
            logging.error("OAuth2 callback: Missing state or code.")
            self.auth_status = "error"
            self.auth_error = "Missing OAuth2 state or authorization code. Please try signing in again."
            self.is_loading = False
            return

        # 5) Restore context from server state (single-use)
        ctx = oauth2_server_state.pop(state, None)
        if not ctx:
            logging.error("OAuth2 callback: Unknown or expired state: %s", state)
            self.auth_status = "error"
            self.auth_error = "Your sign-in session expired. Please try again."
            self.is_loading = False
            return

        provider = ctx.get('provider')
        provider_data = config_oauth2_providers.get(provider or "")
        if not provider_data:
            logging.error("OAuth2 callback: Unknown provider in state: %s", provider)
            self.auth_status = "error"
            self.auth_error = "Unknown identity provider."
            self.is_loading = False
            return

        logging.info("OAuth2 provider restored from server state: %s", provider)

        # Let the dialog render the loading content before network calls
        yield

        try:
            # 6) Exchange authorization code for access token
            token_req_data = {
                'client_id': provider_data['client_id'],
                'client_secret': provider_data['client_secret'],
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': os.getenv('WEBSITE_URL'),
            }
            token_headers = {
                'Accept': 'application/json',
                "Content-Type": "application/x-www-form-urlencoded",
            }

            token_resp = requests.post(
                provider_data['token_url'],
                data=token_req_data,
                headers=token_headers,
                timeout=10
            )
            token_resp.raise_for_status()
            if token_resp.status_code != 200:
                logging.error("OAuth2 token exchange failed (%s): %d - %s",
                            provider, token_resp.status_code, token_resp.text)
                self.auth_status = "error"
                self.auth_error = "Token exchange failed."
                return

            token_json = token_resp.json() if token_resp.headers.get('Content-Type', '').startswith('application/json') else {}
            oauth2_token = token_json.get('access_token')
            if not oauth2_token:
                logging.error("OAuth2 token exchange returned no access_token for provider: %s (payload=%s)",
                            provider, token_json)
                self.auth_status = "error"
                self.auth_error = "No access token received."
                return

            # 7) Fetch userinfo
            headers = {'Authorization': f'Bearer {oauth2_token}', 'Accept': 'application/json'}

            ui_resp = requests.get(provider_data['userinfo']['url'], headers=headers, timeout=10)
            ui_resp.raise_for_status()
            if ui_resp.status_code != 200:
                logging.error("Failed to retrieve userinfo (%s): %d - %s",
                            provider, ui_resp.status_code, ui_resp.text)
                self.auth_status = "error"
                self.auth_error = "Failed to retrieve your profile."
                return

            userinfo = ui_resp.json()

            # 8) Extract identity
            self.email = provider_data['userinfo']['email'](userinfo)
            first_name = provider_data['userinfo']['first_name'](userinfo)
            last_name  = provider_data['userinfo']['last_name'](userinfo)
            try:
                networks = provider_data['userinfo']['networks'](userinfo)
            except Exception:
                networks = []

            logging.info("Authenticated user email from OAuth (%s): %s", provider, self.email)

            # 9) Sign in / sign up
            with rx.session() as session:
                user = session.exec(User.select().where(User.email == self.email)).first()
                if user:
                    self.user = user
                    self.is_authenticated = True
                    logging.info("User found in database: %s", self.email)
                else:
                    self.user = User(
                        email=self.email,
                        password=None,
                        first_name=first_name,
                        last_name=last_name,
                    )
                    session.add(self.user)
                    session.expire_on_commit = False
                    session.commit()
                    self.is_authenticated = True
                    logging.info("Created new user in database: %s", self.email)

                # PeeringDB networks → ASNs
                for n in networks or []:
                    try:
                        self.asns_info.append((str(n['asn']), n['name']))
                        self.asns.append(str(n['asn']))
                    except Exception:
                        pass

                # 10) Create/refresh server-side session and set JWT cookie
                session_id = secrets.token_hex(nbytes=16)
                if self.user.email not in connections:
                    connections[self.user.email] = {}

                try:
                    max_age = int(COOKIE_MAX_AGE)
                except Exception:
                    max_age = 3600

                # drop expired sessions
                connections[self.user.email] = {
                    sid: ts for sid, ts in connections[self.user.email].items()
                    if time.time() - ts <= max_age
                }
                connections[self.user.email][session_id] = time.time()

                self.session_token = jwt.encode(
                    {
                        "email": self.user.email,
                        "session_id": session_id,
                        "asns_info": self.asns_info,
                        "asns": self.asns,
                    },
                    secret_key,
                    algorithm="HS256"
                )

            # 11) Success → update dialog
            self.auth_status = "success"

        except Exception:
            logging.exception("Unhandled error during OAuth2 callback")
            self.auth_status = "error"
            self.auth_error = "Unexpected error during sign-in. Please try again."
        finally:
            self.is_loading = False



    # --- NEW: helpers to control the dialog ---
    def open_auth_dialog(self, status: str = "loading"):
        self.auth_status = status
        self.show_auth_dialog = True
        self.auth_error = None



    def close_auth_dialog(self):
        self.show_auth_dialog = False
        self.auth_status = "idle"
        self.auth_error = None



    @rx.event
    def set_auth_dialog_open(self, is_open: bool):
        """Called by dialog.on_open_change to sync controlled state."""
        # If the user closes the dialog (is_open == False), reset state.
        if not is_open:
            self.close_auth_dialog()
        else:
            self.show_auth_dialog = True



    @rx.event
    def start_exploring(self):
        """Close dialog and redirect to homepage with auth active."""
        self.close_auth_dialog()
        return rx.redirect("/")
    


    @rx.event
    def return_to_site(self):
        """Close dialog and redirect (used on error)."""
        self.close_auth_dialog()
        return rx.redirect("/")
    

    @rx.event
    async def run_oauth_callback(self):
        """Wrapper so oauth2_callback can be used in on_load."""
        async for _ in self.oauth2_callback():
            pass

