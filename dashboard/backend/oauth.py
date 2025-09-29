import os
import time
import secrets
import logging
import urllib.parse
import requests
import jwt
import reflex as rx
from typing import Optional
from datetime import datetime, timezone

from backend.user import User
from sqlmodel import select

# ---- Configuration ----
PEERINGDB_CLIENT_ID = os.getenv("OAUTH2_PEERINGDB_CLIENT_ID")
PEERINGDB_CLIENT_SECRET = os.getenv("OAUTH2_PEERINGDB_CLIENT_SECRET")
PEERINGDB_AUTHORIZE_URL = "https://auth.peeringdb.com/oauth2/authorize/"
PEERINGDB_TOKEN_URL = "https://auth.peeringdb.com/oauth2/token/"
PEERINGDB_USERINFO_URL = "https://auth.peeringdb.com/profile/v1"
REDIRECT_URI = os.getenv("WEBSITE_URL")  # must match PeeringDB config

SECRET_KEY = os.getenv("SESSION_AUTHENTIFICATION_SECRET_KEY")
COOKIE_MAX_AGE = int(os.getenv("COOKIE_MAX_AGE", "3600"))

oauth2_server_state = {}
connections = {}

class AuthState(rx.State):
    """Simplified authentication state (PeeringDB only)."""

    is_authenticated: bool = False
    session_token: str = rx.Cookie(name="session_token", max_age=COOKIE_MAX_AGE, path="/", secure=True, same_site="strict")

    user: Optional[User] = None
    email: Optional[str] = None
    asns_info: list[list[str]] = []
    asns: list[str] = []



    # --- PeeringDB login ---
    def oauth2_authorize_peeringdb(self):
        """Start OAuth2 flow with PeeringDB."""
        state = secrets.token_urlsafe(32)
        oauth2_server_state[state] = {"timestamp": time.time()}
        qs = urllib.parse.urlencode({
            "client_id": PEERINGDB_CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "email profile networks",
            "state": state,
            "response_type": "code",
        })
        return rx.redirect(PEERINGDB_AUTHORIZE_URL + "?" + qs)
    


    @rx.event
    async def oauth2_callback(self):
        """Handle PeeringDB OAuth2 redirect."""
        state = self.router.page.params.get("state")
        code = self.router.page.params.get("code")
        if not state or not code:
            logging.error("OAuth2 callback missing state or code")
            return rx.redirect("/")

        if state not in oauth2_server_state:
            logging.error("Invalid or expired OAuth2 state")
            return rx.redirect("/login")

        # Exchange code for token
        token_resp = requests.post(
            PEERINGDB_TOKEN_URL,
            data={
                "client_id": PEERINGDB_CLIENT_ID,
                "client_secret": PEERINGDB_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        token_resp.raise_for_status()
        token_json = token_resp.json()
        access_token = token_json.get("access_token")
        if not access_token:
            logging.error("PeeringDB token exchange failed")
            return rx.redirect("/login")

        # Fetch userinfo
        ui_resp = requests.get(
            PEERINGDB_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        ui_resp.raise_for_status()
        userinfo = ui_resp.json()

        self.email = userinfo.get("email")
        networks = userinfo.get("networks", [])
        self.asns_info = [[str(n["asn"]), n.get("name", "")] for n in networks]
        self.asns = [asn for asn, _ in self.asns_info]

        # Save user in DB if not exists
        with rx.session() as session:
            user = session.exec(select(User).where(User.email == self.email)).first()
            if not user:
                user = User(email=self.email)
                session.add(user)
                session.commit()
            self.user = user

        # Create session
        session_id = secrets.token_hex(16)
        connections.setdefault(self.email, {})[session_id] = time.time()
        self.session_token = jwt.encode(
            {"email": self.email, "session_id": session_id, "asns_info": self.asns_info},
            SECRET_KEY,
            algorithm="HS256",
        )

        self.is_authenticated = True
        return rx.redirect("/profile")
    
    

    def logout(self):
        """Log out user and clear session."""
        if self.is_authenticated:
            rx.remove_cookie("session_token")
            self.reset()
        return rx.redirect("/")
    

    