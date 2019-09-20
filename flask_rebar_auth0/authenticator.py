from typing import Callable, Any, List, Dict
import logging

import requests

from jose import jwt

from flask import request, g
from flask import Flask
from flask_rebar.authenticators.base import Authenticator
from flask_rebar import errors, messages

from .helpers import get_access_token_claims


logger = logging.getLogger(__name__)


class Auth0AuthenticatorRBAC(Authenticator):
    def __init__(
        self, authenticator: "Auth0Authenticator", scopes: List[str] = []
    ) -> None:
        self.authenticator = authenticator
        self.scopes = set(scopes)

    def authenticate(self):
        self.authenticator.authenticate()

        claims = get_access_token_claims()
        scopes = claims.get("permissions", []).copy()  # RBAC
        scopes.extend(claims.get("scope", "").split())  # Otherwise

        if not self.scopes.issubset(set(scopes)):
            raise errors.Forbidden("Missing the right permissions")


class Auth0Authenticator(Authenticator):
    # URL to fetch the public keys used to verify the signature
    AUTH0_KEYS_URL = "https://{}/.well-known/jwks.json"

    def __init__(self, app: Flask = None) -> None:
        self.identity_callback = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        # Check if testing
        self.testing = app.config.get("AUTH0_TESTING", False)

        # Set general Auth0 params
        endpoint = self._get_config(app, "AUTH0_ENDPOINT")
        self.auth0_url = self.AUTH0_KEYS_URL.format(endpoint)
        self.issuer = f"https://{endpoint}/"
        self.algorithms = self._get_config(app, "AUTH0_ALGORITHMS")
        self.audience = self._get_config(app, "AUTH0_AUDIENCE")

        # Find the method of authentication
        self.header_authentication = bool(app.config.get("AUTH0_HEADER_AUTHENTICATION"))
        if self.header_authentication:
            self.header_name = str(app.config.get("AUTH0_HEADER_NAME", "Authorization"))
            self.header_prefix = str(
                app.config.get("AUTH0_HEADER_PREFIX", "Bearer")
            ).lower()

        self.cookie_authentication = bool(app.config.get("AUTH0_COOKIE_AUTHENTICATION"))
        if self.cookie_authentication:
            self.cookie_name = str(self._get_config(app, "AUTH0_COOKIE_NAME"))

        if not self.cookie_authentication and not self.header_authentication:
            raise Exception("Must specify at least one method of authentication")

        # Force a keys refresh on creation to be ready to authenticate requests
        self.keys = {}
        if not self.testing:
            self._refresh_keys()

    def authenticate(self):
        try:
            # Decode token
            token = self._get_token()
            kid = self._get_kid(token)
            key = self._get_key(kid)
            payload = self._get_payload(token, key)

            # Store user information
            if self.identity_callback:
                g.authenticated_user = self.identity_callback(payload)
            else:
                g.authenticated_user = payload
            g.access_token_claims = payload

        except Exception as e:
            logger.debug("Failed to login user: %s", e)
            raise errors.Unauthorized(messages.invalid_auth_token)

    def identity_handler(
        self, callback: Callable[[Dict[str, Any]], Any]
    ) -> Callable[[Dict[str, Any]], Any]:
        """Register a callback to create the user object during authentication.
        
        The callback will receive the verified claims and should return an object.
        """
        self.identity_callback = callback
        return callback

    def with_scopes(self, scopes: List[str]) -> Authenticator:
        """Wraps the authenticator with the needed scopes to access the ressource."""
        # Avoid frustrating the users if they provide a string
        if isinstance(scopes, str):
            scopes = [scopes]

        return Auth0AuthenticatorRBAC(self, scopes)

    def _get_payload(self, token, key) -> Dict[str, Any]:
        try:
            options = {"verify_exp": False} if self.testing else {}
            return jwt.decode(
                token,
                key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                options=options,
            )
        except jwt.ExpiredSignatureError:
            raise Exception("Token is expired")
        except jwt.JWTClaimsError:
            raise Exception("Invalid claims")
        except jwt.JWTError:
            raise Exception("Invalid signature")

    def _get_token(self) -> str:
        if self.cookie_authentication:
            token = request.cookies.get(self.cookie_name)
            if token is not None:
                return token

        if self.header_authentication:
            auth_header = request.headers.get(self.header_name)
            if auth_header is not None:
                parts = auth_header.split()
                if parts[0].lower() != self.header_prefix:
                    raise Exception(f"Header must start with {self.header_prefix}")
                elif len(parts) == 1:
                    raise Exception("Token not found in header")
                elif len(parts) > 2:
                    raise Exception("Too many parts in the header")
                return parts[1]

        raise Exception("Missing token")

    def _get_key(self, kid: str) -> Dict[str, str]:
        key = self.keys.get(kid, None)

        if key is None:
            # AWS recommends refreshing the keys, but that might cause a DDOS
            # if a malicious kid is used. Until key rotation is setup, don't refresh.
            raise Exception(f"Missing key for kid {kid}")

        return key

    def _refresh_keys(self) -> None:
        try:
            keys_response = requests.get(self.auth0_url).json()
            keys = keys_response.get("keys")
            for key in keys:
                self._add_key(key)
        except Exception:
            logger.error("An error occured when refreshing the pool keys")

    def _add_key(self, key: Dict[str, Any]) -> None:
        self.keys[key.get("kid")] = key

    @staticmethod
    def _get_kid(token: str) -> str:
        headers = jwt.get_unverified_headers(token)
        kid = headers.get("kid", None)

        if kid is None:
            raise Exception("Missing kid in header")

        return kid

    @staticmethod
    def _get_config(app: Flask, config_name: str):
        value = app.config.get(config_name, None)
        if value is None:
            raise Exception(f"{config_name} not found in app configuration")
        return value
