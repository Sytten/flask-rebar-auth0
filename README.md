# Flask-Rebar-Auth0

Simple [Flask-Rebar](https://github.com/plangrid/flask-rebar) authenticator for [Auth0](https://auth0.com).
Your access tokens need to be [JWT tokens](https://auth0.com/docs/api-auth/tutorials/verify-access-token) for this authenticator to work.

## Initialization
```python
# Config
app.config.from_mapping({
    "AUTH0_ENDPOINT": "perdu.auth0.com",      # The Auth0 domain for your tenant
    "AUTH0_ALGORITHMS": ["RS256"],            # The authorized algorithms, you should not have to change it
    "AUTH0_AUDIENCE": "https://api.perdu.com" # The API Identifier as set on Auth0

    "AUTH0_HEADER_AUTHENTICATION": True       # USe the authentication by header
    "AUTH0_HEADER_NAME": "Authorization"      # (OPTIONAL) Change the header used
    "AUTH0_HEADER_PREFIX": "Bearer"           # (OPTIONAL) Change the prefix used
    # OR
    "AUTH0_COOKIE_AUTHENTICATION": True       # Use the authentication by cookie
    "AUTH0_COOKIE_NAME": "Some Cookie"        # Name of the cookie containing the access token
})

# Create
authenticator = Auth0Authenticator(app)

@authenticator.identity_handler
def lookup_cognito_user(claims: Dict[str, Any]) -> Any:
    """Built a user object from the claims"""
    return { "id": claims["sub"] }
```

## Usage
```python
from flask_rebar_auth0 import get_authenticated_user


@registry.handles(
    rule="/users/me",
    method="GET",
    marshal_schema=UserSchema(),
    authenticator=authenticator, # Use the authenticator
)
def get_user():
    return get_authenticated_user() # Get the user data created by the identity_handler


@registry.handles(
    rule="/users/me/location",
    method="GET",
    marshal_schema=UserLocationSchema(),
    authenticator=authenticator.with_scopes(["read:location"]), # Require some scopes to access the ressource
)
def get_user_location():
    user = get_authenticated_user()
    return locationService.get(user)
```
