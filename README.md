# Flask-Rebar-Auth0
[![PyPI version](https://badge.fury.io/py/flask-rebar-auth0.svg)](https://badge.fury.io/py/flask-rebar-auth0)
[![Python versions](https://img.shields.io/pypi/pyversions/Flask-Rebar-Auth0.svg)](https://badge.fury.io/py/flask-rebar-auth0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Sytten/flask-rebar-auth0/blob/master/LICENSE)

Simple [Flask-Rebar](https://github.com/plangrid/flask-rebar) authenticator for [Auth0](https://auth0.com).
Your access tokens need to be [JWT tokens](https://auth0.com/docs/api-auth/tutorials/verify-access-token) for this authenticator to work.

## Initialization
```python
# Config
app.config.from_mapping({
    "AUTH0_ENDPOINT": "perdu.auth0.com",      # The Auth0 domain for your tenant
    "AUTH0_ALGORITHMS": ["RS256"],            # The authorized algorithms, you should not have to change it
    "AUTH0_AUDIENCE": "https://api.perdu.com" # The API Identifier as set on Auth0

    "AUTH0_HEADER_AUTHENTICATION": True       # Use the authentication by header
    "AUTH0_HEADER_NAME": "Authorization"      # (OPTIONAL) Change the header used
    "AUTH0_HEADER_PREFIX": "Bearer"           # (OPTIONAL) Change the prefix used
    # OR
    "AUTH0_COOKIE_AUTHENTICATION": True       # Use the authentication by cookie
    "AUTH0_COOKIE_NAME": "Some Cookie"        # Name of the cookie containing the access token
    
    "AUTH0_TESTING": False                    # (OPTIONAL) Disable expiration check of tokens during tests   
})

# Create
authenticator = Auth0Authenticator(app)

@authenticator.identity_handler
def create_user(claims: Dict[str, Any]) -> Any:
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

## Swagger
If you wish to use swagger, you will need to register the custom authenticators.
This is needed by `rebar` to be able to convert them to the right swagger [security definition](https://swagger.io/docs/specification/2-0/authentication/).
If you use the `Cookie` authentication, please note that swagger 2.0 does support this method of authentication. It will be registered as a `Cookie` header.
```python
from flask_rebar_auth0 import register_authenticators

register_authenticators(registry)
```

## Testing
During tests, we suggest setting `AUTH0_TESTING` to `True` to allow expired tokens to be used.
The setting also disables the request to auth0 for the keys, you MUST supply them manually.
```python
my_key = {
  "alg": "RS256",
  "kty": "RSA",
  "use": "sig",
  "x5c": [
    "MIIC+TCCAeGgAwIBAgIJFDs6wMv+QZ3IMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMTD3BlcmR1LmF1dGgwLmNvbTAeFw0xOTAzMjkwNDM2MDhaFw0zMjEyMDUwNDM2MDhaMBoxGDAWBgNVBAMTD3BlcmR1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKEsfpuY/dOCI1yFnBV8MtUmq/SvzAhOW8SJvLyZpvx+zVnz9Wrk7LX/HVlxjdoQZXGtyIISuMG5rcQaA+4jZ6Bcphl4Ox9o6b0pw9aNQPS12IU2HM8b+szY+AqfZZr1xwTNaH8mOOtpfcQT4zHj+cYnrjfsN5d7o7P2dkpmk+E02tg/jq6MsoYaTL5rDL1clL1Rn0osLrpFFx6Ev8wrEUb2wCRgMeKlSALrc0YgmmSzJzeTW9dIgfoskBixk+OmtC/Oubq5R/bu6roF3VWbNlX7tQSyLNNLMZbmva1GMlvNWwgTHvg+hsYaknDN6PDfV6mWiNS1EPaX+j9GdMa59kUCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUCFdAmevfXzhKYNyOuWozLN1r5U8wDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQAkIoi8ddKGcqSgesaDgmWwp4oZr4NVX/g9wq7M9aU6SS4P2gwEvVLqAzyWNMMJaA4h7g2V/gKK8+zfGODLf7rCNAyl5ABJriLQywxBj0jTzFbVDMeiZMdE+6kFnERQMc2e4UqpLcsv2Mwt9hfdXDeSwzoVwCU14Y3wXNrT6QUSk5hDEiEUdVuB+v2CB8Xgp4CokiigMCXQ9uKttVuBhv6oLjcx9rM5z6dtxSFiNuBZafcejZsGCzD9J1l2CVEN4vNSGag8Y9yxCUXZ1DXRZvdsmbialzd4PqCus26IgtuvJLdQuk7doxGCdNlTVb2Ig8BhrjGg+5oGZh7KeZX7qHOb"
  ],
  "n": "oSx-m5j904IjXIWcFXwy1Sar9K_MCE5bxIm8vJmm_H7NWfP1auTstf8dWXGN2hBlca3IghK4wbmtxBoD7iNnoFymGXg7H2jpvSnD1o1A9LXYhTYczxv6zNj4Cp9lmvXHBM1ofyY462l9xBPjMeP5xieuN-w3l3ujs_Z2SmaT4TTa2D-OroyyhhpMvmsMvVyUvVGfSiwuukUXHoS_zCsRRvbAJGAx4qVIAutzRiCaZLMnN5Nb10iB-iyQGLGT46a0L865urlH9u7qugXdVZs2Vfu1BLIs00sxlua9rUYyW81bCBMe-D6GxhqScM3o8N9XqZaI1LUQ9pf6P0Z0xrn2RQ",
  "e": "AQAB",
  "kid": "OTEyNDRCREE1OTlEOUYwNEM2QTM5RkJEODkxOEQyMDQ0NjYxRENEMw",
  "x5t": "OTEyNDRCREE1OTlEOUYwNEM2QTM5RkJEODkxOEQyMDQ0NjYxRENEMw"
}

authenticator = Auth0Authenticator(app)
authenticator._add_key(my_key)
```
