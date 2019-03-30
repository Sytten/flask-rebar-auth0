from flask_rebar import HandlerRegistry
from flask_rebar.swagger_generation import swagger_words as sw

from .authenticator import Auth0Authenticator, Auth0AuthenticatorRBAC


KEY = "auth0"


def register_authenticators(registry: HandlerRegistry):
    registry.swagger_generator.register_authenticator_converter(
        Auth0Authenticator, _convert_auth0_authenticator
    )
    registry.swagger_generator.register_authenticator_converter(
        Auth0AuthenticatorRBAC, _convert_auth0_authenticator_rbac
    )


def _convert_auth0_authenticator(authenticator: Auth0Authenticator):
    if authenticator.header_authentication:
        header_name = authenticator.header_name
    else:
        header_name = "Cookie"
    definition = {sw.name: header_name, sw.in_: sw.header, sw.type_: sw.api_key}
    return KEY, definition


def _convert_auth0_authenticator_rbac(authenticator: Auth0AuthenticatorRBAC):
    return _convert_auth0_authenticator(authenticator.authenticator)
