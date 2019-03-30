from typing import Dict, Any

from flask import g


def get_authenticated_user() -> Any:
    return g.authenticated_user


def get_access_token_claims() -> Dict[str, Any]:
    return g.access_token_claims
