from typing import Dict, Any, List
import json
from os.path import join, dirname
from datetime import datetime
from unittest.mock import Mock

import pytest
from pytest_mock import MockFixture
import requests
from requests_mock import Mocker

from flask import Flask
from flask_rebar import errors
from werkzeug.http import dump_cookie

from flask_rebar_auth0 import (
    Auth0Authenticator,
    get_access_token_claims,
    get_authenticated_user,
)


@pytest.fixture
def keys() -> Dict[str, List[Dict[str, Any]]]:
    with open(join(dirname(__file__), "keys.json")) as data_file:
        return json.loads(data_file.read())


@pytest.fixture
def tokens() -> Dict[str, str]:
    with open(join(dirname(__file__), "tokens.json")) as data_file:
        return json.loads(data_file.read())


@pytest.fixture
def access_token(tokens: Dict[str, str]) -> str:
    return tokens["accessToken"]


@pytest.fixture
def sign_key(keys: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    return keys["keys"][0]


@pytest.fixture
def flask_app() -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        {
            "AUTH0_ENDPOINT": "perdu.auth0.com",
            "AUTH0_ALGORITHMS": ["RS256"],
            "AUTH0_AUDIENCE": "https://api.perdu.com",
            "AUTH0_HEADER_AUTHENTICATION": True,
        }
    )
    return app


@pytest.fixture
def authenticator(
    flask_app: Flask, requests_mock: Mocker, keys: Dict[str, str]
) -> Auth0Authenticator:
    requests_mock.get("https://perdu.auth0.com/.well-known/jwks.json", json=keys)
    return Auth0Authenticator(flask_app)


def mock_valid_time(mocker: MockFixture):
    datetime_mock = mocker.patch("jose.jwt.datetime")
    datetime_mock.utcnow = Mock(return_value=datetime(2019, 1, 1))


# Scopes tests
def test_all_scopes_present(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    mock_valid_time(mocker)
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        authenticator.with_scopes(["read:location"]).authenticate()


def test_missing_scopes(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    mock_valid_time(mocker)
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        with pytest.raises(errors.Forbidden):
            authenticator.with_scopes(
                ["read:location", "write:location"]
            ).authenticate()


def test_no_scopes(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    mock_valid_time(mocker)
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        authenticator.with_scopes([]).authenticate()


def test_string_scope(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    mock_valid_time(mocker)
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        authenticator.with_scopes("read:location").authenticate()


def test_claims_are_not_modified(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    mock_valid_time(mocker)
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        authenticator.with_scopes(["read:location"]).authenticate()


# Authenticate tests
def test_authenticate_ok(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    mock_valid_time(mocker)
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        authenticator.authenticate()
        assert get_access_token_claims() != {}


def test_authenticate_failure(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    mock_valid_time(mocker)
    authenticator.audience = "SomeRandomAudience"
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        with pytest.raises(errors.Unauthorized):
            authenticator.authenticate()


def test_create_user_ok(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    @authenticator.identity_handler
    def create_user(claims: Dict[str, Any]):
        return {"User": claims["sub"]}

    mock_valid_time(mocker)
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        authenticator.authenticate()
        assert (
            get_authenticated_user()["User"]
            == "Tlapef2d0GHcq32k2W0PycmFL4wIxuGM@clients"
        )


def test_create_user_failure(
    mocker: MockFixture,
    flask_app: Flask,
    authenticator: Auth0Authenticator,
    access_token: str,
):
    @authenticator.identity_handler
    def create_user(claims: Dict[str, Any]):
        raise Exception

    mock_valid_time(mocker)
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        with pytest.raises(errors.Unauthorized):
            authenticator.authenticate()


# Tokens tests
def test_valid_token(
    mocker: MockFixture,
    authenticator: Auth0Authenticator,
    access_token: str,
    sign_key: Dict[str, Any],
):
    mock_valid_time(mocker)
    payload = authenticator._get_payload(access_token, sign_key)
    assert payload != {}


def test_expired_token(
    mocker: MockFixture,
    authenticator: Auth0Authenticator,
    access_token: str,
    sign_key: Dict[str, Any],
):
    datetime_mock = mocker.patch("jose.jwt.datetime")
    datetime_mock.utcnow = Mock(return_value=datetime(2050, 1, 1))
    authenticator.audience = "SomeRandomAudience"
    with pytest.raises(Exception, match=r"Token is expired"):
        authenticator._get_payload(access_token, sign_key)


def test_invalid_signature(
    mocker: MockFixture,
    authenticator: Auth0Authenticator,
    tokens: Dict[str, str],
    sign_key: Dict[str, Any],
):
    mock_valid_time(mocker)
    with pytest.raises(Exception, match=r"Invalid signature"):
        authenticator._get_payload(tokens["invalidSignature"], sign_key)


def test_invalid_audience(
    mocker: MockFixture,
    authenticator: Auth0Authenticator,
    access_token: str,
    sign_key: Dict[str, Any],
):
    mock_valid_time(mocker)
    authenticator.audience = "SomeRandomAudience"
    with pytest.raises(Exception, match=r"Invalid claims"):
        authenticator._get_payload(access_token, sign_key)


def test_missing_signature(
    mocker: MockFixture,
    authenticator: Auth0Authenticator,
    tokens: Dict[str, str],
    sign_key: Dict[str, Any],
):
    mock_valid_time(mocker)
    with pytest.raises(Exception, match=r"Invalid signature"):
        authenticator._get_payload(tokens["noSignature"], sign_key)


# Refresh keys tests
def test_refresh_keys_ok(authenticator: Auth0Authenticator):
    assert (
        authenticator.keys["OTEyNDRCREE1OTlEOUYwNEM2QTM5RkJEODkxOEQyMDQ0NjYxRENEMw"]
        != {}
    )


def test_refresh_keys_failure(requests_mock: Mocker, flask_app: Flask):
    requests_mock.get(
        "https://perdu.auth0.com/.well-known/jwks.json",
        exc=requests.exceptions.ConnectTimeout,
    )
    authenticator = Auth0Authenticator(flask_app)
    assert authenticator.keys == {}


# Authentication methods tests
def test_missing_authentication(flask_app: Flask):
    with pytest.raises(
        Exception, match=r"Must specify at least one method of authentication"
    ):
        flask_app.config["AUTH0_HEADER_AUTHENTICATION"] = False
        Auth0Authenticator(flask_app)


def test_cookie_extract(
    flask_app: Flask, authenticator: Auth0Authenticator, access_token: str
):
    cookie_name = "TestCookie"
    authenticator.header_authentication = False
    authenticator.cookie_authentication = True
    authenticator.cookie_name = cookie_name
    header = dump_cookie(cookie_name, access_token)
    with flask_app.test_request_context(headers={"COOKIE": header}):
        token = authenticator._get_token()
        assert token == access_token


def test_header_extract(
    flask_app: Flask, authenticator: Auth0Authenticator, access_token: str
):
    with flask_app.test_request_context(
        headers={"Authorization": f"Bearer {access_token}"}
    ):
        token = authenticator._get_token()
        assert token == access_token


def test_no_token(flask_app: Flask, authenticator: Auth0Authenticator):
    with flask_app.test_request_context():
        with pytest.raises(Exception, match=r"Missing token"):
            authenticator._get_token()


# Testing
def test_testing_wont_refresh_keys(flask_app: Flask, requests_mock: Mocker):
    flask_app.config["AUTH0_TESTING"] = True
    auth0_endpoint_mock = requests_mock.get(
        "https://perdu.auth0.com/.well-known/jwks.json"
    )
    Auth0Authenticator(flask_app)

    assert auth0_endpoint_mock.call_count == 0


def test_testing_accepts_expired_token(
    mocker: MockFixture,
    authenticator: Auth0Authenticator,
    access_token: str,
    sign_key: Dict[str, Any],
):
    authenticator.testing = True
    datetime_mock = mocker.patch("jose.jwt.datetime")
    datetime_mock.utcnow = Mock(return_value=datetime(2050, 1, 1))
    payload = authenticator._get_payload(access_token, sign_key)
    assert payload is not None


def test_testing_add_key(
    flask_app: Flask, requests_mock: Mocker, sign_key: Dict[str, Any]
):
    flask_app.config["AUTH0_TESTING"] = True
    auth0_endpoint_mock = requests_mock.get(
        "https://perdu.auth0.com/.well-known/jwks.json"
    )
    authenticator = Auth0Authenticator(flask_app)
    assert not authenticator.keys

    authenticator.add_key(sign_key)
    assert authenticator.keys


def test_testing_add_invalid_key(authenticator: Auth0Authenticator,):
    with pytest.raises(Exception, match=r"Invalid key"):
        authenticator.add_key({"test": "bad key"})
