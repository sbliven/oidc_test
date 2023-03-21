#!/usr/bin/env python
import asyncio
import hashlib
import logging
import random
import sys
import webbrowser

import click
import click_logging
import tornado.web
import yaml
from oic import rndstr
from oic.oic import Client
from oic.oic.message import (
    AccessTokenResponse,
    AddressClaim,
    AuthorizationResponse,
    OpenIDSchema,
    RegistrationResponse,
)
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from tornado.log import enable_pretty_logging

access_log = logging.getLogger("tornado.access")
enable_pretty_logging()
logger = logging.getLogger(__name__)
click_logging.basic_config(logger)

session = None  # single global session
client = None  # global client
shutdown_event = asyncio.Event()


def dict_representor(dumper, data):
    return dumper.represent(data.to_dict())


yaml.add_representer(AddressClaim, dict_representor)


@click.command()
@click_logging.simple_verbosity_option(logger)
@click.option(
    "--client_id", help="OIDC client ID", required=True, envvar="OIDC_CLIENT_ID"
)
@click.option(
    "--client_secret",
    help="OIDC client secret. May be 'PKCE' for public access clients",
    required=True,
    envvar="OIDC_CLIENT_SECRET",
)
@click.option(
    "--port",
    default=18546,
    help="Port for OIDC communication. Must match the registered redirect_uri.",
    envvar="OIDC_PORT",
)
@click.option(
    "--issuer",
    help="OpenID provider. Should be the base url for a "
    ".well-known/openid-configuration file",
    default="https://morgana-kc.psi.ch/auth/realms/master",
    envvar="OIDC_ISSUER",
)
@click.option(
    "--scopes",
    help="Extra scopes to request (comma separated)",
    default="",
    envvar="OIDC_SCOPES",
)
def main(client_id, client_secret, port, issuer, scopes):
    """Run an OpenID Connect authentication code flow from the command line"""
    logger.info("###  OIDC TEST ###")

    asyncio.run(async_main(client_id, client_secret, port, issuer, scopes.split(",")))


async def async_main(client_id, client_secret, port, issuer, scopes=[]):
    tasks = [web_server(port)]
    # tasks.append(timeout())  # exit app after timeout
    if client_secret.lower() == "pkce":
        tasks.append(authorization_code_flow_pkce(port, issuer, client_id, scopes))
    else:
        tasks.append(
            authorization_code_flow(port, issuer, client_id, client_secret, scopes)
        )
    await asyncio.gather(*tasks)


async def timeout(timeout=5 * 60):
    "Exit the app"
    await asyncio.sleep(timeout)
    logger.error("Authentication timed out")
    shutdown_event.set()
    sys.exit(1)


async def authorization_code_flow(port, issuer, client_id, client_secret, scopes=[]):
    "Start a new OIDC authorization code flow"
    global client
    # Configure endpoints
    logger.info(
        f"Configuring OpenId provider from {issuer} for authorization code flow"
    )
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    client.provider_config(issuer)

    # Register client
    info = {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uris": [f"http://localhost:{port}/auth"],
    }
    client_reg = RegistrationResponse(**info)
    client.store_registration_info(client_reg)

    # Make Authentication request
    authenticate(client, scopes)

    logger.info("Waiting for authentication")


def authenticate(client, scopes=[]):
    "Makes an authentication request"
    global session
    if session is not None:
        raise Exception("Invalid state")

    session = {}
    session["state"] = rndstr()
    session["nonce"] = rndstr()

    args = {
        "client_id": client.client_id,
        "response_type": "code",
        "scope": " ".join(["openid"] + scopes),
        "nonce": session["nonce"],
        "redirect_uri": client.registration_response["redirect_uris"][0],
        "state": session["state"],
    }
    code_challenge, code_verifier = client.add_code_challenge()
    session["code_verifier"] = code_verifier
    args.update(code_challenge)

    auth_req = client.construct_AuthorizationRequest(request_args=args)
    login_url = auth_req.request(client.authorization_endpoint)

    logger.info(f"Opening browser for authorization: {login_url}")
    webbrowser.open(login_url, new=2)
    return session


async def authorization_code_flow_pkce(port, issuer, client_id, scopes=[]):
    "Start a new OIDC authorization code flow"
    global client
    # Configure endpoints
    logger.info(
        f"Configuring OpenId provider from {issuer} "
        f"for authorization code flow with PKCE"
    )
    client = Client(
        client_authn_method=CLIENT_AUTHN_METHOD,
        config={"code_challenge": {"method": "S256", "length": 128}},
    )
    client.provider_config(issuer)

    # Register client
    info = {
        "client_id": client_id,
        "redirect_uris": [f"http://localhost:{port}/auth"],
    }
    client_reg = RegistrationResponse(**info)
    client.store_registration_info(client_reg)

    # Make Authentication request
    authenticate(client, scopes)

    logger.info("Waiting for authentication")


async def web_server(port):
    "Start tornado web server"
    global shutdown_event
    app = make_app()
    app.listen(port)
    logger.info(f"Listening on {port}")

    await shutdown_event.wait()


def make_app():
    "Routes for tornado server"
    return tornado.web.Application(
        [
            (r"/auth", AuthHandler),
        ]
    )


class AuthHandler(tornado.web.RequestHandler):
    "Handle redirects from the OP after the authentication request"

    def _auth_error(self, error, code=500):
        self.set_status(code)
        self.write(
            f"""<!DOCTYPE html>
                <html><head><title>Authorization failed</title></head>
                <body><h1>Authorization failed</h1>
                <pre>{error}</pre>
                </body></html>
                """
        )
        self.flush()

    def get(self):
        logger.info(f"GET {self.request.path}")

        try:
            # Parse response for code
            aresp = client.parse_response(
                AuthorizationResponse, info=self.request.query, sformat="urlencoded"
            )
            if not isinstance(aresp, AuthorizationResponse):
                logger.error(f"Error getting code: {aresp}")
                self._auth_error(f"Error getting code: {aresp}", 401)
                sys.exit(1)
            if aresp["state"] != session["state"]:
                logger.error("State didn't match!")
                self._auth_error("State didn't match!", 500)
                sys.exit(1)
            assert "code" in aresp
            logger.info("Got authorization code.")

            # Request access token
            request_token(aresp)

            # Respond to user
            self.set_status(200)
            self.write(
                """<!DOCTYPE html>
                    <html><head><title>Authorization successful</title></head>
                    <body><h1>Authorization Successful</h1>
                    <p>You may close this window.</p>
                    </body></html>
                    """
            )
            self.flush()
        except Exception as ex:
            self._auth_error(ex)


# TODO Should this be a coroutine?
def request_token(aresp):
    logger.info("Requesting access token")
    args = {
        "code": aresp["code"],
    }
    if "code_verifier" in session:
        args["code_verifier"] = session["code_verifier"]

    resp = client.do_access_token_request(
        state=aresp["state"], request_args=args, authn_method="client_secret_basic"
    )
    if not isinstance(resp, AccessTokenResponse):
        logger.error(f"Error getting access token: {aresp}")
        sys.exit(1)

    userinfo = client.do_user_info_request(state=aresp["state"])
    if not isinstance(userinfo, OpenIDSchema):
        logger.error(f"Error getting access token: {userinfo}")
        sys.exit(1)

    logged_in(userinfo)


def logged_in(userinfo):
    "Authentication is concluded"
    name = userinfo.get("name", "Unknown")
    email = userinfo.get("email", "unknown@email")
    logger.info(f"Hello, {name} <{email}>")
    logger.info(yaml.safe_dump({"Known claims": userinfo.to_dict()}))
    shutdown_event.set()


if __name__ == "__main__":
    main()
