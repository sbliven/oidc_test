#!/usr/bin/env python
import asyncio
import logging
import sys
import webbrowser

import click
import click_logging
import tornado.web
from oic import rndstr
from oic.oic import Client
from oic.oic.message import (
    AccessTokenResponse,
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
def main(client_id, client_secret, port, issuer):
    """Run an OpenID Connect authentication code flow from the command line"""
    logger.info("###  OIDC TEST ###")

    asyncio.run(async_main(client_id, client_secret, port, issuer))


async def async_main(client_id, client_secret, port, issuer):
    tasks = [web_server(port)]
    if client_secret.lower() == "pkce":
        tasks.append(authorization_code_flow_pkce(port, issuer, client_id))
    else:
        tasks.append(authorization_code_flow(port, issuer, client_id, client_secret))
    await asyncio.gather(*tasks)


async def authorization_code_flow(port, issuer, client_id, client_secret):
    "Start a new OIDC authorization code flow"
    global client
    # Configure endpoints
    logger.info(f"Configuring OpenId provider from {issuer} for authorization code flow")
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
    authenticate(client)

    logger.info("Waiting for authentication")


def authenticate(client):
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
        "scope": ["openid"],
        "nonce": session["nonce"],
        "redirect_uri": client.registration_response["redirect_uris"][0],
        "state": session["state"],
    }

    auth_req = client.construct_AuthorizationRequest(request_args=args)
    login_url = auth_req.request(client.authorization_endpoint)

    logger.info(f"Opening browser for authorization: {login_url}")
    webbrowser.open(login_url, new=2)
    return session


async def authorization_code_flow_pkce(port, issuer, client_id):
    "Start a new OIDC authorization code flow"
    global client
    # Configure endpoints
    logger.info(f"Configuring OpenId provider from {issuer} for authorization code flow with PKCE")
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD, config={"code_challenge": {"method": "S256", "length": 64}})
    client.provider_config(issuer)

    # Register client
    info = {
        "client_id": client_id,
        "redirect_uris": [f"http://localhost:{port}/auth"],
    }
    client_reg = RegistrationResponse(**info)
    client.store_registration_info(client_reg)

    # Make Authentication request
    authenticate(client)

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

    def get(self):
        logger.info(f"GET {self.request.path}")
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

        # Parse response for code
        aresp = client.parse_response(
            AuthorizationResponse, info=self.request.query, sformat="urlencoded"
        )
        if not isinstance(aresp, AuthorizationResponse):
            logger.error(f"Error getting code: {aresp}")
            sys.exit(1)
        if aresp["state"] != session["state"]:
            logger.error("State didn't match!")
            sys.exit(1)
        assert "code" in aresp
        logger.info("Got authorization code.")

        # Request access token
        request_token(aresp)


# TODO Should this be a coroutine?
def request_token(aresp):
    logger.info("Requesting access token")
    args = {
        "code": aresp["code"],
    }
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

    shutdown_event.set()


if __name__ == "__main__":
    main()
