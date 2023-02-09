# OpenID Connect demo

This is a demo app for the OIDC authentication code flow in a command line tool.

The tool constructs the authentication request and redirects the user's browser
to the single sign-on page. It starts a tornado webserver to handle the OIDC
redirect. After the callback arrives it requests an access token and basic user
info.

## Client setup

The client should be registered out-of-band. You will need the following information:

- The issuer. This should be an https url, and there should be a valid
  configuration file at {issuer}/.well-known/openid-configuration
- Client ID
- Client Secret

The redirect URL must be registered with the issuer as http://0.0.0.0:18546/auth
(port can be customized if needed).

## Usage

Parameters can be specified at the command line or as environmental variables.
For instance,

    export OIDC_CLIENT_ID=...
    export OIDC_CLIENT_SECRET=...
    export OIDC_ISSUER=...

    python oidc_test.py

## Example output

```

###  OIDC TEST ###
Listening on 18546
Configuring OpenId provider from https://morgana-kc.psi.ch/auth/realms/master
Opening browser for authorization: https://morgana-kc.psi.ch/auth/realms/master/protocol/openid-connect/auth?client_id=datacatalog-test&response_type=code&scope=openid&nonce=oV6vwUoyg0Bh6WCw&redirect_uri=http%3A%2F%2F0.0.0.0%3A18546%2Fauth&state=HE5d4n0d1XQK0EFJ
Waiting for authentication
GET /auth
Got authorization code.
Requesting access token
Hello, Spencer Bliven <spencer.bliven@psi.ch>
[I 230209 20:52:43 web:2271] 200 GET /auth?state=HE5d4n0d1XQK0EFJ&session_state=REDACTED (127.0.0.1) 297.69ms
```
