from typing import Dict
from urllib.parse import urlparse

from flask import request, render_template, redirect, flash, url_for
from flask_login import current_user

from app.alias_suffix import get_alias_suffixes, check_suffix_signature
from app.alias_utils import check_alias_prefix
from app.config import EMAIL_DOMAIN
from app.db import Session
from app.jose_utils import make_id_token
from app.log import LOG
from app.models import (
    Client,
    AuthorizationCode,
    ClientUser,
    Alias,
    RedirectUri,
    OauthToken,
    DeletedAlias,
    DomainDeletedAlias,
)
from app.oauth.base import oauth_bp
from app.oauth_models import (
    get_response_types,
    ResponseType,
    Scope,
    SUPPORTED_OPENID_FLOWS,
    SUPPORTED_OPENID_FLOWS_STR,
    response_types_to_str,
)
from app.utils import random_string, encode_url


@oauth_bp.route("/authorize", methods=["GET", "POST"])
def authorize():
    """
    Redirected from client when user clicks on "Login with Server".
    This is a GET request with the following field in url
    - client_id
    - (optional) state
    - response_type: must be code
    """
    oauth_client_id = request.args.get("client_id")
    state = request.args.get("state")
    scope = request.args.get("scope")
    redirect_uri = request.args.get("redirect_uri")
    response_mode = request.args.get("response_mode")
    nonce = request.args.get("nonce")

    try:
        response_types: [ResponseType] = get_response_types(request)
    except ValueError:
        return (
            "response_type must be code, token, id_token or certain combination of these."
            " Please see /.well-known/openid-configuration to see what response_type are supported ",
            400,
        )

    if set(response_types) not in SUPPORTED_OPENID_FLOWS:
        return (
            f"Login only support the following OIDC flows: {SUPPORTED_OPENID_FLOWS_STR}",
            400,
        )

    if not redirect_uri:
        LOG.d("no redirect uri")
        return "redirect_uri must be set", 400

    client = Client.get_by(oauth_client_id=oauth_client_id)
    if not client:
        return redirect(url_for("auth.login"))

    # allow localhost by default
    # allow any redirect_uri if the app isn't approved
    hostname, scheme = get_host_name_and_scheme(redirect_uri)
    if hostname != "localhost" and hostname != "127.0.0.1":
        # support custom scheme for mobile app
        if scheme == "http":
            flash("The external client must use HTTPS", "error")
            return redirect(url_for("dashboard.index"))

        # check if redirect_uri is valid
        if not RedirectUri.get_by(client_id=client.id, uri=redirect_uri):
            flash("The external client is using an invalid URL", "error")
            return redirect(url_for("dashboard.index"))

