import secrets
import string

import facebook
import google.oauth2.credentials
import googleapiclient.discovery
from flask import jsonify, request
from flask_login import login_user
from itsdangerous import Signer

from app import email_utils
from app.api.base import api_bp
from app.config import FLASK_SECRET, DISABLE_REGISTRATION
from app.dashboard.views.account_setting import send_reset_password_email
from app.db import Session
from app.email_utils import (
    email_can_be_used_as_mailbox,
    personal_email_already_used,
    send_email,
    render,
)
from app.events.auth_event import LoginEvent, RegisterEvent
from app.extensions import limiter
from app.log import LOG
from app.models import User, ApiKey, SocialAuth, AccountActivation
from app.utils import sanitize_email, canonicalize_email


@api_bp.route("/auth/login", methods=["POST"])
@limiter.limit("10/minute")
def auth_login():
    """
    Authenticate user
    Input:
        email
        password
        device: to create an ApiKey associated with this device
    Output:
        200 and user info containing:
        {
            name: "John Wick",
            mfa_enabled: true,
            mfa_key: "a long string",
            api_key: "a long string"
        }

    """
    data = request.get_json()
    if not data:
        return jsonify(error="request body cannot be empty"), 400

    password = data.get("password")
    device = data.get("device")

    email = sanitize_email(data.get("email"))
    canonical_email = canonicalize_email(data.get("email"))

    user = User.get_by(email=email) or User.get_by(email=canonical_email)

    if not user or not user.check_password(password):
        LoginEvent(LoginEvent.ActionType.failed, LoginEvent.Source.api).send()
        return jsonify(error="Email or password incorrect"), 400
    elif user.disabled:
        LoginEvent(LoginEvent.ActionType.disabled_login, LoginEvent.Source.api).send()
        return jsonify(error="Account disabled"), 400
    elif user.delete_on is not None:
        LoginEvent(
            LoginEvent.ActionType.scheduled_to_be_deleted, LoginEvent.Source.api
        ).send()
        return jsonify(error="Account scheduled for deletion"), 400
    elif not user.activated:
        LoginEvent(LoginEvent.ActionType.not_activated, LoginEvent.Source.api).send()
        return jsonify(error="Account not activated"), 422
    elif user.fido_enabled():
        # allow user who has TOTP enabled to continue using the mobile app
        if not user.enable_otp:
            return jsonify(error="Currently we don't support FIDO on mobile yet"), 403

    LoginEvent(LoginEvent.ActionType.success, LoginEvent.Source.api).send()
    return jsonify(**auth_payload(user, device)), 200


@api_bp.route("/auth/register", methods=["POST"])
@limiter.limit("10/minute")
def auth_register():
    """
    User signs up - will need to activate their account with an activation code.
    Input:
        email
        password
    Output:
        200: user needs to confirm their account

    """
    data = request.get_json()
    if not data:
        return jsonify(error="request body cannot be empty"), 400

    dirty_email = data.get("email")
    email = canonicalize_email(dirty_email)
    password = data.get("password")

    if DISABLE_REGISTRATION:
        RegisterEvent(RegisterEvent.ActionType.failed, RegisterEvent.Source.api).send()
        return jsonify(error="registration is closed"), 400
    if not email_can_be_used_as_mailbox(email) or personal_email_already_used(email):
        RegisterEvent(
            RegisterEvent.ActionType.invalid_email, RegisterEvent.Source.api
        ).send()
        return jsonify(error=f"cannot use {email} as personal inbox"), 400

    if not password or len(password) < 8:
        RegisterEvent(RegisterEvent.ActionType.failed, RegisterEvent.Source.api).send()
        return jsonify(error="password too short"), 400

    if len(password) > 100:
        RegisterEvent(RegisterEvent.ActionType.failed, RegisterEvent.Source.api).send()
        return jsonify(error="password too long"), 400

    LOG.d("create user %s", email)
    user = User.create(email=email, name=dirty_email, password=password)
    Session.flush()

    # create activation code
    code = "".join([str(secrets.choice(string.digits)) for _ in range(6)])
    AccountActivation.create(user_id=user.id, code=code)
    Session.commit()

    send_email(
        email,
        "Just one more step to join Login",
        render("transactional/code-activation.txt.jinja2", user=user, code=code),
        render("transactional/code-activation.html", user=user, code=code),
    )

    RegisterEvent(RegisterEvent.ActionType.success, RegisterEvent.Source.api).send()
    return jsonify(msg="User needs to confirm their account"), 200


@api_bp.route("/auth/activate", methods=["POST"])
@limiter.limit("10/minute")
def auth_activate():
    """
    User enters the activation code to confirm their account.
    Input:
        email
        code
    Output:
        200: user account is now activated, user can login now
        400: wrong email, code
        410: wrong code too many times

    """
    data = request.get_json()
    if not data:
        return jsonify(error="request body cannot be empty"), 400

    email = sanitize_email(data.get("email"))
    canonical_email = canonicalize_email(data.get("email"))
    code = data.get("code")

    user = User.get_by(email=email) or User.get_by(email=canonical_email)

    # do not use a different message to avoid exposing existing email
    if not user or user.activated:
        return jsonify(error="Wrong email or code"), 400

    account_activation = AccountActivation.get_by(user_id=user.id)
    if not account_activation:
        return jsonify(error="Wrong email or code"), 400

    if account_activation.code != code:
        # decrement nb tries
        account_activation.tries -= 1
        Session.commit()

        if account_activation.tries == 0:
            AccountActivation.delete(account_activation.id)
            Session.commit()
            return jsonify(error="Too many wrong tries"), 410

        return jsonify(error="Wrong email or code"), 400

    LOG.d("activate user %s", user)
    user.activated = True
    AccountActivation.delete(account_activation.id)
    Session.commit()

    return jsonify(msg="Account is activated, user can login now"), 200

