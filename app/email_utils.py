import base64
import binascii
import enum
import hmac
import json
import os
import quopri
import random
import time
import uuid
from copy import deepcopy
from email import policy, message_from_bytes, message_from_string
from email.header import decode_header, Header
from email.message import Message, EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import make_msgid, formatdate, formataddr
from smtplib import SMTP, SMTPException
from typing import Tuple, List, Optional, Union

import arrow
import dkim
import re2 as re
import spf
from aiosmtpd.smtp import Envelope
from cachetools import cached, TTLCache
from email_validator import (
    validate_email,
    EmailNotValidError,
    ValidatedEmail,
)
from flanker.addresslib import address
from flanker.addresslib.address import EmailAddress
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import func
from flask_login import current_user

from app import config
from app.db import Session
from app.dns_utils import get_mx_domains
from app.email import headers
from app.log import LOG
from app.mail_sender import sl_sendmail
from app.message_utils import message_to_bytes
from app.models import (
    Mailbox,
    User,
    SentAlert,
    CustomDomain,
    SLDomain,
    Contact,
    Alias,
    EmailLog,
    TransactionalEmail,
    IgnoreBounceSender,
    InvalidMailboxDomain,
    VerpType,
    available_sl_email,
)
from app.utils import (
    random_string,
    convert_to_id,
    convert_to_alphanumeric,
    sanitize_email,
)

# 2022-01-01 00:00:00
VERP_TIME_START = 1640995200
VERP_HMAC_ALGO = "sha3-224"


def render(template_name: str, user: Optional[User], **kwargs) -> str:
    templates_dir = os.path.join(config.ROOT_DIR, "templates", "emails")
    env = Environment(loader=FileSystemLoader(templates_dir))

    template = env.get_template(template_name)

    if user is None:
        if current_user and current_user.is_authenticated:
            user = current_user

    use_partner_template = False
    if user:
        use_partner_template = user.has_used_alias_from_partner()
        kwargs["user"] = user

    return template.render(
        MAX_NB_EMAIL_FREE_PLAN=config.MAX_NB_EMAIL_FREE_PLAN,
        URL=config.URL,
        LANDING_PAGE_URL=config.LANDING_PAGE_URL,
        YEAR=arrow.now().year,
        USE_PARTNER_TEMPLATE=use_partner_template,
        **kwargs,
    )


def send_welcome_email(user):
    comm_email, unsubscribe_link, via_email = user.get_communication_email()
    if not comm_email:
        return

    # whether this email is sent to an alias
    alias = comm_email if comm_email != user.email else None

    send_email(
        comm_email,
        "Welcome to Login",
        render("com/welcome.txt", user=user, alias=alias),
        render("com/welcome.html", user=user, alias=alias),
        unsubscribe_link,
        via_email,
    )


def send_trial_end_soon_email(user):
    send_email(
        user.email,
        "Your trial will end soon",
        render("transactional/trial-end.txt.jinja2", user=user),
        render("transactional/trial-end.html", user=user),
        ignore_smtp_error=True,
    )


def send_activation_email(user: User, activation_link):
    send_email(
        user.email,
        "Just one more step to join Login",
        render(
            "transactional/activation.txt",
            user=user,
            activation_link=activation_link,
            email=user.email,
        ),
        render(
            "transactional/activation.html",
            user=user,
            activation_link=activation_link,
            email=user.email,
        ),
    )


def send_reset_password_email(user: User, reset_password_link):
    send_email(
        user.email,
        "Reset your password on Login",
        render(
            "transactional/reset-password.txt",
            user=user,
            reset_password_link=reset_password_link,
        ),
        render(
            "transactional/reset-password.html",
            user=user,
            reset_password_link=reset_password_link,
        ),
    )


def send_change_email(user: User, new_email, link):
    send_email(
        new_email,
        "Confirm email update on Login",
        render(
            "transactional/change-email.txt",
            user=user,
            link=link,
            new_email=new_email,
            current_email=user.email,
        ),
        render(
            "transactional/change-email.html",
            user=user,
            link=link,
            new_email=new_email,
            current_email=user.email,
        ),
    )


def send_invalid_totp_login_email(user, totp_type):
    send_email_with_rate_control(
        user,
        config.ALERT_INVALID_TOTP_LOGIN,
        user.email,
        "Unsuccessful attempt to login to your Login account",
        render(
            "transactional/invalid-totp-login.txt",
            user=user,
            type=totp_type,
        ),
        render(
            "transactional/invalid-totp-login.html",
            user=user,
            type=totp_type,
        ),
        1,
    )


def send_test_email_alias(user: User, email: str):
    send_email(
        email,
        f"This email is sent to {email}",
        render(
            "transactional/test-email.txt",
            user=user,
            name=user.name,
            alias=email,
        ),
        render(
            "transactional/test-email.html",
            user=user,
            name=user.name,
            alias=email,
        ),
    )


def send_cannot_create_directory_alias(user, alias_address, directory_name):
    """when user cancels their subscription, they cannot create alias on the fly.
    If this happens, send them an email to notify
    """
    send_email(
        user.email,
        f"Alias {alias_address} cannot be created",
        render(
            "transactional/cannot-create-alias-directory.txt",
            user=user,
            alias=alias_address,
            directory=directory_name,
        ),
        render(
            "transactional/cannot-create-alias-directory.html",
            user=user,
            alias=alias_address,
            directory=directory_name,
        ),
    )


def send_cannot_create_directory_alias_disabled(user, alias_address, directory_name):
    """when the directory is disabled, new alias can't be created on-the-fly.
    Send user an email to notify of an attempt
    """
    send_email_with_rate_control(
        user,
        config.ALERT_DIRECTORY_DISABLED_ALIAS_CREATION,
        user.email,
        f"Alias {alias_address} cannot be created",
        render(
            "transactional/cannot-create-alias-directory-disabled.txt",
            user=user,
            alias=alias_address,
            directory=directory_name,
        ),
        render(
            "transactional/cannot-create-alias-directory-disabled.html",
            user=user,
            alias=alias_address,
            directory=directory_name,
        ),
    )
