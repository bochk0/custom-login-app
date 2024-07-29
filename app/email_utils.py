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


def send_cannot_create_domain_alias(user, alias, domain):
    """when user cancels their subscription, they cannot create alias on the fly with custom domain.
    If this happens, send them an email to notify
    """
    send_email(
        user.email,
        f"Alias {alias} cannot be created",
        render(
            "transactional/cannot-create-alias-domain.txt",
            user=user,
            alias=alias,
            domain=domain,
        )
    )


def send_email(
    to_email,
    subject,
    plaintext,
    html=None,
    unsubscribe_link=None,
    unsubscribe_via_email=False,
    retries=0,  # by default no retry if sending fails
    ignore_smtp_error=False,
    from_name=None,
    from_addr=None,
):
    to_email = sanitize_email(to_email)

    LOG.d("send email to %s, subject '%s'", to_email, subject)

    from_name = from_name or config.NOREPLY
    from_addr = from_addr or config.NOREPLY
    from_domain = get_email_domain_part(from_addr)

    if html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(plaintext))
        msg.attach(MIMEText(html, "html"))
    else:
        msg = EmailMessage()
        msg.set_payload(plaintext)
        msg[headers.CONTENT_TYPE] = "text/plain"

    msg[headers.SUBJECT] = subject
    msg[headers.FROM] = f'"{from_name}" <{from_addr}>'
    msg[headers.TO] = to_email

    msg_id_header = make_msgid(domain=config.EMAIL_DOMAIN)
    msg[headers.MESSAGE_ID] = msg_id_header

    date_header = formatdate()
    msg[headers.DATE] = date_header


    # add DKIM
    email_domain = from_addr[from_addr.find("@") + 1 :]
    add_dkim_signature(msg, email_domain)

    transaction = TransactionalEmail.create(email=to_email, commit=True)

    # use a different envelope sender for each transactional email (aka VERP)
    sl_sendmail(
        generate_verp_email(VerpType.transactional, transaction.id, from_domain),
        to_email,
        msg,
        retries=retries,
        ignore_smtp_error=ignore_smtp_error,
    )


def send_email_with_rate_control(
    user: User,
    alert_type: str,
    to_email: str,
    subject,
    plaintext,
    html=None,
    max_nb_alert=config.MAX_ALERT_24H,
    nb_day=1,
    ignore_smtp_error=False,
    retries=0,
) -> bool:
    """Same as send_email with rate control over alert_type.
    Make sure no more than `max_nb_alert` emails are sent over the period of `nb_day` days

    Return true if the email is sent, otherwise False
    """
    to_email = sanitize_email(to_email)
    min_dt = arrow.now().shift(days=-1 * nb_day)
    nb_alert = (
        SentAlert.filter_by(alert_type=alert_type, to_email=to_email)
        .filter(SentAlert.created_at > min_dt)
        .count()
    )

    if nb_alert >= max_nb_alert:
        LOG.w(
            "%s emails were sent to %s in the last %s days, alert type %s",
            nb_alert,
            to_email,
            nb_day,
            alert_type,
        )
        return False

    SentAlert.create(user_id=user.id, alert_type=alert_type, to_email=to_email)
    Session.commit()

    if ignore_smtp_error:
        try:
            send_email(to_email, subject, plaintext, html, retries=retries)
        except SMTPException:
            LOG.w("Cannot send email to %s, subject %s", to_email, subject)
    else:
        send_email(to_email, subject, plaintext, html, retries=retries)

    return True


def send_email_at_most_times(
    user: User,
    alert_type: str,
    to_email: str,
    subject,
    plaintext,
    html=None,
    max_times=1,
) -> bool:
    """Same as send_email with rate control over alert_type.
    Sent at most `max_times`
    This is used to inform users about a warning.

    Return true if the email is sent, otherwise False
    """
    to_email = sanitize_email(to_email)
    nb_alert = SentAlert.filter_by(alert_type=alert_type, to_email=to_email).count()

    if nb_alert >= max_times:
        LOG.w(
            "%s emails were sent to %s alert type %s",
            nb_alert,
            to_email,
            alert_type,
        )
        return False

    SentAlert.create(user_id=user.id, alert_type=alert_type, to_email=to_email)
    Session.commit()
    send_email(to_email, subject, plaintext, html)
    return True


def get_email_local_part(address) -> str:
    """
    Get the local part from email
    ab@cd.com -> ab
    Convert the local part to lowercase
    """
    r: ValidatedEmail = validate_email(
        address, check_deliverability=False, allow_smtputf8=False
    )
    return r.local_part.lower()


def get_email_domain_part(address):
    """
    Get the domain part from email
    ab@cd.com -> cd.com
    """
    address = sanitize_email(address)
    return address[address.find("@") + 1 :]


def add_dkim_signature(msg: Message, email_domain: str):
    if config.RSPAMD_SIGN_DKIM:
        LOG.d("DKIM signature will be added by rspamd")
        msg[headers.SL_WANT_SIGNING] = "yes"
        return

    for dkim_headers in headers.DKIM_HEADERS:
        try:
            add_dkim_signature_with_header(msg, email_domain, dkim_headers)
            return
        except dkim.DKIMException:
            LOG.w("DKIM fail with %s", dkim_headers, exc_info=True)
            # try with another headers
            continue

    # To investigate why some emails can't be DKIM signed. todo: remove
    if config.TEMP_DIR:
        file_name = str(uuid.uuid4()) + ".eml"
        with open(os.path.join(config.TEMP_DIR, file_name), "wb") as f:
            f.write(msg.as_bytes())

        LOG.w("email saved to %s", file_name)

    raise Exception("Cannot create DKIM signature")

    def add_dkim_signature_with_header(
    msg: Message, email_domain: str, dkim_headers: [bytes]
):
    delete_header(msg, "DKIM-Signature")

    # Specify headers in "byte" form
    # Generate message signature
    if config.DKIM_PRIVATE_KEY:
        sig = dkim.sign(
            message_to_bytes(msg),
            config.DKIM_SELECTOR,
            email_domain.encode(),
            config.DKIM_PRIVATE_KEY.encode(),
            include_headers=dkim_headers,
        )
        sig = sig.decode()

        # remove linebreaks from sig
        sig = sig.replace("\n", " ").replace("\r", "")
        msg[headers.DKIM_SIGNATURE] = sig[len("DKIM-Signature: ") :]


def add_or_replace_header(msg: Message, header: str, value: str):
    """
    Remove all occurrences of `header` and add `header` with `value`.
    """
    delete_header(msg, header)
    msg[header] = value


def delete_header(msg: Message, header: str):
    """a header can appear several times in message."""
    # inspired from https://stackoverflow.com/a/47903323/1428034
    for i in reversed(range(len(msg._headers))):
        header_name = msg._headers[i][0].lower()
        if header_name == header.lower():
            del msg._headers[i]


def sanitize_header(msg: Message, header: str):
    """remove trailing space and remove linebreak from a header"""
    header_lowercase = header.lower()
    for i in reversed(range(len(msg._headers))):
        header_name = msg._headers[i][0].lower()
        if header_name == header_lowercase:
            # msg._headers[i] is a tuple like ('From', 'hey@google.com')
            if msg._headers[i][1]:
                msg._headers[i] = (
                    msg._headers[i][0],
                    msg._headers[i][1].strip().replace("\n", " "),
                )


def delete_all_headers_except(msg: Message, headers: [str]):
    headers = [h.lower() for h in headers]

    for i in reversed(range(len(msg._headers))):
        header_name = msg._headers[i][0].lower()
        if header_name not in headers:
            del msg._headers[i]


def can_create_directory_for_address(email_address: str) -> bool:
    """return True if an email ends with one of the alias domains provided by Login"""
    # not allow creating directory with premium domain
    for domain in config.ALIAS_DOMAINS:
        if email_address.endswith("@" + domain):
            return True

    return False


def is_valid_alias_address_domain(email_address) -> bool:
    """Return whether an address domain might a domain handled by Login"""
    domain = get_email_domain_part(email_address)
    if SLDomain.get_by(domain=domain):
        return True

    if CustomDomain.get_by(domain=domain, verified=True):
        return True

    return False


def email_can_be_used_as_mailbox(email_address: str) -> bool:
    """Return True if an email can be used as a personal email.
    Use the email domain as criteria. A domain can be used if it is not:
    - one of ALIAS_DOMAINS
    - one of PREMIUM_ALIAS_DOMAINS
    - one of custom domains
    - a disposable domain
    """
    try:
        domain = validate_email(
            email_address, check_deliverability=False, allow_smtputf8=False
        ).domain
    except EmailNotValidError:
        LOG.d("%s is invalid email address", email_address)
        return False

    if not domain:
        LOG.d("no valid domain associated to %s", email_address)
        return False

    if SLDomain.get_by(domain=domain):
        LOG.d("%s is a SL domain", email_address)
        return False

    from app.models import CustomDomain

    if CustomDomain.get_by(domain=domain, verified=True):
        LOG.d("domain %s is a Login custom domain", domain)
        return False

    if is_invalid_mailbox_domain(domain):
        LOG.d("Domain %s is invalid mailbox domain", domain)
        return False

    # check if email MX domain is disposable
    mx_domains = get_mx_domain_list(domain)

    # if no MX record, email is not valid
    if not config.SKIP_MX_LOOKUP_ON_CHECK and not mx_domains:
        LOG.d("No MX record for domain %s", domain)
        return False

    for mx_domain in mx_domains:
        if is_invalid_mailbox_domain(mx_domain):
            LOG.d("MX Domain %s %s is invalid mailbox domain", mx_domain, domain)
            return False

    existing_user = User.get_by(email=email_address)
    if existing_user and existing_user.disabled:
        LOG.d(
            f"User {existing_user} is disabled. {email_address} cannot be used for other mailbox"
        )
        return False

    for existing_user in (
        User.query()
        .join(Mailbox, User.id == Mailbox.user_id)
        .filter(Mailbox.email == email_address)
        .group_by(User.id)
        .all()
    ):
        if existing_user.disabled:
            LOG.d(
                f"User {existing_user} is disabled and has a mailbox with {email_address}. Id cannot be used for other mailbox"
            )
            return False

    return True


def is_invalid_mailbox_domain(domain):
    """
    Whether a domain is invalid mailbox domain
    Also return True if `domain` is a subdomain of an invalid mailbox domain
    """
    parts = domain.split(".")
    for i in range(0, len(parts) - 1):
        parent_domain = ".".join(parts[i:])

        if InvalidMailboxDomain.get_by(domain=parent_domain):
            return True

    return False


def get_mx_domain_list(domain) -> [str]:
    """return list of MX domains for a given email.
    domain name ends *without* a dot (".") at the end.
    """
    priority_domains = get_mx_domains(domain)

    return [d[:-1] for _, d in priority_domains]


def personal_email_already_used(email_address: str) -> bool:
    """test if an email can be used as user email"""
    if User.get_by(email=email_address):
        return True

    return False


def mailbox_already_used(email: str, user) -> bool:
    if Mailbox.get_by(email=email, user_id=user.id):
        return True

    # support the case user wants to re-add their real email as mailbox
    # can happen when user changes their root email and wants to add this new email as mailbox
    if email == user.email:
        return False

    return False


def get_orig_message_from_bounce(bounce_report: Message) -> Optional[Message]:
    """parse the original email from Bounce"""
    i = 0
    for part in bounce_report.walk():
        i += 1

        # 1st part is the container (bounce report)
        # 2nd part is the report from our own Postfix
        # 3rd is report from other mailbox
        # 4th is the container of the original message
        # ...
        # 7th is original message
        if i == 7:
            return part


def get_mailbox_bounce_info(bounce_report: Message) -> Optional[Message]: