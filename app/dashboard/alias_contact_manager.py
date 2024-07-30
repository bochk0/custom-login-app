from dataclasses import dataclass
from operator import or_

from flask import render_template, request, redirect, flash
from flask import url_for
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from sqlalchemy import and_, func, case
from wtforms import StringField, validators, ValidationError

# Need to import directly from config to allow modification from the tests
from app import config, parallel_limiter
from app.dashboard.base import dashboard_bp
from app.db import Session
from app.email_utils import (
    generate_reply_email,
    parse_full_address,
)
from app.email_validation import is_valid_email
from app.errors import (
    CannotCreateContactForReverseAlias,
    ErrContactErrorUpgradeNeeded,
    ErrAddressInvalid,
    ErrContactAlreadyExists,
)
from app.log import LOG
from app.models import Alias, Contact, EmailLog, User
from app.utils import sanitize_email, CSRFValidationForm


def email_validator():
    """validate email address. Handle both only email and email with name:
    - ab@cd.com
    - AB CD <ab@cd.com>

    """
    message = "Invalid email format. Email must be either email@example.com or *First Last <email@example.com>*"

    def _check(form, field):
        email = field.data
        email = email.strip()
        email_part = email

        if "<" in email and ">" in email:
            if email.find("<") + 1 < email.find(">"):
                email_part = email[email.find("<") + 1 : email.find(">")].strip()

        if not is_valid_email(email_part):
            raise ValidationError(message)

    return _check


def create_contact(user: User, alias: Alias, contact_address: str) -> Contact:

    if not contact_address:
        raise ErrAddressInvalid("Empty address")
    try:
        contact_name, contact_email = parse_full_address(contact_address)
    except ValueError:
        raise ErrAddressInvalid(contact_address)

    contact_email = sanitize_email(contact_email)
    if not is_valid_email(contact_email):
        raise ErrAddressInvalid(contact_email)

    contact = Contact.get_by(alias_id=alias.id, website_email=contact_email)
    if contact:
        raise ErrContactAlreadyExists(contact)

    if not user.can_create_contacts():
        raise ErrContactErrorUpgradeNeeded()

    contact = Contact.create(
        user_id=alias.user_id,
        alias_id=alias.id,
        website_email=contact_email,
        name=contact_name,
        reply_email=generate_reply_email(contact_email, alias),
    )

    LOG.d(
        "create reverse-alias for %s %s, reverse alias:%s",
        contact_address,
        alias,
        contact.reply_email,
    )
    Session.commit()

    return contact


class NewContactForm(FlaskForm):
    email = StringField(
        "Email", validators=[validators.DataRequired(), email_validator()]
    )


@dataclass
class ContactInfo(object):
    contact: Contact

    nb_forward: int
    nb_reply: int

    latest_email_log: EmailLog


def get_contact_infos(
    alias: Alias, page=0, contact_id=None, query: str = ""
) -> [ContactInfo]:
    """if contact_id is set, only return the contact info for this contact"""
    sub = (
        Session.query(
            Contact.id,
            func.sum(case([(EmailLog.is_reply, 1)], else_=0)).label("nb_reply"),
            func.sum(
                case(
                    [
                        (
                            and_(
                                EmailLog.is_reply.is_(False),
                                EmailLog.blocked.is_(False),
                            ),
                            1,
                        )
                    ],
                    else_=0,
                )
            ).label("nb_forward"),
            func.max(EmailLog.created_at).label("max_email_log_created_at"),
        )
        .join(
            EmailLog,
            EmailLog.contact_id == Contact.id,
            isouter=True,
        )
        .filter(Contact.alias_id == alias.id)
        .group_by(Contact.id)
        .subquery()
    )

    q = (
        Session.query(
            Contact,
            EmailLog,
            sub.c.nb_reply,
            sub.c.nb_forward,
        )
        .join(
            EmailLog,
            EmailLog.contact_id == Contact.id,
            isouter=True,
        )
        .filter(Contact.alias_id == alias.id)
        .filter(Contact.id == sub.c.id)
        .filter(
            or_(
                EmailLog.created_at == sub.c.max_email_log_created_at,
                # no email log yet for this contact
                sub.c.max_email_log_created_at.is_(None),
            )
        )
    )

    if query:
        q = q.filter(
            or_(
                Contact.website_email.ilike(f"%{query}%"),
                Contact.name.ilike(f"%{query}%"),
            )
        )

    if contact_id:
        q = q.filter(Contact.id == contact_id)

    latest_activity = case(
        [
            (EmailLog.created_at > Contact.created_at, EmailLog.created_at),
            (EmailLog.created_at < Contact.created_at, Contact.created_at),
        ],
        else_=Contact.created_at,
    )
    q = (
        q.order_by(latest_activity.desc())
        .limit(config.PAGE_LIMIT)
        .offset(page * config.PAGE_LIMIT)
    )

    ret = []
    for contact, latest_email_log, nb_reply, nb_forward in q:
        contact_info = ContactInfo(
            contact=contact,
            nb_forward=nb_forward,
            nb_reply=nb_reply,
            latest_email_log=latest_email_log,
        )
        ret.append(contact_info)

    return ret


def delete_contact(alias: Alias, contact_id: int):
    contact = Contact.get(contact_id)

    if not contact:
        flash("Unknown error. Refresh the page", "warning")
    elif contact.alias_id != alias.id:
        flash("You cannot delete reverse-alias", "warning")
    else:
        delete_contact_email = contact.website_email
        Contact.delete(contact_id)
        Session.commit()

        flash(f"Reverse-alias for {delete_contact_email} has been deleted", "success")

