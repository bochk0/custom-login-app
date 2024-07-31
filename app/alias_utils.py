import csv
from io import StringIO
import re
from typing import Optional, Tuple

from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import IntegrityError, DataError
from flask import make_response

from app.config import (
    BOUNCE_PREFIX_FOR_REPLY_PHASE,
    BOUNCE_PREFIX,
    BOUNCE_SUFFIX,
    VERP_PREFIX,
)
from app.db import Session
from app.email_utils import (
    get_email_domain_part,
    send_cannot_create_directory_alias,
    can_create_directory_for_address,
    send_cannot_create_directory_alias_disabled,
    get_email_local_part,
    send_cannot_create_domain_alias,
    send_email,
    render,
)
from app.errors import AliasInTrashError
from app.events.event_dispatcher import EventDispatcher
from app.events.generated.event_pb2 import (
    AliasDeleted,
    AliasStatusChanged,
    EventContent,
)
from app.log import LOG
from app.models import (
    Alias,
    AliasDeleteReason,
    CustomDomain,
    Directory,
    User,
    DeletedAlias,
    DomainDeletedAlias,
    AliasMailbox,
    Mailbox,
    EmailLog,
    Contact,
    AutoCreateRule,
    AliasUsedOn,
    ClientUser,
)
from app.regex_utils import regex_match


def get_user_if_alias_would_auto_create(
    address: str, notify_user: bool = False
) -> Optional[User]:
    banned_prefix = f"{VERP_PREFIX}."
    if address.startswith(banned_prefix):
        LOG.w("alias %s can't start with %s", address, banned_prefix)
        return None

    try:
        
        validate_email(address, check_deliverability=False, allow_smtputf8=False)
    except EmailNotValidError:
        return None

    domain_and_rule = check_if_alias_can_be_auto_created_for_custom_domain(
        address, notify_user=notify_user
    )
    if DomainDeletedAlias.get_by(email=address):
        return None
    if domain_and_rule:
        return domain_and_rule[0].user
    directory = check_if_alias_can_be_auto_created_for_a_directory(
        address, notify_user=notify_user
    )
    if directory:
        return directory.user

    return None


def check_if_alias_can_be_auto_created_for_custom_domain(
    address: str, notify_user: bool = True
) -> Optional[Tuple[CustomDomain, Optional[AutoCreateRule]]]:

    alias_domain = get_email_domain_part(address)
    custom_domain: CustomDomain = CustomDomain.get_by(domain=alias_domain)

    if not custom_domain:
        return None

    user: User = custom_domain.user
    if user.disabled:
        LOG.i("Disabled user %s can't create new alias via custom domain", user)
        return None

    if not user.can_create_new_alias():
        LOG.d(f"{user} can't create new custom-domain alias {address}")
        if notify_user:
            send_cannot_create_domain_alias(custom_domain.user, address, alias_domain)
        return None

    if not custom_domain.catch_all:
        if len(custom_domain.auto_create_rules) == 0:
            return None
        local = get_email_local_part(address)

        for rule in custom_domain.auto_create_rules:
            if regex_match(rule.regex, local):
                LOG.d(
                    "%s passes %s on %s",
                    address,
                    rule.regex,
                    custom_domain,
                )
                return custom_domain, rule
        else:  
            LOG.d("no rule passed to create %s", local)
            return None
    LOG.d("Create alias via catchall")

    return custom_domain, None


def check_if_alias_can_be_auto_created_for_a_directory(
    address: str, notify_user: bool = True
) -> Optional[Directory]:

    
    if not can_create_directory_for_address(address):
        return None

    
    if "/" in address:
        sep = "/"
    elif "+" in address:
        sep = "+"
    elif "
        sep = "
    else:
        
        return None

    directory_name = address[: address.find(sep)]
    LOG.d("directory_name %s", directory_name)

    directory = Directory.get_by(name=directory_name)
    if not directory:
        return None

    user: User = directory.user
    if user.disabled:
        LOG.i("Disabled %s can't create new alias with directory", user)
        return None

    if not user.can_create_new_alias():
        LOG.d(f"{user} can't create new directory alias {address}")
        if notify_user:
            send_cannot_create_directory_alias(user, address, directory_name)
        return None

    if directory.disabled:
        if notify_user:
            send_cannot_create_directory_alias_disabled(user, address, directory_name)
        return None

    return directory


def try_auto_create(address: str) -> Optional[Alias]:
    
    if address.startswith(f"{BOUNCE_PREFIX_FOR_REPLY_PHASE}+") and "+@" in address:
        LOG.e("alias %s can't start with %s", address, BOUNCE_PREFIX_FOR_REPLY_PHASE)
        return None

    
    if address.startswith(BOUNCE_PREFIX) and address.endswith(BOUNCE_SUFFIX):
        LOG.e("alias %s can't start with %s", address, BOUNCE_PREFIX)
        return None

    try:
        
        validate_email(address, check_deliverability=False, allow_smtputf8=False)
    except EmailNotValidError:
        return None

    alias = try_auto_create_via_domain(address)
    if not alias:
        alias = try_auto_create_directory(address)

    return alias


def try_auto_create_directory(address: str) -> Optional[Alias]:
    directory = check_if_alias_can_be_auto_created_for_a_directory(
        address, notify_user=True
    )
    if not directory:
        return None

try:
        LOG.d("create alias %s for directory %s", address, directory)

        mailboxes = directory.mailboxes

        alias = Alias.create(
            email=address,
            user_id=directory.user_id,
            directory_id=directory.id,
            mailbox_id=mailboxes[0].id,
        )
        if not directory.user.disable_automatic_alias_note:
            alias.note = f"Created by directory {directory.name}"
        Session.flush()
        for i in range(1, len(mailboxes)):
            AliasMailbox.create(
                alias_id=alias.id,
                mailbox_id=mailboxes[i].id,
            )

        Session.commit()