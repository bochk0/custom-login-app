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
        return alias
    except AliasInTrashError:
        LOG.w(
            "Alias %s was deleted before, cannot auto-create using directory %s, user %s",
            address,
            directory.name,
            directory.user,
        )
        return None
    except IntegrityError:
        LOG.w("Alias %s already exists", address)
        Session.rollback()
        alias = Alias.get_by(email=address)
        return alias


def try_auto_create_via_domain(address: str) -> Optional[Alias]:

    can_create = check_if_alias_can_be_auto_created_for_custom_domain(address)
    if not can_create:
        return None
    custom_domain, rule = can_create

    if rule:
        alias_note = f"Created by rule {rule.order} with regex {rule.regex}"
        mailboxes = rule.mailboxes
    else:
        alias_note = "Created by catchall option"
        mailboxes = custom_domain.mailboxes

    
    if not mailboxes:
        LOG.d(
            "use %s default mailbox for %s %s",
            custom_domain.user,
            address,
            custom_domain,
        )
        mailboxes = [custom_domain.user.default_mailbox]

    try:
        LOG.d("create alias %s for domain %s", address, custom_domain)
        alias = Alias.create(
            email=address,
            user_id=custom_domain.user_id,
            custom_domain_id=custom_domain.id,
            automatic_creation=True,
            mailbox_id=mailboxes[0].id,
        )
        if not custom_domain.user.disable_automatic_alias_note:
            alias.note = alias_note
        Session.flush()
        for i in range(1, len(mailboxes)):
            AliasMailbox.create(
                alias_id=alias.id,
                mailbox_id=mailboxes[i].id,
            )
        Session.commit()
        return alias
    except AliasInTrashError:
        LOG.w(
            "Alias %s was deleted before, cannot auto-create using domain catch-all %s, user %s",
            address,
            custom_domain,
            custom_domain.user,
        )
        return None
    except IntegrityError:
        LOG.w("Alias %s already exists", address)
        Session.rollback()
        alias = Alias.get_by(email=address)
        return alias
    except DataError:
        LOG.w("Cannot create alias %s", address)
        Session.rollback()
        return None


def delete_alias(
    alias: Alias, user: User, reason: AliasDeleteReason = AliasDeleteReason.Unspecified
):

    LOG.i(f"User {user} has deleted alias {alias}")
    
    if alias.custom_domain_id:
        if not DomainDeletedAlias.get_by(
            email=alias.email, domain_id=alias.custom_domain_id
        ):
            domain_deleted_alias = DomainDeletedAlias(
                user_id=user.id,
                email=alias.email,
                domain_id=alias.custom_domain_id,
                reason=reason,
            )
            Session.add(domain_deleted_alias)
            Session.commit()
            LOG.i(
                f"Moving {alias} to domain {alias.custom_domain_id} trash {domain_deleted_alias}"
            )
    else:
        if not DeletedAlias.get_by(email=alias.email):
            deleted_alias = DeletedAlias(email=alias.email, reason=reason)
            Session.add(deleted_alias)
            Session.commit()
            LOG.i(f"Moving {alias} to global trash {deleted_alias}")

    Alias.filter(Alias.id == alias.id).delete()
    Session.commit()

    EventDispatcher.send_event(
        user, EventContent(alias_deleted=AliasDeleted(alias_id=alias.id))
    )


def aliases_for_mailbox(mailbox: Mailbox) -> [Alias]:

    ret = set(Alias.filter(Alias.mailbox_id == mailbox.id).all())

    for alias in (
        Session.query(Alias)
        .join(AliasMailbox, Alias.id == AliasMailbox.alias_id)
        .filter(AliasMailbox.mailbox_id == mailbox.id)
    ):
        ret.add(alias)

    return list(ret)


def nb_email_log_for_mailbox(mailbox: Mailbox):
    aliases = aliases_for_mailbox(mailbox)
    alias_ids = [alias.id for alias in aliases]
    return (
        Session.query(EmailLog)
        .join(Contact, EmailLog.contact_id == Contact.id)
        .filter(Contact.alias_id.in_(alias_ids))
        .count()
    )



_ALIAS_PREFIX_PATTERN = r"[0-9a-z-_.]{1,}"


def check_alias_prefix(alias_prefix) -> bool:
    if len(alias_prefix) > 40:
        return False

    if re.fullmatch(_ALIAS_PREFIX_PATTERN, alias_prefix) is None:
        return False

    return True


def alias_export_csv(user, csv_direct_export=False):

    data = [["alias", "note", "enabled", "mailboxes"]]
    for alias in Alias.filter_by(user_id=user.id).all():  
        
        
        alias_mailboxes = alias.mailboxes
        alias_mailboxes.insert(
            0, alias_mailboxes.pop(alias_mailboxes.index(alias.mailbox))
        )

        mailboxes = " ".join([mailbox.email for mailbox in alias_mailboxes])
        data.append([alias.email, alias.note, alias.enabled, mailboxes])

    si = StringIO()
    cw = csv.writer(si)
    cw.writerows(data)
    if csv_direct_export:
        return si.getvalue()
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=aliases.csv"
    output.headers["Content-type"] = "text/csv"
    return output


def transfer_alias(alias, new_user, new_mailboxes: [Mailbox]):
    
    if User.get_by(newsletter_alias_id=alias.id):
        raise Exception("Cannot transfer alias that's used to receive newsletter")

    
    Session.query(Contact).filter(Contact.alias_id == alias.id).update(
        {"user_id": new_user.id}
    )

    Session.query(AliasUsedOn).filter(AliasUsedOn.alias_id == alias.id).update(
        {"user_id": new_user.id}
    )

    Session.query(ClientUser).filter(ClientUser.alias_id == alias.id).update(
        {"user_id": new_user.id}
    )

    
    Session.query(AliasMailbox).filter(AliasMailbox.alias_id == alias.id).delete()

    
    alias.mailbox_id = new_mailboxes.pop().id
    for mb in new_mailboxes:
        AliasMailbox.create(alias_id=alias.id, mailbox_id=mb.id)

    
    if not alias.original_owner_id:
        alias.original_owner_id = alias.user_id

    
    old_user = alias.user
    send_email(
        old_user.email,
        f"Alias {alias.email} has been received",
        render(
            "transactional/alias-transferred.txt",
            user=old_user,
            alias=alias,
        ),
        render(
            "transactional/alias-transferred.html",
            user=old_user,
            alias=alias,
        ),
    )

    
    alias.user_id = new_user.id

    
    alias.disable_pgp = False
    alias.pinned = False

    Session.commit()


def change_alias_status(alias: Alias, enabled: bool, commit: bool = False):
    LOG.i(f"Changing alias {alias} enabled to {enabled}")
    alias.enabled = enabled

    event = AliasStatusChanged(
        alias_id=alias.id, alias_email=alias.email, enabled=enabled
    )
    EventDispatcher.send_event(alias.user, EventContent(alias_status_change=event))

    if commit:
        Session.commit()
