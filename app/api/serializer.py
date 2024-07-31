from dataclasses import dataclass
from typing import Optional

from arrow import Arrow
from sqlalchemy import or_, func, case, and_
from sqlalchemy.orm import joinedload

from app.config import PAGE_LIMIT
from app.db import Session
from app.models import (
    Alias,
    Contact,
    EmailLog,
    Mailbox,
    AliasMailbox,
    CustomDomain,
    User,
)


@dataclass
class AliasInfo:
    alias: Alias
    mailbox: Mailbox
    mailboxes: [Mailbox]

    nb_forward: int
    nb_blocked: int
    nb_reply: int

    latest_email_log: EmailLog = None
    latest_contact: Contact = None
    custom_domain: Optional[CustomDomain] = None

    def contain_mailbox(self, mailbox_id: int) -> bool:
        return mailbox_id in [m.id for m in self.mailboxes]


def serialize_alias_info(alias_info: AliasInfo) -> dict:
    return {
        
        "id": alias_info.alias.id,
        "email": alias_info.alias.email,
        "creation_date": alias_info.alias.created_at.format(),
        "creation_timestamp": alias_info.alias.created_at.timestamp,
        "enabled": alias_info.alias.enabled,
        "note": alias_info.alias.note,
        
        "nb_forward": alias_info.nb_forward,
        "nb_block": alias_info.nb_blocked,
        "nb_reply": alias_info.nb_reply,
    }


def serialize_alias_info_v2(alias_info: AliasInfo) -> dict:
    res = {
        
        "id": alias_info.alias.id,
        "email": alias_info.alias.email,
        "creation_date": alias_info.alias.created_at.format(),
        "creation_timestamp": alias_info.alias.created_at.timestamp,
        "enabled": alias_info.alias.enabled,
        "note": alias_info.alias.note,
        "name": alias_info.alias.name,
        
        "nb_forward": alias_info.nb_forward,
        "nb_block": alias_info.nb_blocked,
        "nb_reply": alias_info.nb_reply,
        
        "mailbox": {"id": alias_info.mailbox.id, "email": alias_info.mailbox.email},
        "mailboxes": [
            {"id": mailbox.id, "email": mailbox.email}
            for mailbox in alias_info.mailboxes
        ],
        "support_pgp": alias_info.alias.mailbox_support_pgp(),
        "disable_pgp": alias_info.alias.disable_pgp,
        "latest_activity": None,
        "pinned": alias_info.alias.pinned,
    }
    if alias_info.latest_email_log:
        email_log = alias_info.latest_email_log
        contact = alias_info.latest_contact
        
        res["latest_activity"] = {
            "timestamp": email_log.created_at.timestamp,
            "action": email_log.get_action(),
            "contact": {
                "email": contact.website_email,
                "name": contact.name,
                "reverse_alias": contact.website_send_to(),
            },
        }
    return res


def serialize_contact(contact: Contact, existed=False) -> dict:
    res = {
        "id": contact.id,
        "creation_date": contact.created_at.format(),
        "creation_timestamp": contact.created_at.timestamp,
        "last_email_sent_date": None,
        "last_email_sent_timestamp": None,
        "contact": contact.website_email,
        "reverse_alias": contact.website_send_to(),
        "reverse_alias_address": contact.reply_email,
        "existed": existed,
        "block_forward": contact.block_forward,
    }

    email_log: EmailLog = contact.last_reply()
    if email_log:
        res["last_email_sent_date"] = email_log.created_at.format()
        res["last_email_sent_timestamp"] = email_log.created_at.timestamp

    return res


def get_alias_infos_with_pagination(user, page_id=0, query=None) -> [AliasInfo]:
    ret = []
    q = (
        Session.query(Alias)
        .options(joinedload(Alias.mailbox))
        .filter(Alias.user_id == user.id)
        .order_by(Alias.created_at.desc())
    )

    if query:
        q = q.filter(
            or_(Alias.email.ilike(f"%{query}%"), Alias.note.ilike(f"%{query}%"))
        )

    q = q.limit(PAGE_LIMIT).offset(page_id * PAGE_LIMIT)

    for alias in q:
        ret.append(get_alias_info(alias))

    return ret


def get_alias_infos_with_pagination_v3(
    user,
    page_id=0,
    query=None,
    sort=None,
    alias_filter=None,
    mailbox_id=None,
    directory_id=None,
    page_limit=PAGE_LIMIT,
    page_size=PAGE_LIMIT,
) -> [AliasInfo]:
    q = construct_alias_query(user)

    if query:
        q = q.filter(
            or_(
                Alias.email.ilike(f"%{query}%"),
                Alias.note.ilike(f"%{query}%"),
                
                
                Alias.ts_vector.op("@@")(func.plainto_tsquery("english", query)),
                Alias.name.ilike(f"%{query}%"),
            )
        )

    if mailbox_id:
        q = q.join(
            AliasMailbox, Alias.id == AliasMailbox.alias_id, isouter=True
        ).filter(
            or_(Alias.mailbox_id == mailbox_id, AliasMailbox.mailbox_id == mailbox_id)
        )

    if directory_id:
        q = q.filter(Alias.directory_id == directory_id)

    if alias_filter == "enabled":
        q = q.filter(Alias.enabled)
    elif alias_filter == "disabled":
        q = q.filter(Alias.enabled.is_(False))
    elif alias_filter == "pinned":
        q = q.filter(Alias.pinned)
    elif alias_filter == "hibp":
        q = q.filter(Alias.hibp_breaches.any())

    if sort == "old2new":
        q = q.order_by(Alias.created_at)
    elif sort == "new2old":
        q = q.order_by(Alias.created_at.desc())
    elif sort == "a2z":
        q = q.order_by(Alias.email)
    elif sort == "z2a":
        q = q.order_by(Alias.email.desc())
    else:
        
        latest_activity = case(
            [
                (Alias.created_at > EmailLog.created_at, Alias.created_at),
                (Alias.created_at < EmailLog.created_at, EmailLog.created_at),
            ],
            else_=Alias.created_at,
        )
        q = q.order_by(Alias.pinned.desc())
        q = q.order_by(latest_activity.desc())

    q = q.limit(page_limit).offset(page_id * page_size)

    ret = []
