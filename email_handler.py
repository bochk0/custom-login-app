import email

from app import pgp_utils, s3, config
from app.alias_utils import try_auto_create, change_alias_status
from app.config import (
    EMAIL_DOMAIN,
    URL,
    UNSUBSCRIBER,
    LOAD_PGP_EMAIL_HANDLER,
    ENFORCE_SPF,
    ALERT_REVERSE_ALIAS_UNKNOWN_MAILBOX,
    ALERT_BOUNCE_EMAIL,
    ALERT_SPAM_EMAIL,
    SPAMASSASSIN_HOST,
    MAX_SPAM_SCORE,
    MAX_REPLY_PHASE_SPAM_SCORE,
    ALERT_SEND_EMAIL_CYCLE,
    ALERT_MAILBOX_IS_ALIAS,
    PGP_SENDER_PRIVATE_KEY,
    ALERT_BOUNCE_EMAIL_REPLY_PHASE,
    NOREPLY,
    BOUNCE_PREFIX,
    BOUNCE_SUFFIX,
    TRANSACTIONAL_BOUNCE_PREFIX,
    TRANSACTIONAL_BOUNCE_SUFFIX,
    ENABLE_SPAM_ASSASSIN,
    BOUNCE_PREFIX_FOR_REPLY_PHASE,
    POSTMASTER,
    OLD_UNSUBSCRIBER,
    ALERT_FROM_ADDRESS_IS_REVERSE_ALIAS,
    ALERT_TO_NOREPLY,
)

from app.db import Session
from app.email import status, headers
from app.email.rate_limit import rate_limited
from app.email.spam import get_spam_score
from app.email_utils import (
    send_email,
    add_dkim_signature,
    add_or_replace_header,
    delete_header,
    render,
    get_orig_message_from_bounce,
    delete_all_headers_except,
    get_spam_info,
    get_orig_message_from_spamassassin_report,
    send_email_with_rate_control,
    get_email_domain_part,
    copy,
    send_email_at_most_times,
    is_valid_alias_address_domain,
    should_add_dkim_signature,
    add_header,
    get_header_unicode,
    generate_reply_email,
    is_reverse_alias,
    replace,
    should_disable,
    parse_id_from_bounce,
    spf_pass,
    sanitize_header,
    get_queue_id,
    should_ignore_bounce,
    parse_full_address,
    get_mailbox_bounce_info,
    save_email_for_debugging,
    save_envelope_for_debugging,
    get_verp_info_from_email,
    generate_verp_email,
    sl_formataddr,
)

from app.handler.unsubscribe_generator import UnsubscribeGenerator
from app.handler.unsubscribe_handler import UnsubscribeHandler
from app.log import LOG, set_message_id
from app.mail_sender import sl_sendmail
from app.message_utils import message_to_bytes
from app.models import (
    Alias,
    Contact,
    BlockBehaviourEnum,
    EmailLog,
    User,
    RefusedEmail,
    Mailbox,
    Bounce,
    TransactionalEmail,
    IgnoredEmail,
    MessageIDMatching,
    Notification,
    VerpType,
    SLDomain,
)



def get_or_create_contact(from_header: str, mail_from: str, alias: Alias) -> Contact:

    try:
        contact_name, contact_email = parse_full_address(from_header)
    except ValueError:
        contact_name, contact_email = "", ""

    
    if len(contact_name) >= Contact.MAX_NAME_LENGTH:
        contact_name = contact_name[0 : Contact.MAX_NAME_LENGTH]

    if not is_valid_email(contact_email):
        
        if mail_from and mail_from != "<>":
            LOG.w(
                "Cannot parse email from from_header %s, use mail_from %s",
                from_header,
                mail_from,
            )
            contact_email = mail_from

    if not is_valid_email(contact_email):
        LOG.w(
            "invalid contact email %s. Parse from %s %s",
            contact_email,
            from_header,
            mail_from,
        )
        
        contact_email = ""

    contact_email = sanitize_email(contact_email, not_lower=True)

    if contact_name and "\x00" in contact_name:
        LOG.w("issue with contact name %s", contact_name)
        contact_name = ""

    contact = Contact.get_by(alias_id=alias.id, website_email=contact_email)
    if contact:
        if contact.name != contact_name:
            LOG.d(
                "Update contact %s name %s to %s",
                contact,
                contact.name,
                contact_name,
            )
            contact.name = contact_name
            Session.commit()

        
        if not contact.mail_from and mail_from:
            LOG.d(
                "Set contact mail_from %s: %s to %s",
                contact,
                contact.mail_from,
                mail_from,
            )
            contact.mail_from = mail_from
            Session.commit()
    else:
        alias_id = alias.id
        try:
            contact_email_for_reply = (
                contact_email if is_valid_email(contact_email) else ""
            )
            contact = Contact.create(
                user_id=alias.user_id,
                alias_id=alias_id,
                website_email=contact_email,
                name=contact_name,
                mail_from=mail_from,
                reply_email=generate_reply_email(contact_email_for_reply, alias),
                automatic_created=True,
            )
            if not contact_email:
                LOG.d("Create a contact with invalid email for %s", alias)
                contact.invalid_email = True

            LOG.d(
                "create contact %s for %s, reverse alias:%s",
                contact_email,
                alias,
                contact.reply_email,
            )

            Session.commit()
        except IntegrityError:
            
            Session.close()
            LOG.info(
                f"Contact with email {contact_email} for alias_id {alias_id} already existed, fetching from DB"
            )
            contact = Contact.get_by(alias_id=alias_id, website_email=contact_email)

    return contact


def get_or_create_reply_to_contact(
    reply_to_header: str, alias: Alias, msg: Message
) -> Optional[Contact]:

    try:
        contact_name, contact_address = parse_full_address(reply_to_header)
    except ValueError:
        return

    if len(contact_name) >= Contact.MAX_NAME_LENGTH:
        contact_name = contact_name[0 : Contact.MAX_NAME_LENGTH]

    if not is_valid_email(contact_address):
        LOG.w(
            "invalid reply-to address %s. Parse from %s",
            contact_address,
            reply_to_header,
        )
        return None

    contact = Contact.get_by(alias_id=alias.id, website_email=contact_address)
    if contact:
        return contact
    else:
        LOG.d(
            "create contact %s for alias %s via reply-to header %s",
            contact_address,
            alias,
            reply_to_header,
        )

        try:
            contact = Contact.create(
                user_id=alias.user_id,
                alias_id=alias.id,
                website_email=contact_address,
                name=contact_name,
                reply_email=generate_reply_email(contact_address, alias),
                automatic_created=True,
            )
            Session.commit()
        except IntegrityError:
            LOG.w("Contact %s %s already exist", alias, contact_address)
            Session.rollback()
            contact = Contact.get_by(alias_id=alias.id, website_email=contact_address)

    return contact