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


    def replace_header_when_forward(msg: Message, alias: Alias, header: str):

    new_addrs: [str] = []
    headers = msg.get_all(header, [])
    
    headers = [get_header_unicode(h) for h in headers]

    full_addresses: [EmailAddress] = []
    for h in headers:
        full_addresses += address.parse_list(h)

    for full_address in full_addresses:
        contact_email = sanitize_email(full_address.address, not_lower=True)

        
        if contact_email.lower() == alias.email:
            new_addrs.append(full_address.full_spec())
            continue

        try:
            
            validate_email(
                contact_email, check_deliverability=False, allow_smtputf8=False
            )
        except EmailNotValidError:
            LOG.w("invalid contact email %s. %s. Skip", contact_email, headers)
            continue

        contact = Contact.get_by(alias_id=alias.id, website_email=contact_email)
        contact_name = full_address.display_name
        if len(contact_name) >= Contact.MAX_NAME_LENGTH:
            contact_name = contact_name[0 : Contact.MAX_NAME_LENGTH]

        if contact:
            
            if contact.name != full_address.display_name:
                LOG.d(
                    "Update contact %s name %s to %s",
                    contact,
                    contact.name,
                    contact_name,
                )
                contact.name = contact_name
                Session.commit()
        else:
            LOG.d(
                "create contact for alias %s and email %s, header %s",
                alias,
                contact_email,
                header,
            )

            try:
                contact = Contact.create(
                    user_id=alias.user_id,
                    alias_id=alias.id,
                    website_email=contact_email,
                    name=contact_name,
                    reply_email=generate_reply_email(contact_email, alias),
                    is_cc=header.lower() == "cc",
                    automatic_created=True,
                )
                Session.commit()
            except IntegrityError:
                LOG.w("Contact %s %s already exist", alias, contact_email)
                Session.rollback()
                contact = Contact.get_by(alias_id=alias.id, website_email=contact_email)

        new_addrs.append(contact.new_addr())

    if new_addrs:
        new_header = ",".join(new_addrs)
        LOG.d("Replace %s header, old: %s, new: %s", header, msg[header], new_header)
        add_or_replace_header(msg, header, new_header)
    else:
        LOG.d("Delete %s header, old value %s", header, msg[header])
        delete_header(msg, header)


def replace_header_when_reply(msg: Message, alias: Alias, header: str):

    new_addrs: [str] = []
    headers = msg.get_all(header, [])
    
    headers = [str(h) for h in headers]

    
    headers = [h.replace("\r", "") for h in headers]
    headers = [h.replace("\n", "") for h in headers]

    for _, reply_email in getaddresses(headers):
        
        
        if reply_email == alias.email:
            continue

        contact = Contact.get_by(reply_email=reply_email)
        if not contact:
            LOG.w(
                "email %s contained in %s header in reply phase must be reply emails. headers:%s",
                reply_email,
                header,
                headers,
            )
            raise NonReverseAliasInReplyPhase(reply_email)
            
            
        else:
            new_addrs.append(sl_formataddr((contact.name, contact.website_email)))

    if new_addrs:
        new_header = ",".join(new_addrs)
        LOG.d("Replace %s header, old: %s, new: %s", header, msg[header], new_header)
        add_or_replace_header(msg, header, new_header)
    else:
        LOG.d("delete the %s header. Old value %s", header, msg[header])
        delete_header(msg, header)


def prepare_pgp_message(
    orig_msg: Message, pgp_fingerprint: str, public_key: str, can_sign: bool = False
) -> Message:
    msg = MIMEMultipart("encrypted", protocol="application/pgp-encrypted")

    
    clone_msg = copy(orig_msg)

    
    for i in reversed(range(len(clone_msg._headers))):
        header_name = clone_msg._headers[i][0].lower()
        if header_name.lower() not in headers.MIME_HEADERS:
            msg[header_name] = clone_msg._headers[i][1]

    
    delete_all_headers_except(
        clone_msg,
        headers.MIME_HEADERS,
    )

    if clone_msg[headers.CONTENT_TYPE] is None:
        LOG.d("Content-Type missing")
        clone_msg[headers.CONTENT_TYPE] = "text/plain"

    if clone_msg[headers.MIME_VERSION] is None:
        LOG.d("Mime-Version missing")
        clone_msg[headers.MIME_VERSION] = "1.0"

    first = MIMEApplication(
        _subtype="pgp-encrypted", _encoder=encoders.encode_7or8bit, _data=""
    )
    first.set_payload("Version: 1")
    msg.attach(first)

    if can_sign and PGP_SENDER_PRIVATE_KEY:
        LOG.d("Sign msg")
        clone_msg = sign_msg(clone_msg)

    
    second = MIMEApplication(
        "octet-stream", _encoder=encoders.encode_7or8bit, name="encrypted.asc"
    )
    second.add_header("Content-Disposition", 'inline; filename="encrypted.asc"')

    
    
    msg_bytes = message_to_bytes(clone_msg)
    try:
        encrypted_data = pgp_utils.encrypt_file(BytesIO(msg_bytes), pgp_fingerprint)
        second.set_payload(encrypted_data)
    except PGPException:
        LOG.w(
            "Cannot encrypt using python-gnupg, check if public key is valid and try with pgpy"
        )
        
        load_public_key_and_check(public_key)

        encrypted = pgp_utils.encrypt_file_with_pgpy(msg_bytes, public_key)
        second.set_payload(str(encrypted))
        LOG.i(
            f"encryption works with pgpy and not with python-gnupg, public key {public_key}"
        )

    msg.attach(second)

    return msg


def sign_msg(msg: Message) -> Message:
    container = MIMEMultipart(
        "signed", protocol="application/pgp-signature", micalg="pgp-sha256"
    )
    container.attach(msg)

    signature = MIMEApplication(
        _subtype="pgp-signature", name="signature.asc", _data="", _encoder=encode_noop
    )
    signature.add_header("Content-Disposition", 'attachment; filename="signature.asc"')

    try:
        payload = sign_data(message_to_bytes(msg).replace(b"\n", b"\r\n"))

        if not payload:
            raise PGPException("Empty signature by gnupg")

        signature.set_payload(payload)
    except Exception:
        LOG.e("Cannot sign, try using pgpy")
        payload = sign_data_with_pgpy(message_to_bytes(msg).replace(b"\n", b"\r\n"))

        if not payload:
            raise PGPException("Empty signature by pgpy")

        signature.set_payload(payload)

    container.attach(signature)

    return container


def handle_email_sent_to_ourself(alias, from_addr: str, msg: Message, user):
    
    random_name = str(uuid.uuid4())
    full_report_path = f"refused-emails/cycle-{random_name}.eml"
    s3.upload_email_from_bytesio(
        full_report_path, BytesIO(message_to_bytes(msg)), random_name
    )
    refused_email = RefusedEmail.create(
        path=None, full_report_path=full_report_path, user_id=alias.user_id
    )
    Session.commit()
    LOG.d("Create refused email %s", refused_email)
    
    refused_email_url = refused_email.get_url(expires_in=518400)

    Notification.create(
        user_id=user.id,
        title=f"Email sent to {alias.email} from its own mailbox {from_addr}",
        message=Notification.render(
            "notification/cycle-email.html",
            alias=alias,
            from_addr=from_addr,
            refused_email_url=refused_email_url,
        ),
        commit=True,
    )

    send_email_at_most_times(
        user,
        ALERT_SEND_EMAIL_CYCLE,
        from_addr,
        f"Email sent to {alias.email} from its own mailbox {from_addr}",
        render(
            "transactional/cycle-email.txt.jinja2",
            user=user,
            alias=alias,
            from_addr=from_addr,
            refused_email_url=refused_email_url,
        ),
        render(
            "transactional/cycle-email.html",
            user=user,
            alias=alias,
            from_addr=from_addr,
            refused_email_url=refused_email_url,
        ),
    )


def handle_forward(envelope, msg: Message, rcpt_to: str) -> List[Tuple[bool, str]]:

    alias_address = rcpt_to  

    alias = Alias.get_by(email=alias_address)
    if not alias:
        LOG.d(
            "alias %s not exist. Try to see if it can be created on the fly",
            alias_address,
        )
        alias = try_auto_create(alias_address)
        if not alias:
            LOG.d("alias %s cannot be created on-the-fly, return 550", alias_address)
            if should_ignore_bounce(envelope.mail_from):
                return [(True, status.E207)]
            else:
                return [(False, status.E515)]

    user = alias.user

    if not user.is_active():
        LOG.w(f"User {user} has been soft deleted")
        return False, status.E502

    if not user.can_send_or_receive():
        LOG.i(f"User {user} cannot receive emails")
        if should_ignore_bounce(envelope.mail_from):
            return [(True, status.E207)]
        else:
            return [(False, status.E504)]

    
    mail_from = envelope.mail_from
    for addr in alias.authorized_addresses():
        
        if addr == mail_from:
            LOG.i("cycle email sent from %s to %s", addr, alias)
            handle_email_sent_to_ourself(alias, addr, msg, user)
            return [(True, status.E209)]

    from_header = get_header_unicode(msg[headers.FROM])
    LOG.d("Create or get contact for from_header:%s", from_header)
    contact = get_or_create_contact(from_header, envelope.mail_from, alias)
    alias = (
        contact.alias
    )  

    reply_to_contact = None
    if msg[headers.REPLY_TO]:
        reply_to = get_header_unicode(msg[headers.REPLY_TO])
        LOG.d("Create or get contact for reply_to_header:%s", reply_to)
        
        if reply_to == alias.email:
            LOG.i("Reply-to same as alias %s", alias)
        else:
            reply_to_contact = get_or_create_reply_to_contact(reply_to, alias, msg)

    if not alias.enabled or contact.block_forward:
        LOG.d("%s is disabled, do not forward", alias)
        EmailLog.create(
            contact_id=contact.id,
            user_id=contact.user_id,
            blocked=True,
            alias_id=contact.alias_id,
            commit=True,
        )

        res_status = status.E200
        if user.block_behaviour == BlockBehaviourEnum.return_5xx:
            res_status = status.E502

        return [(True, res_status)]

    
    msg, dmarc_delivery_status = apply_dmarc_policy_for_forward_phase(
        alias, contact, envelope, msg
    )
    if dmarc_delivery_status is not None:
        return [(False, dmarc_delivery_status)]

    ret = []
    mailboxes = alias.mailboxes

    
    if not mailboxes:
        LOG.w("no valid mailboxes for %s", alias)
        if should_ignore_bounce(envelope.mail_from):
            return [(True, status.E207)]
        else:
            return [(False, status.E516)]

    for mailbox in mailboxes:
        if not mailbox.verified:
            LOG.d("%s unverified, do not forward", mailbox)
            ret.append((False, status.E517))
        else:
            
            mailbox_as_alias = Alias.get_by(email=mailbox.email)
            if mailbox_as_alias is not None:
                LOG.info(
                    f"Mailbox {mailbox.id} has email {mailbox.email} that is also alias {alias.id}. Stopping loop"
                )
                mailbox.verified = False
                Session.commit()
                mailbox_url = f"{URL}/dashboard/mailbox/{mailbox.id}/"
                send_email_with_rate_control(
                    user,
                    ALERT_MAILBOX_IS_ALIAS,
                    user.email,
                    f"Your mailbox {mailbox.email} is an alias",
                    render(
                        "transactional/mailbox-invalid.txt.jinja2",
                        user=mailbox.user,
                        mailbox=mailbox,
                        mailbox_url=mailbox_url,
                        alias=alias,
                    ),
                    render(
                        "transactional/mailbox-invalid.html",
                        user=mailbox.user,
                        mailbox=mailbox,
                        mailbox_url=mailbox_url,
                        alias=alias,
                    ),
                    max_nb_alert=1,
                )
                ret.append((False, status.E525))
                continue
            
            ret.append(
                forward_email_to_mailbox(
                    alias, copy(msg), contact, envelope, mailbox, user, reply_to_contact
                )
            )

    return ret