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


    def forward_email_to_mailbox(
    alias,
    msg: Message,
    contact: Contact,
    envelope,
    mailbox,
    user,
    reply_to_contact: Optional[Contact],
) -> (bool, str):
    LOG.d("Forward %s -> %s -> %s", contact, alias, mailbox)

    if mailbox.disabled:
        LOG.d("%s disabled, do not forward")
        if should_ignore_bounce(envelope.mail_from):
            return True, status.E207
        else:
            return False, status.E518

    
    if get_email_domain_part(alias.email) == get_email_domain_part(mailbox.email):
        LOG.w(
            "Mailbox has the same domain as alias. %s -> %s -> %s",
            contact,
            alias,
            mailbox,
        )
        mailbox_url = f"{URL}/dashboard/mailbox/{mailbox.id}/"
        send_email_with_rate_control(
            user,
            ALERT_MAILBOX_IS_ALIAS,
            user.email,
            f"Your mailbox {mailbox.email} and alias {alias.email} use the same domain",
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

        return False, status.E405

    email_log = EmailLog.create(
        contact_id=contact.id,
        user_id=user.id,
        mailbox_id=mailbox.id,
        alias_id=contact.alias_id,
        message_id=str(msg[headers.MESSAGE_ID]),
        commit=True,
    )
    LOG.d("Create %s for %s, %s, %s", email_log, contact, user, mailbox)

    if ENABLE_SPAM_ASSASSIN:
        
        spam_status = ""
        is_spam = False

        if SPAMASSASSIN_HOST:
            start = time.time()
            spam_score, spam_report = get_spam_score(msg, email_log)
            LOG.d(
                "%s -> %s - spam score:%s in %s seconds. Spam report %s",
                contact,
                alias,
                spam_score,
                time.time() - start,
                spam_report,
            )
            email_log.spam_score = spam_score
            Session.commit()

            if (user.max_spam_score and spam_score > user.max_spam_score) or (
                not user.max_spam_score and spam_score > MAX_SPAM_SCORE
            ):
                is_spam = True
                
                email_log.spam_report = spam_report
        else:
            is_spam, spam_status = get_spam_info(msg, max_score=user.max_spam_score)

        if is_spam:
            LOG.w(
                "Email detected as spam. %s -> %s. Spam Score: %s, Spam Report: %s",
                contact,
                alias,
                email_log.spam_score,
                email_log.spam_report,
            )
            email_log.is_spam = True
            email_log.spam_status = spam_status
            Session.commit()

            handle_spam(contact, alias, msg, user, mailbox, email_log)
            return False, status.E519

    if contact.invalid_email:
        LOG.d("add noreply information %s %s", alias, mailbox)
        msg = add_header(
            msg,
            f"""Email sent to {alias.email} from an invalid address and cannot be replied""",
            f"""Email sent to {alias.email} from an invalid address and cannot be replied""",
        )

    headers_to_keep = [
        headers.FROM,
        headers.TO,
        headers.CC,
        headers.SUBJECT,
        headers.DATE,
        
        headers.MESSAGE_ID,
        
        headers.REFERENCES,
        headers.IN_REPLY_TO,
        headers.SL_QUEUE_ID,
        headers.LIST_UNSUBSCRIBE,
        headers.LIST_UNSUBSCRIBE_POST,
    ] + headers.MIME_HEADERS
    if user.include_header_email_header:
        headers_to_keep.append(headers.AUTHENTICATION_RESULTS)
    delete_all_headers_except(msg, headers_to_keep)


    if mailbox.pgp_enabled() and user.is_premium() and not alias.disable_pgp:
        LOG.d("Encrypt message using mailbox %s", mailbox)

        try:
            msg = prepare_pgp_message(
                msg, mailbox.pgp_finger_print, mailbox.pgp_public_key, can_sign=True
            )
        except PGPException:
            LOG.w(
                "Cannot encrypt message %s -> %s. %s %s", contact, alias, mailbox, user
            )
            msg = add_header(
                msg,
                f"""PGP encryption fails with {mailbox.email}'s PGP key""",
            )

    
    add_or_replace_header(msg, headers.SL_DIRECTION, "Forward")

    msg[headers.SL_EMAIL_LOG_ID] = str(email_log.id)
    if user.include_header_email_header:
        msg[headers.SL_ENVELOPE_FROM] = envelope.mail_from
        if contact.name:
            original_from = f"{contact.name} <{contact.website_email}>"
        else:
            original_from = contact.website_email
        msg[headers.SL_ORIGINAL_FROM] = original_from
    
    msg[headers.SL_ENVELOPE_TO] = alias.email

    if not msg[headers.DATE]:
        LOG.w("missing date header, create one")
        msg[headers.DATE] = formatdate()

    replace_sl_message_id_by_original_message_id(msg)

    old_from_header = msg[headers.FROM]
    new_from_header = contact.new_addr()
    add_or_replace_header(msg, "From", new_from_header)
    LOG.d("From header, new:%s, old:%s", new_from_header, old_from_header)

    if reply_to_contact:
        reply_to_header = msg[headers.REPLY_TO]
        new_reply_to_header = reply_to_contact.new_addr()
        add_or_replace_header(msg, "Reply-To", new_reply_to_header)
        LOG.d("Reply-To header, new:%s, old:%s", new_reply_to_header, reply_to_header)

    try:
        replace_header_when_forward(msg, alias, headers.CC)
        replace_header_when_forward(msg, alias, headers.TO)
    except CannotCreateContactForReverseAlias:
        LOG.d("CannotCreateContactForReverseAlias error, delete %s", email_log)
        EmailLog.delete(email_log.id)
        Session.commit()
        raise

    add_alias_to_header_if_needed(msg, alias)

    
    msg = UnsubscribeGenerator().add_header_to_message(alias, contact, msg)

    add_dkim_signature(msg, EMAIL_DOMAIN)

    LOG.d(
        "Forward mail from %s to %s, mail_options:%s, rcpt_options:%s ",
        contact.website_email,
        mailbox.email,
        envelope.mail_options,
        envelope.rcpt_options,
    )

    contact_domain = get_email_domain_part(contact.reply_email)
    try:
        sl_sendmail(
            
            generate_verp_email(VerpType.bounce_forward, email_log.id, contact_domain),
            mailbox.email,
            msg,
            envelope.mail_options,
            envelope.rcpt_options,
            is_forward=True,
        )
    except (SMTPServerDisconnected, SMTPRecipientsRefused, TimeoutError):
        LOG.w(
            "Postfix error during forward phase %s -> %s -> %s",
            contact,
            alias,
            mailbox,
            exc_info=True,
        )
        if should_ignore_bounce(envelope.mail_from):
            return True, status.E207
        else:
            EmailLog.delete(email_log.id, commit=True)
            
            return False, status.E407
    else:
        Session.commit()
        return True, status.E200


def handle_reply(envelope, msg: Message, rcpt_to: str) -> (bool, str):

    reply_email = rcpt_to

    reply_domain = get_email_domain_part(reply_email)

    
    if not reply_email.endswith(EMAIL_DOMAIN):
        sl_domain: SLDomain = SLDomain.get_by(domain=reply_domain)
        if sl_domain is None:
            LOG.w(f"Reply email {reply_email} has wrong domain")
            return False, status.E501

    
    reply_email = normalize_reply_email(reply_email)

    contact = Contact.get_by(reply_email=reply_email)
    if not contact:
        LOG.w(f"No contact with {reply_email} as reverse alias")
        return False, status.E502
    if not contact.user.is_active():
        LOG.w(f"User {contact.user} has been soft deleted")
        return False, status.E502

    alias = contact.alias
    alias_address: str = contact.alias.email
    alias_domain = get_email_domain_part(alias_address)
    
    if not is_valid_alias_address_domain(alias.email):
        LOG.e("%s domain isn't known", alias)
        return False, status.E503

    user = alias.user
    mail_from = envelope.mail_from

    if not user.can_send_or_receive():
        LOG.i(f"User {user} cannot send emails")
        return False, status.E504

    
    dmarc_delivery_status = apply_dmarc_policy_for_reply_phase(
        alias, contact, envelope, msg
    )
    if dmarc_delivery_status is not None:
        return False, dmarc_delivery_status

    
    mailbox = get_mailbox_from_mail_from(mail_from, alias)


    if ENFORCE_SPF and mailbox.force_spf and not alias.disable_email_spoofing_check:
        if not spf_pass(envelope, mailbox, user, alias, contact.website_email, msg):
            
            
            return True, status.E201

    email_log = EmailLog.create(
        contact_id=contact.id,
        alias_id=contact.alias_id,
        is_reply=True,
        user_id=contact.user_id,
        mailbox_id=mailbox.id,
        message_id=msg[headers.MESSAGE_ID],
        commit=True,
    )
    LOG.d("Create %s for %s, %s, %s", email_log, contact, user, mailbox)

    
    if ENABLE_SPAM_ASSASSIN:
        spam_status = ""
        is_spam = False

        
        if SPAMASSASSIN_HOST:
            start = time.time()
            spam_score, spam_report = get_spam_score(msg, email_log)
            LOG.d(
                "%s -> %s - spam score %s in %s seconds. Spam report %s",
                alias,
                contact,
                spam_score,
                time.time() - start,
                spam_report,
            )
            email_log.spam_score = spam_score
            if spam_score > MAX_REPLY_PHASE_SPAM_SCORE:
                is_spam = True
                
                email_log.spam_report = spam_report
        else:
            is_spam, spam_status = get_spam_info(
                msg, max_score=MAX_REPLY_PHASE_SPAM_SCORE
            )

        if is_spam:
            LOG.w(
                "Email detected as spam. Reply phase. %s -> %s. Spam Score: %s, Spam Report: %s",
                alias,
                contact,
                email_log.spam_score,
                email_log.spam_report,
            )

            email_log.is_spam = True
            email_log.spam_status = spam_status
            Session.commit()

            handle_spam(contact, alias, msg, user, mailbox, email_log, is_reply=True)
            return False, status.E506

    delete_all_headers_except(
        msg,
        [
            headers.FROM,
            headers.TO,
            headers.CC,
            headers.SUBJECT,
            headers.DATE,
            
            headers.MESSAGE_ID,
            
            headers.REFERENCES,
            headers.IN_REPLY_TO,
            headers.SL_QUEUE_ID,
        ]
        + headers.MIME_HEADERS,
    )

    orig_to = msg[headers.TO]
    orig_cc = msg[headers.CC]

    
    if user.replace_reverse_alias:
        LOG.d("Replace reverse-alias %s by contact email %s", reply_email, contact)
        msg = replace(msg, reply_email, contact.website_email)
        LOG.d("Replace mailbox %s by alias email %s", mailbox.email, alias.email)
        msg = replace(msg, mailbox.email, alias.email)

        if config.ENABLE_ALL_REVERSE_ALIAS_REPLACEMENT:
            start = time.time()
            
            contact_query = (
                Contact.query()
                .filter(Contact.alias_id == alias.id)
                .limit(config.MAX_NB_REVERSE_ALIAS_REPLACEMENT)
            )
            
            for reply_email, website_email in contact_query.values(
                Contact.reply_email, Contact.website_email
            ):
                msg = replace(msg, reply_email, website_email)

            elapsed = time.time() - start
            LOG.d(
                "Replace reverse alias by real address for %s contacts takes %s seconds",
                contact_query.count(),
                elapsed,
            )
            newrelic.agent.record_custom_metric(
                "Custom/reverse_alias_replacement_time", elapsed
            )

    
    if contact.pgp_finger_print and user.is_premium():
        LOG.d("Encrypt message for contact %s", contact)
        try:
            msg = prepare_pgp_message(
                msg, contact.pgp_finger_print, contact.pgp_public_key
            )
        except PGPException:
            LOG.e(
                "Cannot encrypt message %s -> %s. %s %s", alias, contact, mailbox, user
            )
            
            EmailLog.delete(email_log.id, commit=True)
            
            return False, status.E402

    Session.commit()

    
    from_header = alias.email
    
    if alias.name:
        LOG.d("Put alias name %s in from header", alias.name)
        from_header = sl_formataddr((alias.name, alias.email))
    elif alias.custom_domain:
        
        if alias.custom_domain.name:
            LOG.d(
                "Put domain default alias name %s in from header",
                alias.custom_domain.name,
            )
            from_header = sl_formataddr((alias.custom_domain.name, alias.email))

    LOG.d("From header is %s", from_header)
    add_or_replace_header(msg, headers.FROM, from_header)

    try:
        if str(msg[headers.TO]).lower() == "undisclosed-recipients:;":
            
            LOG.d("email is sent in BCC mode")
        else:
            replace_header_when_reply(msg, alias, headers.TO)

        replace_header_when_reply(msg, alias, headers.CC)


    if not msg[headers.DATE]:
        date_header = formatdate()
        LOG.w("missing date header, add one")
        msg[headers.DATE] = date_header

    msg[headers.SL_DIRECTION] = "Reply"
    msg[headers.SL_EMAIL_LOG_ID] = str(email_log.id)

    LOG.d(
        "send email from %s to %s, mail_options:%s,rcpt_options:%s",
        alias.email,
        contact.website_email,
        envelope.mail_options,
        envelope.rcpt_options,
    )

    if should_add_dkim_signature(alias_domain):
        add_dkim_signature(msg, alias_domain)

    try:
        sl_sendmail(
            generate_verp_email(VerpType.bounce_reply, email_log.id, alias_domain),
            contact.website_email,
            msg,
            envelope.mail_options,
            envelope.rcpt_options,
            is_forward=False,
        )

        
        other_mailboxes = [mb for mb in alias.mailboxes if mb.email != mailbox.email]
        for mb in other_mailboxes:
            notify_mailbox(alias, mailbox, mb, msg, orig_to, orig_cc, alias_domain)

    except Exception:
        LOG.w("Cannot send email from %s to %s", alias, contact)
        EmailLog.delete(email_log.id, commit=True)
        send_email(
            mailbox.email,
            f"Email cannot be sent to {contact.email} from {alias.email}",
            render(
                "transactional/reply-error.txt.jinja2",
                user=user,
                alias=alias,
                contact=contact,
                contact_domain=get_email_domain_part(contact.email),
            ),
            render(
                "transactional/reply-error.html",
                user=user,
                alias=alias,
                contact=contact,
                contact_domain=get_email_domain_part(contact.email),
            ),
        )

    
    return True, status.E200


def notify_mailbox(
    alias, mailbox, other_mb: Mailbox, msg, orig_to, orig_cc, alias_domain
):
    """Notify another mailbox about an email sent by a mailbox to a reverse alias"""
    LOG.d(
        f"notify {other_mb.email} about email sent "
        f"from {mailbox.email} on behalf of {alias.email} to {msg[headers.TO]}"
    )
    notif = add_header(
        msg,
        f"""**** Don't forget to remove this section if you reply to this email ****
Email sent on behalf of alias {alias.email} using mailbox {mailbox.email}""",
    )
    
    add_or_replace_header(notif, headers.FROM, alias.email)
    
    add_or_replace_header(notif, headers.TO, orig_to)
    add_or_replace_header(notif, headers.CC, orig_cc)

    
    if should_add_dkim_signature(alias_domain):
        add_dkim_signature(msg, alias_domain)

    
    transaction = TransactionalEmail.create(email=other_mb.email, commit=True)
    sl_sendmail(
        generate_verp_email(VerpType.transactional, transaction.id, alias_domain),
        other_mb.email,
        notif,
    )


def replace_original_message_id(alias: Alias, email_log: EmailLog, msg: Message):

    original_message_id = msg[headers.MESSAGE_ID]
    if original_message_id:
        matching = MessageIDMatching.get_by(original_message_id=original_message_id)
        
        if matching:
            sl_message_id = matching.sl_message_id
            LOG.d("reuse the sl_message_id %s", sl_message_id)
            else:
            sl_message_id = make_msgid(
                str(email_log.id), get_email_domain_part(alias.email)
            )
            LOG.d("create a new sl_message_id %s", sl_message_id)
            try:
                MessageIDMatching.create(
                    sl_message_id=sl_message_id,
                    original_message_id=original_message_id,
                    email_log_id=email_log.id,
                    commit=True,
                )
            except IntegrityError:
                LOG.w(
                    "another matching with original_message_id %s was created in the mean time",
                    original_message_id,
                )
                Session.rollback()
                matching = MessageIDMatching.get_by(
                    original_message_id=original_message_id
                )
                sl_message_id = matching.sl_message_id
    else:
        sl_message_id = make_msgid(
            str(email_log.id), get_email_domain_part(alias.email)
        )
        LOG.d("no original_message_id, create a new sl_message_id %s", sl_message_id)

    del msg[headers.MESSAGE_ID]
    msg[headers.MESSAGE_ID] = sl_message_id

    email_log.sl_message_id = sl_message_id
    Session.commit()

    
    if msg[headers.REFERENCES]:
        message_ids = str(msg[headers.REFERENCES]).split()
        new_message_ids = []
        for message_id in message_ids:
            matching = MessageIDMatching.get_by(original_message_id=message_id)
            if matching:
                LOG.d(
                    "replace original message id by SL one, %s -> %s",
                    message_id,
                    matching.sl_message_id,
                )
                new_message_ids.append(matching.sl_message_id)
            else:
                new_message_ids.append(message_id)

        del msg[headers.REFERENCES]
        msg[headers.REFERENCES] = " ".join(new_message_ids)



def handle_unknown_mailbox(
    envelope, msg, reply_email: str, user: User, alias: Alias, contact: Contact
):
    LOG.w(
        "Reply email can only be used by mailbox. "
        "Actual mail_from: %s. msg from header: %s, reverse-alias %s, %s %s %s",
        envelope.mail_from,
        msg[headers.FROM],
        reply_email,
        alias,
        user,
        contact,
    )

    authorize_address_link = (
        f"{URL}/dashboard/mailbox/{alias.mailbox_id}/
    )
    mailbox_emails = [mailbox.email for mailbox in alias.mailboxes]
    send_email_with_rate_control(
        user,
        ALERT_REVERSE_ALIAS_UNKNOWN_MAILBOX,
        user.email,
        f"Attempt to use your alias {alias.email} from {envelope.mail_from}",
        render(
            "transactional/reply-must-use-personal-email.txt",
            user=user,
            alias=alias,
            sender=envelope.mail_from,
            authorize_address_link=authorize_address_link,
            mailbox_emails=mailbox_emails,
        ),
        render(
            "transactional/reply-must-use-personal-email.html",
            user=user,
            alias=alias,
            sender=envelope.mail_from,
            authorize_address_link=authorize_address_link,
            mailbox_emails=mailbox_emails,
        ),
    )


def handle_bounce_forward_phase(msg: Message, email_log: EmailLog):

    contact = email_log.contact
    alias = contact.alias
    user = alias.user
    mailbox = email_log.mailbox

    
    if not mailbox:
        LOG.e("Use %s default mailbox %s", alias, alias.mailbox)
        mailbox = alias.mailbox

    bounce_info = get_mailbox_bounce_info(msg)
    if bounce_info:
        Bounce.create(
            email=mailbox.email, info=bounce_info.as_bytes().decode(), commit=True
        )
    else:
        LOG.w("cannot get bounce info, debug at %s", save_email_for_debugging(msg))
        Bounce.create(email=mailbox.email, commit=True)

    LOG.d(
        "Handle forward bounce %s -> %s -> %s. %s", contact, alias, mailbox, email_log
    )

    
    random_name = str(uuid.uuid4())

    full_report_path = f"refused-emails/full-{random_name}.eml"
    s3.upload_email_from_bytesio(
        full_report_path, BytesIO(message_to_bytes(msg)), f"full-{random_name}"
    )

    file_path = None

    orig_msg = get_orig_message_from_bounce(msg)
    if not orig_msg:
        
        
        LOG.w(
            "Cannot parse original message from bounce message %s %s %s %s",
            alias,
            user,
            contact,
            full_report_path,
        )
    else:
        file_path = f"refused-emails/{random_name}.eml"
        s3.upload_email_from_bytesio(
            file_path, BytesIO(message_to_bytes(orig_msg)), random_name
        )

    refused_email = RefusedEmail.create(
        path=file_path, full_report_path=full_report_path, user_id=user.id
    )
    Session.flush()
    LOG.d("Create refused email %s", refused_email)

    email_log.bounced = True
    email_log.refused_email_id = refused_email.id
    email_log.bounced_mailbox_id = mailbox.id
    Session.commit()

    refused_email_url = f"{URL}/dashboard/refused_email?highlight_id={email_log.id}"

    alias_will_be_disabled, reason = should_disable(alias)
    if alias_will_be_disabled:
        LOG.w(
            f"Disable alias {alias} because {reason}. {alias.mailboxes} {alias.user}. Last contact {contact}"
        )
        change_alias_status(alias, enabled=False)

        Notification.create(
            user_id=user.id,
            title=f"{alias.email} has been disabled due to multiple bounces",
            message=Notification.render(
                "notification/alias-disable.html", alias=alias, mailbox=mailbox
            ),
        )

        Session.commit()
        send_email_with_rate_control(
            user,
            ALERT_BOUNCE_EMAIL,
            user.email,
            f"Alias {alias.email} has been disabled due to multiple bounces",
            render(
                "transactional/bounce/automatic-disable-alias.txt",
                user=alias.user,
                alias=alias,
                refused_email_url=refused_email_url,
                mailbox_email=mailbox.email,
            ),
            render(
                "transactional/bounce/automatic-disable-alias.html",
                user=alias.user,
                alias=alias,
                refused_email_url=refused_email_url,
                mailbox_email=mailbox.email,
            ),
            max_nb_alert=10,
            ignore_smtp_error=True,
        )
    else:
        LOG.d(
            "Inform user %s about a bounce from contact %s to alias %s",
            user,
            contact,
            alias,
        )
        disable_alias_link = f"{URL}/dashboard/unsubscribe/{alias.id}"
        block_sender_link = f"{URL}/dashboard/alias_contact_manager/{alias.id}?highlight_contact_id={contact.id}"

        Notification.create(
            user_id=user.id,
            title=f"Email from {contact.website_email} to {alias.email} cannot be delivered to {mailbox.email}",
            message=Notification.render(
                "notification/bounce-forward-phase.html",
                alias=alias,
                website_email=contact.website_email,
                disable_alias_link=disable_alias_link,
                refused_email_url=refused_email.get_url(),
                mailbox_email=mailbox.email,
                block_sender_link=block_sender_link,
            ),
            commit=True,
        )
        send_email_with_rate_control(
            user,
            ALERT_BOUNCE_EMAIL,
            user.email,
            f"An email sent to {alias.email} cannot be delivered to your mailbox",
            render(
                "transactional/bounce/bounced-email.txt.jinja2",
                user=alias.user,
                alias=alias,
                website_email=contact.website_email,
                disable_alias_link=disable_alias_link,
                block_sender_link=block_sender_link,
                refused_email_url=refused_email_url,
                mailbox_email=mailbox.email,
            ),
            render(
                "transactional/bounce/bounced-email.html",
                user=alias.user,
                alias=alias,
                website_email=contact.website_email,
                disable_alias_link=disable_alias_link,
                refused_email_url=refused_email_url,
                mailbox_email=mailbox.email,
            ),
            max_nb_alert=10,
            
            ignore_smtp_error=True,
        )


def handle_bounce_reply_phase(envelope, msg: Message, email_log: EmailLog):

    contact: Contact = email_log.contact
    alias = contact.alias
    user = alias.user
    mailbox = email_log.mailbox or alias.mailbox

    LOG.d("Handle reply bounce %s -> %s -> %s.%s", mailbox, alias, contact, email_log)

    bounce_info = get_mailbox_bounce_info(msg)
    if bounce_info:
        Bounce.create(
            email=sanitize_email(contact.website_email, not_lower=True),
            info=bounce_info.as_bytes().decode(),
            commit=True,
        )
    else:
        LOG.w("cannot get bounce info, debug at %s", save_email_for_debugging(msg))
        Bounce.create(
            email=sanitize_email(contact.website_email, not_lower=True), commit=True
        )

    
    
    random_name = str(uuid.uuid4())

    full_report_path = f"refused-emails/full-{random_name}.eml"
    s3.upload_email_from_bytesio(
        full_report_path, BytesIO(message_to_bytes(msg)), random_name
    )

    orig_msg = get_orig_message_from_bounce(msg)
    file_path = None
    if orig_msg:
        file_path = f"refused-emails/{random_name}.eml"
        s3.upload_email_from_bytesio(
            file_path, BytesIO(message_to_bytes(orig_msg)), random_name
        )

    refused_email = RefusedEmail.create(
        path=file_path, full_report_path=full_report_path, user_id=user.id, commit=True
    )
    LOG.d("Create refused email %s", refused_email)

    email_log.bounced = True
    email_log.refused_email_id = refused_email.id

    email_log.bounced_mailbox_id = mailbox.id

    Session.commit()

    refused_email_url = f"{URL}/dashboard/refused_email?highlight_id={email_log.id}"

    LOG.d(
        "Inform user %s about bounced email sent by %s to %s",
        user,
        alias,
        contact,
    )
    Notification.create(
        user_id=user.id,
        title=f"Email cannot be sent to { contact.email } from your alias { alias.email }",
        message=Notification.render(
            "notification/bounce-reply-phase.html",
            alias=alias,
            contact=contact,
            refused_email_url=refused_email.get_url(),
        ),
        commit=True,
    )
    send_email_with_rate_control(
        user,
        ALERT_BOUNCE_EMAIL_REPLY_PHASE,
        mailbox.email,
        f"Email cannot be sent to { contact.email } from your alias { alias.email }",
        render(
            "transactional/bounce/bounce-email-reply-phase.txt",
            user=user,
            alias=alias,
            contact=contact,
            refused_email_url=refused_email_url,
        ),
        render(
            "transactional/bounce/bounce-email-reply-phase.html",
            user=user,
            alias=alias,
            contact=contact,
            refused_email_url=refused_email_url,
        ),
    )


def handle_spam(
    contact: Contact,
    alias: Alias,
    msg: Message,
    user: User,
    mailbox: Mailbox,
    email_log: EmailLog,
    is_reply=False,  
):
    
    orig_msg = get_orig_message_from_spamassassin_report(msg)
    
    random_name = str(uuid.uuid4())

    full_report_path = f"spams/full-{random_name}.eml"
    s3.upload_email_from_bytesio(
        full_report_path, BytesIO(message_to_bytes(msg)), random_name
    )

    file_path = None
    if orig_msg:
        file_path = f"spams/{random_name}.eml"
        s3.upload_email_from_bytesio(
            file_path, BytesIO(message_to_bytes(orig_msg)), random_name
        )

    refused_email = RefusedEmail.create(
        path=file_path, full_report_path=full_report_path, user_id=user.id
    )
    Session.flush()

    email_log.refused_email_id = refused_email.id
    Session.commit()

    LOG.d("Create spam email %s", refused_email)

    refused_email_url = f"{URL}/dashboard/refused_email?highlight_id={email_log.id}"
    disable_alias_link = f"{URL}/dashboard/unsubscribe/{alias.id}"

    if is_reply:
        LOG.d(
            "Inform %s (%s) about spam email sent from alias %s to %s. %s",
            mailbox,
            user,
            alias,
            contact,
            refused_email,
        )
        send_email_with_rate_control(
            user,
            ALERT_SPAM_EMAIL,
            mailbox.email,
            f"Email from {alias.email} to {contact.website_email} is detected as spam",
            render(
                "transactional/spam-email-reply-phase.txt",
                user=user,
                alias=alias,
                website_email=contact.website_email,
                disable_alias_link=disable_alias_link,
                refused_email_url=refused_email_url,
            ),
            render(
                "transactional/spam-email-reply-phase.html",
                user=user,
                alias=alias,
                website_email=contact.website_email,
                disable_alias_link=disable_alias_link,
                refused_email_url=refused_email_url,
            ),
        )
    else:
        
        LOG.d(
            "Inform %s (%s) about spam email sent by %s to alias %s",
            mailbox,
            user,
            contact,
            alias,
        )
        send_email_with_rate_control(
            user,
            ALERT_SPAM_EMAIL,
            mailbox.email,
            f"Email from {contact.website_email} to {alias.email} is detected as spam",
            render(
                "transactional/spam-email.txt",
                user=user,
                alias=alias,
                website_email=contact.website_email,
                disable_alias_link=disable_alias_link,
                refused_email_url=refused_email_url,
            ),
            render(
                "transactional/spam-email.html",
                user=user,
                alias=alias,
                website_email=contact.website_email,
                disable_alias_link=disable_alias_link,
                refused_email_url=refused_email_url,
            ),
        )



def is_bounce(envelope: Envelope, msg: Message):
    """Detect whether an email is a Delivery Status Notification"""
    return (
        envelope.mail_from == "<>"
        and msg.get_content_type().lower() == "multipart/report"
    )


def handle_transactional_bounce(
    envelope: Envelope, msg, rcpt_to, transactional_id=None
):
    LOG.d("handle transactional bounce sent to %s", rcpt_to)
    if transactional_id is None:
        LOG.i(
            f"No transactional record for {envelope.mail_from} -> {envelope.rcpt_tos}"
        )
        return

    transactional = TransactionalEmail.get(transactional_id)
    
    if not transactional:
        LOG.i(
            f"No transactional record for {envelope.mail_from} -> {envelope.rcpt_tos}"
        )
        return
    LOG.i("Create bounce for %s", transactional.email)
    bounce_info = get_mailbox_bounce_info(msg)
    if bounce_info:
        Bounce.create(
            email=transactional.email,
            info=bounce_info.as_bytes().decode(),
            commit=True,
        )
    else:
        LOG.w("cannot get bounce info, debug at %s", save_email_for_debugging(msg))
        Bounce.create(email=transactional.email, commit=True)


def handle_bounce(envelope, email_log: EmailLog, msg: Message) -> str:

    if not email_log:
        LOG.w("No such email log")
        return status.E512

    contact: Contact = email_log.contact
    alias = contact.alias
    LOG.d(
        "handle bounce for %s, phase=%s, contact=%s, alias=%s",
        email_log,
        email_log.get_phase(),
        contact,
        alias,
    )
    if not email_log.user.is_active():
        LOG.d(f"User {email_log.user} is not active")
        return status.E510

    if email_log.is_reply:
        content_type = msg.get_content_type().lower()

        if content_type != "multipart/report" or envelope.mail_from != "<>":
            
            LOG.i(
                "Handle auto reply %s %s",
                content_type,
                envelope.mail_from,
            )

            contact: Contact = email_log.contact
            alias = contact.alias

            email_log.auto_replied = True
            Session.commit()

            
            add_or_replace_header(msg, "To", alias.email)
            envelope.rcpt_tos = [alias.email]

            
            
            
            res: [(bool, str)] = []

            for is_delivered, smtp_status in handle_forward(envelope, msg, alias.email):
                res.append((is_delivered, smtp_status))

            for is_success, smtp_status in res:
                
                if is_success:
                    return smtp_status

            
            return res[0][1]

        handle_bounce_reply_phase(envelope, msg, email_log)
        return status.E212
    else:  
        handle_bounce_forward_phase(msg, email_log)
        return status.E211


def should_ignore(mail_from: str, rcpt_tos: List[str]) -> bool:
    if len(rcpt_tos) != 1:
        return False

    rcpt_to = rcpt_tos[0]
    if IgnoredEmail.get_by(mail_from=mail_from, rcpt_to=rcpt_to):
        return True

    return False


    def send_no_reply_response(mail_from: str, msg: Message):
    mailbox = Mailbox.get_by(email=mail_from)
    if not mailbox:
        LOG.d("Unknown sender. Skipping reply from {}".format(NOREPLY))
        return
    if not mailbox.user.is_active():
        LOG.d(f"User {mailbox.user} is soft-deleted. Skipping sending reply response")
        return
    send_email_at_most_times(
        mailbox.user,
        ALERT_TO_NOREPLY,
        mailbox.user.email,
        "Auto: {}".format(msg[headers.SUBJECT] or "No subject"),
        render("transactional/noreply.text.jinja2", user=mailbox.user),
    )


def handle(envelope: Envelope, msg: Message) -> str:

    
    mail_from = sanitize_email(envelope.mail_from)
    rcpt_tos = [sanitize_email(rcpt_to) for rcpt_to in envelope.rcpt_tos]
    envelope.mail_from = mail_from
    envelope.rcpt_tos = rcpt_tos

    
    if headers.CONTENT_TRANSFER_ENCODING not in msg:
        LOG.i("Set CONTENT_TRANSFER_ENCODING")
        msg[headers.CONTENT_TRANSFER_ENCODING] = "7bit"

    postfix_queue_id = get_queue_id(msg)
    if postfix_queue_id:
        set_message_id(postfix_queue_id)
    else:
        LOG.d(
            "Cannot parse Postfix queue ID from %s %s",
            msg.get_all(headers.RECEIVED),
            msg[headers.RECEIVED],
        )

    if should_ignore(mail_from, rcpt_tos):
        LOG.w("Ignore email mail_from=%s rcpt_to=%s", mail_from, rcpt_tos)
        return status.E204

    
    sanitize_header(msg, headers.FROM)
    sanitize_header(msg, headers.TO)
    sanitize_header(msg, headers.CC)
    sanitize_header(msg, headers.REPLY_TO)
    sanitize_header(msg, headers.MESSAGE_ID)

    LOG.d(
        "==>> Handle mail_from:%s, rcpt_tos:%s, header_from:%s, header_to:%s, "
        "cc:%s, reply-to:%s, message_id:%s, client_ip:%s, headers:%s, mail_options:%s, rcpt_options:%s",
        mail_from,
        rcpt_tos,
        msg[headers.FROM],
        msg[headers.TO],
        msg[headers.CC],
        msg[headers.REPLY_TO],
        msg[headers.MESSAGE_ID],
        msg[headers.SL_CLIENT_IP],
        msg._headers,
        envelope.mail_options,
        envelope.rcpt_options,
    )

    
    email_sent_from_reverse_alias = False
    contact = Contact.get_by(reply_email=mail_from)
    if contact:
        email_sent_from_reverse_alias = True

    from_header = get_header_unicode(msg[headers.FROM])
    if from_header:
        try:
            _, from_header_address = parse_full_address(from_header)
        except ValueError:
            LOG.w("cannot parse the From header %s", from_header)
        else:
            contact = Contact.get_by(reply_email=from_header_address)
            if contact:
                email_sent_from_reverse_alias = True

    if email_sent_from_reverse_alias:
        LOG.w(f"email sent from reverse alias {contact} {contact.alias} {contact.user}")
        user = contact.user
        send_email_at_most_times(
            user,
            ALERT_FROM_ADDRESS_IS_REVERSE_ALIAS,
            user.email,
            "Login shouldn't be used with another email forwarding system",
            render(
                "transactional/email-sent-from-reverse-alias.txt.jinja2",
                user=user,
            ),
        )

    
    if UNSUBSCRIBER and (rcpt_tos == [UNSUBSCRIBER] or rcpt_tos == [OLD_UNSUBSCRIBER]):
        LOG.d("Handle unsubscribe request from %s", mail_from)
        return UnsubscribeHandler().handle_unsubscribe_from_message(envelope, msg)

    
    verp_info = get_verp_info_from_email(rcpt_tos[0])

    
    if (
        len(rcpt_tos) == 1
        and rcpt_tos[0].startswith(TRANSACTIONAL_BOUNCE_PREFIX)
        and rcpt_tos[0].endswith(TRANSACTIONAL_BOUNCE_SUFFIX)
    ) or (verp_info and verp_info[0] == VerpType.transactional):
        if is_bounce(envelope, msg):
            handle_transactional_bounce(
                envelope, msg, rcpt_tos[0], verp_info and verp_info[1]
            )
            return status.E205
        elif is_automatic_out_of_office(msg):
            LOG.d(
                "Ignore out-of-office for transactional emails. Headers: %s", msg.items
            )
            return status.E206
        else:
            raise VERPTransactional

    
    if (
        len(rcpt_tos) == 1
        and rcpt_tos[0].startswith(BOUNCE_PREFIX)
        and rcpt_tos[0].endswith(BOUNCE_SUFFIX)
    ) or (verp_info and verp_info[0] == VerpType.bounce_forward):
        email_log_id = (verp_info and verp_info[1]) or parse_id_from_bounce(rcpt_tos[0])
        email_log = EmailLog.get(email_log_id)

        if not email_log:
            LOG.w("No such email log")
            return status.E512

        if is_bounce(envelope, msg):
            return handle_bounce(envelope, email_log, msg)
        elif is_automatic_out_of_office(msg):
            handle_out_of_office_forward_phase(email_log, envelope, msg, rcpt_tos)
        else:
            raise VERPForward

    
    if (
        len(rcpt_tos) == 1
        and rcpt_tos[0].startswith(f"{BOUNCE_PREFIX_FOR_REPLY_PHASE}+")
        or (verp_info and verp_info[0] == VerpType.bounce_reply)
    ):
        email_log_id = (verp_info and verp_info[1]) or parse_id_from_bounce(rcpt_tos[0])
        email_log = EmailLog.get(email_log_id)

        if not email_log:
            LOG.w("No such email log")
            return status.E512

        
        if is_bounce(envelope, msg):
            return handle_bounce(envelope, email_log, msg)
        elif is_automatic_out_of_office(msg):
            handle_out_of_office_reply_phase(email_log, envelope, msg, rcpt_tos)
        else:
            raise VERPReply(
                f"cannot handle email sent to reply VERP, "
                f"{email_log.alias} -> {email_log.contact} ({email_log}, {email_log.user}"
            )

    
    verp_info = get_verp_info_from_email(mail_from[0])
    if (
        len(rcpt_tos) == 1
        and mail_from.startswith(BOUNCE_PREFIX)
        and mail_from.endswith(BOUNCE_SUFFIX)
    ) or (verp_info and verp_info[0] == VerpType.bounce_forward):
        email_log_id = (verp_info and verp_info[1]) or parse_id_from_bounce(mail_from)
        email_log = EmailLog.get(email_log_id)
        alias = Alias.get_by(email=rcpt_tos[0])
        LOG.w(
            "iCloud bounces %s %s, saved to%s",
            email_log,
            alias,
            save_email_for_debugging(msg, file_name_prefix="icloud_bounce_"),
        )
        return handle_bounce(envelope, email_log, msg)

    
    if rate_limited(mail_from, rcpt_tos):
        LOG.w("Rate Limiting applied for mail_from:%s rcpt_tos:%s", mail_from, rcpt_tos)

        
        if len(rcpt_tos) == 1:
            alias = Alias.get_by(email=rcpt_tos[0])
            if alias:
                LOG.w(
                    "total number email log on %s, %s is %s, %s",
                    alias,
                    alias.user,
                    EmailLog.filter(EmailLog.alias_id == alias.id).count(),
                    EmailLog.filter(EmailLog.user_id == alias.user_id).count(),
                )

        if should_ignore_bounce(envelope.mail_from):
            return status.E207
        else:
            return status.E522

    
    if len(rcpt_tos) == 1 and is_reverse_alias(rcpt_tos[0]) and mail_from == "<>":
        contact = Contact.get_by(reply_email=rcpt_tos[0])
        LOG.w(
            "out-of-office email to reverse alias %s. Saved to %s",
            contact,
            save_email_for_debugging(msg),  
        )
        return status.E206

    
    
    res: [(bool, str)] = []

    nb_rcpt_tos = len(rcpt_tos)
    for rcpt_index, rcpt_to in enumerate(rcpt_tos):
        if rcpt_to in config.NOREPLIES:
            LOG.i("email sent to {} address from {}".format(NOREPLY, mail_from))
            send_no_reply_response(mail_from, msg)
            return status.E200

        
        
        if rcpt_index < nb_rcpt_tos - 1:
            LOG.d("copy message for rcpt %s", rcpt_to)
            copy_msg = copy(msg)
        else:
            copy_msg = msg

        
        if is_reverse_alias(rcpt_to):
            LOG.d(
                "Reply phase %s(%s) -> %s", mail_from, copy_msg[headers.FROM], rcpt_to
            )
            is_delivered, smtp_status = handle_reply(envelope, copy_msg, rcpt_to)
            res.append((is_delivered, smtp_status))
        else:  
            LOG.d(
                "Forward phase %s(%s) -> %s",
                mail_from,
                copy_msg[headers.FROM],
                rcpt_to,
            )
            for is_delivered, smtp_status in handle_forward(
                envelope, copy_msg, rcpt_to
            ):
                res.append((is_delivered, smtp_status))

    
    nb_success = len([is_success for (is_success, smtp_status) in res if is_success])
    
    nb_non_success = len(
        [
            is_success
            for (is_success, smtp_status) in res
            if not is_success and smtp_status != status.E518
        ]
    )

    if nb_success > 0 and nb_non_success > 0:
        LOG.e(f"some deliveries fail and some success, {mail_from}, {rcpt_tos}, {res}")

    for is_success, smtp_status in res:
        
        if is_success:
            return smtp_status

    
    return res[0][1]


def handle_out_of_office_reply_phase(email_log, envelope, msg, rcpt_tos):

    LOG.d(
        "send the out-of-office email to the alias %s, old to_header:%s rcpt_tos:%s, %s",
        email_log.alias,
        msg[headers.TO],
        rcpt_tos,
        email_log,
    )
    alias_address = email_log.alias.email

    rcpt_tos[0] = alias_address
    envelope.rcpt_tos = [alias_address]

    add_or_replace_header(msg, headers.TO, alias_address)
    
    delete_header(msg, headers.REPLY_TO)

    LOG.d(
        "after out-of-office transformation to_header:%s reply_to:%s rcpt_tos:%s",
        msg.get_all(headers.TO),
        msg.get_all(headers.REPLY_TO),
        rcpt_tos,
    )


def handle_out_of_office_forward_phase(email_log, envelope, msg, rcpt_tos):

    LOG.d(
        "send the out-of-office email to the contact %s, old to_header:%s rcpt_tos:%s %s",
        email_log.contact,
        msg[headers.TO],
        rcpt_tos,
        email_log,
    )
    reverse_alias = email_log.contact.reply_email

    rcpt_tos[0] = reverse_alias
    envelope.rcpt_tos = [reverse_alias]

    add_or_replace_header(msg, headers.TO, reverse_alias)
    
    delete_header(msg, headers.REPLY_TO)

    LOG.d(
        "after out-of-office transformation to_header:%s reply_to:%s rcpt_tos:%s",
        msg.get_all(headers.TO),
        msg.get_all(headers.REPLY_TO),
        rcpt_tos,
    )


class MailHandler:
    async def handle_DATA(self, server, session, envelope: Envelope):
        msg = email.message_from_bytes(envelope.original_content)
        try:
            ret = self._handle(envelope, msg)
            return ret
        
        except CannotCreateContactForReverseAlias as e:
            LOG.w(
                "Probably due to reverse-alias used in the forward phase, "
                "error:%s mail_from:%s, rcpt_tos:%s, header_from:%s, header_to:%s",
                e,
                envelope.mail_from,
                envelope.rcpt_tos,
                msg[headers.FROM],
                msg[headers.TO],
            )
            return status.E524
        except (VERPReply, VERPForward, VERPTransactional) as e:
            LOG.w(
                "email handling fail with error:%s "
                "mail_from:%s, rcpt_tos:%s, header_from:%s, header_to:%s",
                e,
                envelope.mail_from,
                envelope.rcpt_tos,
                msg[headers.FROM],
                msg[headers.TO],
            )
            return status.E213
        except Exception as e:
            LOG.e(
                "email handling fail with error:%s "
                "mail_from:%s, rcpt_tos:%s, header_from:%s, header_to:%s, saved to %s",
                e,
                envelope.mail_from,
                envelope.rcpt_tos,
                msg[headers.FROM],
                msg[headers.TO],
                save_envelope_for_debugging(
                    envelope, file_name_prefix=e.__class__.__name__
                ),  
            )
            return status.E404

    @newrelic.agent.background_task()
    def _handle(self, envelope: Envelope, msg: Message):
        start = time.time()

        
        message_id = str(uuid.uuid4())
        set_message_id(message_id)

        LOG.d("====>=====>====>====>====>====>====>====>")
        LOG.i(
            "New message, mail from %s, rctp tos %s ",
            envelope.mail_from,
            envelope.rcpt_tos,
        )
        newrelic.agent.record_custom_metric(
            "Custom/nb_rcpt_tos", len(envelope.rcpt_tos)
        )

        with create_light_app().app_context():
            return_status = handle(envelope, msg)
            elapsed = time.time() - start
            
            spamd_result = SpamdResult.extract_from_headers(msg)
            if return_status[0] == "5":
                if spamd_result and spamd_result.spf in (
                    SPFCheckResult.fail,
                    SPFCheckResult.soft_fail,
                ):
                    LOG.i(
                        "Replacing 5XX to 216 status because the return-path failed the spf check"
                    )
                    return_status = status.E216

            LOG.i(
                "Finish mail_from %s, rcpt_tos %s, takes %s seconds with return code '%s'<<===",
                envelope.mail_from,
                envelope.rcpt_tos,
                elapsed,
                return_status,
            )

            SpamdResult.send_to_new_relic(msg)
            newrelic.agent.record_custom_metric("Custom/email_handler_time", elapsed)
            newrelic.agent.record_custom_metric("Custom/number_incoming_email", 1)
            return return_status

def main(port: int):
    controller = Controller(MailHandler(), hostname="0.0.0.0", port=port)

    controller.start()
    LOG.d("Start mail controller %s %s", controller.hostname, controller.port)

    if LOAD_PGP_EMAIL_HANDLER:
        LOG.w("LOAD PGP keys")
        load_pgp_public_keys()

    while True:
        time.sleep(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--port", help="SMTP port to listen for", type=int, default=20381
    )
    args = parser.parse_args()

    LOG.i("Listen for port %s", args.port)
    main(port=args.port)
