import time
from typing import List

import arrow
from sqlalchemy.sql.expression import or_, and_

from app import config
from app.db import Session
from app.email_utils import (
    send_email,
    render,
)
from app.import_utils import handle_batch_import
from app.jobs.event_jobs import send_alias_creation_events_for_user
from app.jobs.export_user_data_job import ExportUserDataJob
from app.log import LOG
from app.models import User, Job, BatchImport, Mailbox, CustomDomain, JobState
from server import create_light_app


def onboarding_send_from_alias(user):
    comm_email, unsubscribe_link, via_email = user.get_communication_email()
    if not comm_email:
        return

    send_email(
        comm_email,
        "Login Tip: Send emails from your alias",
        render(
            "com/onboarding/send-from-alias.txt.j2",
            user=user,
            to_email=comm_email,
        ),
        render("com/onboarding/send-from-alias.html", user=user, to_email=comm_email),
        unsubscribe_link,
        via_email,
        retries=3,
        ignore_smtp_error=True,
    )


def onboarding_pgp(user):
    comm_email, unsubscribe_link, via_email = user.get_communication_email()
    if not comm_email:
        return

    send_email(
        comm_email,
        "Login Tip: Secure your emails with PGP",
        render("com/onboarding/pgp.txt", user=user, to_email=comm_email),
        render("com/onboarding/pgp.html", user=user, to_email=comm_email),
        unsubscribe_link,
        via_email,
        retries=3,
        ignore_smtp_error=True,
    )


def onboarding_browser_extension(user):
    comm_email, unsubscribe_link, via_email = user.get_communication_email()
    if not comm_email:
        return

    send_email(
        comm_email,
        "Login Tip: Chrome/Firefox/Safari extensions and Android/iOS apps",
        render(
            "com/onboarding/browser-extension.txt",
            user=user,
            to_email=comm_email,
        ),
        render(
            "com/onboarding/browser-extension.html",
            user=user,
            to_email=comm_email,
        ),
        unsubscribe_link,
        via_email,
        retries=3,
        ignore_smtp_error=True,
    )


def onboarding_mailbox(user):
    comm_email, unsubscribe_link, via_email = user.get_communication_email()
    if not comm_email:
        return

    send_email(
        comm_email,
        "Login Tip: Multiple mailboxes",
        render("com/onboarding/mailbox.txt", user=user, to_email=comm_email),
        render("com/onboarding/mailbox.html", user=user, to_email=comm_email),
        unsubscribe_link,
        via_email,
        retries=3,
        ignore_smtp_error=True,
    )


def welcome_yepatron(user):
    comm_email, _, _ = user.get_communication_email()
    if not comm_email:
        return

    send_email(
        comm_email,
        "Welcome to Login, an email masking service provided by yepatron",
        render(
            "com/onboarding/welcome-yepatron-user.txt.jinja2",
            user=user,
            to_email=comm_email,
        ),
        render(
            "com/onboarding/welcome-yepatron-user.html",
            user=user,
            to_email=comm_email,
        ),
        retries=3,
        ignore_smtp_error=True,
    )


def delete_mailbox_job(job: Job):
    mailbox_id = job.payload.get("mailbox_id")
    mailbox = Mailbox.get(mailbox_id)
    if not mailbox:
        return

    transfer_mailbox_id = job.payload.get("transfer_mailbox_id")
    alias_transferred_to = None
    if transfer_mailbox_id:
        transfer_mailbox = Mailbox.get(transfer_mailbox_id)
        if transfer_mailbox:
            alias_transferred_to = transfer_mailbox.email

            for alias in mailbox.aliases:
                if alias.mailbox_id == mailbox.id:
                    alias.mailbox_id = transfer_mailbox.id
                    if transfer_mailbox in alias._mailboxes:
                        alias._mailboxes.remove(transfer_mailbox)
                else:
                    alias._mailboxes.remove(mailbox)
                    if transfer_mailbox not in alias._mailboxes:
                        alias._mailboxes.append(transfer_mailbox)
                Session.commit()

    mailbox_email = mailbox.email
    user = mailbox.user
    Mailbox.delete(mailbox_id)
    Session.commit()
    LOG.d("Mailbox %s %s deleted", mailbox_id, mailbox_email)

    if alias_transferred_to:
        send_email(
            user.email,
            f"Your mailbox {mailbox_email} has been deleted",
            f"""Mailbox {mailbox_email} and its alias have been transferred to {alias_transferred_to}.
Regards,
Login team.
""",
            retries=3,
        )
    else:
        send_email(
            user.email,
            f"Your mailbox {mailbox_email} has been deleted",
            f"""Mailbox {mailbox_email} along with its aliases have been deleted successfully.
Regards,
Login team.
""",
            retries=3,
        )


def process_job(job: Job):
    if job.name == config.JOB_ONBOARDING_1:
        user_id = job.payload.get("user_id")
        user = User.get(user_id)
        
        if user and user.notification and user.activated:
            LOG.d("send onboarding send-from-alias email to user %s", user)
            onboarding_send_from_alias(user)
    elif job.name == config.JOB_ONBOARDING_2:
        user_id = job.payload.get("user_id")
        user = User.get(user_id)
        
        if user and user.notification and user.activated:
            LOG.d("send onboarding mailbox email to user %s", user)
            onboarding_mailbox(user)
    elif job.name == config.JOB_ONBOARDING_4:
        user_id = job.payload.get("user_id")
        user: User = User.get(user_id)

        if user and user.notification and user.activated:
            
            mailboxes = user.mailboxes()
            if len(mailboxes) == 1 and mailboxes[0].is_yepatron():
                LOG.d("Do not send onboarding PGP email to yepatron mailbox")
            else:
                LOG.d("send onboarding pgp email to user %s", user)
                onboarding_pgp(user)

    elif job.name == config.JOB_BATCH_IMPORT:
        batch_import_id = job.payload.get("batch_import_id")
        batch_import = BatchImport.get(batch_import_id)
        handle_batch_import(batch_import)
    elif job.name == config.JOB_DELETE_ACCOUNT:
        user_id = job.payload.get("user_id")
        user = User.get(user_id)
