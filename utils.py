import argparse
import asyncio
import urllib.parse
from typing import List, Tuple

from app import s3, config
from app.alias_utils import nb_email_log_for_mailbox
from app.api.views.apple import verify_receipt
from app.db import Session
from app.dns_utils import get_mx_domains, is_mx_equivalent
from app.email_utils import (
    send_email,
    send_trial_end_soon_email,
    render,
    email_can_be_used_as_mailbox,
    send_email_with_rate_control,
    get_email_domain_part,
)
from app.email_validation import is_valid_email, normalize_reply_email
from app.errors import ProtonPartnerNotSetUp
from app.log import LOG
from app.mail_sender import load_unsent_mails_from_fs_and_resend
from app.models import (
    Subscription,
    User,
    Alias,
    EmailLog,
    CustomDomain,
    Client,
    ManualSubscription,
    RefusedEmail,
    AppleSubscription,
    Mailbox,
    Monitoring,
    Contact,
    CoinbaseSubscription,
    TransactionalEmail,
    Bounce,
    Metric2,
    SLDomain,
    DeletedAlias,
    DomainDeletedAlias,
    Hibp,
    HibpNotifiedAlias,
    Directory,
    DeletedDirectory,
    DeletedSubdomain,
    PartnerSubscription,
    PartnerUser,
    ApiToCookieToken,
)

DELETE_GRACE_DAYS = 30

def notify_trial_end():
    for user in User.filter(
        User.activated.is_(True),
        User.trial_end.isnot(None),
        User.trial_end >= arrow.now().shift(days=2),
        User.trial_end < arrow.now().shift(days=3),
        User.lifetime.is_(False),
    ).all():
        try:
            if user.in_trial():
                LOG.d("Send trial end email to user %s", user)
                send_trial_end_soon_email(user)
        
        except ObjectDeletedError:
            LOG.i("user has been deleted")


def delete_logs():

    delete_refused_emails()
    delete_old_monitoring()

    for t_email in TransactionalEmail.filter(
        TransactionalEmail.created_at < arrow.now().shift(days=-7)
    ):
        TransactionalEmail.delete(t_email.id)

    for b in Bounce.filter(Bounce.created_at < arrow.now().shift(days=-7)):
        Bounce.delete(b.id)

    Session.commit()

    LOG.d("Deleting EmailLog older than 2 weeks")

    total_deleted = 0
    batch_size = 500
    Session.execute("set session statement_timeout=30000").rowcount
    queries_done = 0
    cutoff_time = arrow.now().shift(days=-14)
    rows_to_delete = EmailLog.filter(EmailLog.created_at < cutoff_time).count()
    expected_queries = int(rows_to_delete / batch_size)
    sql = text(
        "DELETE FROM email_log WHERE id IN (SELECT id FROM email_log WHERE created_at < :cutoff_time order by created_at limit :batch_size)"
    )
    str_cutoff_time = cutoff_time.isoformat()
    while total_deleted < rows_to_delete:
        deleted_count = Session.execute(
            sql, {"cutoff_time": str_cutoff_time, "batch_size": batch_size}
        ).rowcount
        Session.commit()
        total_deleted += deleted_count
        queries_done += 1
        LOG.i(
            f"[{queries_done}/{expected_queries}] Deleted {total_deleted} EmailLog entries"
        )
        if deleted_count < batch_size:
            break

    LOG.i("Deleted %s email logs", total_deleted)


def delete_refused_emails():
    for refused_email in (
        RefusedEmail.filter_by(deleted=False).order_by(RefusedEmail.id).all()
    ):
        if arrow.now().shift(days=1) > refused_email.delete_at >= arrow.now():
            LOG.d("Delete refused email %s", refused_email)
            if refused_email.path:
                s3.delete(refused_email.path)

            s3.delete(refused_email.full_report_path)

            refused_email.delete_at = arrow.now()
            refused_email.deleted = True
            Session.commit()

    LOG.d("Finish delete_refused_emails")


def notify_premium_end():

    for sub in Subscription.filter_by(cancelled=True).all():
        if (
            arrow.now().shift(days=3).date()
            > sub.next_bill_date
            >= arrow.now().shift(days=2).date()
        ):
            user = sub.user

            if user.lifetime:
                continue

            LOG.d(f"Send subscription ending soon email to user {user}")

            send_email(
                user.email,
                "Your subscription will end soon",
                render(
                    "transactional/subscription-end.txt",
                    user=user,
                    next_bill_date=sub.next_bill_date.strftime("%Y-%m-%d"),
                ),
                render(
                    "transactional/subscription-end.html",
                    user=user,
                    next_bill_date=sub.next_bill_date.strftime("%Y-%m-%d"),
                ),
                retries=3,
            )
