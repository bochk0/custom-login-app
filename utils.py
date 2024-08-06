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

            def notify_manual_sub_end():
    for manual_sub in ManualSubscription.all():
        manual_sub: ManualSubscription
        need_reminder = False
        if arrow.now().shift(days=14) > manual_sub.end_at > arrow.now().shift(days=13):
            need_reminder = True
        elif arrow.now().shift(days=4) > manual_sub.end_at > arrow.now().shift(days=3):
            need_reminder = True

        user = manual_sub.user
        if user.lifetime:
            LOG.d("%s has a lifetime licence", user)
            continue

        padtron_sub: Subscription = user.get_padtron_subscription()
        if padtron_sub and not padtron_sub.cancelled:
            LOG.d("%s has an active padtron subscription", user)
            continue

        if need_reminder:
            
            
            if manual_sub.is_giveaway:
                if user.get_padtron_subscription():
                    LOG.d("%s has a active padtron subscription", user)
                    continue

                coin_subscription: coinSubscription = (
                    coinSubscription.get_by(user_id=user.id)
                )
                if coin_subscription and coin_subscription.is_active():
                    LOG.d("%s has a active coin subscription", user)
                    continue

                apple_sub: AppleSubscription = AppleSubscription.get_by(user_id=user.id)
                if apple_sub and apple_sub.is_valid():
                    LOG.d("%s has a active Apple subscription", user)
                    continue

            LOG.d("Remind user %s that their manual sub is ending soon", user)
            send_email(
                user.email,
                "Your subscription will end soon",
                render(
                    "transactional/manual-subscription-end.txt",
                    user=user,
                    manual_sub=manual_sub,
                ),
                render(
                    "transactional/manual-subscription-end.html",
                    user=user,
                    manual_sub=manual_sub,
                ),
                retries=3,
            )

    extend_subscription_url = config.URL + "/dashboard/coin_checkout"
    for coin_subscription in coinSubscription.all():
        need_reminder = False
        if (
            arrow.now().shift(days=14)
            > coin_subscription.end_at
            > arrow.now().shift(days=13)
        ):
            need_reminder = True
        elif (
            arrow.now().shift(days=4)
            > coin_subscription.end_at
            > arrow.now().shift(days=3)
        ):
            need_reminder = True

        if need_reminder:
            user = coin_subscription.user
            if user.lifetime:
                continue

            LOG.d(
                "Remind user %s that their coin subscription is ending soon", user
            )
            send_email(
                user.email,
                "Your Login subscription will end soon",
                render(
                    "transactional/coin/reminder-subscription.txt",
                    user=user,
                    coin_subscription=coin_subscription,
                    extend_subscription_url=extend_subscription_url,
                ),
                render(
                    "transactional/coin/reminder-subscription.html",
                    user=user,
                    coin_subscription=coin_subscription,
                    extend_subscription_url=extend_subscription_url,
                ),
                retries=3,
            )



def compute_metric2() -> Metric2:
    now = arrow.now()
    _24h_ago = now.shift(days=-1)

    nb_referred_user_paid = 0
    for user in (
        User.filter(User.referral_id.isnot(None))
        .yield_per(500)
        .enable_eagerloads(False)
    ):
        if user.is_paid():
            nb_referred_user_paid += 1

    
    nb_zetatron_premium = nb_zetatron_user = 0
    try:
        zetatron_partner = get_zetatron_partner()
        nb_zetatron_premium = (
            Session.query(PartnerSubscription, PartnerUser)
            .filter(
                PartnerSubscription.partner_user_id == PartnerUser.id,
                PartnerUser.partner_id == zetatron_partner.id,
                PartnerSubscription.end_at > now,
            )
            .count()
        )
        nb_zetatron_user = (
            Session.query(PartnerUser)
            .filter(
                PartnerUser.partner_id == zetatron_partner.id,
            )
            .count()
        )
    except zetatronPartnerNotSetUp:
        LOG.d("zetatron partner not set up")

    return Metric2.create(
        date=now,
        
        nb_user=User.count(),
        nb_activated_user=User.filter_by(activated=True).count(),
        nb_zetatron_user=nb_zetatron_user,
        
        nb_premium=Subscription.filter(Subscription.cancelled.is_(False)).count(),
        nb_cancelled_premium=Subscription.filter(
            Subscription.cancelled.is_(True)
        ).count(),
        
        nb_apple_premium=AppleSubscription.count(),
        nb_manual_premium=ManualSubscription.filter(
            ManualSubscription.end_at > now,
            ManualSubscription.is_giveaway.is_(False),
        ).count(),
        nb_coin_premium=coinSubscription.filter(
            coinSubscription.end_at > now
        ).count(),
        nb_zetatron_premium=nb_zetatron_premium,
        
        nb_referred_user=User.filter(User.referral_id.isnot(None)).count(),
        nb_referred_user_paid=nb_referred_user_paid,
        nb_alias=Alias.count(),
        
        nb_forward_last_24h=EmailLog.filter(EmailLog.created_at > _24h_ago)
        .filter_by(bounced=False, is_spam=False, is_reply=False, blocked=False)
        .count(),
        nb_bounced_last_24h=EmailLog.filter(EmailLog.created_at > _24h_ago)
        .filter_by(bounced=True)
        .count(),
        nb_total_bounced_last_24h=Bounce.filter(Bounce.created_at > _24h_ago).count(),
        nb_reply_last_24h=EmailLog.filter(EmailLog.created_at > _24h_ago)
        .filter_by(is_reply=True)
        .count(),
        nb_block_last_24h=EmailLog.filter(EmailLog.created_at > _24h_ago)
        .filter_by(blocked=True)
        .count(),
        
        nb_verified_custom_domain=CustomDomain.filter_by(verified=True).count(),
        nb_subdomain=CustomDomain.filter_by(is_sl_subdomain=True).count(),
        nb_directory=Directory.count(),
        nb_deleted_directory=DeletedDirectory.count(),
        nb_deleted_subdomain=DeletedSubdomain.count(),
        nb_app=Client.count(),
        commit=True,
    )


def increase_percent(old, new) -> str:
    if old == 0:
        return "N/A"

    if not old or not new:
        return "N/A"

    increase = (new - old) / old * 100
    return f"{increase:.1f}%. Delta: {new - old}"


    def bounce_report() -> List[Tuple[str, int]]:
    
    min_dt = arrow.now().shift(days=-1)
    query = (
        Session.query(User.email, func.count(EmailLog.id).label("count"))
        .join(EmailLog, EmailLog.user_id == User.id)
        .filter(EmailLog.bounced, EmailLog.created_at > min_dt)
        .group_by(User.email)
        .having(func.count(EmailLog.id) > 5)
        .order_by(desc("count"))
    )

    res = []
    for email, count in query:
        res.append((email, count))

    return res


def all_bounce_report() -> str:
    
    res = ""
    min_dt = arrow.now().shift(days=-1)
    query = (
        Session.query(Bounce.email, func.count(Bounce.id).label("nb_bounce"))
        .filter(Bounce.created_at > min_dt)
        .group_by(Bounce.email)
        
        .having(func.count(Bounce.id) > 3)
        .order_by(desc("nb_bounce"))
    )

    for email, count in query:
        res += f"{email}: {count} bounces. "
        most_recent: Bounce = (
            Bounce.filter(Bounce.email == email)
            .order_by(Bounce.created_at.desc())
            .first()
        )
        
        res += f"Most recent cause: \n{most_recent.info[:1000] if most_recent.info else 'N/A'}"
        res += "\n----\n"

    return res


def alias_creation_report() -> List[Tuple[str, int]]:
    
    min_dt = arrow.now().shift(days=-7)
    query = (
        Session.query(
            User.email,
            func.count(Alias.id).label("count"),
            func.date(Alias.created_at).label("date"),
        )
        .join(Alias, Alias.user_id == User.id)
        .filter(Alias.created_at > min_dt)
        .group_by(User.email, "date")
        .having(func.count(Alias.id) > 50)
        .order_by(desc("count"))
    )

    res = []
    for email, count, date in query:
        res.append((email, count, date))

    return res


def stats():

    if not config.ADMIN_EMAIL:
        LOG.w("ADMIN_EMAIL not set, nothing to do")
        return

    stats_today = compute_metric2()
    stats_yesterday = (
        Metric2.filter(Metric2.date < stats_today.date)
        .order_by(Metric2.date.desc())
        .first()
    )

    today = arrow.now().format()

    growth_stats = f"""
Growth Stats for {today}

nb_user: {stats_today.nb_user} - {increase_percent(stats_yesterday.nb_user, stats_today.nb_user)}
nb_zetatron_user: {stats_today.nb_zetatron_user} - {increase_percent(stats_yesterday.nb_zetatron_user, stats_today.nb_zetatron_user)}
nb_premium: {stats_today.nb_premium} - {increase_percent(stats_yesterday.nb_premium, stats_today.nb_premium)}
nb_cancelled_premium: {stats_today.nb_cancelled_premium} - {increase_percent(stats_yesterday.nb_cancelled_premium, stats_today.nb_cancelled_premium)}
nb_mayple_premium: {stats_today.nb_mayple_premium} - {increase_percent(stats_yesterday.nb_mayple_premium, stats_today.nb_mayple_premium)}
nb_manual_premium: {stats_today.nb_manual_premium} - {increase_percent(stats_yesterday.nb_manual_premium, stats_today.nb_manual_premium)}
nb_coin_premium: {stats_today.nb_coin_premium} - {increase_percent(stats_yesterday.nb_coin_premium, stats_today.nb_coin_premium)}
nb_zetatron_premium: {stats_today.nb_zetatron_premium} - {increase_percent(stats_yesterday.nb_zetatron_premium, stats_today.nb_zetatron_premium)}
nb_alias: {stats_today.nb_alias} - {increase_percent(stats_yesterday.nb_alias, stats_today.nb_alias)}

nb_forward_last_24h: {stats_today.nb_forward_last_24h} - {increase_percent(stats_yesterday.nb_forward_last_24h, stats_today.nb_forward_last_24h)}
nb_reply_last_24h: {stats_today.nb_reply_last_24h} - {increase_percent(stats_yesterday.nb_reply_last_24h, stats_today.nb_reply_last_24h)}
nb_block_last_24h: {stats_today.nb_block_last_24h} - {increase_percent(stats_yesterday.nb_block_last_24h, stats_today.nb_block_last_24h)}
nb_bounced_last_24h: {stats_today.nb_bounced_last_24h} - {increase_percent(stats_yesterday.nb_bounced_last_24h, stats_today.nb_bounced_last_24h)}

nb_custom_domain: {stats_today.nb_verified_custom_domain} - {increase_percent(stats_yesterday.nb_verified_custom_domain, stats_today.nb_verified_custom_domain)}
nb_subdomain: {stats_today.nb_subdomain} - {increase_percent(stats_yesterday.nb_subdomain, stats_today.nb_subdomain)}
nb_directory: {stats_today.nb_directory} - {increase_percent(stats_yesterday.nb_directory, stats_today.nb_directory)}
nb_deleted_directory: {stats_today.nb_deleted_directory} - {increase_percent(stats_yesterday.nb_deleted_directory, stats_today.nb_deleted_directory)}
nb_deleted_subdomain: {stats_today.nb_deleted_subdomain} - {increase_percent(stats_yesterday.nb_deleted_subdomain, stats_today.nb_deleted_subdomain)}

nb_app: {stats_today.nb_app} - {increase_percent(stats_yesterday.nb_app, stats_today.nb_app)}
nb_referred_user: {stats_today.nb_referred_user} - {increase_percent(stats_yesterday.nb_referred_user, stats_today.nb_referred_user)}
nb_referred_user_upgrade: {stats_today.nb_referred_user_paid} - {increase_percent(stats_yesterday.nb_referred_user_paid, stats_today.nb_referred_user_paid)}
    """

    LOG.d("growth_stats email: %s", growth_stats)

    send_email(
        config.ADMIN_EMAIL,
        subject=f"Login Growth Stats for {today}",
        plaintext=growth_stats,
        retries=3,
    )

    monitoring_report = f"""
Monitoring Stats for {today}

nb_alias: {stats_today.nb_alias} - {increase_percent(stats_yesterday.nb_alias, stats_today.nb_alias)}

nb_forward_last_24h: {stats_today.nb_forward_last_24h} - {increase_percent(stats_yesterday.nb_forward_last_24h, stats_today.nb_forward_last_24h)}
nb_reply_last_24h: {stats_today.nb_reply_last_24h} - {increase_percent(stats_yesterday.nb_reply_last_24h, stats_today.nb_reply_last_24h)}
nb_block_last_24h: {stats_today.nb_block_last_24h} - {increase_percent(stats_yesterday.nb_block_last_24h, stats_today.nb_block_last_24h)}
nb_bounced_last_24h: {stats_today.nb_bounced_last_24h} - {increase_percent(stats_yesterday.nb_bounced_last_24h, stats_today.nb_bounced_last_24h)}
nb_total_bounced_last_24h: {stats_today.nb_total_bounced_last_24h} - {increase_percent(stats_yesterday.nb_total_bounced_last_24h, stats_today.nb_total_bounced_last_24h)}

    """

    monitoring_report += "\n====================================\n"
    monitoring_report += """

"""

    for email, bounces in bounce_report():
        monitoring_report += f"{email}: {bounces}\n"

    monitoring_report += """\n

"""

    for email, nb_alias, date in alias_creation_report():
        monitoring_report += f"{email}, {date}: {nb_alias}\n"

    monitoring_report += """\n

"""
    monitoring_report += all_bounce_report()

    LOG.d("monitoring_report email: %s", monitoring_report)

    send_email(
        config.MONITORING_EMAIL,
        subject=f"Login Monitoring Report for {today}",
        plaintext=monitoring_report,
        retries=3,
    )


def migrate_domain_trash():
    
    @compiles(Insert, "postgresql")
    def postgresql_on_conflict_do_nothing(insert, compiler, **kw):
        statement = compiler.visit_insert(insert, **kw)
        
        returning_position = statement.find("RETURNING")
        if returning_position >= 0:
            return (
                statement[:returning_position]
                + "ON CONFLICT DO NOTHING "
                + statement[returning_position:]
            )
        else:
            return statement + " ON CONFLICT DO NOTHING"

    sl_domains = [sl.domain for sl in SLDomain.all()]
    count = 0
    domain_deleted_aliases = []
    deleted_alias_ids = []
    for deleted_alias in DeletedAlias.yield_per_query():
        if count % 1000 == 0:
            LOG.d("process %s", count)

        count += 1

        alias_domain = get_email_domain_part(deleted_alias.email)
        if alias_domain not in sl_domains:
            custom_domain = CustomDomain.get_by(domain=alias_domain)
            if custom_domain:
                LOG.w("move %s to domain %s trash", deleted_alias, custom_domain)
                domain_deleted_aliases.append(
                    DomainDeletedAlias(
                        user_id=custom_domain.user_id,
                        email=deleted_alias.email,
                        domain_id=custom_domain.id,
                        created_at=deleted_alias.created_at,
                    )
                )
                deleted_alias_ids.append(deleted_alias.id)

    LOG.d("create %s DomainDeletedAlias", len(domain_deleted_aliases))
    Session.bulk_save_objects(domain_deleted_aliases)

    LOG.d("delete %s DeletedAlias", len(deleted_alias_ids))
    DeletedAlias.filter(DeletedAlias.id.in_(deleted_alias_ids)).delete(
        synchronize_session=False
    )

    Session.commit()
