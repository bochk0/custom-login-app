import re

import arrow
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, validators, IntegerField

from app.config import EMAIL_SERVERS_WITH_PRIORITY, EMAIL_DOMAIN, JOB_DELETE_DOMAIN
from app.custom_domain_validation import CustomDomainValidation
from app.dashboard.base import dashboard_bp
from app.db import Session
from app.dns_utils import (
    get_mx_domains,
    get_spf_domain,
    get_txt_record,
    is_mx_equivalent,
)
from app.log import LOG
from app.models import (
    CustomDomain,
    Alias,
    DomainDeletedAlias,
    Mailbox,
    DomainMailbox,
    AutoCreateRule,
    AutoCreateRuleMailbox,
    Job,
)
from app.regex_utils import regex_match
from app.utils import random_string, CSRFValidationForm


@dashboard_bp.route("/domains/<int:custom_domain_id>/dns", methods=["GET", "POST"])
@login_required
def domain_detail_dns(custom_domain_id):
    custom_domain: CustomDomain = CustomDomain.get(custom_domain_id)
    if not custom_domain or custom_domain.user_id != current_user.id:
        flash("You cannot see this page", "warning")
        return redirect(url_for("dashboard.index"))

    # generate a domain ownership txt token if needed
    if not custom_domain.ownership_verified and not custom_domain.ownership_txt_token:
        custom_domain.ownership_txt_token = random_string(30)
        Session.commit()

    spf_record = f"v=spf1 include:{EMAIL_DOMAIN} ~all"

    domain_validator = CustomDomainValidation(EMAIL_DOMAIN)
    csrf_form = CSRFValidationForm()

    dmarc_record = "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s"

    mx_ok = spf_ok = dkim_ok = dmarc_ok = ownership_ok = True
    mx_errors = spf_errors = dkim_errors = dmarc_errors = ownership_errors = []

    if request.method == "POST":
        if not csrf_form.validate():
            flash("Invalid request", "warning")
            return redirect(request.url)
        if request.form.get("form-name") == "check-ownership":
            txt_records = get_txt_record(custom_domain.domain)

            if custom_domain.get_ownership_dns_txt_value() in txt_records:
                flash(
                    "Domain ownership is verified. Please proceed to the other records setup",
                    "success",
                )
                custom_domain.ownership_verified = True
                Session.commit()
                return redirect(
                    url_for(
                        "dashboard.domain_detail_dns",
                        custom_domain_id=custom_domain.id,
                        _anchor="dns-setup",
                    )
                )
            else:
                flash("We can't find the needed TXT record", "error")
                ownership_ok = False
                ownership_errors = txt_records

        elif request.form.get("form-name") == "check-mx":
            mx_domains = get_mx_domains(custom_domain.domain)

            if not is_mx_equivalent(mx_domains, EMAIL_SERVERS_WITH_PRIORITY):
                flash("The MX record is not correctly set", "warning")

                mx_ok = False
                # build mx_errors to show to user
                mx_errors = [
                    f"{priority} {domain}" for (priority, domain) in mx_domains
                ]
            else:
                flash(
                    "Your domain can start receiving emails. You can now use it to create alias",
                    "success",
                )
                custom_domain.verified = True
                Session.commit()
                return redirect(
                    url_for(
                        "dashboard.domain_detail_dns", custom_domain_id=custom_domain.id
                    )
                )
        elif request.form.get("form-name") == "check-spf":
            spf_domains = get_spf_domain(custom_domain.domain)
            if EMAIL_DOMAIN in spf_domains:
                custom_domain.spf_verified = True
                Session.commit()
                flash("SPF is setup correctly", "success")
                return redirect(
                    url_for(
                        "dashboard.domain_detail_dns", custom_domain_id=custom_domain.id
                    )
                )
            else:
                custom_domain.spf_verified = False
                Session.commit()
                flash(
                    f"SPF: {EMAIL_DOMAIN} is not included in your SPF record.",
                    "warning",
                )
                spf_ok = False
                spf_errors = get_txt_record(custom_domain.domain)

        elif request.form.get("form-name") == "check-dkim":
            dkim_errors = domain_validator.validate_dkim_records(custom_domain)
            if len(dkim_errors) == 0:
                flash("DKIM is setup correctly.", "success")
                return redirect(
                    url_for(
                        "dashboard.domain_detail_dns", custom_domain_id=custom_domain.id
                    )
                )
            else:
                dkim_ok = False
                flash("DKIM: the CNAME record is not correctly set", "warning")

        elif request.form.get("form-name") == "check-dmarc":
            txt_records = get_txt_record("_dmarc." + custom_domain.domain)
            if dmarc_record in txt_records:
                custom_domain.dmarc_verified = True
                Session.commit()
                flash("DMARC is setup correctly", "success")
                return redirect(
                    url_for(
                        "dashboard.domain_detail_dns", custom_domain_id=custom_domain.id
                    )
                )
            else:
                custom_domain.dmarc_verified = False
                Session.commit()
                flash(
                    "DMARC: The TXT record is not correctly set",
                    "warning",
                )
                dmarc_ok = False
                dmarc_errors = txt_records

    return render_template(
        "dashboard/domain_detail/dns.html",
        EMAIL_SERVERS_WITH_PRIORITY=EMAIL_SERVERS_WITH_PRIORITY,
        dkim_records=domain_validator.get_dkim_records(),
        **locals(),
    )


@dashboard_bp.route("/domains/<int:custom_domain_id>/info", methods=["GET", "POST"])
@login_required
def domain_detail(custom_domain_id):
    csrf_form = CSRFValidationForm()
    custom_domain: CustomDomain = CustomDomain.get(custom_domain_id)
    mailboxes = current_user.mailboxes()

    if not custom_domain or custom_domain.user_id != current_user.id:
        flash("You cannot see this page", "warning")
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        if not csrf_form.validate():
            flash("Invalid request", "warning")
            return redirect(request.url)
        if request.form.get("form-name") == "switch-catch-all":
            custom_domain.catch_all = not custom_domain.catch_all
            Session.commit()

            if custom_domain.catch_all:
                flash(
                    f"The catch-all has been enabled for {custom_domain.domain}",
                    "success",
                )
            else:
                flash(
                    f"The catch-all has been disabled for {custom_domain.domain}",
                    "warning",
                )
            return redirect(
                url_for("dashboard.domain_detail", custom_domain_id=custom_domain.id)
            )
        elif request.form.get("form-name") == "set-name":
            if request.form.get("action") == "save":
                custom_domain.name = request.form.get("alias-name").replace("\n", "")
                Session.commit()
                flash(
                    f"Default alias name for Domain {custom_domain.domain} has been set",
                    "success",
                )
            else:
                custom_domain.name = None
                Session.commit()
                flash(
                    f"Default alias name for Domain {custom_domain.domain} has been removed",
                    "info",
                )

            return redirect(
                url_for("dashboard.domain_detail", custom_domain_id=custom_domain.id)
            )
        elif request.form.get("form-name") == "switch-random-prefix-generation":
            custom_domain.random_prefix_generation = (
                not custom_domain.random_prefix_generation
            )
            Session.commit()

            if custom_domain.random_prefix_generation:
                flash(
                    f"Random prefix generation has been enabled for {custom_domain.domain}",
                    "success",
                )
            else:
                flash(
                    f"Random prefix generation has been disabled for {custom_domain.domain}",
                    "warning",
                )
            return redirect(
                url_for("dashboard.domain_detail", custom_domain_id=custom_domain.id)
            )
        elif request.form.get("form-name") == "update":
            mailbox_ids = request.form.getlist("mailbox_ids")
            # check if mailbox is not tempered with
            mailboxes = []
            for mailbox_id in mailbox_ids:
                mailbox = Mailbox.get(mailbox_id)
                if (
                    not mailbox
                    or mailbox.user_id != current_user.id
                    or not mailbox.verified
                ):
                    flash("Something went wrong, please retry", "warning")
                    return redirect(
                        url_for(
                            "dashboard.domain_detail", custom_domain_id=custom_domain.id
                        )
                    )
                mailboxes.append(mailbox)

            if not mailboxes:
                flash("You must select at least 1 mailbox", "warning")
                return redirect(
                    url_for(
                        "dashboard.domain_detail", custom_domain_id=custom_domain.id
                    )
                )

