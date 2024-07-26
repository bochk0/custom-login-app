from typing import Optional

import arrow
import sqlalchemy
from flask_admin.form import SecureForm
from flask_admin.model.template import EndpointLinkRowAction
from markupsafe import Markup

from app import models, s3
from flask import redirect, url_for, request, flash, Response
from flask_admin import expose, AdminIndexView
from flask_admin.actions import action
from flask_admin.contrib import sqla
from flask_login import current_user

from app.db import Session
from app.models import (
    User,
    ManualSubscription,
    Fido,
    Subscription,
    AppleSubscription,
    AdminAuditLog,
    AuditLogActionEnum,
    ProviderComplaintState,
    Phase,
    ProviderComplaint,
    Alias,
    Newsletter,
    PADDLE_SUBSCRIPTION_GRACE_DAYS,
)
from app.newsletter_utils import send_newsletter_to_user, send_newsletter_to_address


class SLModelView(sqla.ModelView):
    column_default_sort = ("id", True)
    column_display_pk = True
    page_size = 100

    can_edit = False
    can_create = False
    can_delete = False
    edit_modal = True

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        flash("You don't have access to the admin page", "error")
        return redirect(url_for("dashboard.index", next=request.url))

    def on_model_change(self, form, model, is_created):
        changes = {}
        for attr in sqlalchemy.inspect(model).attrs:
            if attr.history.has_changes() and attr.key not in (
                "created_at",
                "updated_at",
            ):
                value = attr.value
                # If it's a model reference, get the source id
                if issubclass(type(value), models.Base):
                    value = value.id
                # otherwise, if its a generic object stringify it
                if issubclass(type(value), object):
                    value = str(value)
                changes[attr.key] = value
        auditAction = (
            AuditLogActionEnum.create_object
            if is_created
            else AuditLogActionEnum.update_object
        )
        AdminAuditLog.create(
            admin_user_id=current_user.id,
            model=model.__class__.__name__,
            model_id=model.id,
            action=auditAction.value,
            data=changes,
        )

    def on_model_delete(self, model):
        AdminAuditLog.create(
            admin_user_id=current_user.id,
            model=model.__class__.__name__,
            model_id=model.id,
            action=AuditLogActionEnum.delete_object.value,
        )


class SLAdminIndexView(AdminIndexView):
    @expose("/")
    def index(self):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for("auth.login", next=request.url))

        return redirect("/admin/user")


def _user_upgrade_channel_formatter(view, context, model, name):
    return Markup(model.upgrade_channel)


class UserAdmin(SLModelView):
    form_base_class = SecureForm
    column_searchable_list = ["email", "id"]
    column_exclude_list = [
        "salt",
        "password",
        "otp_secret",
        "last_otp",
        "fido_uuid",
        "profile_picture",
    ]
    can_edit = False

    def scaffold_list_columns(self):
        ret = super().scaffold_list_columns()
        ret.insert(0, "upgrade_channel")
        return ret

    column_formatters = {
        "upgrade_channel": _user_upgrade_channel_formatter,
    }

    @action(
        "disable_user",
        "Disable user",
        "Are you sure you want to disable the selected users?",
    )
    def action_disable_user(self, ids):
        for user in User.filter(User.id.in_(ids)):
            user.disabled = True

            flash(f"Disabled user {user.id}")
            AdminAuditLog.disable_user(current_user.id, user.id)

        Session.commit()

    @action(
        "enable_user",
        "Enable user",
        "Are you sure you want to enable the selected users?",
    )
    def action_enable_user(self, ids):
        for user in User.filter(User.id.in_(ids)):
            user.disabled = False

            flash(f"Enabled user {user.id}")
            AdminAuditLog.enable_user(current_user.id, user.id)

        Session.commit()

    @action(
        "education_upgrade",
        "Education upgrade",
        "Are you sure you want to edu-upgrade selected users?",
    )
    def action_edu_upgrade(self, ids):
        manual_upgrade("Edu", ids, is_giveaway=True)

    @action(
        "charity_org_upgrade",
        "Charity Organization upgrade",
        "Are you sure you want to upgrade selected users using the Charity organization program?",
    )
    def action_charity_org_upgrade(self, ids):
        manual_upgrade("Charity Organization", ids, is_giveaway=True)

    @action(
        "journalist_upgrade",
        "Journalist upgrade",
        "Are you sure you want to upgrade selected users using the Journalist program?",
    )
    def action_journalist_upgrade(self, ids):
        manual_upgrade("Journalist", ids, is_giveaway=True)

    @action(
        "cash_upgrade",
        "Cash upgrade",
        "Are you sure you want to cash-upgrade selected users?",
    )
    def action_cash_upgrade(self, ids):
        manual_upgrade("Cash", ids, is_giveaway=False)

    @action(
        "crypto_upgrade",
        "Crypto upgrade",
        "Are you sure you want to crypto-upgrade selected users?",
    )
    def action_monero_upgrade(self, ids):
        manual_upgrade("Crypto", ids, is_giveaway=False)

    @action(
        "adhoc_upgrade",
        "Adhoc upgrade - for exceptional case",
        "Are you sure you want to crypto-upgrade selected users?",
    )
    def action_adhoc_upgrade(self, ids):
        manual_upgrade("Adhoc", ids, is_giveaway=False)

    @action(
        "extend_trial_1w",
        "Extend trial for 1 week more",
        "Extend trial for 1 week more?",
    )
    def extend_trial_1w(self, ids):
        for user in User.filter(User.id.in_(ids)):
            if user.trial_end and user.trial_end > arrow.now():
                user.trial_end = user.trial_end.shift(weeks=1)
            else:
                user.trial_end = arrow.now().shift(weeks=1)

            flash(f"Extend trial for {user} to {user.trial_end}", "success")
            AdminAuditLog.extend_trial(
                current_user.id, user.id, user.trial_end, "1 week"
            )

        Session.commit()

