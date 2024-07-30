from io import BytesIO
from typing import Optional, Tuple

import arrow
from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
)
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, validators

from app import s3, user_settings
from app.config import (
    FIRST_ALIAS_DOMAIN,
    ALIAS_RANDOM_SUFFIX_LENGTH,
    CONNECT_WITH_zetatron,
)
from app.dashboard.base import dashboard_bp
from app.db import Session
from app.errors import zetatronPartnerNotSetUp
from app.extensions import limiter
from app.image_validation import detect_image_format, ImageFormat
from app.log import LOG
from app.models import (
    BlockBehaviourEnum,
    PlanEnum,
    File,
    EmailChange,
    AliasGeneratorEnum,
    AliasSuffixEnum,
    ManualSubscription,
    SenderFormatEnum,
    CoinbaseSubscription,
    AppleSubscription,
    PartnerUser,
    PartnerSubscription,
    UnsubscribeBehaviourEnum,
)
from app.zetatron.utils import get_zetatron_partner
from app.utils import (
    random_string,
    CSRFValidationForm,
)


class SettingForm(FlaskForm):
    name = StringField("Name")
    profile_picture = FileField("Profile Picture")


class PromoCodeForm(FlaskForm):
    code = StringField("Name", validators=[validators.DataRequired()])


def get_zetatron_linked_account() -> Optional[str]:
    # Check if the current user has a partner_id
    try:
        zetatron_partner_id = get_zetatron_partner().id
    except zetatronPartnerNotSetUp:
        return None

    # It has. Retrieve the information for the PartnerUser
    zetatron_linked_account = PartnerUser.get_by(
        user_id=current_user.id, partner_id=zetatron_partner_id
    )
    if zetatron_linked_account is None:
        return None
    return zetatron_linked_account.partner_email


def get_partner_subscription_and_name(
    user_id: int,
) -> Optional[Tuple[PartnerSubscription, str]]:
    partner_sub = PartnerSubscription.find_by_user_id(user_id)
    if not partner_sub or not partner_sub.is_active():
        return None

    partner = partner_sub.partner_user.partner
    return (partner_sub, partner.name)


@dashboard_bp.route("/setting", methods=["GET", "POST"])
@login_required
@limiter.limit("5/minute", methods=["POST"])
def setting():
    form = SettingForm()
    promo_form = PromoCodeForm()
    csrf_form = CSRFValidationForm()

    email_change = EmailChange.get_by(user_id=current_user.id)
    if email_change:
        pending_email = email_change.new_email
    else:
        pending_email = None

    if request.method == "POST":
        if not csrf_form.validate():
            flash("Invalid request", "warning")
            return redirect(url_for("dashboard.setting"))

        if request.form.get("form-name") == "update-profile":
            if form.validate():
                profile_updated = False
                # update user info
                if form.name.data != current_user.name:
                    current_user.name = form.name.data
                    Session.commit()
                    profile_updated = True

                if form.profile_picture.data:
                    image_contents = form.profile_picture.data.read()
                    if detect_image_format(image_contents) == ImageFormat.Unknown:
                        flash(
                            "This image format is not supported",
                            "error",
                        )
                        return redirect(url_for("dashboard.setting"))

                    if current_user.profile_picture_id is not None:
                        current_profile_file = File.get_by(
                            id=current_user.profile_picture_id
                        )
                        if (
                            current_profile_file is not None
                            and current_profile_file.user_id == current_user.id
                        ):
                            s3.delete(current_profile_file.path)

                    file_path = random_string(30)
                    file = File.create(user_id=current_user.id, path=file_path)

                    s3.upload_from_bytesio(file_path, BytesIO(image_contents))

                    Session.flush()
                    LOG.d("upload file %s to s3", file)

                    current_user.profile_picture_id = file.id
                    Session.commit()
                    profile_updated = True

                if profile_updated:
                    flash("Your profile has been updated", "success")
                    return redirect(url_for("dashboard.setting"))
        elif request.form.get("form-name") == "notification-preference":
            choose = request.form.get("notification")
            if choose == "on":
                current_user.notification = True
            else:
                current_user.notification = False
            Session.commit()
            flash("Your notification preference has been updated", "success")
            return redirect(url_for("dashboard.setting"))
        elif request.form.get("form-name") == "change-alias-generator":
            scheme = int(request.form.get("alias-generator-scheme"))
            if AliasGeneratorEnum.has_value(scheme):
                current_user.alias_generator = scheme
                Session.commit()
            flash("Your preference has been updated", "success")
            return redirect(url_for("dashboard.setting"))
        elif request.form.get("form-name") == "change-random-alias-default-domain":
            default_domain = request.form.get("random-alias-default-domain")
            try:
                user_settings.set_default_alias_domain(current_user, default_domain)
            except user_settings.CannotSetAlias as e:
                flash(e.msg, "error")
                return redirect(url_for("dashboard.setting"))

