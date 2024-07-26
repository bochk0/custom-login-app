import arrow
from coinbase_commerce import Client
from flask import render_template, flash, redirect, url_for
from flask_login import login_required, current_user

from app.config import (
    PADDLE_VENDOR_ID,
    PADDLE_MONTHLY_PRODUCT_ID,
    PADDLE_YEARLY_PRODUCT_ID,
    URL,
    COINBASE_YEARLY_PRICE,
    COINBASE_API_KEY,
)
from app.dashboard.base import dashboard_bp
from app.extensions import limiter
from app.log import LOG
from app.models import (
    AppleSubscription,
    Subscription,
    ManualSubscription,
    CoinbaseSubscription,
    PartnerUser,
    PartnerSubscription,
)
from app.proton.utils import get_proton_partner


@dashboard_bp.route("/pricing", methods=["GET", "POST"])
@login_required
def pricing():
    if current_user.lifetime:
        flash("You already have a lifetime subscription", "error")
        return redirect(url_for("dashboard.index"))

    paddle_sub: Subscription = current_user.get_paddle_subscription()
    # user who has canceled can re-subscribe
    if paddle_sub and not paddle_sub.cancelled:
        flash("You already have an active subscription", "error")
        return redirect(url_for("dashboard.index"))

    now = arrow.now()
    manual_sub: ManualSubscription = ManualSubscription.filter(
        ManualSubscription.user_id == current_user.id, ManualSubscription.end_at > now
    ).first()

    coinbase_sub = CoinbaseSubscription.filter(
        CoinbaseSubscription.user_id == current_user.id,
        CoinbaseSubscription.end_at > now,
    ).first()


    return render_template(
        "dashboard/pricing.html",
        PADDLE_VENDOR_ID=PADDLE_VENDOR_ID,
        PADDLE_MONTHLY_PRODUCT_ID=PADDLE_MONTHLY_PRODUCT_ID,
        PADDLE_YEARLY_PRODUCT_ID=PADDLE_YEARLY_PRODUCT_ID,
        success_url=URL + "/dashboard/subscription_success",
        manual_sub=manual_sub,
        coinbase_sub=coinbase_sub,
        now=now,
        proton_upgrade=proton_upgrade,
    )


@dashboard_bp.route("/subscription_success")
@login_required
def subscription_success():
    return render_template(
        "dashboard/thank-you.html",
    )


@dashboard_bp.route("/coinbase_checkout")
@login_required
@limiter.limit("5/minute")
def coinbase_checkout_route():
    client = Client(api_key=COINBASE_API_KEY)
    charge = client.charge.create(
        name="1 Year Login Premium Subscription",
        local_price={"amount": str(COINBASE_YEARLY_PRICE), "currency": "USD"},
        pricing_type="fixed_price",
        metadata={"user_id": current_user.id},
    )

    LOG.d("Create coinbase charge %s", charge)

    return redirect(charge["hosted_url"])
