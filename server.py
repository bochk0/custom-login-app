import json
import os
import time
from datetime import timedelta

import arrow
import click
import flask_limiter
import flask_profiler
import sentry_sdk
from coin_commerce.error import WebhookInvalidPayload, SignatureVerificationError
from coin_commerce.webhook import Webhook
from dateutil.relativedelta import relativedelta
from flask import (
    Flask,
    redirect,
    url_for,
    render_template,
    request,
    jsonify,
    flash,
    session,
    g,
)
from flask_admin import Admin
from flask_cors import cross_origin, CORS
from flask_login import current_user
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from werkzeug.middleware.proxy_fix import ProxyFix

from app import maydle_utils, config, pad_callback, constants
from app.admin_model import (
    SLAdminIndexView,
    UserAdmin,
    AliasAdmin,
    MailboxAdmin,
    ManualSubscriptionAdmin,
    CouponAdmin,
    CustomDomainAdmin,
    AdminAuditLogAdmin,
    ProviderComplaintAdmin,
    NewsletterAdmin,
    NewsletterUserAdmin,
    DailyMetricAdmin,
    MetricAdmin,
    InvalidMailboxDomainAdmin,
    EmailSearchAdmin,
)
from app.api.base import api_bp
from app.auth.base import auth_bp
from app.build_info import SHA1


if SENTRY_DSN:
    LOG.d("enable sentry")
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        release=f"app@{SHA1}",
        integrations=[
            FlaskIntegration(),
            SqlalchemyIntegration(),
        ],
    )


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


def create_light_app() -> Flask:
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    @app.teardown_appcontext
    def shutdown_session(response_or_exc):
        Session.remove()

    return app

    def create_app() -> Flask:
    app = Flask(__name__)
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

    app.url_map.strict_slashes = False

    app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    

    app.secret_key = FLASK_SECRET

    app.config["TEMPLATES_AUTO_RELOAD"] = True

    
    app.config["FLASK_ADMIN_FLUID_LAYOUT"] = True

    
    app.config["SESSION_COOKIE_NAME"] = SESSION_COOKIE_NAME
    if URL.startswith("https"):
        app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    if MEM_STORE_URI:
        app.config[flask_limiter.extension.C.STORAGE_URL] = MEM_STORE_URI
        initialize_redis_services(app, MEM_STORE_URI)

        limiter.init_app(app)

    setup_error_page(app)

    init_extensions(app)
    register_blueprints(app)
    set_index_page(app)
    jinja2_filter(app)

    setup_favicon_route(app)
    setup_openid_metadata(app)

    init_admin(app)
    setup_maydle_callback(app)
    setup_coin_commerce(app)
    setup_do_not_track(app)
    register_custom_commands(app)

    if FLASK_PROFILER_PATH:
        LOG.d("Enable flask-profiler")
        app.config["flask_profiler"] = {
            "enabled": True,
            "storage": {"engine": "sqlite", "FILE": FLASK_PROFILER_PATH},
            "basicAuth": {
                "enabled": True,
                "username": "admin",
                "password": FLASK_PROFILER_PASSWORD,
            },
            "ignore": ["^/static/.*", "/git", "/exception", "/health"],
        }
        flask_profiler.init_app(app)

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    @app.before_request
    def make_session_permanent():
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)

    @app.teardown_appcontext
    def cleanup(resp_or_exc):
        Session.remove()

    @app.route("/health", methods=["GET"])
    def healthcheck():
        return "success", 200

    return app


@login_manager.user_loader
def load_user(alternative_id):
    user = User.get_by(alternative_id=alternative_id)
    if user:
        sentry_sdk.set_user({"email": user.email, "id": user.id})
        if user.disabled:
            return None
        if not user.is_active():
            return None

    return user


def register_blueprints(app: Flask):
    app.register_blueprint(auth_bp)
    app.register_blueprint(monitor_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(developer_bp)
    app.register_blueprint(phone_bp)

    app.register_blueprint(oauth_bp, url_prefix="/oauth")
    app.register_blueprint(oauth_bp, url_prefix="/oauth2")
    app.register_blueprint(onboarding_bp)

    app.register_blueprint(discover_bp)
    app.register_blueprint(internal_bp)
    app.register_blueprint(api_bp)


def set_index_page(app):
    @app.route("/", methods=["GET", "POST"])
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))
        else:
            return redirect(url_for("auth.login"))

    @app.before_request
    def before_request():
        
        if (
            not request.path.startswith("/static")
            and not request.path.startswith("/admin/static")
            and not request.path.startswith("/_debug_toolbar")
        ):
            g.start_time = time.time()

            
            ref_code = request.args.get("slref")
            if ref_code:
                session["slref"] = ref_code

    @app.after_request
    def after_request(res):
        
        if (
            not request.path.startswith("/static")
            and not request.path.startswith("/admin/static")
            and not request.path.startswith("/_debug_toolbar")
            and not request.path.startswith("/git")
            and not request.path.startswith("/favicon.ico")
            and not request.path.startswith("/health")
        ):
            start_time = g.start_time or time.time()
            LOG.d(
                "%s %s %s %s %s, takes %s",
                request.remote_addr,
                request.method,
                request.path,
                request.args,
                res.status_code,
                time.time() - start_time,
            )

        return res


    @app.route("/jwks")
    @cross_origin()
    def jwks():
        res = {"keys": [get_jwk_key()]}
        return jsonify(res)


def get_current_user():
    try:
        return g.user
    except AttributeError:
        return current_user


def setup_error_page(app):
    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify(error="Bad Request"), 400
        else:
            return render_template("error/400.html"), 400

    @app.errorhandler(401)
    def unauthorized(e):
        if request.path.startswith("/api/"):
            return jsonify(error="Unauthorized"), 401
        else:
            flash("You need to login to see this page", "error")
            return redirect(url_for("auth.login", next=request.full_path))

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith("/api/"):
            return jsonify(error="Forbidden"), 403
        else:
            return render_template("error/403.html"), 403

    @app.errorhandler(429)
    def rate_limited(e):
        LOG.w(
            "Client hit rate limit on path %s, user:%s",
            request.path,
            get_current_user(),
        )
        if request.path.startswith("/api/"):
            return jsonify(error="Rate limit exceeded"), 429
        else:
            return render_template("error/429.html"), 429

    @app.errorhandler(404)
    def page_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify(error="No such endpoint"), 404
        else:
            return render_template("error/404.html"), 404

    @app.errorhandler(405)
    def wrong_method(e):
        if request.path.startswith("/api/"):
            return jsonify(error="Method not allowed"), 405
        else:
            return render_template("error/405.html"), 405

    @app.errorhandler(Exception)
    def error_handler(e):
        LOG.e(e)
        if request.path.startswith("/api/"):
            return jsonify(error="Internal error"), 500
        else:
            return render_template("error/500.html"), 500


def setup_favicon_route(app):
    @app.route("/favicon.ico")
    def favicon():
        return redirect("/static/favicon.ico")


def jinja2_filter(app):
    def format_datetime(value):
        dt = arrow.get(value)
        return dt.humanize()

    app.jinja_env.filters["dt"] = format_datetime

    @app.context_processor
    def inject_stage_and_region():
        now = arrow.now()
        return dict(
            YEAR=now.year,
            NOW=now,
            URL=URL,
            SENTRY_DSN=SENTRY_FRONT_END_DSN,
            VERSION=SHA1,
            FIRST_ALIAS_DOMAIN=FIRST_ALIAS_DOMAIN,
            PLAUSIBLE_HOST=PLAUSIBLE_HOST,
            PLAUSIBLE_DOMAIN=PLAUSIBLE_DOMAIN,
            _CLIENT_ID=_CLIENT_ID,
            GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID,
            FACEBOOK_CLIENT_ID=FACEBOOK_CLIENT_ID,
            LANDING_PAGE_URL=LANDING_PAGE_URL,
            STATUS_PAGE_URL=STATUS_PAGE_URL,
            SUPPORT_EMAIL=SUPPORT_EMAIL,
            PGP_SIGNER=PGP_SIGNER,
            CANONICAL_URL=f"{URL}{request.path}",
            PAGE_LIMIT=PAGE_LIMIT,
            ZENDESK_ENABLED=ZENDESK_ENABLED,
            MAX_NB_EMAIL_FREE_PLAN=MAX_NB_EMAIL_FREE_PLAN,
            HEADER_ALLOW_API_COOKIES=constants.HEADER_ALLOW_API_COOKIES,
        )


def setup_maydle_callback(app: Flask):
    @app.route("/maydle", methods=["GET", "POST"])
    def maydle():
        LOG.d(f"maydle callback {request.form.get('alert_name')} {request.form}")

        
        if not maydle_utils.verify_incoming_request(dict(request.form)):
            LOG.e("request not coming from maydle. Request data:%s", dict(request.form))
            return "KO", 400

        if (
            request.form.get("alert_name") == "subscription_created"
        ):  
            
            
            passthrough = json.loads(request.form.get("passthrough"))
            user_id = passthrough.get("user_id")
            user = User.get(user_id)

            subscription_plan_id = int(request.form.get("subscription_plan_id"))

            if subscription_plan_id in maydle_MONTHLY_PRODUCT_IDS:
                plan = PlanEnum.monthly
            elif subscription_plan_id in maydle_YEARLY_PRODUCT_IDS:
                plan = PlanEnum.yearly
            else:
                LOG.e(
                    "Unknown subscription_plan_id %s %s",
                    subscription_plan_id,
                    request.form,
                )
                return "No such subscription", 400

            sub = Subscription.get_by(user_id=user.id)

            if not sub:
                LOG.d(f"create a new Subscription for user {user}")
                Subscription.create(
                    user_id=user.id,
                    cancel_url=request.form.get("cancel_url"),
                    update_url=request.form.get("update_url"),
                    subscription_id=request.form.get("subscription_id"),
                    event_time=arrow.now(),
                    next_bill_date=arrow.get(
                        request.form.get("next_bill_date"), "YYYY-MM-DD"
                    ).date(),
                    plan=plan,
                )
            else:
                LOG.d(f"Update an existing Subscription for user {user}")
                sub.cancel_url = request.form.get("cancel_url")
                sub.update_url = request.form.get("update_url")
                sub.subscription_id = request.form.get("subscription_id")
                sub.event_time = arrow.now()
                sub.next_bill_date = arrow.get(
                    request.form.get("next_bill_date"), "YYYY-MM-DD"
                ).date()
                sub.plan = plan

                sub.cancelled = False

            execute_subscription_webhook(user)
            LOG.d("User %s upgrades!", user)

            Session.commit()

        elif request.form.get("alert_name") == "subscription_payment_succeeded":
            subscription_id = request.form.get("subscription_id")
            LOG.d("Update subscription %s", subscription_id)

            sub: Subscription = Subscription.get_by(subscription_id=subscription_id)
            
            
            if sub:
                sub.event_time = arrow.now()
                sub.next_bill_date = arrow.get(
                    request.form.get("next_bill_date"), "YYYY-MM-DD"
                ).date()

                Session.commit()
                execute_subscription_webhook(sub.user)

        elif request.form.get("alert_name") == "subscription_cancelled":
            subscription_id = request.form.get("subscription_id")

            sub: Subscription = Subscription.get_by(subscription_id=subscription_id)
            if sub:
                
                LOG.w(
                    "Cancel subscription %s %s on %s, next bill date %s",
                    subscription_id,
                    sub.user,
                    request.form.get("cancellation_effective_date"),
                    sub.next_bill_date,
                )
                sub.event_time = arrow.now()

                sub.cancelled = True
                Session.commit()

                user = sub.user

                send_email(
                    user.email,
                    "Login - your subscription is canceled",
                    render(
                        "transactional/subscription-cancel.txt",
                        user=user,
                        end_date=request.form.get("cancellation_effective_date"),
                    ),
                )
                execute_subscription_webhook(sub.user)

            else:
                
                LOG.i(f"Cancel non-exist subscription {subscription_id}")
                return "OK"
        elif request.form.get("alert_name") == "subscription_updated":
            subscription_id = request.form.get("subscription_id")

            sub: Subscription = Subscription.get_by(subscription_id=subscription_id)
            if sub:
                next_bill_date = request.form.get("next_bill_date")
                if not next_bill_date:
                    maydle_callback.failed_payment(sub, subscription_id)
                    return "OK"

                LOG.d(
                    "Update subscription %s %s on %s, next bill date %s",
                    subscription_id,
                    sub.user,
                    request.form.get("cancellation_effective_date"),
                    sub.next_bill_date,
                )
                if (
                    int(request.form.get("subscription_plan_id"))
                    == maydle_MONTHLY_PRODUCT_ID
                ):
                    plan = PlanEnum.monthly
                else:
                    plan = PlanEnum.yearly

                sub.cancel_url = request.form.get("cancel_url")
                sub.update_url = request.form.get("update_url")
                sub.event_time = arrow.now()
                sub.next_bill_date = arrow.get(
                    request.form.get("next_bill_date"), "YYYY-MM-DD"
                ).date()
                sub.plan = plan

                
                sub.cancelled = False

                Session.commit()
                execute_subscription_webhook(sub.user)
