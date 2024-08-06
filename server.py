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
