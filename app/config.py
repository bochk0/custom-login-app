import os
import random
import socket
import string
from ast import literal_eval
from typing import Callable, List
from urllib.parse import urlparse

from dotenv import load_dotenv

ROOT_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


def get_abs_path(file_path: str):
    """append ROOT_DIR for relative path"""
    # Already absolute path
    if file_path.startswith("/"):
        return file_path
    else:
        return os.path.join(ROOT_DIR, file_path)


def sl_getenv(env_var: str, default_factory: Callable = None):
    """
    Get env value, convert into Python object
    Args:
        env_var (str): env var, example: SL_DB
        default_factory: returns value if this env var is not set.

    """
    value = os.getenv(env_var)
    if value is None:
        return default_factory()

    return literal_eval(value)


config_file = os.environ.get("CONFIG")
if config_file:
    config_file = get_abs_path(config_file)
    print("load config file", config_file)
    load_dotenv(get_abs_path(config_file))
else:
    load_dotenv()

COLOR_LOG = "COLOR_LOG" in os.environ

# Allow user to have 1 year of premium: set the expiration_date to 1 year more
PROMO_CODE = "weareBETTER"

# Server url
URL = os.environ["URL"]
print(">>> URL:", URL)

# Calculate RP_ID for WebAuthn
RP_ID = urlparse(URL).hostname

SENTRY_DSN = os.environ.get("SENTRY_DSN")

# can use another sentry project for the front-end to avoid noises
SENTRY_FRONT_END_DSN = os.environ.get("SENTRY_FRONT_END_DSN") or SENTRY_DSN

# Email related settings
NOT_SEND_EMAIL = "NOT_SEND_EMAIL" in os.environ
EMAIL_DOMAIN = os.environ["EMAIL_DOMAIN"].lower()
SUPPORT_EMAIL = os.environ["SUPPORT_EMAIL"]
SUPPORT_NAME = os.environ.get("SUPPORT_NAME", "Son from Login")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
# to receive monitoring daily report
MONITORING_EMAIL = os.environ.get("MONITORING_EMAIL")

# VERP: mail_from set to BOUNCE_PREFIX + email_log.id + BOUNCE_SUFFIX
BOUNCE_PREFIX = os.environ.get("BOUNCE_PREFIX") or "bounce+"
BOUNCE_SUFFIX = os.environ.get("BOUNCE_SUFFIX") or f"+@{EMAIL_DOMAIN}"

# Used for VERP during reply phase. It's similar to BOUNCE_PREFIX.
# It's needed when sending emails from custom domain to respect DMARC.
# BOUNCE_PREFIX_FOR_REPLY_PHASE should never be used in any existing alias
# and can't be used for creating a new alias on custom domain
# Note BOUNCE_PREFIX_FOR_REPLY_PHASE doesn't have the trailing plus sign (+) as BOUNCE_PREFIX
BOUNCE_PREFIX_FOR_REPLY_PHASE = (
    os.environ.get("BOUNCE_PREFIX_FOR_REPLY_PHASE") or "bounce_reply"
)

# VERP for transactional email: mail_from set to BOUNCE_PREFIX + email_log.id + BOUNCE_SUFFIX
TRANSACTIONAL_BOUNCE_PREFIX = (
    os.environ.get("TRANSACTIONAL_BOUNCE_PREFIX") or "transactional+"
)
TRANSACTIONAL_BOUNCE_SUFFIX = (
    os.environ.get("TRANSACTIONAL_BOUNCE_SUFFIX") or f"+@{EMAIL_DOMAIN}"
)

try:
    MAX_NB_EMAIL_FREE_PLAN = int(os.environ["MAX_NB_EMAIL_FREE_PLAN"])
except Exception:
    print("MAX_NB_EMAIL_FREE_PLAN is not set, use 5 as default value")
    MAX_NB_EMAIL_FREE_PLAN = 5

MAX_NB_EMAIL_OLD_FREE_PLAN = int(os.environ.get("MAX_NB_EMAIL_OLD_FREE_PLAN", 15))

# maximum number of directory a premium user can create
MAX_NB_DIRECTORY = 50
MAX_NB_SUBDOMAIN = 5

ENFORCE_SPF = "ENFORCE_SPF" in os.environ

# override postfix server locally
# use 240.0.0.1 here instead of 10.0.0.1 as existing SL instances use the 240.0.0.0 network
POSTFIX_SERVER = os.environ.get("POSTFIX_SERVER", "240.0.0.1")

DISABLE_REGISTRATION = "DISABLE_REGISTRATION" in os.environ

# allow using a different postfix port, useful when developing locally

# Use port 587 instead of 25 when sending emails through Postfix
# Useful when calling Postfix from an external network
POSTFIX_SUBMISSION_TLS = "POSTFIX_SUBMISSION_TLS" in os.environ
if POSTFIX_SUBMISSION_TLS:
    default_postfix_port = 587
else:
    default_postfix_port = 25
POSTFIX_PORT = int(os.environ.get("POSTFIX_PORT", default_postfix_port))
POSTFIX_TIMEOUT = int(os.environ.get("POSTFIX_TIMEOUT", 3))

# ["domain1.com", "domain2.com"]
OTHER_ALIAS_DOMAINS = sl_getenv("OTHER_ALIAS_DOMAINS", list)
OTHER_ALIAS_DOMAINS = [d.lower().strip() for d in OTHER_ALIAS_DOMAINS]

# List of domains user can use to create alias
if "ALIAS_DOMAINS" in os.environ:
    ALIAS_DOMAINS = sl_getenv("ALIAS_DOMAINS")  # ["domain1.com", "domain2.com"]
else:
    ALIAS_DOMAINS = OTHER_ALIAS_DOMAINS + [EMAIL_DOMAIN]
ALIAS_DOMAINS = [d.lower().strip() for d in ALIAS_DOMAINS]

# ["domain1.com", "domain2.com"]
PREMIUM_ALIAS_DOMAINS = sl_getenv("PREMIUM_ALIAS_DOMAINS", list)
PREMIUM_ALIAS_DOMAINS = [d.lower().strip() for d in PREMIUM_ALIAS_DOMAINS]

# the alias domain used when creating the first alias for user
FIRST_ALIAS_DOMAIN = os.environ.get("FIRST_ALIAS_DOMAIN") or EMAIL_DOMAIN

# list of (priority, email server)
# e.g. [(10, "mx1.hostname."), (10, "mx2.hostname.")]
EMAIL_SERVERS_WITH_PRIORITY = sl_getenv("EMAIL_SERVERS_WITH_PRIORITY")

# disable the alias suffix, i.e. the ".random_word" part
DISABLE_ALIAS_SUFFIX = "DISABLE_ALIAS_SUFFIX" in os.environ

# the email address that receives all unsubscription request
UNSUBSCRIBER = os.environ.get("UNSUBSCRIBER")

# due to a typo, both UNSUBSCRIBER and OLD_UNSUBSCRIBER are supported
OLD_UNSUBSCRIBER = os.environ.get("OLD_UNSUBSCRIBER")

DKIM_SELECTOR = b"dkim"
DKIM_PRIVATE_KEY = None

if "DKIM_PRIVATE_KEY_PATH" in os.environ:
    DKIM_PRIVATE_KEY_PATH = get_abs_path(os.environ["DKIM_PRIVATE_KEY_PATH"])
    with open(DKIM_PRIVATE_KEY_PATH) as f:
        DKIM_PRIVATE_KEY = f.read()

# Database
DB_URI = os.environ["DB_URI"]
DB_CONN_NAME = os.environ.get("DB_CONN_NAME", "webapp")

# Flask secret
FLASK_SECRET = os.environ["FLASK_SECRET"]
if not FLASK_SECRET:
    raise RuntimeError("FLASK_SECRET is empty. Please define it.")
SESSION_COOKIE_NAME = "slapp"
MAILBOX_SECRET = FLASK_SECRET + "mailbox"
CUSTOM_ALIAS_SECRET = FLASK_SECRET + "custom_alias"
UNSUBSCRIBE_SECRET = FLASK_SECRET + "unsub"

# AWS
AWS_REGION = os.environ.get("AWS_REGION") or "eu-west-3"
BUCKET = os.environ.get("BUCKET")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL", None)

# OpenID keys, used to sign id_token
OPENID_PRIVATE_KEY_PATH = get_abs_path(
    os.environ.get("OPENID_PRIVATE_KEY_PATH", "local_data/jwtRS256.key")
)
OPENID_PUBLIC_KEY_PATH = get_abs_path(
    os.environ.get("OPENID_PUBLIC_KEY_PATH", "local_data/jwtRS256.key.pub")
)

# Used to generate random email
# words.txt is a list of English words and doesn't contain any "bad" word
WORDS_FILE_PATH = get_abs_path(
    os.environ.get("WORDS_FILE_PATH", "local_data/words.txt")
)

# Used to generate random email
if os.environ.get("GNUPGHOME"):
    GNUPGHOME = get_abs_path(os.environ.get("GNUPGHOME"))
else:
    letters = string.ascii_lowercase
    random_dir_name = "".join(random.choice(letters) for _ in range(20))
    GNUPGHOME = f"/tmp/{random_dir_name}"
    if not os.path.exists(GNUPGHOME):
        os.mkdir(GNUPGHOME, mode=0o700)

    print("WARNING: Use a temp directory for GNUPGHOME", GNUPGHOME)

