from __future__ import annotations

import base64
import dataclasses
import enum
import hashlib
import hmac
import os
import random
import secrets
import uuid
from typing import List, Tuple, Optional, Union


from app import config, rate_limiter
from app import s3
from app.db import Session
from app.dns_utils import get_mx_domains

from app.errors import (
    AliasInTrashError,
    DirectoryInTrashError,
    SubdomainInTrashError,
    CannotCreateContactForReverseAlias,
)
from app.handler.unsubscribe_encoder import UnsubscribeAction, UnsubscribeEncoder
from app.log import LOG
from app.oauth_models import Scope
from app.pw_models import PasswordOracle
from app.utils import (
    convert_to_id,
    random_string,
    random_words,
    sanitize_email,
)

Base = declarative_base()


class TSVector(sa.types.TypeDecorator):
    impl = TSVECTOR


class ModelMixin(object):
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    created_at = sa.Column(ArrowType, default=arrow.utcnow, nullable=False)
    updated_at = sa.Column(ArrowType, default=None, onupdate=arrow.utcnow)

    _repr_hide = ["created_at", "updated_at"]

    @classmethod
    def query(cls):
        return Session.query(cls)

    @classmethod
    def yield_per_query(cls, page=1000):

        return Session.query(cls).yield_per(page).enable_eagerloads(False)

    @classmethod
    def get(cls, id):
        return Session.query(cls).get(id)

    @classmethod
    def get_by(cls, **kw):
        return Session.query(cls).filter_by(**kw).first()

    @classmethod
    def filter_by(cls, **kw):
        return Session.query(cls).filter_by(**kw)

    @classmethod
    def filter(cls, *args, **kw):
        return Session.query(cls).filter(*args, **kw)

    @classmethod
    def order_by(cls, *args, **kw):
        return Session.query(cls).order_by(*args, **kw)

    @classmethod
    def all(cls):
        return Session.query(cls).all()

    @classmethod
    def count(cls):
        return Session.query(cls).count()

    @classmethod
    def get_or_create(cls, **kw):
        r = cls.get_by(**kw)
        if not r:
            r = cls(**kw)
            Session.add(r)

        return r

    @classmethod
    def create(cls, **kw):
        
        commit = kw.pop("commit", False)
        flush = kw.pop("flush", False)

        r = cls(**kw)
        Session.add(r)

        if commit:
            Session.commit()

        if flush:
            Session.flush()

        return r

    def save(self):
        Session.add(self)

    @classmethod
    def delete(cls, obj_id, commit=False):
        Session.query(cls).filter(cls.id == obj_id).delete()

        if commit:
            Session.commit()

    @classmethod
    def first(cls):
        return Session.query(cls).first()

    def __repr__(self):
        values = ", ".join(
            "%s=%r" % (n, getattr(self, n))
            for n in self.__table__.c.keys()
            if n not in self._repr_hide
        )
        return "%s(%s)" % (self.__class__.__name__, values)


class File(Base, ModelMixin):
    __tablename__ = "file"
    path = sa.Column(sa.String(128), unique=True, nullable=False)
    user_id = sa.Column(sa.ForeignKey("users.id", ondelete="cascade"), nullable=True)

    def get_url(self, expires_in=3600):
        return s3.get_url(self.path, expires_in)

    def __repr__(self):
        return f"<File {self.path}>"


class EnumE(enum.Enum):
    @classmethod
    def has_value(cls, value: int) -> bool:
        return value in set(item.value for item in cls)

    @classmethod
    def get_name(cls, value: int) -> Optional[str]:
        for item in cls:
            if item.value == value:
                return item.name

        return None

    @classmethod
    def has_name(cls, name: str) -> bool:
        for item in cls:
            if item.name == name:
                return True

        return False

    @classmethod
    def get_value(cls, name: str) -> Optional[int]:
        for item in cls:
            if item.name == name:
                return item.value

        return None


class PlanEnum(EnumE):
    monthly = 2
    yearly = 3



class SenderFormatEnum(EnumE):
    AT = 0  
    A = 2  
    NAME_ONLY = 5  
    AT_ONLY = 6  
    NO_NAME = 7


class AliasGeneratorEnum(EnumE):
    word = 1  
    uuid = 2  


class AliasSuffixEnum(EnumE):
    word = 0  
    random_string = 1  


class BlockBehaviourEnum(EnumE):
    return_2xx = 0
    return_5xx = 1



class Phase(EnumE):
    unknown = 0
    forward = 1
    reply = 2


class VerpType(EnumE):
    bounce_forward = 0
    bounce_reply = 1
    transactional = 2


class JobState(EnumE):
    ready = 0
    taken = 1
    done = 2
    error = 3


class UnsubscribeBehaviourEnum(EnumE):
    DisableAlias = 0
    BlockContact = 1
    PreserveOriginal = 2


    class AliasDeleteReason(EnumE):
    Unspecified = 0
    UserHasBeenDeleted = 1
    ManualAction = 2
    DirectoryDeleted = 3
    MailboxDeleted = 4
    CustomDomainDeleted = 5


class IntEnumType(sa.types.TypeDecorator):
    impl = sa.Integer

    def __init__(self, enumtype, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._enum_type = enumtype

    def process_bind_param(self, enum_obj, dialect):
        return enum_obj.value

    def process_result_value(self, enum_value, dialect):
        return self._enum_type(enum_value)


@dataclasses.dataclass
class AliasOptions:
    show_sl_domains: bool = True
    show_partner_domains: Optional[Partner] = None
    show_partner_premium: Optional[bool] = None


class Hibp(Base, ModelMixin):
    __tablename__ = "hibp"
    name = sa.Column(sa.String(), nullable=False, unique=True, index=True)
    breached_aliases = orm.relationship("Alias", secondary="alias_hibp")

    description = sa.Column(sa.Text)
    date = sa.Column(ArrowType, nullable=True)

    def __repr__(self):
        return f"<HIBP Breach {self.id} {self.name}>"


class HibpNotifiedAlias(Base, ModelMixin):

    __tablename__ = "hibp_notified_alias"
    alias_id = sa.Column(
        sa.ForeignKey("alias.id", ondelete="cascade"), nullable=False, index=True
    )
    user_id = sa.Column(sa.ForeignKey("users.id", ondelete="cascade"), nullable=False)

    notified_at = sa.Column(ArrowType, default=arrow.utcnow, nullable=False)


class Fido(Base, ModelMixin):
    __tablename__ = "fido"
    credential_id = sa.Column(sa.String(), nullable=False, unique=True, index=True)
    uuid = sa.Column(
        sa.ForeignKey("users.fido_uuid", ondelete="cascade"),
        unique=False,
        nullable=False,
    )
    public_key = sa.Column(sa.String(), nullable=False, unique=True)
    sign_count = sa.Column(sa.BigInteger(), nullable=False)
    name = sa.Column(sa.String(128), nullable=False, unique=False)
    user_id = sa.Column(sa.ForeignKey("users.id", ondelete="cascade"), nullable=True)


class User(Base, ModelMixin, UserMixin, PasswordOracle):
    __tablename__ = "users"

    FLAG_FREE_DISABLE_CREATE_ALIAS = 1 << 0
    FLAG_CREATED_FROM_PARTNER = 1 << 1
    FLAG_FREE_OLD_ALIAS_LIMIT = 1 << 2
    FLAG_CREATED_ALIAS_FROM_PARTNER = 1 << 3

    email = sa.Column(sa.String(256), unique=True, nullable=False)

    name = sa.Column(sa.String(128), nullable=True)
    is_admin = sa.Column(sa.Boolean, nullable=False, default=False)
    alias_generator = sa.Column(
        sa.Integer,
        nullable=False,
        default=AliasGeneratorEnum.word.value,
        server_default=str(AliasGeneratorEnum.word.value),
    )
    notification = sa.Column(
        sa.Boolean, default=True, nullable=False, server_default="1"
    )

    activated = sa.Column(sa.Boolean, default=False, nullable=False, index=True)

    
    disabled = sa.Column(sa.Boolean, default=False, nullable=False, server_default="0")

    profile_picture_id = sa.Column(sa.ForeignKey(File.id), nullable=True)

    otp_secret = sa.Column(sa.String(16), nullable=True)
    enable_otp = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )
    last_otp = sa.Column(sa.String(12), nullable=True, default=False)

    
    fido_uuid = sa.Column(sa.String(), nullable=True, unique=True)

    
    
    default_alias_custom_domain_id = sa.Column(
        sa.ForeignKey("custom_domain.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )

    default_alias_public_domain_id = sa.Column(
        sa.ForeignKey("public_domain.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )

    
    lifetime = sa.Column(sa.Boolean, default=False, nullable=False, server_default="0")
    paid_lifetime = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )
    lifetime_coupon_id = sa.Column(
        sa.ForeignKey("lifetime_coupon.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )

    
    trial_end = sa.Column(
        ArrowType, default=lambda: arrow.now().shift(days=7, hours=1), nullable=True
    )

    
    
    
    
    default_mailbox_id = sa.Column(
        sa.ForeignKey("mailbox.id"), nullable=True, default=None
    )

    profile_picture = orm.relationship(File, foreign_keys=[profile_picture_id])

    
    
    sender_format = sa.Column(
        sa.Integer, default="0", nullable=False, server_default="0"
    )
    
    
    sender_format_updated_at = sa.Column(ArrowType, default=None)

    replace_reverse_alias = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    referral_id = sa.Column(
        sa.ForeignKey("referral.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
        index=True,
    )

    referral = orm.relationship("Referral", foreign_keys=[referral_id])

    
    intro_shown = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    default_mailbox = orm.relationship("Mailbox", foreign_keys=[default_mailbox_id])

    
    max_spam_score = sa.Column(sa.Integer, nullable=True)

    

    expand_alias_info = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    
    
    ignore_loop_email = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    
    
    alternative_id = sa.Column(sa.String(128), unique=True, nullable=True)

    
    
    disable_automatic_alias_note = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    
    
    one_click_unsubscribe_block_sender = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )


    include_website_in_one_click_alias = sa.Column(
        sa.Boolean,
        
        default=True,
        nullable=False,
        
        server_default="0",
    )

    _directory_quota = sa.Column(
        "directory_quota", sa.Integer, default=50, nullable=False, server_default="50"
    )

    _subdomain_quota = sa.Column(
        "subdomain_quota", sa.Integer, default=5, nullable=False, server_default="5"
    )

    
    disable_import = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    
    can_use_phone = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    
    phone_quota = sa.Column(sa.Integer, nullable=True)

    
    block_behaviour = sa.Column(
        sa.Enum(BlockBehaviourEnum),
        nullable=False,
        server_default=BlockBehaviourEnum.return_2xx.name,
    )

    include_header_email_header = sa.Column(
        sa.Boolean, default=True, nullable=False, server_default="1"
    )

    
    enable_data_breach_check = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    
    flags = sa.Column(
        sa.BigInteger,
        default=FLAG_FREE_DISABLE_CREATE_ALIAS,
        server_default="0",
        nullable=False,
    )

    
    unsub_behaviour = sa.Column(
        IntEnumType(UnsubscribeBehaviourEnum),
        default=UnsubscribeBehaviourEnum.PreserveOriginal,
        server_default=str(UnsubscribeBehaviourEnum.DisableAlias.value),
        nullable=False,
    )

    
    delete_on = sa.Column(ArrowType, default=None)

    __table_args__ = (
        sa.Index(
            "ix_users_activated_trial_end_lifetime", activated, trial_end, lifetime
        ),
        sa.Index("ix_users_delete_on", delete_on),
    )

    @property
    def directory_quota(self):
        return min(
            self._directory_quota,
            config.MAX_NB_DIRECTORY - Directory.filter_by(user_id=self.id).count(),
        )

    @property
    def subdomain_quota(self):
        return min(
            self._subdomain_quota,
            config.MAX_NB_SUBDOMAIN
            - CustomDomain.filter_by(user_id=self.id, is_sl_subdomain=True).count(),
        )

    @property
    def created_by_partner(self):
        return User.FLAG_CREATED_FROM_PARTNER == (
            self.flags & User.FLAG_CREATED_FROM_PARTNER
        )

    @staticmethod
    def subdomain_is_available():
        return SLDomain.filter_by(can_use_subdomain=True).count() > 0

    
    def get_id(self):
        if self.alternative_id:
            return self.alternative_id
        else:
            return str(self.id)

    @classmethod
    def create(cls, email, name="", password=None, from_partner=False, **kwargs):
        email = sanitize_email(email)
        user: User = super(User, cls).create(email=email, name=name[:100], **kwargs)

        if password:
            user.set_password(password)

        Session.flush()

        mb = Mailbox.create(user_id=user.id, email=user.email, verified=True)
        Session.flush()
        user.default_mailbox_id = mb.id

        
        if "alternative_id" not in kwargs:
            user.alternative_id = str(uuid.uuid4())

        
        
        if from_partner:
            user.flags = User.FLAG_CREATED_FROM_PARTNER
            user.notification = False
            user.trial_end = None
            Job.create(
                name=config.JOB_SEND__WELCOME_1,
                payload={"user_id": user.id},
                run_at=arrow.now(),
            )
            Session.flush()
            return user

        
        alias = Alias.create_new(
            user,
            prefix="login-newsletter",
            mailbox_id=mb.id,
            note="This is your first alias. It's used to receive Login communications "
            "like new features announcements, newsletters.",
        )
        Session.flush()

        user.newsletter_alias_id = alias.id
        Session.flush()

        if config.DISABLE_ONBOARDING:
            LOG.d("Disable onboarding emails")
            return user

        
        Job.create(
            name=config.JOB_ONBOARDING_1,
            payload={"user_id": user.id},
            run_at=arrow.now().shift(days=1),
        )
        Job.create(
            name=config.JOB_ONBOARDING_2,
            payload={"user_id": user.id},
            run_at=arrow.now().shift(days=2),
        )
        Job.create(
            name=config.JOB_ONBOARDING_4,
            payload={"user_id": user.id},
            run_at=arrow.now().shift(days=3),
        )
        Session.flush()

        return user


    def get_active_subscription(
        self, include_partner_subscription: bool = True
    ) -> Optional[
        Union[
            Subscription
            | AppleSubscription
            | ManualSubscription
            | CoinbaseSubscription
            | PartnerSubscription
        ]
    ]:
        sub: Subscription = self.get__subscription()
        if sub:
            return sub

        return None

        def get_active_subscription_end(
        self, include_partner_subscription: bool = True

    
    def lifetime_or_active_subscription(
        self, include_partner_subscription: bool = True
    ) -> bool:
        """True if user has lifetime licence or active subscription"""
        if self.lifetime:
            return True

        return self.get_active_subscription(include_partner_subscription) is not None

    def is_paid(self) -> bool:
        """same as _lifetime_or_active_subscription but not include free manual subscription"""
        sub = self.get_active_subscription()
        if sub is None:
            return False

        if isinstance(sub, ManualSubscription) and sub.is_giveaway:
            return False

        return True


    def is_premium(self, include_partner_subscription: bool = True) -> bool:
        """
        user is premium if they:
        - have a lifetime deal or
        - in trial period or
        - active subscription
        """
        if self.lifetime_or_active_subscription(include_partner_subscription):
            return True

        if self.trial_end and arrow.now() < self.trial_end:
            return True

        return False

    @property
    def upgrade_channel(self) -> str:
        """Used on admin dashboard"""
        
        channels = []
        if self.lifetime:
            channels.append("Lifetime")

        sub: Subscription = self.get__subscription()
        if sub:
            if sub.cancelled:
                channels.append(
                    f"""Cancelled  Subscription <a href="https://..com/subscriptions/customers/manage/{sub.subscription_id}">{sub.subscription_id}</a> {sub.plan_name()} ends at {sub.next_bill_date}"""
                )
            else:
                channels.append(
                    f"""Active  Subscription <a href="https://v..com/subscriptions/customers/manage/{sub.subscription_id}">{sub.subscription_id}</a> {sub.plan_name()}, renews at {sub.next_bill_date}"""
                )

        _sub: Subscription = Subscription.get_by(user_id=self.id)
        if _sub and _sub.is_valid():
            channels.append(f" Subscription {_sub.expires_date.humanize()}")

        manual_sub: ManualSubscription = ManualSubscription.get_by(user_id=self.id)

        return ".\n".join(channels)


    def max_alias_for_free_account(self) -> int:
        if (
            self.FLAG_FREE_OLD_ALIAS_LIMIT
            == self.flags & self.FLAG_FREE_OLD_ALIAS_LIMIT
        ):
            return config.MAX_NB_EMAIL_OLD_FREE_PLAN
        else:
            return config.MAX_NB_EMAIL_FREE_PLAN

    def can_create_new_alias(self) -> bool:
        """
        Whether user can create a new alias. User can't create a new alias if
        - has more than 15 aliases in the free plan, *even in the free trial*
        """
        if not self.is_active():
            return False

        if self.disabled:
            return False

        if self.lifetime_or_active_subscription():
            return True
        else:
            return (
                Alias.filter_by(user_id=self.id).count()
                < self.max_alias_for_free_account()
            )

    def can_send_or_receive(self) -> bool:
        if self.disabled:
            LOG.i(f"User {self} is disabled. Cannot receive or send emails")
            return False
        if self.delete_on is not None:
            LOG.i(
                f"User {self} is scheduled to be deleted. Cannot receive or send emails"
            )
            return False
        return True

    def profile_picture_url(self):
        if self.profile_picture_id:
            return self.profile_picture.get_url()
        else:
            return url_for("static", filename="default-avatar.png")

    def suggested_emails(self, website_name) -> (str, [str]):
        """return suggested email and other email choices"""
        website_name = convert_to_id(website_name)

        all_aliases = [
            ge.email for ge in Alias.filter_by(user_id=self.id, enabled=True)
        ]
        if self.can_create_new_alias():
            suggested_alias = Alias.create_new(self, prefix=website_name).email
        else:
            
            suggested_alias = random.choice(all_aliases)

        return (
            suggested_alias,
            list(set(all_aliases).difference({suggested_alias})),
        )

    def suggested_names(self) -> (str, [str]):
        """return suggested name and other name choices"""
        other_name = convert_to_id(self.name)

        return self.name, [other_name, "Anonymous", "whoami"]

    def get_name_initial(self) -> str:
        if not self.name:
            return ""
        names = self.name.split(" ")
        return "".join([n[0].upper() for n in names if n])

    def get__subscription(self) -> Optional["Subscription"]:
        """return *active*  subscription
        Return None if the subscription is already expired
        TODO: support user unsubscribe and re-subscribe
        """
        sub = Subscription.get_by(user_id=self.id)

        if sub:
            
            
            if (
                sub.next_bill_date
                >= arrow.now().shift(days=-_SUBSCRIPTION_GRACE_DAYS).date()
            ):
                return sub
            
            else:
                return None
        else:
            return sub


         def verified_custom_domains(self) -> List["CustomDomain"]:
        return (
            CustomDomain.filter_by(user_id=self.id, ownership_verified=True)
            .order_by(CustomDomain.domain.asc())
            .all()
        )

    def mailboxes(self) -> List["Mailbox"]:
        """list of mailbox that user own"""
        mailboxes = []

        for mailbox in Mailbox.filter_by(user_id=self.id, verified=True):
            mailboxes.append(mailbox)

        return mailboxes

    def nb_directory(self):
        return Directory.filter_by(user_id=self.id).count()

    def has_custom_domain(self):
        return CustomDomain.filter_by(user_id=self.id, verified=True).count() > 0

    def custom_domains(self):
        return CustomDomain.filter_by(user_id=self.id, verified=True).all()

    def available_domains_for_random_alias(
        self, alias_options: Optional[AliasOptions] = None
    ) -> List[Tuple[bool, str]]:
        """Return available domains for user to create random aliases
        Each result record contains:
        - whether the domain belongs to Login
        - the domain
        """
        res = []
        for domain in self.get_sl_domains(alias_options=alias_options):
            res.append((True, domain.domain))

        for custom_domain in self.verified_custom_domains():
            res.append((False, custom_domain.domain))

        return res

    def default_random_alias_domain(self) -> str:
        """return the domain used for the random alias"""
        if self.default_alias_custom_domain_id:
            custom_domain = CustomDomain.get(self.default_alias_custom_domain_id)
            
            if (
                not custom_domain
                or not custom_domain.verified
                or custom_domain.user_id != self.id
            ):
                LOG.w("Problem with %s default random alias domain", self)
                return config.FIRST_ALIAS_DOMAIN

            return custom_domain.domain

        if self.default_alias_public_domain_id:
            sl_domain = SLDomain.get(self.default_alias_public_domain_id)
            
            if not sl_domain:
                LOG.e("Problem with %s public random alias domain", self)
                return config.FIRST_ALIAS_DOMAIN

            if sl_domain.premium_only and not self.is_premium():
                LOG.w(
                    "%s is not premium and cannot use %s. Reset default random alias domain setting",
                    self,
                    sl_domain,
                )
                self.default_alias_custom_domain_id = None
                self.default_alias_public_domain_id = None
                Session.commit()
                return config.FIRST_ALIAS_DOMAIN

            return sl_domain.domain

        return config.FIRST_ALIAS_DOMAIN

    def fido_enabled(self) -> bool:
        if self.fido_uuid is not None:
            return True
        return False

    def two_factor_authentication_enabled(self) -> bool:
        return self.enable_otp or self.fido_enabled()

    def get_communication_email(self) -> (Optional[str], str, bool):
        """
        Return
        - the email that user uses to receive email communication. None if user unsubscribes from newsletter
        - the unsubscribe URL
        - whether the unsubscribe method is via sending email (mailto:) or Http POST
        """
        if self.notification and self.activated and not self.disabled:
            if self.newsletter_alias_id:
                alias = Alias.get(self.newsletter_alias_id)
                if alias.enabled:
                    unsub = UnsubscribeEncoder.encode(
                        UnsubscribeAction.DisableAlias, alias.id
                    )
                    return alias.email, unsub.link, unsub.via_email
                
                else:
                    return None, "", False
            else:
                
                if config.UNSUBSCRIBER:
                    
                    return (
                        self.email,
                        UnsubscribeEncoder.encode_mailto(
                            UnsubscribeAction.UnsubscribeNewsletter, self.id
                        ),
                        True,
                    )

        return None, "", False

    def available_sl_domains(
        self, alias_options: Optional[AliasOptions] = None
    ) -> [str]:
        """
        Return all Login domains that user can use when creating a new alias, including:
        - Login public domains, available for all users (ALIAS_DOMAIN)
        - Login premium domains, only available for Premium accounts (PREMIUM_ALIAS_DOMAIN)
        """
        return [
            sl_domain.domain
            for sl_domain in self.get_sl_domains(alias_options=alias_options)
        ]

    def get_sl_domains(
        self, alias_options: Optional[AliasOptions] = None
    ) -> list["SLDomain"]:
        if alias_options is None:
            alias_options = AliasOptions()
        top_conds = [SLDomain.hidden == False]  
        or_conds = []  
        if self.default_alias_public_domain_id is not None:
            default_domain_conds = [SLDomain.id == self.default_alias_public_domain_id]
            if not self.is_premium():
                default_domain_conds.append(
                    SLDomain.premium_only == False  
                )
            or_conds.append(and_(*default_domain_conds).self_group())
        if alias_options.show_partner_domains is not None:
            partner_user = PartnerUser.filter_by(
                user_id=self.id, partner_id=alias_options.show_partner_domains.id
            ).first()
            if partner_user is not None:
                partner_domain_cond = [SLDomain.partner_id == partner_user.partner_id]
                if alias_options.show_partner_premium is None:
                    alias_options.show_partner_premium = self.is_premium()
                if not alias_options.show_partner_premium:
                    partner_domain_cond.append(
                        SLDomain.premium_only == False  
                    )
                or_conds.append(and_(*partner_domain_cond).self_group())
        if alias_options.show_sl_domains:
            sl_conds = [SLDomain.partner_id == None]  
            if not self.is_premium():
                sl_conds.append(SLDomain.premium_only == False)  
            or_conds.append(and_(*sl_conds).self_group())
        top_conds.append(or_(*or_conds))
        query = Session.query(SLDomain).filter(*top_conds).order_by(SLDomain.order)
        return query.all()

    def available_alias_domains(
        self, alias_options: Optional[AliasOptions] = None
    ) -> [str]:
        """return all domains that user can use when creating a new alias, including:
        - Login public domains, available for all users (ALIAS_DOMAIN)
        - Login premium domains, only available for Premium accounts (PREMIUM_ALIAS_DOMAIN)
        - Verified custom domains

        """
        domains = [
            sl_domain.domain
            for sl_domain in self.get_sl_domains(alias_options=alias_options)
        ]

        for custom_domain in self.verified_custom_domains():
            domains.append(custom_domain.domain)

        
        return list(set(domains))

    def should_show_app_page(self) -> bool:
        """whether to show the app page"""
        return (
            
            ClientUser.filter(ClientUser.user_id == self.id).count()
            
            + Client.filter(Client.user_id == self.id).count()
            > 0
        )

    def get_random_alias_suffix(self, custom_domain: Optional["CustomDomain"] = None):
        """Get random suffix for an alias based on user's preference.

        Use a shorter suffix in case of custom domain

        Returns:
            str: the random suffix generated
        """
        if self.random_alias_suffix == AliasSuffixEnum.random_string.value:
            return random_string(config.ALIAS_RANDOM_SUFFIX_LENGTH, include_digits=True)

        if custom_domain is None:
            return random_words(1, 3)

        return random_words(1)

    def can_create_contacts(self) -> bool:
        if self.is_premium():
            return True
        if self.flags & User.FLAG_FREE_DISABLE_CREATE_ALIAS == 0:
            return True
        return not config.DISABLE_CREATE_CONTACTS_FOR_FREE_USERS

    def has_used_alias_from_partner(self) -> bool:
        return (
            self.flags
            & (User.FLAG_CREATED_ALIAS_FROM_PARTNER | User.FLAG_CREATED_FROM_PARTNER)
            > 0
        )

    def __repr__(self):
        return f"<User {self.id} {self.name} {self.email}>"


def _expiration_1h():
    return arrow.now().shift(hours=1)


def _expiration_12h():
    return arrow.now().shift(hours=12)


def _expiration_5m():
    return arrow.now().shift(minutes=5)


def _expiration_7d():
    return arrow.now().shift(days=7)


class ActivationCode(Base, ModelMixin):
    """For activate user account"""

    __tablename__ = "activation_code"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    code = sa.Column(sa.String(128), unique=True, nullable=False)

    user = orm.relationship(User)

    expired = sa.Column(ArrowType, nullable=False, default=_expiration_1h)

    def is_expired(self):
        return self.expired < arrow.now()


class ResetPasswordCode(Base, ModelMixin):
    """For resetting password"""

    __tablename__ = "reset_password_code"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    code = sa.Column(sa.String(128), unique=True, nullable=False)

    user = orm.relationship(User)

    expired = sa.Column(ArrowType, nullable=False, default=_expiration_1h)

    def is_expired(self):
        return self.expired < arrow.now()


class SocialAuth(Base, ModelMixin):
    """Store how user authenticates with social login"""

    __tablename__ = "social_auth"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)

    
    social = sa.Column(sa.String(128), nullable=False)

    __table_args__ = (sa.UniqueConstraint("user_id", "social", name="uq_social_auth"),)


def generate_oauth_client_id(client_name) -> str:
    oauth_client_id = convert_to_id(client_name) + "-" + random_string()

    
    if not Client.get_by(oauth_client_id=oauth_client_id):
        LOG.d("generate oauth_client_id %s", oauth_client_id)
        return oauth_client_id

    
    LOG.w("client_id %s already exists, generate a new client_id", oauth_client_id)
    return generate_oauth_client_id(client_name)


class MfaBrowser(Base, ModelMixin):
    __tablename__ = "mfa_browser"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    token = sa.Column(sa.String(64), default=False, unique=True, nullable=False)
    expires = sa.Column(ArrowType, default=False, nullable=False)

    user = orm.relationship(User)

    @classmethod
    def create_new(cls, user, token_length=64) -> "MfaBrowser":
        found = False
        while not found:
            token = random_string(token_length)

            if not cls.get_by(token=token):
                found = True

        return MfaBrowser.create(
            user_id=user.id,
            token=token,
            expires=arrow.now().shift(days=30),
        )

    @classmethod
    def delete(cls, token):
        cls.filter(cls.token == token).delete()
        Session.commit()

    @classmethod
    def delete_expired(cls):
        cls.filter(cls.expires < arrow.now()).delete()
        Session.commit()

    def is_expired(self):
        return self.expires < arrow.now()

    def reset_expire(self):
        self.expires = arrow.now().shift(days=30)


class Client(Base, ModelMixin):
    __tablename__ = "client"
    oauth_client_id = sa.Column(sa.String(128), unique=True, nullable=False)
    oauth_client_secret = sa.Column(sa.String(128), nullable=False)

    name = sa.Column(sa.String(128), nullable=False)
    home_url = sa.Column(sa.String(1024))

    
    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    icon_id = sa.Column(sa.ForeignKey(File.id), nullable=True)

    
    approved = sa.Column(sa.Boolean, nullable=False, default=False, server_default="0")
    description = sa.Column(sa.Text, nullable=True)

    
    
    referral_id = sa.Column(
        sa.ForeignKey("referral.id", ondelete="SET NULL"), nullable=True
    )

    icon = orm.relationship(File)
    user = orm.relationship(User)
    referral = orm.relationship("Referral")

    def nb_user(self):
        return ClientUser.filter_by(client_id=self.id).count()

    def get_scopes(self) -> [Scope]:
        
        return [Scope.NAME, Scope.EMAIL, Scope.AVATAR_URL]

    @classmethod
    def create_new(cls, name, user_id) -> "Client":
        
        oauth_client_id = generate_oauth_client_id(name)
        oauth_client_secret = random_string(40)
        client = Client.create(
            name=name,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
            user_id=user_id,
        )

        return client

    def get_icon_url(self):
        if self.icon_id:
            return self.icon.get_url()
        else:
            return config.URL + "/static/default-icon.svg"

    def last_user_login(self) -> "ClientUser":
        client_user = (
            ClientUser.filter(ClientUser.client_id == self.id)
            .order_by(ClientUser.updated_at)
            .first()
        )
        if client_user:
            return client_user
        return None


class RedirectUri(Base, ModelMixin):
    """Valid redirect uris for a client"""

    __tablename__ = "redirect_uri"

    client_id = sa.Column(sa.ForeignKey(Client.id, ondelete="cascade"), nullable=False)
    uri = sa.Column(sa.String(1024), nullable=False)

    client = orm.relationship(Client, backref="redirect_uris")

    class AuthorizationCode(Base, ModelMixin):
    __tablename__ = "authorization_code"

    code = sa.Column(sa.String(128), unique=True, nullable=False)
    client_id = sa.Column(sa.ForeignKey(Client.id, ondelete="cascade"), nullable=False)
    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)

    scope = sa.Column(sa.String(128))
    redirect_uri = sa.Column(sa.String(1024))

    
    response_type = sa.Column(sa.String(128))

    nonce = sa.Column(sa.Text, nullable=True, default=None, server_default=text("NULL"))

    user = orm.relationship(User, lazy=False)
    client = orm.relationship(Client, lazy=False)

    expired = sa.Column(ArrowType, nullable=False, default=_expiration_5m)

    def is_expired(self):
        return self.expired < arrow.now()


class OauthToken(Base, ModelMixin):
    __tablename__ = "oauth_token"

    access_token = sa.Column(sa.String(128), unique=True)
    client_id = sa.Column(sa.ForeignKey(Client.id, ondelete="cascade"), nullable=False)
    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)

    scope = sa.Column(sa.String(128))
    redirect_uri = sa.Column(sa.String(1024))

    
    response_type = sa.Column(sa.String(128))

    user = orm.relationship(User)
    client = orm.relationship(Client)

    expired = sa.Column(ArrowType, nullable=False, default=_expiration_1h)

    def is_expired(self):
        return self.expired < arrow.now()


def available_sl_email(email: str) -> bool:
    if (
        Alias.get_by(email=email)
        or Contact.get_by(reply_email=email)
        or DeletedAlias.get_by(email=email)
    ):
        return False
    return True


def generate_random_alias_email(
    scheme: int = AliasGeneratorEnum.word.value,
    in_hex: bool = False,
    alias_domain: str = config.FIRST_ALIAS_DOMAIN,
    retries: int = 10,
) -> str:

    if retries <= 0:
        raise Exception("Cannot generate alias after many retries")
    if scheme == AliasGeneratorEnum.uuid.value:
        name = uuid.uuid4().hex if in_hex else uuid.uuid4().__str__()
        random_email = name + "@" + alias_domain
    else:
        random_email = random_words(2, 3) + "@" + alias_domain

    random_email = random_email.lower().strip()

    
    if available_sl_email(random_email):
        LOG.d("generate email %s", random_email)
        return random_email

    
    LOG.w("email %s already exists, generate a new email", random_email)
    return generate_random_alias_email(
        scheme=scheme, in_hex=in_hex, retries=retries - 1
    )


class Alias(Base, ModelMixin):
    __tablename__ = "alias"

    FLAG_PARTNER_CREATED = 1 << 0

    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, index=True
    )
    email = sa.Column(sa.String(128), unique=True, nullable=False)

    
    name = sa.Column(sa.String(128), nullable=True, default=None)

    enabled = sa.Column(sa.Boolean(), default=True, nullable=False)
    flags = sa.Column(
        sa.BigInteger(), default=0, server_default="0", nullable=False, index=True
    )

    custom_domain_id = sa.Column(
        sa.ForeignKey("custom_domain.id", ondelete="cascade"), nullable=True, index=True
    )

    custom_domain = orm.relationship("CustomDomain", foreign_keys=[custom_domain_id])

    
    automatic_creation = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    
    directory_id = sa.Column(
        sa.ForeignKey("directory.id", ondelete="cascade"), nullable=True, index=True
    )

    note = sa.Column(sa.Text, default=None, nullable=True)

    
    mailbox_id = sa.Column(
        sa.ForeignKey("mailbox.id", ondelete="cascade"), nullable=False, index=True
    )

    
    
    _mailboxes = orm.relationship("Mailbox", secondary="alias_mailbox", lazy="joined")

    
    
    disable_pgp = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    
    cannot_be_disabled = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    
    disable_email_spoofing_check = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    
    batch_import_id = sa.Column(
        sa.ForeignKey("batch_import.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )

    
    original_owner_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="SET NULL"), nullable=True
    )

    
    pinned = sa.Column(sa.Boolean, nullable=False, default=False, server_default="0")

    
    transfer_token = sa.Column(sa.String(64), default=None, unique=True, nullable=True)
    transfer_token_expiration = sa.Column(
        ArrowType, default=arrow.utcnow, nullable=True
    )

    
    hibp_last_check = sa.Column(ArrowType, default=None, index=True)
    hibp_breaches = orm.relationship("Hibp", secondary="alias_hibp")

    
    
    ts_vector = sa.Column(
        TSVector(), sa.Computed("to_tsvector('english', note)", persisted=True)
    )

    last_email_log_id = sa.Column(sa.Integer, default=None, nullable=True)

    __table_args__ = (
        Index("ix_video___ts_vector__", ts_vector, postgresql_using="gin"),
        
        Index(
            "note_pg_trgm_index",
            "note",
            postgresql_ops={"note": "gin_trgm_ops"},
            postgresql_using="gin",
        ),
    )

    user = orm.relationship(User, foreign_keys=[user_id])
    mailbox = orm.relationship("Mailbox", lazy="joined")

    @property
    def mailboxes(self):
        ret = [self.mailbox]
        for m in self._mailboxes:
            if m.id is not self.mailbox.id:
                ret.append(m)

        ret = [mb for mb in ret if mb.verified]
        ret = sorted(ret, key=lambda mb: mb.email)

        return ret


    def pgp_enabled(self) -> bool:
        if self.mailbox_support_pgp() and not self.disable_pgp:
            return True
        return False

    @staticmethod
    def get_custom_domain(alias_address) -> Optional["CustomDomain"]:
        alias_domain = validate_email(
            alias_address, check_deliverability=False, allow_smtputf8=False
        ).domain

        
        if SLDomain.get_by(domain=alias_domain) is None:
            custom_domain = CustomDomain.get_by(domain=alias_domain)
            if custom_domain:
                return custom_domain

    @classmethod
    def create(cls, **kw):
        commit = kw.pop("commit", False)
        flush = kw.pop("flush", False)

        new_alias = cls(**kw)
        user = User.get(new_alias.user_id)
        if user.is_premium():
            limits = config.ALIAS_CREATE_RATE_LIMIT_PAID
        else:
            limits = config.ALIAS_CREATE_RATE_LIMIT_FREE
        
        for limit in limits:
            key = f"alias_create_{limit[1]}d:{user.id}"
            rate_limiter.check_bucket_limit(key, limit[0], limit[1])

        email = kw["email"]
        
        email = sanitize_email(email)

        
        if DeletedAlias.get_by(email=email):
            raise AliasInTrashError

        if DomainDeletedAlias.get_by(email=email):
            raise AliasInTrashError

        
        if "custom_domain_id" not in kw:
            custom_domain = Alias.get_custom_domain(email)
            if custom_domain:
                new_alias.custom_domain_id = custom_domain.id

        Session.add(new_alias)
        DailyMetric.get_or_create_today_metric().nb_alias += 1

        
        from app.events.event_dispatcher import EventDispatcher
        from app.events.generated.event_pb2 import AliasCreated, EventContent

        event = AliasCreated(
            alias_id=new_alias.id,
            alias_email=new_alias.email,
            alias_note=new_alias.note,
            enabled=True,
        )
        EventDispatcher.send_event(user, EventContent(alias_created=event))

        if (
            new_alias.flags & cls.FLAG_PARTNER_CREATED > 0
            and new_alias.user.flags & User.FLAG_CREATED_ALIAS_FROM_PARTNER == 0
        ):
            user.flags = user.flags | User.FLAG_CREATED_ALIAS_FROM_PARTNER

        if commit:
            Session.commit()

        if flush:
            Session.flush()

        return new_alias

    @classmethod
    def create_new(cls, user, prefix, note=None, mailbox_id=None):
        prefix = prefix.lower().strip().replace(" ", "")

        if not prefix:
            raise Exception("alias prefix cannot be empty")

        
        for _ in range(1000):
            suffix = user.get_random_alias_suffix()
            email = f"{prefix}.{suffix}@{config.FIRST_ALIAS_DOMAIN}"

            if available_sl_email(email):
                break

        return Alias.create(
            user_id=user.id,
            email=email,
            note=note,
            mailbox_id=mailbox_id or user.default_mailbox_id,
        )

        @classmethod
    def delete(cls, obj_id):
        raise Exception("should use delete_alias(alias,user) instead")

    @classmethod
    def create_new_random(
        cls,
        user,
        scheme: int = AliasGeneratorEnum.word.value,
        in_hex: bool = False,
        note: str = None,
    ):
        """create a new random alias"""
        custom_domain = None

        random_email = None

        if user.default_alias_custom_domain_id:
            custom_domain = CustomDomain.get(user.default_alias_custom_domain_id)
            random_email = generate_random_alias_email(
                scheme=scheme, in_hex=in_hex, alias_domain=custom_domain.domain
            )
        elif user.default_alias_public_domain_id:
            sl_domain: SLDomain = SLDomain.get(user.default_alias_public_domain_id)
            if sl_domain.premium_only and not user.is_premium():
                LOG.w("%s not premium, cannot use %s", user, sl_domain)
            else:
                random_email = generate_random_alias_email(
                    scheme=scheme, in_hex=in_hex, alias_domain=sl_domain.domain
                )

        if not random_email:
            random_email = generate_random_alias_email(scheme=scheme, in_hex=in_hex)

        alias = Alias.create(
            user_id=user.id,
            email=random_email,
            mailbox_id=user.default_mailbox_id,
            note=note,
        )

        if custom_domain:
            alias.custom_domain_id = custom_domain.id

        return alias

    def mailbox_email(self):
        if self.mailbox_id:
            return self.mailbox.email
        else:
            return self.user.email

    def __repr__(self):
        return f"<Alias {self.id} {self.email}>"


class ClientUser(Base, ModelMixin):
    __tablename__ = "client_user"
    __table_args__ = (
        sa.UniqueConstraint("user_id", "client_id", name="uq_client_user"),
    )

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    client_id = sa.Column(sa.ForeignKey(Client.id, ondelete="cascade"), nullable=False)

    
    alias_id = sa.Column(
        sa.ForeignKey(Alias.id, ondelete="cascade"), nullable=True, index=True
    )

    
    name = sa.Column(
        sa.String(128), nullable=True, default=None, server_default=text("NULL")
    )

    
    default_avatar = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    alias = orm.relationship(Alias, backref="client_users")

    user = orm.relationship(User)
    client = orm.relationship(Client)

    def get_email(self):
        return self.alias.email if self.alias_id else self.user.email

    def get_user_name(self):
        if self.name:
            return self.name
        else:
            return self.user.name

    def get_user_info(self) -> dict:
        res = {
            "id": self.id,
            "client": self.client.name,
            "email_verified": True,
            "sub": str(self.id),
        }



class Contact(Base, ModelMixin):
    """
    Store configuration of sender (website-email) and alias.
    """

    MAX_NAME_LENGTH = 512

    __tablename__ = "contact"

    __table_args__ = (
        sa.UniqueConstraint("alias_id", "website_email", name="uq_contact"),
    )

    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, index=True
    )
    alias_id = sa.Column(
        sa.ForeignKey(Alias.id, ondelete="cascade"), nullable=False, index=True
    )

    name = sa.Column(
        sa.String(512), nullable=True, default=None, server_default=text("NULL")
    )

    website_email = sa.Column(sa.String(512), nullable=False)

        
    website_from = sa.Column(sa.String(1024), nullable=True)

    
    reply_email = sa.Column(sa.String(512), nullable=False, index=True)

    
    is_cc = sa.Column(sa.Boolean, nullable=False, default=False, server_default="0")

    pgp_public_key = sa.Column(sa.Text, nullable=True)
    pgp_finger_print = sa.Column(sa.String(512), nullable=True, index=True)

    alias = orm.relationship(Alias, backref="contacts")
    user = orm.relationship(User)

    
    latest_reply: Optional[Arrow] = None

    
    
    mail_from = sa.Column(sa.Text, nullable=True, default=None)

    
    invalid_email = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    
    block_forward = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    
    automatic_created = sa.Column(sa.Boolean, nullable=True, default=False)

    @property
    def email(self):
        return self.website_email

    @classmethod
    def create(cls, **kw):
        commit = kw.pop("commit", False)
        flush = kw.pop("flush", False)

        new_contact = cls(**kw)

        website_email = kw["website_email"]
        
        website_email = sanitize_email(website_email)

        
        if website_email != config.NOREPLY:
            orig_contact = Contact.get_by(reply_email=website_email)
            if orig_contact:
                raise CannotCreateContactForReverseAlias(str(orig_contact))

        Session.add(new_contact)

        if commit:
            Session.commit()

        if flush:
            Session.flush()

        return new_contact

    def website_send_to(self):

        user = self.user
        name = self.name
        email = self.website_email

        if (
            not user
            or not SenderFormatEnum.has_value(user.sender_format)
            or user.sender_format == SenderFormatEnum.AT.value
        ):
            email = email.replace("@", " at ")
        elif user.sender_format == SenderFormatEnum.A.value:
            email = email.replace("@", "(a)")

        
        if not name and self.website_from:
            try:
                name = address.parse(self.website_from).display_name
            except Exception:
                
                LOG.e(
                    "Cannot parse contact %s website_from %s", self, self.website_from
                )
                name = ""

        
        if name:
            name = name.replace('"', "")

        if name:
            name = name + " | " + email
        else:
            name = email
        
        return f'"{name}" <{self.reply_email}>'

    def new_addr(self):

        user = self.user
        sender_format = user.sender_format if user else SenderFormatEnum.AT.value

        if sender_format == SenderFormatEnum.NO_NAME.value:
            return self.reply_email

        if sender_format == SenderFormatEnum.NAME_ONLY.value:
            new_name = self.name
        elif sender_format == SenderFormatEnum.AT_ONLY.value:
            new_name = self.website_email.replace("@", " at ").strip()
        elif sender_format == SenderFormatEnum.AT.value:
            formatted_email = self.website_email.replace("@", " at ").strip()
            new_name = (
                (self.name + " - " + formatted_email)
                if self.name and self.name != self.website_email.strip()
                else formatted_email
            )
        else:  
            formatted_email = self.website_email.replace("@", "(a)").strip()
            new_name = (
                (self.name + " - " + formatted_email)
                if self.name and self.name != self.website_email.strip()
                else formatted_email
            )

        from app.email_utils import sl_formataddr

        new_addr = sl_formataddr((new_name, self.reply_email)).strip()
        return new_addr.strip()

    def last_reply(self) -> "EmailLog":
        """return the most recent reply"""
        return (
            EmailLog.filter_by(contact_id=self.id, is_reply=True)
            .order_by(desc(EmailLog.created_at))
            .first()
        )

    def __repr__(self):
        return f"<Contact {self.id} {self.website_email} {self.alias_id}>"


class EmailLog(Base, ModelMixin):
    __tablename__ = "email_log"
    __table_args__ = (Index("ix_email_log_created_at", "created_at"),)

    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, index=True
    )
    contact_id = sa.Column(
        sa.ForeignKey(Contact.id, ondelete="cascade"), nullable=False, index=True
    )
    alias_id = sa.Column(
        sa.ForeignKey(Alias.id, ondelete="cascade"), nullable=True, index=True
    )

    
    is_reply = sa.Column(sa.Boolean, nullable=False, default=False)

    
    blocked = sa.Column(sa.Boolean, nullable=False, default=False)

    
    
    bounced = sa.Column(sa.Boolean, nullable=False, default=False, server_default="0")

    
    auto_replied = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    
    is_spam = sa.Column(sa.Boolean, nullable=False, default=False, server_default="0")
    spam_score = sa.Column(sa.Float, nullable=True)
    spam_status = sa.Column(sa.Text, nullable=True, default=None)
    
    spam_report = deferred(sa.Column(sa.JSON, nullable=True))

    
    refused_email_id = sa.Column(
        sa.ForeignKey("refused_email.id", ondelete="SET NULL"), nullable=True
    )

    
    
    mailbox_id = sa.Column(
        sa.ForeignKey("mailbox.id", ondelete="cascade"), nullable=True
    )

    
    
    bounced_mailbox_id = sa.Column(
        sa.ForeignKey("mailbox.id", ondelete="cascade"), nullable=True
    )

    
    message_id = deferred(sa.Column(sa.String(1024), nullable=True))
    
    sl_message_id = deferred(sa.Column(sa.String(512), nullable=True))

    refused_email = orm.relationship("RefusedEmail")
    forward = orm.relationship(Contact)

    contact = orm.relationship(Contact, backref="email_logs")
    alias = orm.relationship(Alias)
    mailbox = orm.relationship("Mailbox", lazy="joined", foreign_keys=[mailbox_id])
    user = orm.relationship(User)

    def bounced_mailbox(self) -> str:
        if self.bounced_mailbox_id:
            return Mailbox.get(self.bounced_mailbox_id).email
        
        return self.contact.alias.mailboxes[0].email

    def get_action(self) -> str:
        """return the action name: forward|reply|block|bounced"""
        if self.is_reply:
            return "reply"
        elif self.bounced:
            return "bounced"
        elif self.blocked:
            return "block"
        else:
            return "forward"

    def get_phase(self) -> str:
        if self.is_reply:
            return "reply"
        else:
            return "forward"

    def get_dashboard_url(self):
        return f"{config.URL}/dashboard/refused_email?highlight_id={self.id}"

    @classmethod
    def create(cls, *args, **kwargs):
        commit = kwargs.pop("commit", False)
        email_log = super().create(*args, **kwargs)
        Session.flush()
        if "alias_id" in kwargs:
            sql = "UPDATE alias SET last_email_log_id = :el_id WHERE id = :alias_id"
            Session.execute(
                sql, {"el_id": email_log.id, "alias_id": kwargs["alias_id"]}
            )
        if commit:
            Session.commit()
        return email_log

    def __repr__(self):
        return f"<EmailLog {self.id}>"


class Subscription(Base, ModelMixin):
    """ subscription"""

    __tablename__ = "subscription"

    
    cancel_url = sa.Column(sa.String(1024), nullable=False)
    update_url = sa.Column(sa.String(1024), nullable=False)
    subscription_id = sa.Column(sa.String(1024), nullable=False, unique=True)
    event_time = sa.Column(ArrowType, nullable=False)
    next_bill_date = sa.Column(sa.Date, nullable=False)

    cancelled = sa.Column(sa.Boolean, nullable=False, default=False)

    plan = sa.Column(sa.Enum(PlanEnum), nullable=False)

    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, unique=True
    )

    user = orm.relationship(User)

    def plan_name(self):
        if self.plan == PlanEnum.monthly:
            return "Monthly"
        else:
            return "Yearly"

    def __repr__(self):
        return f"<Subscription {self.plan} {self.next_bill_date}>"


class ManualSubscription(Base, ModelMixin):


    __tablename__ = "manual_subscription"

    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, unique=True
    )

    
    end_at = sa.Column(ArrowType, nullable=False)

    
    comment = sa.Column(sa.Text, nullable=True)

    
    is_giveaway = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    user = orm.relationship(User)

    def is_active(self):
        return self.end_at > arrow.now()


class Subscription(Base, ModelMixin):

    __tablename__ = "_subscription"

    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, unique=True
    )

    expires_date = sa.Column(ArrowType, nullable=False)

    
    original_transaction_id = sa.Column(sa.String(256), nullable=False, unique=True)
    receipt_data = sa.Column(sa.Text(), nullable=False)

    plan = sa.Column(sa.Enum(PlanEnum), nullable=False)

    
    
    product_id = sa.Column(sa.String(256), nullable=True)

    user = orm.relationship(User)

    def is_valid(self):
        return self.expires_date > arrow.now().shift(days=-__GRACE_PERIOD_DAYS)


    class DeletedAlias(Base, ModelMixin):
    """Store all deleted alias to make sure they are NOT reused"""

    __tablename__ = "deleted_alias"

    email = sa.Column(sa.String(256), unique=True, nullable=False)
    reason = sa.Column(
        IntEnumType(AliasDeleteReason),
        nullable=False,
        default=AliasDeleteReason.Unspecified,
        server_default=str(AliasDeleteReason.Unspecified.value),
    )

    @classmethod
    def create(cls, **kw):
        raise Exception("should use delete_alias(alias,user) instead")

    def __repr__(self):
        return f"<Deleted Alias {self.email}>"


class EmailChange(Base, ModelMixin):
    """Used when user wants to update their email"""

    __tablename__ = "email_change"

    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"),
        nullable=False,
        unique=True,
        index=True,
    )
    new_email = sa.Column(sa.String(256), unique=True, nullable=False)
    code = sa.Column(sa.String(128), unique=True, nullable=False)
    expired = sa.Column(ArrowType, nullable=False, default=_expiration_12h)

    user = orm.relationship(User)

    def is_expired(self):
        return self.expired < arrow.now()

    def __repr__(self):
        return f"<EmailChange {self.id} {self.new_email} {self.user_id}>"


class ApiKey(Base, ModelMixin):
    """used in browser extension to identify user"""

    __tablename__ = "api_key"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    code = sa.Column(sa.String(128), unique=True, nullable=False)
    name = sa.Column(sa.String(128), nullable=True)
    last_used = sa.Column(ArrowType, default=None)
    times = sa.Column(sa.Integer, default=0, nullable=False)
    sudo_mode_at = sa.Column(ArrowType, default=None)

    user = orm.relationship(User)

    @classmethod
    def create(cls, user_id, name=None, **kwargs):
        code = random_string(60)
        if cls.get_by(code=code):
            code = str(uuid.uuid4())

        return super().create(user_id=user_id, name=name, code=code, **kwargs)

    @classmethod
    def delete_all(cls, user_id):
        Session.query(cls).filter(cls.user_id == user_id).delete()


class CustomDomain(Base, ModelMixin):
    __tablename__ = "custom_domain"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    domain = sa.Column(sa.String(128), unique=True, nullable=False)

    
    name = sa.Column(sa.String(128), nullable=True, default=None)

    
    verified = sa.Column(sa.Boolean, nullable=False, default=False)
    dkim_verified = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )
    spf_verified = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )
    dmarc_verified = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    _mailboxes = orm.relationship("Mailbox", secondary="domain_mailbox", lazy="joined")

    
    catch_all = sa.Column(sa.Boolean, nullable=False, default=False, server_default="0")

    
    random_prefix_generation = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )
    
    nb_failed_checks = sa.Column(
        sa.Integer, default=0, server_default="0", nullable=False
    )

    
    ownership_verified = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )    
    
    ownership_txt_token = sa.Column(sa.String(128), nullable=True)

    
    is_sl_subdomain = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    __table_args__ = (
        Index(
            "ix_unique_domain",  
            "domain",  
            unique=True,
            postgresql_where=Column("ownership_verified"),
        ),  
    )

    user = orm.relationship(User, foreign_keys=[user_id], backref="custom_domains")

    @property
    def mailboxes(self):
        if self._mailboxes:
            return self._mailboxes
        else:
            return [self.user.default_mailbox]

    def nb_alias(self):
        return Alias.filter_by(custom_domain_id=self.id).count()

    def get_trash_url(self):
        return config.URL + f"/dashboard/domains/{self.id}/trash"

    def get_ownership_dns_txt_value(self):
        return f"sl-verification={self.ownership_txt_token}"

    @classmethod
    def create(cls, **kwargs):
        domain = kwargs.get("domain")
        kwargs["domain"] = domain.replace("\n", "")
        if DeletedSubdomain.get_by(domain=domain):
            raise SubdomainInTrashError

        domain: CustomDomain = super(CustomDomain, cls).create(**kwargs)

        
        if not domain.ownership_txt_token:
            domain.ownership_txt_token = random_string(30)
            Session.commit()

        if domain.is_sl_subdomain:
            user = domain.user
            user._subdomain_quota -= 1
            Session.flush()

        return domain

    @classmethod
    def delete(cls, obj_id):
        obj: CustomDomain = cls.get(obj_id)
        if obj.is_sl_subdomain:
            DeletedSubdomain.create(domain=obj.domain)

        from app import alias_utils

        for alias in Alias.filter_by(custom_domain_id=obj_id):
            alias_utils.delete_alias(
                alias, obj.user, AliasDeleteReason.CustomDomainDeleted
            )

        return super(CustomDomain, cls).delete(obj_id)

    @property
    def auto_create_rules(self):
        return sorted(self._auto_create_rules, key=lambda rule: rule.order)

    def __repr__(self):
        return f"<Custom Domain {self.id} {self.domain}>"


class AutoCreateRule(Base, ModelMixin):
    """Alias auto creation rule for custom domain"""

    __tablename__ = "auto_create_rule"

    __table_args__ = (
        sa.UniqueConstraint(
            "custom_domain_id", "order", name="uq_auto_create_rule_order"
        ),
    )

    custom_domain_id = sa.Column(
        sa.ForeignKey(CustomDomain.id, ondelete="cascade"), nullable=False
    )
    
    regex = sa.Column(sa.String(512), nullable=False)

    
    order = sa.Column(sa.Integer, default=0, nullable=False)

    custom_domain = orm.relationship(CustomDomain, backref="_auto_create_rules")

    mailboxes = orm.relationship(
        "Mailbox", secondary="auto_create_rule__mailbox", lazy="joined"
    )


class AutoCreateRuleMailbox(Base, ModelMixin):
    """store auto create rule - mailbox association"""

    __tablename__ = "auto_create_rule__mailbox"
    __table_args__ = (
        sa.UniqueConstraint(
            "auto_create_rule_id", "mailbox_id", name="uq_auto_create_rule_mailbox"
        ),
    )

    auto_create_rule_id = sa.Column(
        sa.ForeignKey(AutoCreateRule.id, ondelete="cascade"), nullable=False
    )
    mailbox_id = sa.Column(
        sa.ForeignKey("mailbox.id", ondelete="cascade"), nullable=False
    )


class DomainDeletedAlias(Base, ModelMixin):
    """Store all deleted alias for a domain"""

    __tablename__ = "domain_deleted_alias"

    __table_args__ = (
        sa.UniqueConstraint("domain_id", "email", name="uq_domain_trash"),
    )

    email = sa.Column(sa.String(256), nullable=False)
    domain_id = sa.Column(
        sa.ForeignKey("custom_domain.id", ondelete="cascade"), nullable=False
    )
    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)

    domain = orm.relationship(CustomDomain)
    user = orm.relationship(User, foreign_keys=[user_id])
    reason = sa.Column(
        IntEnumType(AliasDeleteReason),
        nullable=False,
        default=AliasDeleteReason.Unspecified,
        server_default=str(AliasDeleteReason.Unspecified.value),
    )

    @classmethod
    def create(cls, **kw):
        raise Exception("should use delete_alias(alias,user) instead")

    def __repr__(self):
        return f"<DomainDeletedAlias {self.id} {self.email}>"


class LifetimeCoupon(Base, ModelMixin):
    __tablename__ = "lifetime_coupon"

    code = sa.Column(sa.String(128), nullable=False, unique=True)
    nb_used = sa.Column(sa.Integer, nullable=False)
    paid = sa.Column(sa.Boolean, default=False, server_default="0", nullable=False)
    comment = sa.Column(sa.Text, nullable=True)


    @property
    def mailboxes(self):
        if self._mailboxes:
            return self._mailboxes
        else:
            return [self.user.default_mailbox]

    def nb_alias(self):
        return Alias.filter_by(directory_id=self.id).count()

    @classmethod
    def create(cls, *args, **kwargs):
        name = kwargs.get("name")
        if DeletedDirectory.get_by(name=name):
            raise DirectoryInTrashError

        directory = super(Directory, cls).create(*args, **kwargs)
        Session.flush()

        user = directory.user
        user._directory_quota -= 1

        Session.flush()
        return directory

    @classmethod
    def delete(cls, obj_id):
        obj: Directory = cls.get(obj_id)
        user = obj.user
        
        for alias in Alias.filter_by(directory_id=obj_id):
            from app import alias_utils

            alias_utils.delete_alias(alias, user, AliasDeleteReason.DirectoryDeleted)

        DeletedDirectory.create(name=obj.name)
        cls.filter(cls.id == obj_id).delete()

        Session.commit()

    def __repr__(self):
        return f"<Directory {self.name}>"


class Job(Base, ModelMixin):
    """Used to schedule one-time job in the future"""

    __tablename__ = "job"

    name = sa.Column(sa.String(128), nullable=False)
    payload = sa.Column(sa.JSON)

    
    taken = sa.Column(sa.Boolean, default=False, nullable=False)
    run_at = sa.Column(ArrowType)
    state = sa.Column(
        sa.Integer,
        nullable=False,
        server_default=str(JobState.ready.value),
        default=JobState.ready.value,
        index=True,
    )
    attempts = sa.Column(sa.Integer, nullable=False, server_default="0", default=0)
    taken_at = sa.Column(ArrowType, nullable=True)

    __table_args__ = (Index("ix_state_run_at_taken_at", state, run_at, taken_at),)

    def __repr__(self):
        return f"<Job {self.id} {self.name} {self.payload}>"


class Mailbox(Base, ModelMixin):
    __tablename__ = "mailbox"
    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, index=True
    )
    email = sa.Column(sa.String(256), nullable=False, index=True)
    verified = sa.Column(sa.Boolean, default=False, nullable=False)
    force_spf = sa.Column(sa.Boolean, default=True, server_default="1", nullable=False)

    
    new_email = sa.Column(sa.String(256), unique=True)

    pgp_public_key = sa.Column(sa.Text, nullable=True)
    pgp_finger_print = sa.Column(sa.String(512), nullable=True)
    disable_pgp = sa.Column(
        sa.Boolean, default=False, nullable=False, server_default="0"
    )

    
    nb_failed_checks = sa.Column(
        sa.Integer, default=0, server_default="0", nullable=False
    )

    
    disabled = sa.Column(sa.Boolean, default=False, nullable=False, server_default="0")

    generic_subject = sa.Column(sa.String(78), nullable=True)

    __table_args__ = (sa.UniqueConstraint("user_id", "email", name="uq_mailbox_user"),)

    user = orm.relationship(User, foreign_keys=[user_id])

    def pgp_enabled(self) -> bool:
        if self.pgp_finger_print and not self.disable_pgp:
            return True

        return False

    def nb_alias(self):
        alias_ids = set(
            am.alias_id
            for am in AliasMailbox.filter_by(mailbox_id=self.id).values(
                AliasMailbox.alias_id
            )
        )
        for alias in Alias.filter_by(mailbox_id=self.id).values(Alias.id):
            alias_ids.add(alias.id)
        return len(alias_ids)

    def is_(self) -> bool:
        if (
            self.email.endswith("@.me")
            or self.email.endswith("@mail.com")
            or self.email.endswith("@mail.ch")
            or self.email.endswith("@.ch")
            or self.email.endswith("@pm.me")
        ):
            return True

        from app.email_utils import get_email_local_part

        mx_domains: [(int, str)] = get_mx_domains(get_email_local_part(self.email))
        
        if mx_domains and mx_domains[0][1] in (
            "mail.mail.ch.",
            "mailsec.mail.ch.",
        ):
            return True

        return False

    @classmethod
    def delete(cls, obj_id):
        mailbox: Mailbox = cls.get(obj_id)
        user = mailbox.user

        
        for alias in Alias.filter_by(mailbox_id=obj_id):
            
            if len(alias.mailboxes) > 1:
                
                first_mb = alias._mailboxes[0]
                alias.mailbox_id = first_mb.id
                alias._mailboxes.remove(first_mb)
            else:
                from app import alias_utils

                
                alias_utils.delete_alias(alias, user, AliasDeleteReason.MailboxDeleted)
            Session.commit()

        cls.filter(cls.id == obj_id).delete()
        Session.commit()

    @property
    def aliases(self) -> [Alias]:
        ret = dict(
            (alias.id, alias) for alias in Alias.filter_by(mailbox_id=self.id).all()
        )

        for am in AliasMailbox.filter_by(mailbox_id=self.id):
            if am.alias_id not in ret:
                ret[am.alias_id] = am.alias

        return list(ret.values())

    @classmethod
    def create(cls, **kw):
        if "email" in kw:
            kw["email"] = sanitize_email(kw["email"])
        return super().create(**kw)

    def __repr__(self):
        return f"<Mailbox {self.id} {self.email}>"


class MailboxActivation(Base, ModelMixin):
    __tablename__ = "mailbox_activation"

    mailbox_id = sa.Column(
        sa.ForeignKey(Mailbox.id, ondelete="cascade"), nullable=False, index=True
    )
    code = sa.Column(sa.String(32), nullable=False, index=True)
    tries = sa.Column(sa.Integer, default=0, nullable=False)


class AccountActivation(Base, ModelMixin):
    """contains code to activate the user account when they sign up on mobile"""

    __tablename__ = "account_activation"

    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, unique=True
    )
    
    code = sa.Column(sa.String(10), nullable=False)

    
    tries = sa.Column(sa.Integer, default=3, nullable=False)

    __table_args__ = (
        CheckConstraint(tries >= 0, name="account_activation_tries_positive"),
        {},
    )


class RefusedEmail(Base, ModelMixin):
    """Store emails that have been refused, i.e. bounced or classified as spams"""

    __tablename__ = "refused_email"

    
    full_report_path = sa.Column(sa.String(128), unique=True, nullable=False)

    
    path = sa.Column(sa.String(128), unique=True, nullable=True)

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)

    
    delete_at = sa.Column(ArrowType, nullable=False, default=_expiration_7d)

    
    deleted = sa.Column(sa.Boolean, nullable=False, default=False, server_default="0")

    def get_url(self, expires_in=3600):
        if self.path:
            return s3.get_url(self.path, expires_in)
        else:
            return s3.get_url(self.full_report_path, expires_in)

    def __repr__(self):
        return f"<Refused Email {self.id} {self.path} {self.delete_at}>"


class Referral(Base, ModelMixin):
    """Referral code so user can invite others"""

    __tablename__ = "referral"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    name = sa.Column(sa.String(512), nullable=True, default=None)

    code = sa.Column(sa.String(128), unique=True, nullable=False)

    user = orm.relationship(User, foreign_keys=[user_id], backref="referrals")

    @property
    def nb_user(self) -> int:
        return User.filter_by(referral_id=self.id, activated=True).count()

    @property
    def nb_paid_user(self) -> int:
        res = 0
        for user in User.filter_by(referral_id=self.id, activated=True):
            if user.is_paid():
                res += 1

        return res

    def link(self):
        return f"{config.LANDING_PAGE_URL}?slref={self.code}"

    def __repr__(self):
        return f"<Referral {self.code}>"


class SentAlert(Base, ModelMixin):

    __tablename__ = "sent_alert"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    to_email = sa.Column(sa.String(256), nullable=False)
    alert_type = sa.Column(sa.String(256), nullable=False)


class AliasMailbox(Base, ModelMixin):
    __tablename__ = "alias_mailbox"
    __table_args__ = (
        sa.UniqueConstraint("alias_id", "mailbox_id", name="uq_alias_mailbox"),
    )

    alias_id = sa.Column(
        sa.ForeignKey(Alias.id, ondelete="cascade"), nullable=False, index=True
    )
    mailbox_id = sa.Column(
        sa.ForeignKey(Mailbox.id, ondelete="cascade"), nullable=False, index=True
    )

    alias = orm.relationship(Alias)


class AliasHibp(Base, ModelMixin):
    __tablename__ = "alias_hibp"

    __table_args__ = (sa.UniqueConstraint("alias_id", "hibp_id", name="uq_alias_hibp"),)

    alias_id = sa.Column(
        sa.Integer(), sa.ForeignKey("alias.id", ondelete="cascade"), index=True
    )
    hibp_id = sa.Column(
        sa.Integer(), sa.ForeignKey("hibp.id", ondelete="cascade"), index=True
    )

    alias = orm.relationship(
        "Alias", backref=orm.backref("alias_hibp", cascade="all, delete-orphan")
    )
    hibp = orm.relationship(
        "Hibp", backref=orm.backref("alias_hibp", cascade="all, delete-orphan")
    )


class DirectoryMailbox(Base, ModelMixin):
    __tablename__ = "directory_mailbox"
    __table_args__ = (
        sa.UniqueConstraint("directory_id", "mailbox_id", name="uq_directory_mailbox"),
    )

    directory_id = sa.Column(
        sa.ForeignKey(Directory.id, ondelete="cascade"), nullable=False
    )
    mailbox_id = sa.Column(
        sa.ForeignKey(Mailbox.id, ondelete="cascade"), nullable=False
    )


class DomainMailbox(Base, ModelMixin):
    """store the owning mailboxes for a domain"""

    __tablename__ = "domain_mailbox"

    __table_args__ = (
        sa.UniqueConstraint("domain_id", "mailbox_id", name="uq_domain_mailbox"),
    )

    domain_id = sa.Column(
        sa.ForeignKey(CustomDomain.id, ondelete="cascade"), nullable=False
    )
    mailbox_id = sa.Column(
        sa.ForeignKey(Mailbox.id, ondelete="cascade"), nullable=False
    )


_NB_RECOVERY_CODE = 8
_RECOVERY_CODE_LENGTH = 8


class RecoveryCode(Base, ModelMixin):
    """allow user to login in case you lose any of your authenticators"""

    __tablename__ = "recovery_code"
    __table_args__ = (sa.UniqueConstraint("user_id", "code", name="uq_recovery_code"),)

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    code = sa.Column(sa.String(64), nullable=False)
    used = sa.Column(sa.Boolean, nullable=False, default=False)
    used_at = sa.Column(ArrowType, nullable=True, default=None)

    user = orm.relationship(User)

    @classmethod
    def _hash_code(cls, code: str) -> str:
        code_hmac = hmac.new(
            config.RECOVERY_CODE_HMAC_SECRET.encode("utf-8"),
            code.encode("utf-8"),
            "sha3_224",
        )
        return base64.urlsafe_b64encode(code_hmac.digest()).decode("utf-8").rstrip("=")

    @classmethod
    def generate(cls, user):
        """generate recovery codes for user"""
        
        cls.filter_by(user_id=user.id).delete()
        Session.flush()

        nb_code = 0
        raw_codes = []
        while nb_code < _NB_RECOVERY_CODE:
            raw_code = random_string(_RECOVERY_CODE_LENGTH)
            encoded_code = cls._hash_code(raw_code)
            if not cls.get_by(user_id=user.id, code=encoded_code):
                cls.create(user_id=user.id, code=encoded_code)
                raw_codes.append(raw_code)
                nb_code += 1

        LOG.d("Create recovery codes for %s", user)
        Session.commit()
        return raw_codes

    @classmethod
    def find_by_user_code(cls, user: User, code: str):
        hashed_code = cls._hash_code(code)
        return cls.get_by(user_id=user.id, code=hashed_code)

    @classmethod
    def empty(cls, user):
        """Delete all recovery codes for user"""
        cls.filter_by(user_id=user.id).delete()
        Session.commit()


class Notification(Base, ModelMixin):
    __tablename__ = "notification"
    user_id = sa.Column(
        sa.ForeignKey(User.id, ondelete="cascade"), nullable=False, index=True
    )
    message = sa.Column(sa.Text, nullable=False)
    title = sa.Column(sa.String(512))

    
    read = sa.Column(sa.Boolean, nullable=False, default=False)

    @staticmethod
    def render(template_name, **kwargs) -> str:
        templates_dir = os.path.join(config.ROOT_DIR, "templates")
        env = Environment(loader=FileSystemLoader(templates_dir))

        template = env.get_template(template_name)

        return template.render(
            URL=config.URL,
            LANDING_PAGE_URL=config.LANDING_PAGE_URL,
            YEAR=arrow.now().year,
            **kwargs,
        )


class Partner(Base, ModelMixin):
    __tablename__ = "partner"

    name = sa.Column(sa.String(128), unique=True, nullable=False)
    contact_email = sa.Column(sa.String(128), unique=True, nullable=False)

    @staticmethod
    def find_by_token(token: str) -> Optional[Partner]:
        hmaced = PartnerApiToken.hmac_token(token)
        res = (
            Session.query(Partner, PartnerApiToken)
            .filter(
                and_(
                    PartnerApiToken.token == hmaced,
                    Partner.id == PartnerApiToken.partner_id,
                )
            )
            .first()
        )
        if res:
            partner, partner_api_token = res
            return partner
        return None


class SLDomain(Base, ModelMixin):
    """Login domains"""

    __tablename__ = "public_domain"

    domain = sa.Column(sa.String(128), unique=True, nullable=False)

    
    premium_only = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    
    can_use_subdomain = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    partner_id = sa.Column(
        sa.ForeignKey(Partner.id, ondelete="cascade"),
        nullable=True,
        default=None,
        server_default="NULL",
    )

       hidden = sa.Column(sa.Boolean, nullable=False, default=False, server_default="0")

    
    order = sa.Column(sa.Integer, nullable=False, default=0, server_default="0")

    use_as_reverse_alias = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default="0"
    )

    def __repr__(self):
        return f"<SLDomain {self.id} {self.domain} {'Premium' if self.premium_only else 'Free'}>"


class Monitoring(Base, ModelMixin):

    __tablename__ = "monitoring"

    host = sa.Column(sa.String(256), nullable=False)

    
    incoming_queue = sa.Column(sa.Integer, nullable=False)
    active_queue = sa.Column(sa.Integer, nullable=False)
    deferred_queue = sa.Column(sa.Integer, nullable=False)

    __table_args__ = (Index("ix_monitoring_created_at", "created_at"),)


class BatchImport(Base, ModelMixin):
    __tablename__ = "batch_import"
    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    file_id = sa.Column(sa.ForeignKey(File.id, ondelete="cascade"), nullable=False)
    processed = sa.Column(sa.Boolean, nullable=False, default=False)
    summary = sa.Column(sa.Text, nullable=True, default=None)

    file = orm.relationship(File)
    user = orm.relationship(User)

    def nb_alias(self):
        return Alias.filter_by(batch_import_id=self.id).count()

    def __repr__(self):
        return f"<BatchImport {self.id}>"


class AuthorizedAddress(Base, ModelMixin):
    """Authorize other addresses to send emails from aliases that are owned by a mailbox"""

    __tablename__ = "authorized_address"

    user_id = sa.Column(sa.ForeignKey(User.id, ondelete="cascade"), nullable=False)
    mailbox_id = sa.Column(
        sa.ForeignKey(Mailbox.id, ondelete="cascade"), nullable=False
    )
    email = sa.Column(sa.String(256), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("mailbox_id", "email", name="uq_authorize_address"),
    )

    mailbox = orm.relationship(Mailbox, backref="authorized_addresses")

    def __repr__(self):
        return f"<AuthorizedAddress {self.id} {self.email} {self.mailbox_id}>"


class Metric2(Base, ModelMixin):

    __tablename__ = "metric2"
    date = sa.Column(ArrowType, default=arrow.utcnow, nullable=False)

    nb_user = sa.Column(sa.Float, nullable=True)
    nb_activated_user = sa.Column(sa.Float, nullable=True)
    nb__user = sa.Column(sa.Float, nullable=True)

    nb_premium = sa.Column(sa.Float, nullable=True)
    nb__premium = sa.Column(sa.Float, nullable=True)
    nb_cancelled_premium = sa.Column(sa.Float, nullable=True)
    nb_manual_premium = sa.Column(sa.Float, nullable=True)
    nb_coinbase_premium = sa.Column(sa.Float, nullable=True)
    nb__premium = sa.Column(sa.Float, nullable=True)

    
    nb_referred_user = sa.Column(sa.Float, nullable=True)
    nb_referred_user_paid = sa.Column(sa.Float, nullable=True)

    nb_alias = sa.Column(sa.Float, nullable=True)

    
    nb_forward = sa.Column(sa.Float, nullable=True)
    nb_block = sa.Column(sa.Float, nullable=True)
    nb_reply = sa.Column(sa.Float, nullable=True)
    nb_bounced = sa.Column(sa.Float, nullable=True)
    nb_spam = sa.Column(sa.Float, nullable=True)

    
    nb_forward_last_24h = sa.Column(sa.Float, nullable=True)
    nb_block_last_24h = sa.Column(sa.Float, nullable=True)
    nb_reply_last_24h = sa.Column(sa.Float, nullable=True)
    nb_bounced_last_24h = sa.Column(sa.Float, nullable=True)
    
    nb_total_bounced_last_24h = sa.Column(sa.Float, nullable=True)

    nb_verified_custom_domain = sa.Column(sa.Float, nullable=True)
    nb_subdomain = sa.Column(sa.Float, nullable=True)
    nb_directory = sa.Column(sa.Float, nullable=True)

    nb_deleted_directory = sa.Column(sa.Float, nullable=True)
    nb_deleted_subdomain = sa.Column(sa.Float, nullable=True)

    nb_app = sa.Column(sa.Float, nullable=True)


class DailyMetric(Base, ModelMixin):

    __tablename__ = "daily_metric"
    date = sa.Column(sa.Date, nullable=False, unique=True)

    
    nb_new_web_non__user = sa.Column(
        sa.Integer, nullable=False, server_default="0", default=0
    )

    nb_alias = sa.Column(sa.Integer, nullable=False, server_default="0", default=0)

    @staticmethod
    def get_or_create_today_metric() -> DailyMetric:
        today = arrow.utcnow().date()
        daily_metric = DailyMetric.get_by(date=today)
        if not daily_metric:
            daily_metric = DailyMetric.create(
                date=today, nb_new_web_non__user=0, nb_alias=0
            )
        return daily_metric


class Bounce(Base, ModelMixin):
    """Record all bounces. Deleted after 7 days"""

    __tablename__ = "bounce"
    email = sa.Column(sa.String(256), nullable=False, index=True)
    info = sa.Column(sa.Text, nullable=True)

    __table_args__ = (sa.Index("ix_bounce_created_at", "created_at"),)


class TransactionalEmail(Base, ModelMixin):

    __tablename__ = "transactional_email"
    email = sa.Column(sa.String(256), nullable=False, unique=False)

    __table_args__ = (sa.Index("ix_transactional_email_created_at", "created_at"),)

    @classmethod
    def create(cls, **kw):
        
        commit = kw.pop("commit", False)

        r = cls(**kw)
        if not config.STORE_TRANSACTIONAL_EMAILS:
            return r

        Session.add(r)
        if commit:
            Session.commit()
        return r


class Payout(Base, ModelMixin):

    __tablename__ = "payout"
    user_id = sa.Column(sa.ForeignKey("users.id", ondelete="cascade"), nullable=False)
    
    amount = sa.Column(sa.Float, nullable=False)
    
    payment_method = sa.Column(sa.String(256), nullable=False)

    number_upgraded_account = sa.Column(sa.Integer, nullable=False)

    comment = sa.Column(sa.Text)

    user = orm.relationship(User)

class IgnoredEmail(Base, ModelMixin):

    __tablename__ = "ignored_email"

    mail_from = sa.Column(sa.String(512), nullable=False)
    rcpt_to = sa.Column(sa.String(512), nullable=False)


class IgnoreBounceSender(Base, ModelMixin):

    __tablename__ = "ignore_bounce_sender"

    mail_from = sa.Column(sa.String(512), nullable=False, unique=True)

    def __repr__(self):
        return f"<NoReplySender {self.mail_from}"