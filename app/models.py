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


class AuditLogActionEnum(EnumE):
    create_object = 0
    update_object = 1
    delete_object = 2
    manual_upgrade = 3
    extend_trial = 4
    disable_2fa = 5
    logged_as_user = 6
    extend_subscription = 7
    download_provider_complaint = 8
    disable_user = 9
    enable_user = 10
    stop_trial = 11


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