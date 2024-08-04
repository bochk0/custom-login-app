from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from arrow import Arrow
from newrelic import agent
from sqlalchemy import or_

from app.db import Session
from app.email_utils import send_welcome_email
from app.utils import sanitize_email, canonicalize_email
from app.errors import (
    AccountAlreadyLinkedToAnotherPartnerException,
    AccountIsUsingAliasAsEmail,
    AccountAlreadyLinkedToAnotherUserException,
)
from app.log import LOG
from app.models import (
    PartnerSubscription,
    Partner,
    PartnerUser,
    User,
    Alias,
)
from app.utils import random_string


class SLPlanType(Enum):
    Free = 1
    Premium = 2


@dataclass
class SLPlan:
    type: SLPlanType
    expiration: Optional[Arrow]


@dataclass
class PartnerLinkRequest:
    name: str
    email: str
    external_user_id: str
    plan: SLPlan
    from_partner: bool


@dataclass
class LinkResult:
    user: User
    strategy: str


def set_plan_for_partner_user(partner_user: PartnerUser, plan: SLPlan):
    sub = PartnerSubscription.get_by(partner_user_id=partner_user.id)
    if plan.type == SLPlanType.Free:
        if sub is not None:
            LOG.i(
                f"Deleting partner_subscription [user_id={partner_user.user_id}] [partner_id={partner_user.partner_id}]"
            )
            PartnerSubscription.delete(sub.id)
            agent.record_custom_event("PlanChange", {"plan": "free"})
    else:
        if sub is None:
            LOG.i(
                f"Creating partner_subscription [user_id={partner_user.user_id}] [partner_id={partner_user.partner_id}]"
            )
            PartnerSubscription.create(
                partner_user_id=partner_user.id,
                end_at=plan.expiration,
            )
            agent.record_custom_event("PlanChange", {"plan": "premium", "type": "new"})
        else:
            if sub.end_at != plan.expiration:
                LOG.i(
                    f"Updating partner_subscription [user_id={partner_user.user_id}] [partner_id={partner_user.partner_id}]"
                )
                agent.record_custom_event(
                    "PlanChange", {"plan": "premium", "type": "extension"}
                )
                sub.end_at = plan.expiration
    Session.commit()
