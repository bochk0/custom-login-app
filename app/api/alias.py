from deprecated import deprecated
from flask import g
from flask import jsonify
from flask import request

from app import alias_utils
from app.api.base import api_bp, require_api_auth
from app.api.serializer import (
    AliasInfo,
    serialize_alias_info,
    serialize_contact,
    get_alias_infos_with_pagination,
    get_alias_contacts,
    serialize_alias_info_v2,
    get_alias_info_v2,
    get_alias_infos_with_pagination_v3,
)
from app.dashboard.views.alias_contact_manager import create_contact
from app.dashboard.views.alias_log import get_alias_log
from app.db import Session
from app.errors import (
    CannotCreateContactForReverseAlias,
    ErrContactErrorUpgradeNeeded,
    ErrContactAlreadyExists,
    ErrAddressInvalid,
)
from app.extensions import limiter
from app.log import LOG
from app.models import Alias, Contact, Mailbox, AliasMailbox, AliasDeleteReason


@deprecated
@api_bp.route("/aliases", methods=["GET", "POST"])
@require_api_auth
@limiter.limit("10/minute", key_func=lambda: g.user.id)
def get_aliases():
    """
    Get aliases
    Input:
        page_id: in query
    Output:
        - aliases: list of alias:
            - id
            - email
            - creation_date
            - creation_timestamp
            - nb_forward
            - nb_block
            - nb_reply
            - note

    """
    user = g.user
    try:
        page_id = int(request.args.get("page_id"))
    except (ValueError, TypeError):
        return jsonify(error="page_id must be provided in request query"), 400

    query = None
    data = request.get_json(silent=True)
    if data:
        query = data.get("query")

    alias_infos: [AliasInfo] = get_alias_infos_with_pagination(
        user, page_id=page_id, query=query
    )

    return (
        jsonify(
            aliases=[serialize_alias_info(alias_info) for alias_info in alias_infos]
        ),
        200,
    )


@api_bp.route("/v2/aliases", methods=["GET", "POST"])
@require_api_auth
@limiter.limit("50/minute", key_func=lambda: g.user.id)
def get_aliases_v2():
    """
    Get aliases
    Input:
        page_id: in query
        pinned: in query
        disabled: in query
        enabled: in query
    Output:
        - aliases: list of alias:
            - id
            - email
            - creation_date
            - creation_timestamp
            - nb_forward
            - nb_block
            - nb_reply
            - note
            - mailbox
            - mailboxes
            - support_pgp
            - disable_pgp
            - latest_activity: null if no activity.
                - timestamp
                - action: forward|reply|block|bounced
                - contact:
                    - email
                    - name
                    - reverse_alias


    """
    user = g.user
    try:
        page_id = int(request.args.get("page_id"))
    except (ValueError, TypeError):
        return jsonify(error="page_id must be provided in request query"), 400

    pinned = "pinned" in request.args
    disabled = "disabled" in request.args
    enabled = "enabled" in request.args

    if pinned:
        alias_filter = "pinned"
    elif disabled:
        alias_filter = "disabled"
    elif enabled:
        alias_filter = "enabled"
    else:
        alias_filter = None

    query = None
    data = request.get_json(silent=True)
    if data:
        query = data.get("query")

    alias_infos: [AliasInfo] = get_alias_infos_with_pagination_v3(
        user, page_id=page_id, query=query, alias_filter=alias_filter
    )

    return (
        jsonify(
            aliases=[serialize_alias_info_v2(alias_info) for alias_info in alias_infos]
        ),
        200,
    )


@api_bp.route("/aliases/<int:alias_id>", methods=["DELETE"])
@require_api_auth
def delete_alias(alias_id):
    """
    Delete alias
    Input:
        alias_id: in url
    Output:
        200 if deleted successfully

    """
    user = g.user
    alias = Alias.get(alias_id)

    if not alias or alias.user_id != user.id:
        return jsonify(error="Forbidden"), 403

    alias_utils.delete_alias(alias, user, AliasDeleteReason.ManualAction)

    return jsonify(deleted=True), 200


@api_bp.route("/aliases/<int:alias_id>/toggle", methods=["POST"])
@require_api_auth
def toggle_alias(alias_id):
    """
    Enable/disable alias
    Input:
        alias_id: in url
    Output:
        200 along with new status:
        - enabled


    """
    user = g.user
    alias: Alias = Alias.get(alias_id)

    if not alias or alias.user_id != user.id:
        return jsonify(error="Forbidden"), 403

    alias_utils.change_alias_status(alias, enabled=not alias.enabled)
    LOG.i(f"User {user} changed alias {alias} enabled status to {alias.enabled}")
    Session.commit()

    return jsonify(enabled=alias.enabled), 200


@api_bp.route("/aliases/<int:alias_id>/activities")
@require_api_auth
def get_alias_activities(alias_id):
    """
    Get aliases
    Input:
        page_id: in query
    Output:
        - activities: list of activity:
            - from
            - to
            - timestamp
            - action: forward|reply|block|bounced
            - reverse_alias

    """
    user = g.user
    try:
        page_id = int(request.args.get("page_id"))
    except (ValueError, TypeError):
        return jsonify(error="page_id must be provided in request query"), 400

    alias: Alias = Alias.get(alias_id)

    if not alias or alias.user_id != user.id:
        return jsonify(error="Forbidden"), 403

    alias_logs = get_alias_log(alias, page_id)

    activities = []
    for alias_log in alias_logs:
        activity = {
            "timestamp": alias_log.when.timestamp,
            "reverse_alias": alias_log.reverse_alias,
            "reverse_alias_address": alias_log.contact.reply_email,
        }
        if alias_log.is_reply:
            activity["from"] = alias_log.alias
            activity["to"] = alias_log.website_email
            activity["action"] = "reply"
        else:
            activity["to"] = alias_log.alias
            activity["from"] = alias_log.website_email

            if alias_log.bounced:
                activity["action"] = "bounced"
            elif alias_log.blocked:
                activity["action"] = "block"
            else:
                activity["action"] = "forward"

        activities.append(activity)

    return jsonify(activities=activities), 200
