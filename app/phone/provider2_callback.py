import jwt
from flask import request
from jwt import InvalidSignatureError, DecodeError

from app.config import (
    PHONE_PROVIDER_2_HEADER,
    PHONE_PROVIDER_2_SECRET,
)
from app.log import LOG
from app.models import PhoneNumber, PhoneMessage
from app.phone.base import phone_bp


@phone_bp.route("/provider2/sms", methods=["GET", "POST"])
def provider2_sms():
    encoded = request.headers.get(PHONE_PROVIDER_2_HEADER)
    try:
        jwt.decode(encoded, key=PHONE_PROVIDER_2_SECRET, algorithms="HS256")
    except (InvalidSignatureError, DecodeError):
        LOG.e(
            "Unauthenticated callback %s %s %s %s",
            request.headers,
            request.method,
            request.args,
            request.json,
        )
        return "not ok", 400


    to_number: str = str(request.json.get("receiver"))
    if not to_number.startswith("+"):
        to_number = "+" + to_number

    from_number = str(request.json.get("msisdn"))
    if not from_number.startswith("+"):
        from_number = "+" + from_number

    body = request.json.get("message")

    LOG.d("%s->%s:%s", from_number, to_number, body)

    phone_number = PhoneNumber.get_by(number=to_number)
    if phone_number:
        PhoneMessage.create(
            number_id=phone_number.id,
            from_number=from_number,
            body=body,
            commit=True,
        )
    else:
        LOG.e("Unknown phone number %s %s", to_number, request.json)
        return "not ok", 200
    return "ok", 200
