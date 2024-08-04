import enum
from typing import Set, Union

import flask

class Scope(enum.Enum):
    EMAIL = "email"
    NAME = "name"
    OPENID = "openid"
    AVATAR_URL = "avatar_url"

class ResponseType(enum.Enum):
    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"


SUPPORTED_OPENID_FLOWS = [
    {ResponseType.CODE},
    {ResponseType.TOKEN},
    {ResponseType.ID_TOKEN},
    {ResponseType.ID_TOKEN, ResponseType.TOKEN},
    {ResponseType.ID_TOKEN, ResponseType.CODE},
]


SUPPORTED_OPENID_FLOWS_STR = "code|token|id_token|id_token,token|id_token,code"


def get_scopes(request: flask.Request) -> Set[Scope]:
    scope_strs = _split_arg(request.args.getlist("scope"))

    return set([Scope(scope_str) for scope_str in scope_strs])


def get_response_types(request: flask.Request) -> Set[ResponseType]:
    response_type_strs = _split_arg(request.args.getlist("response_type"))

    return set([ResponseType(r) for r in response_type_strs if r])


def get_response_types_from_str(response_type_str) -> Set[ResponseType]:
    response_type_strs = _split_arg(response_type_str)

    return set([ResponseType(r) for r in response_type_strs if r])


def response_types_to_str(response_types: [ResponseType]) -> str:
    return ",".join([r.value for r in response_types])


def _split_arg(arg_input: Union[str, list]) -> Set[str]:
    res = set()
    if isinstance(arg_input, str):
        if " " in arg_input:
            for x in arg_input.split(" "):
                if x:
                    res.add(x.lower())
        elif "," in arg_input:
            for x in arg_input.split(","):
                if x:
                    res.add(x.lower())
        else:
            res.add(arg_input)

    else:
        for arg in arg_input:
            res = res.union(_split_arg(arg))

    return res
