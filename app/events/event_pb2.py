from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    27,
    0,
    '',
    'event.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0b\x65vent.proto\x12\x12login_events\"(\n\x0fUserPlanChanged\x12\x15\n\rplan_end_time\x18\x01 \x01(\r\"\r\n\x0bUserDeleted\"Z\n\x0c\x41liasCreated\x12\x10\n\x08\x61lias_id\x18\x01 \x01(\r\x12\x13\n\x0b\x61lias_email\x18\x02 \x01(\t\x12\x12\n\nalias_note\x18\x03 \x01(\t\x12\x0f\n\x07\x65nabled\x18\x04 \x01(\x08\"L\n\x12\x41liasStatusChanged\x12\x10\n\x08\x61lias_id\x18\x01 \x01(\r\x12\x13\n\x0b\x61lias_email\x18\x02 \x01(\t\x12\x0f\n\x07\x65nabled\x18\x03 \x01(\x08\"5\n\x0c\x41liasDeleted\x12\x10\n\x08\x61lias_id\x18\x01 \x01(\r\x12\x13\n\x0b\x61lias_email\x18\x02 \x01(\t\"D\n\x10\x41liasCreatedList\x12\x30\n\x06\x65vents\x18\x01 \x03(\x0b\x32 .login_events.AliasCreated\"\x93\x03\n\x0c\x45ventContent\x12?\n\x10user_plan_change\x18\x01 \x01(\x0b\x32#.login_events.UserPlanChangedH\x00\x12\x37\n\x0cuser_deleted\x18\x02 \x01(\x0b\x32\x1f.login_events.UserDeletedH\x00\x12\x39\n\ralias_created\x18\x03 \x01(\x0b\x32 .login_events.AliasCreatedH\x00\x12\x45\n\x13\x61lias_status_change\x18\x04 \x01(\x0b\x32&.login_events.AliasStatusChangedH\x00\x12\x39\n\ralias_deleted\x18\x05 \x01(\x0b\x32 .login_events.AliasDeletedH\x00\x12\x41\n\x11\x61lias_create_list\x18\x06 \x01(\x0b\x32$.login_events.AliasCreatedListH\x00\x42\t\n\x07\x63ontent\"y\n\x05\x45vent\x12\x0f\n\x07user_id\x18\x01 \x01(\r\x12\x18\n\x10\x65xternal_user_id\x18\x02 \x01(\t\x12\x12\n\npartner_id\x18\x03 \x01(\r\x12\x31\n\x07\x63ontent\x18\x04 \x01(\x0b\x32 .login_events.EventContentb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'event_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_USERPLANCHANGED']._serialized_start=35
  _globals['_USERPLANCHANGED']._serialized_end=75
  _globals['_USERDELETED']._serialized_start=77
  _globals['_USERDELETED']._serialized_end=90
  _globals['_ALIASCREATED']._serialized_start=92
  _globals['_ALIASCREATED']._serialized_end=182
  _globals['_ALIASSTATUSCHANGED']._serialized_start=184
  _globals['_ALIASSTATUSCHANGED']._serialized_end=260
  _globals['_ALIASDELETED']._serialized_start=262
  _globals['_ALIASDELETED']._serialized_end=315
  _globals['_ALIASCREATEDLIST']._serialized_start=317
  _globals['_ALIASCREATEDLIST']._serialized_end=385
  _globals['_EVENTCONTENT']._serialized_start=388
  _globals['_EVENTCONTENT']._serialized_end=791
  _globals['_EVENT']._serialized_start=793
  _globals['_EVENT']._serialized_end=914
# @@protoc_insertion_point(module_scope)
