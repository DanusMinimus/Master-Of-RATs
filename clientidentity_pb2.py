# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: clientidentity.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='clientidentity.proto',
  package='Client',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=b'\n\x14\x63lientidentity.proto\x12\x06\x43lient\"\x92\x02\n\x14\x43lientIdentification\x12\x0f\n\x07Version\x18\x01 \x01(\t\x12\x17\n\x0fOperatingSystem\x18\x02 \x01(\t\x12\x13\n\x0b\x41\x63\x63ountType\x18\x03 \x01(\t\x12\x0f\n\x07\x43ountry\x18\x04 \x01(\t\x12\x13\n\x0b\x43ountryCode\x18\x05 \x01(\t\x12\x0e\n\x06Region\x18\x06 \x01(\t\x12\x0c\n\x04\x43ity\x18\x07 \x01(\t\x12\x12\n\nImageIndex\x18\x08 \x01(\x05\x12\n\n\x02Id\x18\t \x01(\t\x12\x10\n\x08Username\x18\n \x01(\t\x12\x0e\n\x06PcName\x18\x0b \x01(\t\x12\x0b\n\x03Tag\x18\x0c \x01(\t\x12\x15\n\rEncryptionKey\x18\r \x01(\t\x12\x11\n\tSignature\x18\x0e \x01(\x0c\x62\x06proto3'
)


_CLIENTIDENTIFICATION = _descriptor.Descriptor(
  name='ClientIdentification',
  full_name='Client.ClientIdentification',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='Version', full_name='Client.ClientIdentification.Version', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='OperatingSystem', full_name='Client.ClientIdentification.OperatingSystem', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='AccountType', full_name='Client.ClientIdentification.AccountType', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Country', full_name='Client.ClientIdentification.Country', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='CountryCode', full_name='Client.ClientIdentification.CountryCode', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Region', full_name='Client.ClientIdentification.Region', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='City', full_name='Client.ClientIdentification.City', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ImageIndex', full_name='Client.ClientIdentification.ImageIndex', index=7,
      number=8, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Id', full_name='Client.ClientIdentification.Id', index=8,
      number=9, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Username', full_name='Client.ClientIdentification.Username', index=9,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='PcName', full_name='Client.ClientIdentification.PcName', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Tag', full_name='Client.ClientIdentification.Tag', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='EncryptionKey', full_name='Client.ClientIdentification.EncryptionKey', index=12,
      number=13, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Signature', full_name='Client.ClientIdentification.Signature', index=13,
      number=14, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=33,
  serialized_end=307,
)

DESCRIPTOR.message_types_by_name['ClientIdentification'] = _CLIENTIDENTIFICATION
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ClientIdentification = _reflection.GeneratedProtocolMessageType('ClientIdentification', (_message.Message,), {
  'DESCRIPTOR' : _CLIENTIDENTIFICATION,
  '__module__' : 'clientidentity_pb2'
  # @@protoc_insertion_point(class_scope:Client.ClientIdentification)
  })
_sym_db.RegisterMessage(ClientIdentification)


# @@protoc_insertion_point(module_scope)
