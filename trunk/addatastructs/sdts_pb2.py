# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: addatastructs/sdts.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)




DESCRIPTOR = _descriptor.FileDescriptor(
  name='addatastructs/sdts.proto',
  package='memory',
  serialized_pb='\n\x18\x61\x64\x64\x61tastructs/sdts.proto\x12\x06memory\"9\n\x0fUnspecifiedType\x12\x16\n\x0e\x62\x61seObjectType\x18\x01 \x02(\t\x12\x0e\n\x06object\x18\x02 \x02(\x0c\"Z\n\rSSDTEntryType\x12\x14\n\x0c\x46unctionName\x18\x01 \x02(\t\x12\x12\n\nModuleName\x18\x02 \x02(\t\x12\x10\n\x08VirtAddr\x18\x03 \x02(\x04\x12\r\n\x05Index\x18\x04 \x01(\x0c\"J\n\x0fSSDTEntriesType\x12(\n\tSSDTEntry\x18\x01 \x03(\x0b\x32\x15.memory.SSDTEntryType\x12\r\n\x05\x63ount\x18\x02 \x01(\x05\"J\n\x08SSDTType\x12\x10\n\x08VirtAddr\x18\x01 \x02(\x04\x12,\n\x0bSSDTEntries\x18\x02 \x02(\x0b\x32\x17.memory.SSDTEntriesType\"+\n\tSSDTsType\x12\x1e\n\x04SSDT\x18\x01 \x03(\x0b\x32\x10.memory.SSDTType\",\n\x08rootType\x12 \n\x05SSDTs\x18\x01 \x02(\x0b\x32\x11.memory.SSDTsType')




_UNSPECIFIEDTYPE = _descriptor.Descriptor(
  name='UnspecifiedType',
  full_name='memory.UnspecifiedType',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='baseObjectType', full_name='memory.UnspecifiedType.baseObjectType', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='object', full_name='memory.UnspecifiedType.object', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=36,
  serialized_end=93,
)


_SSDTENTRYTYPE = _descriptor.Descriptor(
  name='SSDTEntryType',
  full_name='memory.SSDTEntryType',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='FunctionName', full_name='memory.SSDTEntryType.FunctionName', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ModuleName', full_name='memory.SSDTEntryType.ModuleName', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='VirtAddr', full_name='memory.SSDTEntryType.VirtAddr', index=2,
      number=3, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='Index', full_name='memory.SSDTEntryType.Index', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=95,
  serialized_end=185,
)


_SSDTENTRIESTYPE = _descriptor.Descriptor(
  name='SSDTEntriesType',
  full_name='memory.SSDTEntriesType',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='SSDTEntry', full_name='memory.SSDTEntriesType.SSDTEntry', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='count', full_name='memory.SSDTEntriesType.count', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=187,
  serialized_end=261,
)


_SSDTTYPE = _descriptor.Descriptor(
  name='SSDTType',
  full_name='memory.SSDTType',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='VirtAddr', full_name='memory.SSDTType.VirtAddr', index=0,
      number=1, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='SSDTEntries', full_name='memory.SSDTType.SSDTEntries', index=1,
      number=2, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=263,
  serialized_end=337,
)


_SSDTSTYPE = _descriptor.Descriptor(
  name='SSDTsType',
  full_name='memory.SSDTsType',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='SSDT', full_name='memory.SSDTsType.SSDT', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=339,
  serialized_end=382,
)


_ROOTTYPE = _descriptor.Descriptor(
  name='rootType',
  full_name='memory.rootType',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='SSDTs', full_name='memory.rootType.SSDTs', index=0,
      number=1, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=384,
  serialized_end=428,
)

_SSDTENTRIESTYPE.fields_by_name['SSDTEntry'].message_type = _SSDTENTRYTYPE
_SSDTTYPE.fields_by_name['SSDTEntries'].message_type = _SSDTENTRIESTYPE
_SSDTSTYPE.fields_by_name['SSDT'].message_type = _SSDTTYPE
_ROOTTYPE.fields_by_name['SSDTs'].message_type = _SSDTSTYPE
DESCRIPTOR.message_types_by_name['UnspecifiedType'] = _UNSPECIFIEDTYPE
DESCRIPTOR.message_types_by_name['SSDTEntryType'] = _SSDTENTRYTYPE
DESCRIPTOR.message_types_by_name['SSDTEntriesType'] = _SSDTENTRIESTYPE
DESCRIPTOR.message_types_by_name['SSDTType'] = _SSDTTYPE
DESCRIPTOR.message_types_by_name['SSDTsType'] = _SSDTSTYPE
DESCRIPTOR.message_types_by_name['rootType'] = _ROOTTYPE

class UnspecifiedType(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _UNSPECIFIEDTYPE

  # @@protoc_insertion_point(class_scope:memory.UnspecifiedType)

class SSDTEntryType(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _SSDTENTRYTYPE

  # @@protoc_insertion_point(class_scope:memory.SSDTEntryType)

class SSDTEntriesType(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _SSDTENTRIESTYPE

  # @@protoc_insertion_point(class_scope:memory.SSDTEntriesType)

class SSDTType(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _SSDTTYPE

  # @@protoc_insertion_point(class_scope:memory.SSDTType)

class SSDTsType(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _SSDTSTYPE

  # @@protoc_insertion_point(class_scope:memory.SSDTsType)

class rootType(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _ROOTTYPE

  # @@protoc_insertion_point(class_scope:memory.rootType)


# @@protoc_insertion_point(module_scope)