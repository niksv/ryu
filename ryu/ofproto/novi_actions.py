# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import six

import struct

from ryu import utils, ofproto
from ryu.lib import type_desc
from ryu.ofproto import nicira_ext
from ryu import ofproto

from ryu.ofproto import ofproto_common
from ryu.lib.pack_utils import msg_pack_into


def generate(ofp_name, ofpp_name):
    import sys

    ofp = sys.modules[ofp_name]
    ofpp = sys.modules[ofpp_name]

    class NoviAction(ofpp.OFPActionExperimenter):
        _fmt_str = '>BBH'
        _subtypes = {}
        _experimenter = ofproto_common.NOVI_EXPERIMENTER_ID
        customer = 0xff
        reserved = 0x00

        def __init__(self):
            super(NoviAction, self).__init__(self._experimenter)
            self.subtype = self._subtype

        @classmethod
        def parse(cls, buf):
            fmt_str = NoviAction._fmt_str
            (customer, reserved, novi_action_type) = struct.unpack_from(fmt_str, buf, 0)
            subtype_cls = cls._subtypes.get(novi_action_type)
            rest = buf[struct.calcsize(fmt_str):]
            if subtype_cls is None:
                return NoviActionUnknown(novi_action_type, rest)
            return subtype_cls.parser(rest)

        def serialize(self, buf, offset):
            data = self.serialize_body()
            super(NoviAction, self).serialize(buf, offset)

            buf += data

        @classmethod
        def register(cls, subtype_cls):
            assert subtype_cls._subtype is not cls._subtypes
            cls._subtypes[subtype_cls._subtype] = subtype_cls

    class NoviActionUnknown(NoviAction):
        def __init__(self, novi_action_type, data=None,
                     type_=None, len_=None, experimenter=None):
            self.novi_action_type = novi_action_type
            super(NoviActionUnknown, self).__init__()
            self.data = data

        @classmethod
        def parser(cls, buf):
            return cls(data=buf)

        def serialize_body(self):
            # fixup
            return bytearray() if self.data is None else self.data

    class NoviActionPushVxlan(NoviAction):
        _fmt_str = '>BB6B6BIIHI'

        NOVI_ACTION_PUSH_TUNNEL = 0x0002
        _subtype = NOVI_ACTION_PUSH_TUNNEL
        NOVI_TUNNEL_TYPE_VXLAN = 0x00
        TUNNEL_DATA_PRESENT = 0x01

        def __init__(self, eth_src, eth_dst, ipv4_src, ipv4_dst, udp_src, vni):
            super(NoviActionPushVxlan, self).__init__()
            self.eth_src = eth_src
            self.eth_dst = eth_dst
            self.ipv4_src = ipv4_src
            self.ipv4_dst = ipv4_dst
            self.udp_src = udp_src
            self.vni = vni
            self.len = 40

        @classmethod
        def parser(cls, buf):
            tunnel_type = buf[0]
            flags = buf[1]
            eth_src = type_desc.MacAddr.to_user(buf[2:8])
            eth_dst = type_desc.MacAddr.to_user(buf[8:14])
            ipv4_src = type_desc.IPv4Addr.to_user(buf[14:18])
            ipv4_dst = type_desc.IPv4Addr.to_user(buf[18:22])
            udp_src = int.from_bytes(buf[22:24], byteorder='big')
            vni = int.from_bytes(buf[24:28], byteorder='big')
            return cls(eth_src, eth_dst, ipv4_src, ipv4_dst, udp_src, vni)

        def serialize_body(self):
            data = bytearray()
            data += self.customer.to_bytes(1, 'big')
            data += self.reserved.to_bytes(1, 'big')
            data += self.NOVI_ACTION_PUSH_TUNNEL.to_bytes(2, 'big')
            data += self.NOVI_TUNNEL_TYPE_VXLAN.to_bytes(1, 'big')
            data += self.TUNNEL_DATA_PRESENT.to_bytes(1, 'big')
            data += type_desc.MacAddr.from_user(self.eth_src)
            data += type_desc.MacAddr.from_user(self.eth_dst)
            data += type_desc.IPv4Addr.from_user(self.ipv4_src)
            data += type_desc.IPv4Addr.from_user(self.ipv4_dst)
            data += self.udp_src.to_bytes(2, 'big')
            data += self.vni.to_bytes(4, 'big')
            return data

    class NoviActionHashFieldsSym(NoviAction):
        #_fmt_str = '>BB6B6BIIHI'

        NOVI_ACTION_HASH_FIELDS_SYM = 0x0007
        _subtype = NOVI_ACTION_HASH_FIELDS_SYM

        def __init__(self, fields):
            super(NoviActionHashFieldsSym, self).__init__()
            self.fields = fields
            self.len = 13 + len(fields) * 4
            self.pad_len = utils.round_up(self.len, 8) - self.len
            self.len += self.pad_len

        @classmethod
        def parser(cls, buf):
            count = buf[0]
            fields = []

            for i in range(count):
                offset = 1 + i * 4
                fields.append(int.from_bytes(buf[offset:offset+4], byteorder='big'))

            return cls(fields)

        def serialize_body(self):
            data = bytearray()
            data += self.customer.to_bytes(1, 'big')
            data += self.reserved.to_bytes(1, 'big')
            data += self.NOVI_ACTION_HASH_FIELDS_SYM.to_bytes(2, 'big')
            data += len(self.fields).to_bytes(1, 'big')
            for field in self.fields:
                data += field.to_bytes(4, 'big')
            data += bytearray(self.pad_len)
            return data

    def add_attr(k, v):
        v.__module__ = ofpp.__name__  # Necessary for stringify stuff
        setattr(ofpp, k, v)

    add_attr('NoviAction', NoviAction)
    add_attr('NoviUnknown', NoviActionUnknown)

    classes = [
        'NoviActionPushVxlan',
        'NoviActionHashFieldsSym'
    ]
    vars = locals()
    for name in classes:
        cls = vars[name]
        add_attr(name, cls)
        NoviAction.register(cls)
