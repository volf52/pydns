# -*- coding: utf-8 -*-
import enum

from pydns.shared.constants import TWO_BYTE_STRUCT


class DNSRecordType(enum.Enum):
    A = 1
    CNAME = 5
    AAAA = 28

    def to_bytes(self) -> bytes:
        return TWO_BYTE_STRUCT.pack(self.value)
