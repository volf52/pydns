# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from python_dns_client.dns.buffer import DNSBuffer
from python_dns_client.dns.label_sequence import LabelSequence
from python_dns_client.dns.record import DNSRecordType
from python_dns_client.shared.constants import (
    FOUR_BYTE_STRUCT,
    TWO_BYTE_STRUCT,
)
from python_dns_client.shared.protocols import Packable


@dataclass(frozen=True)
class DNSResponse(Packable):
    label_seq: LabelSequence
    record_type: DNSRecordType
    _class: int
    ttl: int
    _len: int
    data: str

    __packed: bytes

    BYTES_REQUIRED_AFTER_LBL: ClassVar = 10
    # packet_pos: int, jmp_state: dict[int, LabelSequence]
    # jmp_state[packet_pos] = lbl

    @classmethod
    def parse(cls, b: bytes):
        return cls.parse_from(DNSBuffer.create(b))

    @classmethod
    def parse_from(cls, buff: DNSBuffer) -> DNSResponse:
        lbl = LabelSequence.parse_from(buff)

        assert buff.left >= DNSResponse.BYTES_REQUIRED_AFTER_LBL

        b = buff.get(DNSResponse.BYTES_REQUIRED_AFTER_LBL)
        (record_type_val,) = TWO_BYTE_STRUCT.unpack(b[:2])
        record_type = DNSRecordType(record_type_val)

        (_class,) = TWO_BYTE_STRUCT.unpack(b[2:4])

        (ttl,) = FOUR_BYTE_STRUCT.unpack(b[4:8])
        (_len,) = TWO_BYTE_STRUCT.unpack(b[8:10])

        # Answer
        assert buff.left >= _len

        ans_bytes = buff.get(_len)
        ans_lst = []
        for ans_byte in ans_bytes:
            ans_lst.append(str(ans_byte))

        _packed = lbl.to_bytes() + b + ans_bytes
        ans = ".".join(ans_lst)

        return cls(lbl, record_type, _class, ttl, _len, ans, _packed)

    def to_bytes(self) -> bytes:
        return self.__packed
