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
    rdata: str

    __packed: bytes

    BYTES_REQUIRED_AFTER_LBL: ClassVar = 10

    ALLOWED_RECORD_VALUES: ClassVar[set[int]] = set(
        x.value for x in DNSRecordType
    )

    @classmethod
    def parse(cls, b: bytes):
        return cls.parse_from(DNSBuffer.create(b))

    @classmethod
    def parse_from(cls, buff: DNSBuffer) -> DNSResponse:
        lbl = LabelSequence.parse_from(buff)

        assert buff.remaining >= DNSResponse.BYTES_REQUIRED_AFTER_LBL

        b = buff.get(DNSResponse.BYTES_REQUIRED_AFTER_LBL)
        (record_type_val,) = TWO_BYTE_STRUCT.unpack(b[:2])
        if record_type_val not in DNSResponse.ALLOWED_RECORD_VALUES:
            raise ValueError(f"unsupported record value: {record_type_val}")

        record_type = DNSRecordType(record_type_val)

        (_class,) = TWO_BYTE_STRUCT.unpack(b[2:4])

        (ttl,) = FOUR_BYTE_STRUCT.unpack(b[4:8])
        (_len,) = TWO_BYTE_STRUCT.unpack(b[8:10])

        # Answer
        assert buff.remaining >= _len
        data_bytes = buff.get(_len)

        if record_type == DNSRecordType.A:
            rdata = DNSResponse._parse_ip_v4(data_bytes)
        else:
            rdata = ""

        _packed = lbl.to_bytes() + b + data_bytes

        return cls(lbl, record_type, _class, ttl, _len, rdata, _packed)

    def to_bytes(self) -> bytes:
        return self.__packed

    @staticmethod
    def _parse_ip_v4(b: bytes) -> str:
        ip_parts = []
        for bt in b:
            ip_parts.append(str(bt))

        ip = ".".join(ip_parts)
        return ip
