# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from pydns.dns.buffer import DNSBuffer
from pydns.dns.label_sequence import LabelSequence
from pydns.dns.record import DNSRecordType
from pydns.shared.constants import FOUR_BYTE_STRUCT, TWO_BYTE_STRUCT
from pydns.shared.protocols import Packable


@dataclass(frozen=True)
class DNSResponse(Packable):
    label_seq: LabelSequence
    record_type: DNSRecordType
    _class: int
    ttl: int
    _len: int
    rdata: str | LabelSequence

    __packed: bytes

    BYTES_REQUIRED_AFTER_LBL: ClassVar = 10
    IPV6_FORMAT_COLON_RE: ClassVar = re.compile(r"(::){2,}")

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
        data_bytes = buff.rest

        if record_type == DNSRecordType.A:
            rdata = DNSResponse._parse_ip_v4(data_bytes)
        elif record_type == DNSRecordType.AAAA:
            rdata = DNSResponse._parse_ip_v6(data_bytes)
        elif record_type == DNSRecordType.CNAME:
            rdata = DNSResponse._parse_cname(buff)
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

    @staticmethod
    def _parse_ip_v6(b: bytes) -> str:
        ip_parts = []
        for i in range(0, 16, 2):
            ip_parts.append(b[i : i + 2].hex())

        ip = ":".join(ip_parts).replace("0000", "")
        ip = DNSResponse.IPV6_FORMAT_COLON_RE.sub("::", ip)

        return ip

    @staticmethod
    def _parse_cname(buff: DNSBuffer) -> LabelSequence:
        return LabelSequence.parse_from(buff)

    def __str__(self) -> str:
        return f"rtype={self.record_type} || rdata:{self.rdata}"
