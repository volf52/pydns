# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from python_dns_client.dns.buffer import DNSBuffer
from python_dns_client.dns.label_sequence import LabelSequence
from python_dns_client.dns.record import DNSRecordType
from python_dns_client.shared.constants import ONE_AS_SHORT, TWO_BYTE_STRUCT
from python_dns_client.shared.protocols import Packable


@dataclass(frozen=True)
class DNSQuestion(Packable):
    label_seq: LabelSequence
    record_type: DNSRecordType

    __packed: bytes

    _class: int = 1

    BYTES_REQUIRED_AFTER_LBL: ClassVar = 4

    @classmethod
    def create(cls, domain: str, record_type: DNSRecordType) -> DNSQuestion:
        lbl_seq = LabelSequence.create(domain)

        packed = lbl_seq.to_bytes() + record_type.to_bytes() + ONE_AS_SHORT

        return cls(lbl_seq, record_type, packed)

    @classmethod
    def parse(cls, b: bytes):
        return cls.parse_from(DNSBuffer.create(b))

    @classmethod
    def parse_from(
        cls,
        buff: DNSBuffer,
    ) -> DNSQuestion:
        lbl = LabelSequence.parse_from(buff)
        assert buff.left >= DNSQuestion.BYTES_REQUIRED_AFTER_LBL

        b = buff.get(DNSQuestion.BYTES_REQUIRED_AFTER_LBL)
        (record_type_val,) = TWO_BYTE_STRUCT.unpack(b[:2])
        record_type = DNSRecordType(record_type_val)
        (_class,) = TWO_BYTE_STRUCT.unpack(b[2:4])
        _packed = lbl.to_bytes() + b

        return cls(lbl, record_type, _packed, _class)

    @property
    def domain(self) -> str:
        return self.label_seq.domain

    def to_bytes(self) -> bytes:
        return self.__packed
