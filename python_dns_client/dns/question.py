# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass

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

    @classmethod
    def create(cls, domain: str, record_type: DNSRecordType) -> DNSQuestion:
        lbl_seq = LabelSequence.create(domain)

        packed = lbl_seq.to_bytes() + record_type.to_bytes() + ONE_AS_SHORT

        return cls(lbl_seq, record_type, packed)

    @classmethod
    def parse(cls, b: bytes) -> tuple[DNSQuestion, bytes]:
        _packed = b

        lbl, b = LabelSequence.parse(b)
        assert len(b) >= 4  # must be 4 bytes or more

        (record_type_val,) = TWO_BYTE_STRUCT.unpack(b[:2])
        record_type = DNSRecordType(record_type_val)
        (_class,) = TWO_BYTE_STRUCT.unpack(b[2:4])

        return cls(lbl, record_type, _packed, _class), b[4:]

    @property
    def domain(self) -> str:
        return self.label_seq.domain

    def to_bytes(self) -> bytes:
        return self.__packed
