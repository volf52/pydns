import enum
from dataclasses import dataclass
from typing_extensions import Self

from python_dns_client.constants import (
    NULL_BYTE,
    ONE_AS_SHORT,
    ONE_BYTE_STRUCT,
    TWO_BYTE_STRUCT,
)
from python_dns_client.protocols import Packable


class DNSRecordType(enum.Enum):
    A = 1
    CNAME = 5
    TXT = 16

    def to_bytes(self) -> bytes:
        return TWO_BYTE_STRUCT.pack(self.value)

    def __str__(self) -> str:
        return self.to_bytes().decode()


@dataclass(frozen=True)
class LabelSequence(Packable):
    domain: str
    __packed: bytes

    @classmethod
    def create(cls, domain: str) -> Self:
        # buff = []
        # total = 0

        b = []
        for part in domain.split("."):
            # part_enc = part.encode()
            # part_len = len(part_enc)

            # total += part_len + 1

            # buff.append(part_len)
            # buff.extend(part_enc)

            b.append(ONE_BYTE_STRUCT.pack(len(part)).decode())
            b.extend(part)

        # packed = struct.pack(f"! {total}B", *buff)

        packed = "".join(b).encode()
        packed += NULL_BYTE

        return LabelSequence(domain, packed)

    @classmethod
    def parse(cls, b: bytes) -> tuple[Self, bytes]:
        domain_parts = []
        idx = 0
        total_len = len(b)

        part_length: int
        while idx < total_len and (part_length := b[idx]) != 0:
            # part_length = b[idx]

            if idx + part_length >= total_len:
                raise ValueError(
                    f"Invalid part length at idx {idx} for label sequence {b}"
                )

            start = idx + 1
            idx += part_length + 1
            part = b[start:idx].decode()
            domain_parts.append(part)

        domain = ".".join(domain_parts)
        idx += 1

        return LabelSequence(domain, b[:idx]), b[idx:]

    def to_bytes(self) -> bytes:
        return self.__packed

    def __str__(self) -> str:
        return self.__packed.decode()


@dataclass(frozen=True)
class DNSQuestion(Packable):
    label_seq: LabelSequence
    record_type: DNSRecordType

    __packed: bytes

    _class: int = 1

    @classmethod
    def create(cls, domain: str, record_type: DNSRecordType) -> Self:
        lbl_seq = LabelSequence.create(domain)

        packed = lbl_seq.to_bytes() + record_type.to_bytes() + ONE_AS_SHORT

        return cls(lbl_seq, record_type, packed)

    @classmethod
    def parse(cls, b: bytes) -> tuple[Self, bytes]:
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
