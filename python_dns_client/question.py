import enum
from dataclasses import dataclass

from python_dns_client.constants import (
    NULL_BYTE,
    ONE_AS_SHORT,
    ONE_BYTE_STRUCT,
    TWO_BYTE_STRUCT,
)


class DNSRecordType(enum.Enum):
    A = 1
    CNAME = 5
    TXT = 16

    def to_bytes(self) -> bytes:
        return TWO_BYTE_STRUCT.pack(self.value)

    def __str__(self) -> str:
        return self.to_bytes().decode()


@dataclass(frozen=True)
class LabelSequence:
    domain: str
    __packed: bytes

    @classmethod
    def create(cls, domain: str):
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

    def to_bytes(self) -> bytes:
        return self.__packed

    def __str__(self) -> str:
        return self.__packed.decode()


@dataclass(frozen=True)
class DNSQuestion:
    label_seq: LabelSequence
    record_type: DNSRecordType

    __packed: bytes

    _class: int = 1

    @classmethod
    def create(cls, domain: str, record_type: DNSRecordType):
        lbl_seq = LabelSequence.create(domain)

        packed = lbl_seq.to_bytes() + record_type.to_bytes() + ONE_AS_SHORT

        return cls(lbl_seq, record_type, packed)

    @property
    def domain(self) -> str:
        return self.label_seq.domain

    def to_bytes(self) -> bytes:
        return self.__packed
