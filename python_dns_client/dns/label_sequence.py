# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass

from python_dns_client.shared.constants import NULL_BYTE, ONE_BYTE_STRUCT
from python_dns_client.shared.protocols import Packable


@dataclass(frozen=True)
class LabelSequence(Packable):
    domain: str
    __packed: bytes

    @classmethod
    def create(cls, domain: str) -> LabelSequence:
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
    def parse(cls, b: bytes) -> tuple[LabelSequence, bytes]:
        domain_parts = []
        idx = 0
        total_len = len(b)

        part_length: int
        while idx < total_len and (part_length := b[idx]) != 0:
            # part_length = b[idx]

            if idx + part_length >= total_len:
                raise ValueError(
                    f"Invalid part length at idx {idx} for label sequence {b!r}"
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
