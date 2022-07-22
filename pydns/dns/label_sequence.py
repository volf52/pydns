# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

import pydns.shared.utils as utils
from pydns.dns.buffer import DNSBuffer
from pydns.shared.constants import NULL_BYTE, ONE_BYTE_STRUCT, TWO_BYTE_STRUCT
from pydns.shared.protocols import Packable


@dataclass(frozen=True)
class LabelSequence(Packable):
    domain: str
    __packed: bytes

    JMP_BYTE: ClassVar = 0xC0
    JMP_MASK: ClassVar = 0xC000

    @classmethod
    def create(cls, domain: str) -> LabelSequence:
        b = []
        for part in domain.split("."):
            b.append(ONE_BYTE_STRUCT.pack(len(part)).decode())
            b.extend(part)

        packed = "".join(b).encode()
        packed += NULL_BYTE

        return LabelSequence(domain, packed)

    @classmethod
    def parse(cls, b: bytes):
        return cls.parse_from(DNSBuffer.create(b))

    @classmethod
    def parse_from(cls, buff: DNSBuffer) -> LabelSequence:
        domain_parts = []
        init_pos = buff.pos
        total_len = len(buff)

        if utils.is_set(buff.peek, LabelSequence.JMP_BYTE):
            assert buff.remaining >= 2

            jmp_bytes = buff.get(2)
            (jmp_idx,) = TWO_BYTE_STRUCT.unpack(jmp_bytes)

            jmp_idx ^= LabelSequence.JMP_MASK
            assert jmp_idx <= buff.pos

            return cls.parse(buff.get_slice(jmp_idx))

        part_length: int
        while (idx := buff.pos) < total_len and (
            part_length := buff.pop()
        ) != 0:
            if idx + part_length >= total_len:
                raise ValueError(
                    f"Invalid part length at idx {idx} for label sequence {buff!r}"
                )

            b = buff.get(part_length)
            part = b.decode()
            domain_parts.append(part)

        domain = ".".join(domain_parts)
        b = buff.get_slice(init_pos, buff.pos + 1)

        return LabelSequence(domain, b)

    def to_bytes(self) -> bytes:
        return self.__packed

    def __str__(self) -> str:
        return f"LBL = {self.domain}"

    def __len__(self) -> int:
        return len(self.__packed)
