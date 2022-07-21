# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field

from python_dns_client.dns.header import DNSHeader
from python_dns_client.dns.question import DNSQuestion
from python_dns_client.shared.protocols import Packable


@dataclass
class DNSPacket(Packable):
    header: DNSHeader

    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[Packable] = field(default_factory=list)
    # authority: list[Packable] = field(default_factory=list)
    # additional: list[Packable] = field(default_factory=list)

    @classmethod
    def parse(cls, b: bytes) -> DNSPacket:
        header = DNSHeader.parse(b[:12])

        # todo: add check for resp code

        b = b[12:]
        questions, b = cls._parse_questions(header.qd_count, b)
        answers, b = cls._parse_answers(header.an_count, b)

        return cls(header, questions, answers)

    def to_bytes(self) -> bytes:
        b = [self.header.to_bytes()]

        b.extend((q.to_bytes() for q in self.questions))
        b.extend((q.to_bytes() for q in self.answers))
        # b.extend((q.to_bytes() for q in self.authority))
        # b.extend((q.to_bytes() for q in self.additional))

        return b"".join(b)

    @staticmethod
    def _parse_questions(
        n_q: int, b: bytes
    ) -> tuple[list[DNSQuestion], bytes]:
        questions: list[DNSQuestion] = []

        while n_q > 0:
            q, b = DNSQuestion.parse(b)
            questions.append(q)
            n_q -= 1

        return questions, b

    @staticmethod
    def _parse_answers(n_ans: int, b: bytes) -> tuple[list[Packable], bytes]:
        # todo: parse answers

        return [], b
