# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field

from python_dns_client.dns.buffer import DNSBuffer
from python_dns_client.dns.header import DNSHeader
from python_dns_client.dns.question import DNSQuestion
from python_dns_client.dns.response import DNSResponse
from python_dns_client.shared.protocols import Packable


@dataclass
class DNSPacket(Packable):
    header: DNSHeader

    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSResponse] = field(default_factory=list)
    # authority: list[Packable] = field(default_factory=list)
    # additional: list[Packable] = field(default_factory=list)

    @classmethod
    def parse(cls, b: bytes):
        return cls.parse_from(DNSBuffer.create(b))

    @classmethod
    def parse_from(cls, buff: DNSBuffer) -> DNSPacket:
        header = DNSHeader.parse_from(buff)

        # todo: add check for resp code

        questions = cls._parse_questions(
            header.qd_count,
            buff,
        )
        answers = cls._parse_answers(header.an_count, buff)

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
        n_q: int,
        buff: DNSBuffer,
    ) -> list[DNSQuestion]:
        questions: list[DNSQuestion] = []

        while n_q > 0:
            q = DNSQuestion.parse_from(buff)
            questions.append(q)
            n_q -= 1

        return questions

    @staticmethod
    def _parse_answers(n_ans: int, buff: DNSBuffer) -> list[DNSResponse]:
        responses = []

        while n_ans > 0:
            ans = DNSResponse.parse_from(buff)
            responses.append(ans)
            n_ans -= 1

        return responses
