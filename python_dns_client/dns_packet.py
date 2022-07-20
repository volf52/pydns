from dataclasses import dataclass, field

from python_dns_client.header import DNSHeader
from python_dns_client.question import DNSQuestion, DNSRecordType


@dataclass
class DNSPacket:
    header: DNSHeader

    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[None] = field(default_factory=list)
    authority: list[None] = field(default_factory=list)
    additional: list[None] = field(default_factory=list)

    @classmethod
    def create(cls, domain: str, record_type: DNSRecordType):
        header = DNSHeader.query_header(1)
        question = DNSQuestion.create(domain, record_type)

        return cls(header, [question])

    @classmethod
    def ip_query(cls, domain: str):
        return cls.create(domain, DNSRecordType.A)

    def to_bytes(self) -> bytes:
        b = [self.header.to_bytes()]
        b.extend((q.to_bytes() for q in self.questions))

        return b"".join(b)
