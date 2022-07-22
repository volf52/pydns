# -*- coding: utf-8 -*-
from pydns.dns.header import DNSHeader
from pydns.dns.packet import DNSPacket
from pydns.dns.question import DNSQuestion
from pydns.dns.record import DNSRecordType


class DNSQuery:
    @staticmethod
    def create(domain: str, record_type: DNSRecordType) -> DNSPacket:
        header = DNSHeader.query_header(1)
        question = DNSQuestion.create(domain, record_type)

        return DNSPacket(header, [question])

    @staticmethod
    def ip_query(domain: str) -> DNSPacket:
        return DNSQuery.create(domain, DNSRecordType.A)

    @staticmethod
    def cname_query(domain: str) -> DNSPacket:
        return DNSQuery.create(domain, DNSRecordType.CNAME)

    @staticmethod
    def ip_v6_query(domain: str) -> DNSPacket:
        return DNSQuery.create(domain, DNSRecordType.AAAA)
