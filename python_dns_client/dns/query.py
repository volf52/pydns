# -*- coding: utf-8 -*-
from python_dns_client.dns.header import DNSHeader
from python_dns_client.dns.packet import DNSPacket
from python_dns_client.dns.question import DNSQuestion
from python_dns_client.dns.record import DNSRecordType


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
    def text_query(domain: str) -> DNSPacket:
        return DNSQuery.create(domain, DNSRecordType.TXT)
