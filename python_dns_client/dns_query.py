from python_dns_client.dns_packet import DNSPacket
from python_dns_client.header import DNSHeader
from python_dns_client.question import DNSQuestion, DNSRecordType


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
