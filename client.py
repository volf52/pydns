# -*- coding: utf-8 -*-
import socket

from python_dns_client.dns.packet import DNSPacket
from python_dns_client.dns.query import DNSQuery

DNS_SERVER = "8.8.8.8"
DNS_PORT = 53

# googlev6 = 2a00:1450:4019:80a::200e

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    print("Connecting...")
    sock.connect((DNS_SERVER, DNS_PORT))
    print("Connected!")

    query = DNSQuery.ip_v6_query("google.com")
    query_bytes = query.to_bytes()

    sock.send(query_bytes)

    resp = sock.recv(1024)

    # with open("test_data/test_resp", "wb") as f:
    #     f.write(resp)

    resp_packet = DNSPacket.parse(resp)
    assert resp_packet.header.an_count > 0

    print(resp_packet.answers[-1].rdata)
finally:
    sock.close()
    print("Done")
